/* Copyright (c) Citrix Systems Inc.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms,
 * with or without modification, are permitted provided
 * that the following conditions are met:
 *
 * *   Redistributions of source code must retain the above
 *     copyright notice, this list of conditions and the
 *     following disclaimer.
 * *   Redistributions in binary form must reproduce the above
 *     copyright notice, this list of conditions and the
 *     following disclaimer in the documentation and/or other
 *     materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND
 * CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES,
 * INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR
 * CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */
/*
 * uXen changes:
 *
 * Copyright 2015-2019, Bromium, Inc.
 * SPDX-License-Identifier: ISC
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
 * SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION
 * OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
 * CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include "uxenv4vlib_private.h"

static __inline VOID
gh_v4v_requeue_irps(xenv4v_extension_t *pde, LIST_ENTRY *irps)
{
    NTSTATUS    status;
    PIRP        nextIrp = NULL;
    PLIST_ENTRY   next = NULL;

    // Put the IRPs back. They are returned in the order the were pulled off and
    // chained in the original queue. In the case of destination send processing
    // this could cause reordering in the main queue but this is mostly OK. The
    // calling routines do this after their main processing loops so they don't
    // keep picking up the same IRPs.
    //
    // Note that the tiny window where the file went to CLOSED but we put an IRP
    // back is handled by the second IRP cancellation call in gh_v4v_release_context_internal().
    while (!IsListEmpty(irps)) {
        next = irps->Flink;
        nextIrp = CONTAINING_RECORD(next, IRP, Tail.Overlay.ListEntry);
        RemoveEntryList(&nextIrp->Tail.Overlay.ListEntry);
        InitializeListHead(&nextIrp->Tail.Overlay.ListEntry);
        status = IoCsqInsertIrpEx(&pde->csq_object, nextIrp, NULL, NULL);
        if (!NT_SUCCESS(status)) {
            v4v_simple_complete_irp(nextIrp, status);
        }
    }
}

// ---- WRITE ROUTINES ----

static ULONG32
gh_v4v_get_write_irp_values(xenv4v_context_t *ctx, PIRP irp, v4v_addr_t *dstOut, uint8_t **msgOut, uint32_t *lenOut, uint32_t *dg_flags_out)
{
    PIO_STACK_LOCATION  isl = IoGetCurrentIrpStackLocation(irp);

    // For datagrams, destination is in the message
    v4v_datagram_t *dg = (v4v_datagram_t *) irp->MdlAddress->MappedSystemVa;
    *dstOut = dg->addr;
    *dg_flags_out = dg->flags;
    *msgOut = ((UCHAR *)(dg + 1));
    *lenOut = isl->Parameters.Write.Length - sizeof(v4v_datagram_t);
    return V4V_PROTO_DGRAM;
}

static NTSTATUS
gh_v4v_do_write(xenv4v_extension_t *pde, xenv4v_context_t *ctx, PIRP irp)
{
    NTSTATUS    status;
    v4v_addr_t  dst;
    uint8_t    *msg = NULL;
    uint32_t    len;
    uint32_t    dg_flags = 0;
    ULONG32     written = 0;
    ULONG32     protocol;
    ULONG_PTR   flags;
    v4v_stream_t  sh;
    v4v_iov_t   iovs[2];
    int ax = !!(ctx->flags & V4V_FLAG_AX);

    // Already checked that the buffer is big enough for a v4v dgram header and not
    // an issue for streams. Also took care of 0 length drgam writes. Call helper to
    // get relevant values.
    protocol = gh_v4v_get_write_irp_values(ctx, irp, &dst, &msg, &len, &dg_flags);
    flags = (ULONG_PTR)irp->Tail.Overlay.DriverContext[0];
    written = 0;

    if (ctx->ring_object->ring->id.partner != V4V_DOMID_ANY)
        dst.domain = ctx->ring_object->ring->id.partner;

    status = gh_v4v_send(&ctx->ring_object->ring->id.addr, &dst, ax, protocol,
      msg, len, &written);

    if ((status == STATUS_VIRTUAL_CIRCUIT_CLOSED) && (!(dg_flags & V4V_DATAGRAM_FLAG_IGNORE_DLO))) {
        uxen_v4v_warn("ring src (vm%u:%x vm%u) dst (vm%u:%x) - creating placeholder ring",
                      ctx->ring_object->ring->id.addr.domain,
                      ctx->ring_object->ring->id.addr.port,
                      ctx->ring_object->ring->id.partner,
                      dst.domain,
                      dst.port);
        // Datagram write to a ring which doesn't exist - use the dead letter office to handle it
        status = gh_v4v_create_ring(&dst, ctx->ring_object->ring->id.addr.domain, ax);
        if (!NT_SUCCESS(status)) {
            uxen_v4v_err("ring src (vm%u:%x vm%u) dst (vm%u:%x) - failed to create placeholder ring, status %x",
                         ctx->ring_object->ring->id.addr.domain,
                         ctx->ring_object->ring->id.addr.port,
                         ctx->ring_object->ring->id.partner,
                         dst.domain,
                         dst.port,
                         status);
            return v4v_simple_complete_irp(irp, status);
        }
        status = gh_v4v_send(&ctx->ring_object->ring->id.addr, &dst, ax, protocol, msg, len, &written);
    }

    // Datagram write, add on the ammount send by caller
    written += sizeof(v4v_datagram_t);


    if (status == STATUS_RETRY) {
        // Ring is full, just return retry
        return status;
    } else if (status == STATUS_NO_MEMORY) {
        // No memory, retry later
        uxen_v4v_err("ring src (vm%u:%x vm%u) dst (vm%u:%x)- error during send, status %x - no memory",
                     ctx->ring_object->ring->id.addr.domain,
                     ctx->ring_object->ring->id.addr.port,
                     ctx->ring_object->ring->id.partner,
                     dst.domain,
                     dst.port,
                     status);
        return status;
    } else if (!NT_SUCCESS(status)) {
        uxen_v4v_err("ring src (vm%u:%x vm%u) dst (vm%u:%x)- error during send, status %x",
                     ctx->ring_object->ring->id.addr.domain,
                     ctx->ring_object->ring->id.addr.port,
                     ctx->ring_object->ring->id.partner,
                     dst.domain,
                     dst.port,
                     status);

        // Actual error, dump it and try another one
        return v4v_simple_complete_irp(irp, status);
    }

    // Complete it here with bytes written. Indicate that we consumed
    // the appropriate size.
    irp->IoStatus.Information = written;
    irp->IoStatus.Status = STATUS_SUCCESS;
    IoCompleteRequest(irp, IO_NO_INCREMENT);

    return STATUS_SUCCESS;
}

static VOID
gh_v4v_process_destination_writes(xenv4v_extension_t *pde, v4v_ring_data_ent_t *entry)
{
    NTSTATUS            status;
    xenv4v_qpeek_t        peek;
    PIRP                nextIrp = NULL;
    xenv4v_context_t     *ctx = NULL;
    KLOCK_QUEUE_HANDLE  lqh;
    LIST_ENTRY          returnIrps;
    ULONG               counter = 0;
    int                 queue_notify = 0;

    peek.ops   = XENV4V_PEEK_WRITE;    // writes ops
    peek.pfo   = NULL;                 // not using file object search

    InitializeListHead(&returnIrps);

    do {
        // Grab an IRP by destination
        peek.dst = entry->ring; // using destination search
        nextIrp = IoCsqRemoveNextIrp(&pde->csq_object, &peek);
        if (nextIrp == NULL) {
            break;
        }

        // N.B. The assumption is that if the CSQ returned the IRP then the IRP is valid and
        // by extension the file object and all its state must still be intact so safe to access.
        ctx = (xenv4v_context_t *)IoGetCurrentIrpStackLocation(nextIrp)->FileObject->FsContext;

        // Lock our ring to access it
        KeAcquireInStackQueuedSpinLock(&ctx->ring_object->lock, &lqh);

        // In the case of the first write, check the flag to see if the next size we reported will
        // fit at this point, if not then end here. If we get the first item in then we can just try
        // subsequent writes. If any fail with retry, we will get an interrupt later.
        if (((entry->flags & V4V_RING_DATA_F_EXISTS) != 0) && (counter == 0) &&
            ((entry->flags & V4V_RING_DATA_F_SUFFICIENT) == 0)) {
            KeReleaseInStackQueuedSpinLock(&lqh);
            InsertTailList(&returnIrps, &nextIrp->Tail.Overlay.ListEntry);
            break;
        }

        // Call the send helper to do the actual send of the data to the ring. For
        // all non retry/pending statuses, IRPs are completed internally.
        // If destination is closed, attempt write anyway to trigger DLO.
        status = gh_v4v_do_write(pde, ctx, nextIrp);

        // Unlock the ring to lower contention before processing the final send status
        KeReleaseInStackQueuedSpinLock(&lqh);

        // Process the send status
        if (status == STATUS_RETRY) {
            // Ring is full, put the IRP back and try another. Since we got retry
            // we can just break and wait for the next interrupt.
            InsertTailList(&returnIrps, &nextIrp->Tail.Overlay.ListEntry);
            break;
        } else if (status == STATUS_NO_MEMORY) {
            // Requeue & retry later
            uxen_v4v_err("ring src (vm%u:%x vm%u) no memory - retry later",
                ctx->ring_object->ring->id.addr.domain,
                ctx->ring_object->ring->id.addr.port,
                ctx->ring_object->ring->id.partner);
            InsertTailList(&returnIrps, &nextIrp->Tail.Overlay.ListEntry);
            queue_notify++;
            break;
        } else if (status == STATUS_PENDING) {
            // This was a connect SYN successfully written and swizzled. Requeue it, bump counter and
            // go on.
            InsertTailList(&returnIrps, &nextIrp->Tail.Overlay.ListEntry);
            counter++;
        } else if (NT_SUCCESS(status)) {
            // Send successful, update counter and just come around
            counter++;
        }
        // Else if it failed, gh_v4v_do_write() completed it internally.
    } while (TRUE);

    // Put the uncompleted ones back
    gh_v4v_requeue_irps(pde, &returnIrps);
    if (queue_notify)
        KeSetEvent(&pde->virq_event, IO_NO_INCREMENT, FALSE);
}

NTSTATUS
gh_v4v_process_notify(xenv4v_extension_t *pde)
{
    NTSTATUS         status;
    ULONG            i;
    ULONG        gh_count;
    v4v_ring_data_t *ringData;
    int ax;

    for (ax = 0; ax <= 1; ax++) {
      ringData = gh_v4v_copy_destination_ring_data(pde, !!ax, &gh_count);
      if (ringData == NULL) {
        uxen_v4v_err("gh_v4v_copy_destination_ring_data failed");
        return STATUS_UNSUCCESSFUL;
      }

      if (ax && (gh_count == 0)) {
        uxen_v4v_fast_free(ringData);
        continue;
      }

      // Now do the actual notify
      status = gh_v4v_notify(ringData, ax);
      if (!NT_SUCCESS(status)) {
        // That ain't good
        uxen_v4v_fast_free(ringData);
        return status;
      }

      // Process each of the destinations
      for (i = 0; i < gh_count; i++) {
        gh_v4v_process_destination_writes(pde, &ringData->data[i]);
      }

      if (ringData->nent > gh_count)
        uxen_v4v_notify_process_ring_data(pde,  &ringData->data[gh_count], ringData->nent - gh_count);

      uxen_v4v_fast_free(ringData);
    }

    return STATUS_SUCCESS;
}

VOID
gh_v4v_process_context_writes(xenv4v_extension_t *pde, xenv4v_context_t *ctx)
{
    NTSTATUS           status;
    KLOCK_QUEUE_HANDLE lqh;
    PIRP               nextIrp = NULL;
    xenv4v_qpeek_t       peek;
    LIST_ENTRY         returnIrps;
    int queue_notify = 0;

    peek.ops   = XENV4V_PEEK_WRITE;    // writes ops
    peek.pfo   = ctx->pfo_parent;       // for a specific file object

    InitializeListHead(&returnIrps);

    // For datagram writes, we always have a 1 to 1 file to ring relationship so we
    // lock the ring and start popping out pending IRPs either from the write dispatch
    // handler or the VIRQ DPC.
    KeAcquireInStackQueuedSpinLock(&ctx->ring_object->lock, &lqh);

    do {
        // Any IRPs to work with
        nextIrp = IoCsqRemoveNextIrp(&pde->csq_object, &peek);
        if (nextIrp == NULL) {
            // No more IRPs, we are done here.
            break;
        }

        // Call the send helper to do the actual send of the data to the ring. For
        // all non retry statuses, IRPs are completed internally.
        status = gh_v4v_do_write(pde, ctx, nextIrp);
        if (status == STATUS_RETRY) {
            // Ring is full, put the IRP back and try another.
            InsertTailList(&returnIrps, &nextIrp->Tail.Overlay.ListEntry);
            queue_notify++;
        } else if (status == STATUS_NO_MEMORY) {
             uxen_v4v_err("ring src (vm%u:%x vm%u) no memory - retry later",
                ctx->ring_object->ring->id.addr.domain,
                ctx->ring_object->ring->id.addr.port,
                ctx->ring_object->ring->id.partner);
           // No memory, put IRP back and retry later
            InsertTailList(&returnIrps, &nextIrp->Tail.Overlay.ListEntry);
            queue_notify++;
            break;
        }
    } while (TRUE);

    KeReleaseInStackQueuedSpinLock(&lqh);

    // Put the uncompleted ones back
    gh_v4v_requeue_irps(pde, &returnIrps);

    if (queue_notify)
        KeSetEvent(&pde->virq_event, IO_NO_INCREMENT, FALSE);
}

NTSTATUS NTAPI
gh_v4v_dispatch_write(PDEVICE_OBJECT fdo, PIRP irp)
{
    NTSTATUS            status = STATUS_SUCCESS;
    xenv4v_extension_t   *pde = v4v_get_device_extension(fdo);
    PIO_STACK_LOCATION  isl = IoGetCurrentIrpStackLocation(irp);
    xenv4v_context_t     *ctx;
    LONG                val, ds;
    ULONG_PTR           flags = 0;
    ULONG_PTR           dcs[2] = {0, 0};

    TraceReadWrite(("====> '%s'.\n", __FUNCTION__));


    if (isl->Parameters.Write.Length > XENV4V_MAX_RING_LENGTH)
        return v4v_simple_complete_irp(irp, STATUS_INVALID_DEVICE_REQUEST);

    ctx = (xenv4v_context_t *)isl->FileObject->FsContext;
    val = InterlockedExchangeAdd(&ctx->state, 0);
    ds  = InterlockedExchangeAdd(&pde->state, 0);

    // Store any context values passed down by internal writes
    dcs[0] = (ULONG_PTR)irp->Tail.Overlay.DriverContext[0];
    dcs[1] = (ULONG_PTR)irp->Tail.Overlay.DriverContext[1];

    // Any IRPs that are queued are given a sanity initialization
    v4v_initialize_irp(irp);


    switch (val) {
        case XENV4V_STATE_BOUND:
            // Input check for datagram header
            if (isl->Parameters.Write.Length < sizeof(v4v_datagram_t)) {
                return v4v_simple_complete_irp(irp, STATUS_BUFFER_TOO_SMALL);
            }

            // N.B. zero length datagram writes are still dispatched through the hypercall since they
            // can be used to test that the other end is still there.

            // Store the state we have for servicing this IRP
            irp->Tail.Overlay.DriverContext[0] = (PVOID)(ULONG_PTR)(XENV4V_PEEK_WRITE);
            break;
        default:
            uxen_v4v_warn("ctx %p invalid state 0x%x for "
                          "write IRP request %p", ctx, val, irp);
            return v4v_simple_complete_irp(irp, STATUS_INVALID_DEVICE_REQUEST);
    }

    // The rest is common to both types

    // Map in the DIRECT IO locked MDL - do it once up front since we will access it
    // from the Q. If the length is zero, don't touch the MDL, it is NULL.
    if (isl->Parameters.Write.Length > 0) {
        if (MmGetSystemAddressForMdlSafe(irp->MdlAddress, NormalPagePriority) == NULL) {
            return v4v_simple_complete_irp(irp, STATUS_NO_MEMORY);
        }

#if defined(XENV4V_WRITE_RO_PROTECT) && defined(DBG)
        status = MmProtectMdlSystemAddress(irp->MdlAddress, PAGE_READONLY);
        if (!NT_SUCCESS(status)) {
            return v4v_simple_complete_irp(irp, status);
        }
#endif

    }

    // Always queue it to the back and marks it pending (except RSTs)
    status = IoCsqInsertIrpEx(&pde->csq_object, irp, NULL, NULL);
    if (NT_SUCCESS(status)) {
        status = STATUS_PENDING;

        // Drive any write IO unless the device is stopped.
        if ((ds & XENV4V_DEV_STOPPED) == 0) {
            gh_v4v_process_context_writes(pde, ctx);
        }
    } else {
        // Fail it
        v4v_simple_complete_irp(irp, status);
    }

    TraceReadWrite(("<==== '%s'.\n", __FUNCTION__));

    return status;
}

// ---- READ ROUTINES ----

static VOID
gh_v4v_process_datagram_reads_quick(xenv4v_extension_t *pde, xenv4v_context_t *ctx)
{
    if (ctx->ring_object->ring_is_mapped) {
        // The ring is mapped so we just signal to userland to do the work
        if (ctx->ring_object->ring->rx_ptr == ctx->ring_object->ring->tx_ptr) {
            KeClearEvent(ctx->receive_event);
            return;
        } else {
            KeSetEvent(ctx->receive_event, EVENT_INCREMENT, FALSE);
            return;
        }
    }
}



static VOID
gh_v4v_process_datagram_reads(xenv4v_extension_t *pde, xenv4v_context_t *ctx, BOOLEAN *pntfy)
{
    KLOCK_QUEUE_HANDLE  lqh;
    PIRP                nextIrp = NULL;
    PIO_STACK_LOCATION  isl;
    xenv4v_qpeek_t        peek;
    v4v_addr_t         *src = NULL;
    uint8_t            *msg = NULL;
    uint32_t            len;
    uint32_t            protocol;
    ssize_t             ret;

  is_mapped_now:
    if (ctx->ring_object->ring_is_mapped) {
        // The ring is mapped so we just signal to userland to do the work
        if (ctx->ring_object->ring->rx_ptr == ctx->ring_object->ring->tx_ptr) {
            KeClearEvent(ctx->receive_event);
            return;
        } else {
            KeSetEvent(ctx->receive_event, EVENT_INCREMENT, FALSE);
            return;
        }
    }


    peek.ops   = XENV4V_PEEK_READ;  // read ops
    peek.pfo   = ctx->pfo_parent;    // for a specific file object

    // For datagram reads, we always have a 1 to 1 file to ring relationship so we
    // lock the ring and start popping out pending IRPs either from the read dispatch
    // handler or the VIRQ DPC.
    KeAcquireInStackQueuedSpinLock(&ctx->ring_object->lock, &lqh);

    // Re-check ring_is_mapped with lock held
    if (ctx->ring_object->ring_is_mapped) {
        KeReleaseInStackQueuedSpinLock(&lqh);
        goto is_mapped_now;
    }

    do {
        if (ctx->ring_object->ring->rx_ptr == ctx->ring_object->ring->tx_ptr) {
            // No data so clear any events
            KeClearEvent(ctx->receive_event);
            break; // no more to read
        }

        // Is data to read, anybody waiting?
        nextIrp = IoCsqRemoveNextIrp(&pde->csq_object, &peek);
        if (nextIrp == NULL) {
            // Nobody to accept it so set the data ready event for clients who use it.
            KeSetEvent(ctx->receive_event, EVENT_INCREMENT, FALSE);
            break;
        }

        // Already checked there is room for the header in IRP buffer when it was queued
        isl = IoGetCurrentIrpStackLocation(nextIrp);
        src = (v4v_addr_t *)nextIrp->MdlAddress->MappedSystemVa;
        msg = ((UCHAR *)nextIrp->MdlAddress->MappedSystemVa) + sizeof(v4v_datagram_t);
        len = isl->Parameters.Read.Length - sizeof(v4v_datagram_t);
        ret = v4v_copy_out_safe(ctx->ring_object->ring,
                                ctx->ring_object->ring_length, src,
                                &protocol, msg, len, 1);
        if (ret < 0) {
            uxen_v4v_err("ctx %p failure reading data into IRP %p", ctx,
                         nextIrp);
            gh_v4v_recover_ring(ctx);
            // Fail this IRP - let caller know there is a mess
            v4v_simple_complete_irp(nextIrp, STATUS_INTERNAL_DB_CORRUPTION);
            continue;
        }

        // Ok, successfully read 0 or more bytes and consumed one message
        nextIrp->IoStatus.Information = ret + sizeof(v4v_datagram_t);
        nextIrp->IoStatus.Status = STATUS_SUCCESS;
        IoCompleteRequest(nextIrp, IO_NO_INCREMENT);

        // If we did a read, we need to notify the v4v backend (and process any writes
        // that are pending while we are at it).
        XENV4V_SET_BOOL_PTR(pntfy);
    } while (TRUE);

    KeReleaseInStackQueuedSpinLock(&lqh);
}


VOID
gh_v4v_process_context_reads_quick(xenv4v_extension_t *pde, xenv4v_context_t *ctx)
{
    LONG val;

    // Reads can be processed by the current state of the context because it
    // it is during reads that the context can progress to the next state. It
    // is possible to use a ring for datagrams and later switch it to a stream
    // ring but there is no way back to the bound datagram state so we treat it
    // as a one way street.
    val = InterlockedExchangeAdd(&ctx->state, 0);
    switch (val) {
        case XENV4V_STATE_BOUND:
            gh_v4v_process_datagram_reads_quick(pde, ctx);
            break;
        default:
            break;
    };
}


VOID
gh_v4v_process_context_reads(xenv4v_extension_t *pde, xenv4v_context_t *ctx)
{
    LONG val;

    // Reads can be processed by the current state of the context because it
    // it is during reads that the context can progress to the next state. It
    // is possible to use a ring for datagrams and later switch it to a stream
    // ring but there is no way back to the bound datagram state so we treat it
    // as a one way street.
    val = InterlockedExchangeAdd(&ctx->state, 0);
    switch (val) {
        case XENV4V_STATE_CLOSED:
            // Must have just closed - the cleanup dispatch routine will cancel any
            // IRPs for it so just ignore it.
            return;
        case XENV4V_STATE_BOUND:
            gh_v4v_process_datagram_reads(pde, ctx, NULL);
            break;
        default:
            // May be freshly opened file that has not been bound, just ignore.
            break;
    };
}

NTSTATUS NTAPI
gh_v4v_dispatch_read(PDEVICE_OBJECT fdo, PIRP irp)
{
    NTSTATUS            status = STATUS_SUCCESS;
    PIO_STACK_LOCATION  isl = IoGetCurrentIrpStackLocation(irp);
    xenv4v_extension_t   *pde = v4v_get_device_extension(fdo);
    xenv4v_context_t     *ctx;
    LONG                val, ds;
    BOOLEAN             notify = FALSE;

    if (isl->Parameters.Read.Length > XENV4V_MAX_RING_LENGTH)
        return v4v_simple_complete_irp(irp, STATUS_INVALID_DEVICE_REQUEST);

    TraceReadWrite(("====> '%s'.\n", __FUNCTION__));

    ctx = (xenv4v_context_t *)isl->FileObject->FsContext;
    val = InterlockedExchangeAdd(&ctx->state, 0);
    ds  = InterlockedExchangeAdd(&pde->state, 0);

    // Any IRPs that are queued are given a sanity initialization
    v4v_initialize_irp(irp);

    // Map in the DIRECT IO locked MDL - do it once up front since we will access it
    // from the Q. We can do this up front since we are only dealing with READ IRPs.
    // Don't touch the MDL if the read length is zero.
    if (isl->Parameters.Read.Length > 0) {
        if (MmGetSystemAddressForMdlSafe(irp->MdlAddress, NormalPagePriority) == NULL) {
            return v4v_simple_complete_irp(irp, STATUS_NO_MEMORY);
        }
    }

    switch (val) {
        case XENV4V_STATE_BOUND:
            // Input check for datagram header - this weeds out zero length reads too.
            if (isl->Parameters.Read.Length < sizeof(v4v_datagram_t)) {
                status = v4v_simple_complete_irp(irp, STATUS_BUFFER_TOO_SMALL);
                break;
            }

            // Store the state we have for servicing this IRP
            irp->Tail.Overlay.DriverContext[0] = (PVOID)(ULONG_PTR)(XENV4V_PEEK_READ);
            // Always queues it to the back and marks it pending
            status = IoCsqInsertIrpEx(&pde->csq_object, irp, NULL, NULL);
            if (!NT_SUCCESS(status)) {
                v4v_simple_complete_irp(irp, status);
                break;
            }
            status = STATUS_PENDING;

            // If device is stopped, just leave it pended
            if (ds & XENV4V_DEV_STOPPED) {
                break;
            }

            // Drive any read IO
            gh_v4v_process_datagram_reads(pde, ctx, &notify);
            break;
        default:
            uxen_v4v_warn("ctx %p invalid state 0x%x for "
                          "read IRP request %p", ctx, val, irp);
            status = v4v_simple_complete_irp(irp, STATUS_INVALID_DEVICE_REQUEST);
    }

    // If we did a read, we need to notify the v4v backend (and process any writes
    // that are pending while we are at it).
    if (notify) {
        gh_v4v_process_notify(pde);
    }

    TraceReadWrite(("<==== '%s'.\n", __FUNCTION__));

    return status;
}
