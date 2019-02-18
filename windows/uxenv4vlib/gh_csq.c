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

// N.B. Do not put any code in here that calls the CSQ routines because
// this will require the inclusion of csq.h which causes many compile errors.
// Making CSQ calls w/o the header will implicitly link the DDI's exported
// from ntoskrnl - this is bad.

static __inline VOID
gh_v4v_csq_get_destination(PIRP irp, v4v_addr_t **dstOut)
{
    // Datagrams, destination is in the message
    *dstOut = (v4v_addr_t *)irp->MdlAddress->MappedSystemVa;
}

static BOOLEAN
gh_v4v_csq_peek_test(PIRP irp, PVOID peekContext)
{
    xenv4v_qpeek_t       *qp = (xenv4v_qpeek_t *)peekContext;
    PIO_STACK_LOCATION  isl = IoGetCurrentIrpStackLocation(irp);
    xenv4v_destination_t *idst;
    ULONG_PTR           ops   = (ULONG_PTR)irp->Tail.Overlay.DriverContext[0] & XENV4V_PEEK_ANY_OP;

    // First, the types and ops always have to match
    if (qp->ops & ops) {
        // Next we are either searching by file object or destination
        if (qp->pfo == NULL) {
            // If no desitination was supplied, just match it
            if (qp->dst.domain == DOMID_INVALID) {
                return TRUE;
            }
            // Search by destination, safely use the stashed dest record.
            idst = (xenv4v_destination_t *)irp->Tail.Overlay.DriverContext[1];
            if (XENV4V_ADDR_COMPARE(qp->dst, idst->dst)) {
                return TRUE; // destination address match
            }
        } else if (isl->FileObject == qp->pfo) {
            return TRUE; // file object match
        }
    }

    return FALSE;
}

static VOID
gh_v4v_csq_chain_irp(xenv4v_destination_t *xdst, PIRP irp, BOOLEAN front)
{
    xenv4v_destination_t *idst;
    PIRP                nextIrp = NULL;

    // If we found a destination then there is at least one entry in the list
    // so chain this irp at the end unless front is specified. In this case
    // the IRP is being pushed up front on the list and the length is updated.
    nextIrp = xdst->nextIrp;
    ASSERT(nextIrp != NULL);

    if (!front) {
        while (nextIrp != NULL) {
            idst = (xenv4v_destination_t *)nextIrp->Tail.Overlay.DriverContext[1];

            if (idst->nextIrp == NULL) {
                idst->nextIrp = irp;
                break;
            }
            nextIrp = idst->nextIrp;
        }
    } else {
        xdst->nextIrp = irp;
        idst = (xenv4v_destination_t *)irp->Tail.Overlay.DriverContext[1];
        idst->nextIrp = nextIrp;
        xdst->nextLength = xenv4v_payload_data_len(xdst->nextIrp);
    }
}

static VOID
gh_v4v_csq_unchain_irp(xenv4v_destination_t *xdst, PIRP irp)
{
    xenv4v_destination_t *idst, *ldst;
    PIRP                irpLast = NULL;
    PIRP                irpCurr = xdst->nextIrp;

    // Has to be at least one present, just unchain it
    do {
        idst = (xenv4v_destination_t *)irpCurr->Tail.Overlay.DriverContext[1];
        if (irp == irpCurr) {
            if (irpLast == NULL) {
                // Found up front, update next len too
                xdst->nextIrp = idst->nextIrp;
                if (xdst->nextIrp != NULL) {
                    xdst->nextLength = xenv4v_payload_data_len(xdst->nextIrp);
                }
            } else {
                ldst = (xenv4v_destination_t *)irpLast->Tail.Overlay.DriverContext[1];
                ldst->nextIrp = idst->nextIrp;
            }

            // Flag it with an invalid pointer - handy for debugging.
            idst->nextIrp = (PVOID)(ULONG_PTR)(-1);
            return;
        }

        irpLast = irpCurr;
        irpCurr = idst->nextIrp;
    } while (irpCurr != NULL);

    // We should have found it???
    ASSERT(irpCurr != NULL);
}

static BOOLEAN
gh_v4v_csq_link_destination(xenv4v_extension_t *pde, PIRP irp, BOOLEAN front)
{
    xenv4v_destination_t *xdst = NULL;
    xenv4v_destination_t *idst;
    v4v_addr_t         *dst = NULL;
    PLIST_ENTRY         head, next;
    PIO_STACK_LOCATION  isl = IoGetCurrentIrpStackLocation(irp);
    FILE_OBJECT        *pfo;
    xenv4v_context_t   *ctx;

    pfo = isl->FileObject;
    ctx = (xenv4v_context_t *)pfo->FsContext;
    // Get the destination and init things we need
    gh_v4v_csq_get_destination(irp, &dst);
    head = &pde->dest_list;
    next = head->Flink;

    // Allocate a block to hold the destination information needed for unchaining
    // the IRP. During cancelation removal, the IRPs buffer can be freed so we
    // cannot rely on reading the destination information out of the mapped
    // buffer at that point.
    irp->Tail.Overlay.DriverContext[1] =
        ExAllocateFromNPagedLookasideList(&pde->dest_lookaside_list);
    if (irp->Tail.Overlay.DriverContext[1] == NULL) {
        uxen_v4v_err("DriverContext ExAllocateFromNPagedLookasideList failed");
        return FALSE;
    }

    // Some of the fields are not used for the irp's destination record. Only the
    // nextIrp and dst fields.
    idst = (xenv4v_destination_t *)irp->Tail.Overlay.DriverContext[1];
    RtlZeroMemory(idst, sizeof(xenv4v_destination_t));
    idst->dst = *dst;

    while (next != head) {
        xdst = CONTAINING_RECORD(next, xenv4v_destination_t, le);
        if (XENV4V_ADDR_COMPARE(xdst->dst, (*dst))) {
            ASSERT(xdst->refc > 0);
            xdst->refc++;

            // Chain the IRP on this destination entry
            gh_v4v_csq_chain_irp(xdst, irp, front);
            return TRUE;
        }
        next = next->Flink;
    }

    // If we are still here, a destination entry was not found so create a new one
    xdst = (xenv4v_destination_t *)ExAllocateFromNPagedLookasideList(&pde->dest_lookaside_list);
    if (xdst == NULL) {
        ExFreeToNPagedLookasideList(&pde->dest_lookaside_list,
                                    irp->Tail.Overlay.DriverContext[1]);
        irp->Tail.Overlay.DriverContext[1] = NULL;
        uxen_v4v_err("xdst ExAllocateFromNPagedLookasideList failed");
        return FALSE;
    }
    InitializeListHead(&xdst->le);
    xdst->refc = 1;
    xdst->dst = *dst;
    xdst->dst_ax = !!(ctx->flags & V4V_FLAG_AX);
    xdst->nextIrp = irp;
    xdst->nextLength = xenv4v_payload_data_len(irp);
    InsertTailList(&pde->dest_list, &xdst->le);
    pde->dest_count++;

    return TRUE;
}

static VOID
gh_v4v_csq_unlink_destination(xenv4v_extension_t *pde, PIRP irp)
{
    xenv4v_destination_t *xdst;
    xenv4v_destination_t *idst;
    PLIST_ENTRY         head, next;

    ASSERT(pde->dest_count > 0);

    // Get the destination record and init things we need
    idst = (xenv4v_destination_t *)irp->Tail.Overlay.DriverContext[1];
    ASSERT(idst != 0);
    head = &pde->dest_list;
    next = head->Flink;

    while (next != head) {
        xdst = CONTAINING_RECORD(next, xenv4v_destination_t, le);
        if (XENV4V_ADDR_COMPARE(xdst->dst, idst->dst)) {
            ASSERT(xdst->refc > 0);
            ASSERT(xdst->nextIrp != NULL);
            gh_v4v_csq_unchain_irp(xdst, irp);
            ExFreeToNPagedLookasideList(&pde->dest_lookaside_list,
                                        irp->Tail.Overlay.DriverContext[1]);
            irp->Tail.Overlay.DriverContext[1] = NULL;

            xdst->refc--;
            if (xdst->refc == 0) {
                ASSERT(xdst->nextIrp == NULL);
                RemoveEntryList(&xdst->le);
                ExFreeToNPagedLookasideList(&pde->dest_lookaside_list, xdst);
                pde->dest_count--;
            }
            break;
        }
        next = next->Flink;
    }
}

NTSTATUS NTAPI
gh_v4v_csq_insert_irp_ex(PIO_CSQ csq, PIRP irp, PVOID unused)
{
    xenv4v_extension_t *pde = v4v_csq_get_device_extension(csq);
    BOOLEAN insert_head = FALSE;

    ASSERT(((pde->pending_irp_count != 0) || (pde->dest_count == 0)));

    if (pde->pending_irp_count == XENV4V_MAX_IRP_COUNT) {
        uxen_v4v_err("maximun pending IRP count reached!! max: %d",
                     pde->pending_irp_count);
        return STATUS_QUOTA_EXCEEDED;
    }

    if ((ULONG_PTR)irp->Tail.Overlay.DriverContext[0] & XENV4V_PEEK_WRITE) {
        if (!gh_v4v_csq_link_destination(pde, irp, insert_head)) {
            return STATUS_NO_MEMORY;
        }
    }

    // Do this here before we put it on the queue. Once queued we cannot touch the IRP
    // safely outside of CSQ calls.
    IoMarkIrpPending(irp);
    InitializeListHead(&irp->Tail.Overlay.ListEntry);

    // Normally the IRP is inserted at the tail in a queue or re-queue operation. The stream
    // processing may insert it at the head though.
    if (insert_head)
        InsertTailList(&pde->pending_irp_queue, &irp->Tail.Overlay.ListEntry);
    else
        InsertHeadList(&pde->pending_irp_queue, &irp->Tail.Overlay.ListEntry);

    // Bump count
    ASSERT(pde->pending_irp_count >= 0);
    pde->pending_irp_count++;

    return STATUS_SUCCESS;
}

VOID NTAPI
gh_v4v_csq_remove_irp(PIO_CSQ csq, PIRP irp)
{
    xenv4v_extension_t *pde = v4v_csq_get_device_extension(csq);

    if ((ULONG_PTR)irp->Tail.Overlay.DriverContext[0] & XENV4V_PEEK_WRITE)
        gh_v4v_csq_unlink_destination(pde, irp);

    RemoveEntryList(&irp->Tail.Overlay.ListEntry);

    // Clear out dangling list pointers and drop count
    InitializeListHead(&irp->Tail.Overlay.ListEntry);
    pde->pending_irp_count--;
    ASSERT(pde->pending_irp_count >= 0);
    ASSERT(((pde->pending_irp_count != 0) || (pde->dest_count == 0)));
}

PIRP NTAPI
gh_v4v_csq_peek_next_irp(PIO_CSQ csq, PIRP irp, PVOID peekContext)
{
    xenv4v_extension_t *pde = v4v_csq_get_device_extension(csq);
    PIRP              nextIrp = NULL;
    PLIST_ENTRY       head, next;

    head = &pde->pending_irp_queue;

    // If the IRP is NULL, we will start peeking from the head else
    // we will start from that IRP onwards (since irps are inserted
    // at the tail).
    next = ((irp == NULL) ? head->Flink : irp->Tail.Overlay.ListEntry.Flink);

    while (next != head) {
        nextIrp = CONTAINING_RECORD(next, IRP, Tail.Overlay.ListEntry);

        // A context is used during cleanup to remove all IRPs for a given
        // file that has all its handles closed. If there is a context, match it
        // first.
        if (peekContext == NULL) {
            break; // on first one
        }

        if (gh_v4v_csq_peek_test(nextIrp, peekContext)) {
            break; // on first one that matches
        }

        // Onward
        nextIrp = NULL;
        next = next->Flink;
    }

    return nextIrp;
}

VOID NTAPI
gh_v4v_csq_acquire_lock(PIO_CSQ csq, PKIRQL irqlOut)
{
    xenv4v_extension_t *pde = v4v_csq_get_device_extension(csq);

    KeAcquireSpinLock(&pde->queue_lock, irqlOut);
}

VOID NTAPI
gh_v4v_csq_release_lock(PIO_CSQ csq, KIRQL irql)
{
    xenv4v_extension_t *pde = v4v_csq_get_device_extension(csq);

    KeReleaseSpinLock(&pde->queue_lock, irql);
}

VOID NTAPI
gh_v4v_csq_complete_canceled_irp(PIO_CSQ csq, PIRP irp)
{
    xenv4v_extension_t   *pde = v4v_csq_get_device_extension(csq);
    PIO_STACK_LOCATION  isl;
    ULONG               io_control_code;
    xenv4v_context_t     *ctx;
    xenv4v_context_t     *actx;
    struct v4v_addr    *peer;
    v4v_accept_private_t *priv;
    ULONG               size;

    uxen_v4v_verbose("====>");

    uxen_v4v_verbose("Cancelled-IRP %p", irp);

    v4v_simple_complete_irp(irp, STATUS_CANCELLED);

    uxen_v4v_verbose("<====");
}

static ULONG
get_matching_dest_count(xenv4v_extension_t *pde, BOOLEAN ax)
{
    PLIST_ENTRY head, next;
    xenv4v_destination_t *xdst;
    ULONG i;
    ULONG count = 0;

    head = &pde->dest_list;
    next = head->Flink;

    for (i = 0; i < (ULONG)pde->dest_count; i++) {
        ASSERT(next != head);
        xdst = CONTAINING_RECORD(next, xenv4v_destination_t, le);
        if (xdst->dst_ax == ax)
            count++;
        next = next->Flink;
    }

    return count;
}

v4v_ring_data_t *
gh_v4v_copy_destination_ring_data(xenv4v_extension_t *pde, BOOLEAN ax, ULONG *gh_count)
{
    KIRQL               irql;
    v4v_ring_data_t    *ringData;
    xenv4v_destination_t *xdst;
    LONG                i, j;
    ULONG               size;
    PLIST_ENTRY         head, next;
    ULONG               match_gh_count;
    ULONG               extra_count = 0;

    KeAcquireSpinLock(&pde->queue_lock, &irql);

    if (!ax)
        extra_count = uxen_v4v_notify_count(pde);
    match_gh_count = get_matching_dest_count(pde, ax);
    *gh_count = match_gh_count;

    size = sizeof(v4v_ring_data_t) + (match_gh_count + extra_count) * sizeof(v4v_ring_data_ent_t);
    ringData = (v4v_ring_data_t *)uxen_v4v_fast_alloc(size);
    if (ringData == NULL) {
        KeReleaseSpinLock(&pde->queue_lock, irql);
        uxen_v4v_err("ringData uxen_v4v_fast_alloc failed size 0x%x", size);
        return NULL;
    }

    RtlZeroMemory(ringData, sizeof(v4v_ring_data_t));
    ringData->magic = V4V_RING_DATA_MAGIC;

    head = &pde->dest_list;
    next = head->Flink;

    j = 0;
    for (i = 0; i < pde->dest_count; i++) {
        ASSERT(next != head);
        xdst = CONTAINING_RECORD(next, xenv4v_destination_t, le);
        if (xdst->dst_ax == ax) {
            ringData->data[j].ring = xdst->dst;
            ringData->data[j].space_required = xdst->nextLength;
            j++;
        }
        next = next->Flink;
    }

    if (!ax)
        extra_count = uxen_v4v_notify_fill_ring_data(pde, &ringData->data[i], extra_count);

    ringData->nent = match_gh_count + extra_count;

    KeReleaseSpinLock(&pde->queue_lock, irql);

    return ringData;
}
