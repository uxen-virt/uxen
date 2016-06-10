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
 * Copyright 2015-2016, Bromium, Inc.
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

static ULONG32
gh_v4v_release_context_internal(xenv4v_extension_t *pde, xenv4v_context_t *ctx, BOOLEAN lock)
{
    KLOCK_QUEUE_HANDLE  lqh = {0};
    ULONG32             count;
    FILE_OBJECT        *pfo;


    if (lock)
        KeAcquireInStackQueuedSpinLock(&pde->context_lock, &lqh);

    ASSERT(ctx->refc != 0); // SNO, really bad
    count = --ctx->refc;

    if (lock)
        KeReleaseInStackQueuedSpinLock(&lqh);

    // When the count goes to zero, clean it all up. We are out of the list so a lock is not needed.
    // N.B. if we end up doing any cleanup that cannot happen at DISPATCH, we will need a work item.
    if (count == 0) {

        pfo = ctx->pfo_parent;
        // Cleanup the ring - if it is shared, this will just drop the ref count.
        if (ctx->ring_object != NULL)
            gh_v4v_release_ring(pde, ctx->ring_object);

        // Release the event
        if (ctx->receive_event != NULL)
            ObDereferenceObject(ctx->receive_event);

        // Free any that were requeued by the VIRQ handler at the last minute
        if (pfo)
            gh_v4v_cancel_all_file_irps(pde, pfo);

        // Free context itself...
        ExFreePoolWithTag(ctx, XENV4V_TAG);

        // Drop the reference the context held that prevents the final close
        if (pfo)
            ObDereferenceObject(pfo);
    }

    return count;
}

ULONG32
gh_v4v_release_context(xenv4v_extension_t *pde, xenv4v_context_t *ctx)
{
    return gh_v4v_release_context_internal(pde, ctx, TRUE);
}

ULONG32
gh_v4v_add_ref_context(xenv4v_extension_t *pde, xenv4v_context_t *ctx)
{
    KLOCK_QUEUE_HANDLE lqh;
    ULONG32            count;

    KeAcquireInStackQueuedSpinLock(&pde->context_lock, &lqh);
    count = ++ctx->refc;
    KeReleaseInStackQueuedSpinLock(&lqh);

    return count;
}

VOID
gh_v4v_put_all_contexts(xenv4v_extension_t *pde, xenv4v_context_t **ctx_list, ULONG count)
{
    KLOCK_QUEUE_HANDLE lqh;
    ULONG              i;

    if (ctx_list == NULL) {
        return;
    }

    KeAcquireInStackQueuedSpinLock(&pde->context_lock, &lqh);
    for (i = 0; i < count; i++) {
        gh_v4v_release_context_internal(pde, ctx_list[i], FALSE);
    }
    KeReleaseInStackQueuedSpinLock(&lqh);
    uxen_v4v_fast_free(ctx_list);
}

xenv4v_context_t **
gh_v4v_get_all_contexts(xenv4v_extension_t *pde, ULONG *count_out)
{
    KLOCK_QUEUE_HANDLE   lqh;
    xenv4v_context_t      *ctx;
    xenv4v_context_t     **ctx_list;
    ULONG                i = 0;

    *count_out = 0;

    KeAcquireInStackQueuedSpinLock(&pde->context_lock, &lqh);
    if (IsListEmpty(&pde->context_list)) {
        KeReleaseInStackQueuedSpinLock(&lqh);
        return NULL;
    }
    ASSERT(pde->context_count > 0);

    ctx_list = (xenv4v_context_t **)uxen_v4v_fast_alloc(
        pde->context_count * sizeof(xenv4v_context_t *));

    if (ctx_list == NULL) {
        KeReleaseInStackQueuedSpinLock(&lqh);
        TraceError(("failed to allocate context list - out of memory.\n"));
        return NULL;
    }

    ctx = (xenv4v_context_t *)pde->context_list.Flink;
    while (ctx != (xenv4v_context_t *)&pde->context_list) {
        ctx->refc++;
        ctx_list[i++] = ctx;
        ctx = (xenv4v_context_t *)ctx->le.Flink;
    }
    *count_out = pde->context_count;
    KeReleaseInStackQueuedSpinLock(&lqh);

    return ctx_list;
}

static VOID
gh_v4v_link_to_context_list(xenv4v_extension_t *pde, xenv4v_context_t *ctx)
{
    KLOCK_QUEUE_HANDLE lqh;

    KeAcquireInStackQueuedSpinLock(&pde->context_lock, &lqh);

    // Add a reference for the list and up the counter
    ctx->refc++;
    pde->context_count++;

    // Link this context into the adapter list
    InsertHeadList(&pde->context_list, &(ctx->le));
    TraceInfo(("added context %p to list.\n", ctx));

    KeReleaseInStackQueuedSpinLock(&lqh);
}

static VOID
gh_v4v_unlink_from_context_list(xenv4v_extension_t *pde, xenv4v_context_t *ctx)
{
    KLOCK_QUEUE_HANDLE lqh;

    KeAcquireInStackQueuedSpinLock(&pde->context_lock, &lqh);
    RemoveEntryList(&ctx->le);
    gh_v4v_release_context_internal(pde, ctx, FALSE);
    // Drop the count when it gets removed from the list
    pde->context_count--;
    ASSERT(pde->context_count >= 0); // SNO, really bad
    KeReleaseInStackQueuedSpinLock(&lqh);
}

VOID
gh_v4v_cancel_all_file_irps(xenv4v_extension_t *pde, FILE_OBJECT *pfo)
{
    PIRP pendingIrp;
    xenv4v_qpeek_t peek;

    peek.ops   = XENV4V_PEEK_WRITE;    // and any ops
    peek.pfo   = pfo;                  // for a specific file object

    pendingIrp = IoCsqRemoveNextIrp(&pde->csq_object, &peek);
    while (pendingIrp != NULL) {
        v4v_simple_complete_irp(pendingIrp, STATUS_CANCELLED);
        pendingIrp = IoCsqRemoveNextIrp(&pde->csq_object, &peek);
    }
}

NTSTATUS NTAPI
gh_v4v_dispatch_create(PDEVICE_OBJECT fdo, PIRP irp)
{
    xenv4v_extension_t   *pde = v4v_get_device_extension(fdo);
    PIO_STACK_LOCATION  isl;
    FILE_OBJECT        *pfo;
    xenv4v_context_t     *ctx;

    UNREFERENCED_PARAMETER(fdo);

    TraceVerbose(("====> '%s'.\n", __FUNCTION__));

    isl = IoGetCurrentIrpStackLocation(irp);
    isl->FileObject->FsContext = NULL;
    isl->FileObject->FsContext2 = NULL;
    pfo = isl->FileObject;

    if (pfo->FsContext != NULL) {
        TraceError(("context already associated with the file!\n"));
        return v4v_simple_complete_irp(irp, STATUS_INVALID_HANDLE);
    }

    ctx = (xenv4v_context_t *)ExAllocatePoolWithTag(NonPagedPool,
                                                    sizeof(xenv4v_context_t),
                                                    XENV4V_TAG);
    if (ctx == NULL) {
        return v4v_simple_complete_irp(irp, STATUS_NO_MEMORY);
    }
    RtlZeroMemory(ctx, sizeof(xenv4v_context_t));

    InitializeListHead(&ctx->le);
    ctx->state = XENV4V_STATE_UNINITIALIZED;

    // Add one ref count for the handle file object/handle reference
    ctx->refc++;

    // Link it to the device extension list
    gh_v4v_link_to_context_list(pde, ctx);

    // Now it is ready for prime time, set it as the file contex
    // and set a back pointer. The reference on the file object by
    // the context prevents the final close until the ref count goes
    // to zero. Note, this can occur after the cleanup when all the
    // user mode handles are closed.
    isl->FileObject->FsContext = ctx;
    ctx->pfo_parent = isl->FileObject;
    ObReferenceObject(ctx->pfo_parent);

    TraceVerbose(("<==== '%s'.\n", __FUNCTION__));

    return v4v_simple_complete_irp(irp, STATUS_SUCCESS);
}

NTSTATUS NTAPI
gh_v4v_dispatch_cleanup(PDEVICE_OBJECT fdo, PIRP irp)
{
    NTSTATUS            status = STATUS_SUCCESS;
    xenv4v_extension_t   *pde = v4v_get_device_extension(fdo);
    PIO_STACK_LOCATION  isl = IoGetCurrentIrpStackLocation(irp);
    FILE_OBJECT        *pfo;
    xenv4v_context_t     *ctx;

    UNREFERENCED_PARAMETER(fdo);

    TraceVerbose(("====> '%s'.\n", __FUNCTION__));

    pfo = isl->FileObject;

    TraceInfo(("cleanup file - FsContext: 0x%x.\n", pfo->FsContext));

    ctx = (xenv4v_context_t *)pfo->FsContext;
    if (ctx != NULL) {
        // unmap the ring here if userland mapped it as we have the correct prcoess context
        if ((ctx->ring_object != NULL) && (ctx->ring_object->user_map != NULL)) {
            MmUnmapLockedPages(ctx->ring_object->user_map, ctx->ring_object->mdl);
            ctx->ring_object->user_map = NULL;
        }

        // Go to the closed state. If the VIRQ handler picks up an IRP before we cancel the
        // queue for this file, it will see it is closed and cancel it there.
        InterlockedExchange(&ctx->state, XENV4V_STATE_CLOSED);

        // Drop it out of the list
        gh_v4v_unlink_from_context_list(pde, ctx);

        // Release our ref count - if zero then the release routine will do the final cleanup
        gh_v4v_release_context_internal(pde, ctx, TRUE);
    } else {
        // This SNO
        TraceError(("cleanup file - no context associated with the file?!?\n"));
        status = STATUS_UNSUCCESSFUL;
    }

    v4v_simple_complete_irp(irp, status);

    TraceVerbose(("<==== '%s'.\n", __FUNCTION__));

    return status;
}

NTSTATUS NTAPI
gh_v4v_dispatch_close(PDEVICE_OBJECT fdo, PIRP irp)
{
    PIO_STACK_LOCATION isl;

    UNREFERENCED_PARAMETER(fdo);

    TraceVerbose(("====> '%s'.\n", __FUNCTION__));

    isl = IoGetCurrentIrpStackLocation(irp);

    // By the time we reach close, the final release has been called and
    // dropped its ref count in the file object. All that is left is to
    // NULL the context for consistency.
    isl->FileObject->FsContext = NULL;

    v4v_simple_complete_irp(irp, STATUS_SUCCESS);

    TraceVerbose(("<==== '%s'.\n", __FUNCTION__));

    return STATUS_SUCCESS;
}
