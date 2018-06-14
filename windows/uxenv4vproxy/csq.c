/*
 * Copyright 2018, Bromium, Inc.
 * Author: Tomasz Wroblewski <tomasz.wroblewski@gmail.com>
 * SPDX-License-Identifier: ISC
 */

#include "proxy.h"
#include "log.h"

static BOOLEAN
csq_peek_test(PIRP irp, PVOID peekContext)
{
    proxy_qpeek_t *qp = (proxy_qpeek_t*)peekContext;
    PIO_STACK_LOCATION isl = IoGetCurrentIrpStackLocation(irp);
    uint32_t flags = irp_get_flags(irp);

    if (qp->flags_on && !(qp->flags_on & flags))
        return FALSE;
    if (qp->flags_off && (qp->flags_off & flags))
        return FALSE;
    if (qp->context && (qp->context->pfo_parent != isl->FileObject))
        return FALSE;
    if (qp->reqid && (qp->reqid != irp_get_reqid(irp)))
        return FALSE;
    if (qp->backend_context && (qp->backend_context != irp_get_destination(irp)))
        return FALSE;

    return TRUE;
}

NTSTATUS NTAPI
csq_insert_irp_ex(PIO_CSQ csq, PIRP irp, PVOID unused)
{
    proxy_extension_t *pde = CSQ_TO_EXT(csq);
    BOOLEAN insert_head = FALSE;

//    ASSERT(((pde->pending_irp_count != 0) || (pde->dest_count == 0)));

    if (pde->pending_irp_count == MAX_IRP_COUNT) {
        ERROR("maximun pending IRP count reached!! max: %d",
            pde->pending_irp_count);
        return STATUS_QUOTA_EXCEEDED;
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
csq_remove_irp(PIO_CSQ csq, PIRP irp)
{
    proxy_extension_t *pde = CSQ_TO_EXT(csq);

    RemoveEntryList(&irp->Tail.Overlay.ListEntry);

    // Clear out dangling list pointers and drop count
    InitializeListHead(&irp->Tail.Overlay.ListEntry);
    pde->pending_irp_count--;
    ASSERT(pde->pending_irp_count >= 0);
//    ASSERT(((pde->pending_irp_count != 0) || (pde->dest_count == 0)));
}

PIRP NTAPI
csq_peek_next_irp(PIO_CSQ csq, PIRP irp, PVOID peekContext)
{
    proxy_extension_t *pde = CSQ_TO_EXT(csq);
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

        if (csq_peek_test(nextIrp, peekContext)) {
            break; // on first one that matches
        }

        // Onward
        nextIrp = NULL;
        next = next->Flink;
    }

    return nextIrp;
}

VOID NTAPI
csq_acquire_lock(PIO_CSQ csq, PKIRQL irqlOut)
{
    proxy_extension_t *pde = CSQ_TO_EXT(csq);

    KeAcquireSpinLock(&pde->queue_lock, irqlOut);
}

VOID NTAPI
csq_release_lock(PIO_CSQ csq, KIRQL irql)
{
    proxy_extension_t *pde = CSQ_TO_EXT(csq);

    KeReleaseSpinLock(&pde->queue_lock, irql);
}

VOID NTAPI
csq_complete_canceled_irp(PIO_CSQ csq, PIRP irp)
{
    UNREFERENCED_PARAMETER(csq);

    simple_complete_irp(irp, STATUS_CANCELLED);
}
