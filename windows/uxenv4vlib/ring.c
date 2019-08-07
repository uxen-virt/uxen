/*
 * Copyright 2015-2019, Bromium, Inc.
 * SPDX-License-Identifier: ISC
 */

#include "uxenv4vlib_private.h"

void uxen_v4v_reregister_all_rings(void)
{
    KLOCK_QUEUE_HANDLE lqh;
    PLIST_ENTRY le;
    xenv4v_extension_t *pde;
    xenv4v_ring_t *robj;

    pde = uxen_v4v_get_pde();
    if (!pde) return;

    KeAcquireInStackQueuedSpinLock(&pde->ring_lock, &lqh);

    for (le = pde->ring_list.Flink; le != &pde->ring_list; le = le->Flink) {
        robj = CONTAINING_RECORD(le, xenv4v_ring_t, le);
        if (gh_v4v_register_ring(pde, robj) ==
            STATUS_INVALID_DEVICE_REQUEST) {
            /* XXX remove robj from list */
            uxen_v4v_warn(
                "gh_v4v_register_ring (vm%u:%x vm%u) duplicate ring",
                robj->id.addr.domain, robj->id.addr.port,
                robj->id.partner);
        }
    }

    KeReleaseInStackQueuedSpinLock(&lqh);

    uxen_v4v_put_pde(pde);

}

void uxen_v4v_send_read_callbacks(xenv4v_extension_t *pde)
{
    KLOCK_QUEUE_HANDLE lqh;
    PLIST_ENTRY le;
    xenv4v_ring_t *robj;
    LONG gen;

    KeAcquireInStackQueuedSpinLock(&pde->ring_lock, &lqh);
  again:
    gen = InterlockedExchangeAdd(&pde->ring_gen, 0);

    for (le = pde->ring_list.Flink; le != &pde->ring_list; le = le->Flink) {
        robj = CONTAINING_RECORD(le, xenv4v_ring_t, le);
        if (!robj->direct_access) continue;
        if (robj->ring->rx_ptr == robj->ring->tx_ptr) continue;
        if (robj->callback) {
            KIRQL irql;

            KeReleaseInStackQueuedSpinLock(&lqh);
            KeRaiseIrql(DISPATCH_LEVEL, &irql);
            robj->callback(robj->uxen_ring_handle, robj->callback_data1,
                           robj->callback_data2);
            KeLowerIrql(irql);
            KeAcquireInStackQueuedSpinLock(&pde->ring_lock, &lqh);
            if (gen != InterlockedExchangeAdd(&pde->ring_gen, 0))
                goto again;
        }
    }

    KeReleaseInStackQueuedSpinLock(&lqh);
}

static int user_map_exception(void)
{
    uxen_v4v_verbose("failed to map ring to userspace");
    return EXCEPTION_CONTINUE_EXECUTION;
}

NTSTATUS uxen_v4v_mapring(xenv4v_ring_t *robj, v4v_mapring_values_t *mr)
{
    KLOCK_QUEUE_HANDLE  lqh;

    if (!robj)
        return STATUS_INVALID_PARAMETER;

    if (!robj->mdl)
        return STATUS_INVALID_PARAMETER;

    if (robj->user_map)
        return STATUS_INVALID_PARAMETER;

    KeAcquireInStackQueuedSpinLock(&robj->lock, &lqh);
    robj->ring_is_mapped = 1;
    KeReleaseInStackQueuedSpinLock(&lqh);

    try {
        robj->user_map = (void *) MmMapLockedPagesSpecifyCache(robj->mdl, UserMode, MmCached, NULL, FALSE, NormalPagePriority);
    }
    except (user_map_exception()) {
        robj->user_map = NULL;
    }

    if (!robj->user_map) {
        robj->ring_is_mapped = 0;
        return STATUS_INVALID_PARAMETER;
    }

    mr->ring = (v4v_ring_t *) robj->user_map;

    return STATUS_SUCCESS;
}

