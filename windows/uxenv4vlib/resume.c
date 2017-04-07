/*
 * Copyright 2015-2017, Bromium, Inc.
 * SPDX-License-Identifier: ISC
 */

#include "uxenv4vlib_private.h"


void uxen_v4v_resume(void)
{
    unsigned i;
    KLOCK_QUEUE_HANDLE lqh;

    (*state_bar_ptr)->v4v_running++;

    KeMemoryBarrier();

    uxen_v4v_warn("resume, IRQL=%d, cpu=%d", (int)KeGetCurrentIrql(),
        (int)KeGetCurrentProcessorNumber());
    uxen_v4v_warn("reregistering rings");
    uxen_v4v_reregister_all_rings();

    uxen_v4v_warn("executing resume dpcs");
    KeAcquireInStackQueuedSpinLock(&uxen_v4v_pde_lock, &lqh);

    for (i = 0; i < UXEN_V4VLIB_MAX_RESUME_DPCS; ++i) {
        if (!uxen_v4vlib_resume_dpcs[i]) continue;
        KeInsertQueueDpc(uxen_v4vlib_resume_dpcs[i], uxen_v4vlib_resume_dpcs_arg1[i], NULL);
    }
    KeReleaseInStackQueuedSpinLock (&lqh);
    uxen_v4v_warn("resume completed");
}



