/*
 * Copyright 2015, Bromium, Inc.
 * SPDX-License-Identifier: ISC
 */

#include "uxenv4vlib_private.h"

void uxen_v4v_install_pde(xenv4v_extension_t *pde)
{
    KLOCK_QUEUE_HANDLE lqh;
    KeAcquireInStackQueuedSpinLock(&uxen_v4v_pde_lock, &lqh);
    uxen_v4v_pde = pde;
    KeReleaseInStackQueuedSpinLock(&lqh);
}

xenv4v_extension_t *uxen_v4v_get_pde(void)
{
    xenv4v_extension_t *ret;
#if 0
    KLOCK_QUEUE_HANDLE lqh;

    KeAcquireInStackQueuedSpinLock(&uxen_v4v_pde_lock, &lqh);
    ret = uxen_v4v_pde;
    if (ret) ret->refc++;
    KeReleaseInStackQueuedSpinLock(&lqh);
#else
    ret = uxen_v4v_pde;
    if (ret) InterlockedIncrement(&uxen_v4v_pde->refc);
#endif
    return ret;
}

void uxen_v4v_put_pde(xenv4v_extension_t *pde)
{
#if 0
    KLOCK_QUEUE_HANDLE lqh;
    KeAcquireInStackQueuedSpinLock(&uxen_v4v_pde_lock, &lqh);
    if (uxen_v4v_pde)
        uxen_v4v_pde->refc--;
    KeReleaseInStackQueuedSpinLock(&lqh);
#else
    if (uxen_v4v_pde)
        InterlockedDecrement(&uxen_v4v_pde->refc);
#endif
}


xenv4v_extension_t *uxen_v4v_remove_pde(void)
{
    xenv4v_extension_t *ret;
    KLOCK_QUEUE_HANDLE lqh;


    do {
        LARGE_INTEGER stall;


        KeAcquireInStackQueuedSpinLock(&uxen_v4v_pde_lock, &lqh);
        if ((!uxen_v4v_pde)  || (!uxen_v4v_pde->refc)) break;
        KeReleaseInStackQueuedSpinLock(&lqh);
        stall.QuadPart = 10000; //1ms
        KeDelayExecutionThread(KernelMode, FALSE, &stall);
    } while (1);

    ret = uxen_v4v_pde;
    uxen_v4v_pde = NULL;
    KeReleaseInStackQueuedSpinLock(&lqh);

    return ret;
}

