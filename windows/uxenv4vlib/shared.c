/*
 * Copyright 2015-2016, Bromium, Inc.
 * SPDX-License-Identifier: ISC
 */

#include "uxenv4vlib_private.h"

#pragma data_seg(".shared")

uxen_v4vlib_hypercall_func_t *hypercall_func;
uxen_v4vlib_page_notify_func_t *page_notify_func;

struct uxp_state_bar **state_bar_ptr;
xenv4v_extension_t *uxen_v4v_pde;
KSPIN_LOCK uxen_v4v_pde_lock;
int uxen_v4v_am_dom0;
KDPC *uxen_v4vlib_resume_dpcs[UXEN_V4VLIB_MAX_RESUME_DPCS];
void *uxen_v4vlib_resume_dpcs_arg1[UXEN_V4VLIB_MAX_RESUME_DPCS];
uxen_v4v_logger_t uxen_v4v_logger;

#pragma data_seg()

void uxen_v4v_init_shared(void)
{
    unsigned i;

    //KeInitializeSpinLock(&uxen_v4v_pde_lock);

    for (i = 0; i < UXEN_V4VLIB_MAX_RESUME_DPCS; ++i) {
        uxen_v4vlib_resume_dpcs[i] = NULL;
    }

    uxen_v4v_logger = NULL;
}



