/*
 * Copyright 2015-2016, Bromium, Inc.
 * SPDX-License-Identifier: ISC
 */

#include "uxenv4vguest_private.h"

static void
guest_logger(int lvl, const char *str)
{
    (lvl);
    _printk(str);
}

static uintptr_t
v4v_hypercall(uintptr_t privileged,
              uintptr_t a1, uintptr_t a2, uintptr_t a3,
              uintptr_t a4, uintptr_t a5, uintptr_t a6)
{
    (void)privileged;
    return uxen_hypercall6(__HYPERVISOR_v4v_op, a1, a2, a3, a4, a5, a6);
}

void uxen_v4v_guest_do_plumbing(PDRIVER_OBJECT pdo)
{
    uxen_v4vlib_set_logger(guest_logger);
    uxen_v4vlib_set_state_bar_ptr(uxen_get_state_bar_ptr());
    uxen_hypercall_init();
    uxen_v4vlib_set_hypercall_func(v4v_hypercall); /*This will trigger things is the above is correct*/
    uxen_v4v_test();
    uxen_v4vlib_init_driver(pdo);
}


void uxen_v4v_guest_undo_plumbing()
{
    uxen_v4vlib_free_driver();
    uxen_v4vlib_set_state_bar_ptr(NULL);
    uxen_v4vlib_set_hypercall_func(NULL);
}

