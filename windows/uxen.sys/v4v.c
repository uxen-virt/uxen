/*
 * Copyright 2015, Bromium, Inc.
 * SPDX-License-Identifier: ISC
 */

#include "uxen.h"

#include <ntddk.h>
#include <xen/errno.h>
#include <xen/types.h>

#include <uxen_ioctl.h>

#define UXEN_DEFINE_SYMBOLS_PROTO
#include <uxen/uxen_link.h>

/* XXX: should include uxenv4vlib.h, but that conflicts */

typedef uintptr_t (Uxen_v4vlib_hypercall_func)(uintptr_t, uintptr_t, uintptr_t, uintptr_t, uintptr_t, uintptr_t);
void uxen_v4vlib_set_hypercall_func(Uxen_v4vlib_hypercall_func *);
typedef void (Uxen_v4vlib_page_notify_func)(uint64_t *, uint32_t, int);
void uxen_v4vlib_set_page_notify_func(Uxen_v4vlib_page_notify_func *);
void uxen_v4vlib_deliver_signal (void);
void uxen_v4vlib_we_are_dom0(void);

void uxen_v4v_test(void);

static uintptr_t uxen_sys_v4v_hypercall(uintptr_t a1, uintptr_t a2, uintptr_t a3, uintptr_t a4, uintptr_t a5, uintptr_t a6)
{
    intptr_t ret;

    if (!uxen_info) return (uintptr_t) - ENOSYS;
    if (!uxen_info->ui_running) return (uintptr_t) - ENOSYS;

    ret = uxen_dom0_hypercall(NULL, NULL, UXEN_UNRESTRICTED_ACCESS_HYPERCALL,
                              __HYPERVISOR_v4v_op, a1, a2, a3, a4, a5, a6);
    ret = -ret; //no really

    return (uintptr_t) ret;
}


static void uxen_sys_v4v_page_notify(uint64_t *pfns, uint32_t npfn, int add)
{
#ifdef DEBUG_PAGE_ALLOC
    uint32_t i;
    for (i = 0; i < npfn; ++i) {
        uint64_t j = *(pfns++);
        pinfotable[j].allocated = add;
    }
#endif
}

void uxen_sys_start_v4v(void)
{
    uxen_v4vlib_we_are_dom0();
    uxen_v4vlib_set_hypercall_func(uxen_sys_v4v_hypercall);
    uxen_v4vlib_set_page_notify_func(uxen_sys_v4v_page_notify);
    uxen_v4v_test();
}

void uxen_sys_stop_v4v(void)
{
    uxen_v4vlib_set_page_notify_func(NULL);
    uxen_v4vlib_set_hypercall_func(NULL);
}

void __cdecl uxen_sys_signal_v4v(void)
{
    KIRQL oldirql;
    /*This should only schedule DPCs for dispatch - rather than actually execute them as current */
    /*is still pointing at the guest cpu */
    uxen_v4vlib_deliver_signal();
}


