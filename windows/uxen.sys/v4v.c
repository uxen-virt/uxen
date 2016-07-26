/*
 * Copyright 2015-2016, Bromium, Inc.
 * SPDX-License-Identifier: ISC
 */

#include "uxen.h"

#include <ntddk.h>
#include <xen/errno.h>
#include <xen/types.h>

#include <uxen_ioctl.h>

#define UXEN_DEFINE_SYMBOLS_PROTO
#include <uxen/uxen_link.h>

#include <uxenv4vlib.h>

static void
host_logger(int lvl, const char *str)
{
    printk(str);
}

static uintptr_t
uxen_sys_v4v_hypercall(uintptr_t privileged,
                       uintptr_t a1, uintptr_t a2, uintptr_t a3,
                       uintptr_t a4, uintptr_t a5, uintptr_t a6)
{
    intptr_t ret;

    if (!uxen_info)
        return (uintptr_t)-ENOSYS;
    if (!uxen_info->ui_running)
        return (uintptr_t)-ENOSYS;

    /* uxen_sys_v4v_hypercall callers need to ensure all referenced
     * memory is valid, i.e. access doesn't fail and the caller is
     * supposed to have access to the memory
     * (UXEN_UNRESTRICTED_ACCESS_HYPERCALL) and that the arguments to
     * the call have been validated by the system/kernel
     * (UXEN_SYSTEM_HYPERCALL) */
    ret = uxen_dom0_hypercall(NULL, NULL,
                              UXEN_UNRESTRICTED_ACCESS_HYPERCALL |
                              UXEN_SYSTEM_HYPERCALL | privileged,
                              __HYPERVISOR_v4v_op, a1, a2, a3, a4, a5, a6);
    ret = -ret; //no really

    return (uintptr_t)ret;
}

static uintptr_t
uxen_sys_v4v_page_notify(uint64_t *pfns, uint32_t npfn, int add)
{
    uint32_t mfn;
    uint32_t i;

    for (i = 0; i < npfn; ++i) {
        mfn = (uint32_t)*(pfns++);
        if (add && populate_frametable(mfn, 0)) {
            fail_msg("populate_frametable for mfn %x failed", mfn);
            return 1;
        }
#ifdef DEBUG_PAGE_ALLOC
        DASSERT(add ? !pinfotable[mfn].allocated : pinfotable[mfn].allocated);
        pinfotable[mfn].allocated = add;
#endif
    }

    return 0;
}

void uxen_sys_start_v4v(void)
{
    uxen_v4vlib_set_logger(host_logger);
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

    /* only schedule DPCs for dispatch - rather than actually execute
     * them as, when called via ui_signal_v4v, current is still
     * pointing at the guest cpu */
    uxen_v4vlib_deliver_signal();
}


