/*
 *  uxen_call.c
 *  uxen
 *
 * Copyright 2011-2015, Bromium, Inc.
 * Author: Christian Limpach <Christian.Limpach@gmail.com>
 * SPDX-License-Identifier: ISC
 * 
 */

#include "uxen.h"
#include <uxen_ioctl.h>

#include <stdarg.h>

#include <xen/errno.h>
#include <xen/xen.h>
#include <xen/domctl.h>
#include <xen/event_channel.h>
#include <xen/hvm/hvm_op.h>

/* Awful hack to get xen-public header rather than xen private header */
#include <../xen-public/xen/v4v.h>

#define UXEN_DEFINE_SYMBOLS_PROTO
#include <uxen/uxen_link.h>

#include "memcache.h"

#if defined(_WIN64) 
typedef uint64_t mfn_t;
#else
typedef uint32_t mfn_t;
#endif

intptr_t
uxen_hypercall(struct uxen_hypercall_desc *uhd, int snoop_mode,
               struct vm_info_shared *vmis, void *user_access_opaque,
               uint32_t privileged)
{
    intptr_t ret = 0;

    while (/* CONSTCOND */ 1) {
        if (KeGetCurrentIrql() < DISPATCH_LEVEL) 
            memcache_ensure_space();

        uxen_exec_dom0_start();
        uxen_call(ret =, -EINVAL, _uxen_snoop_hypercall(uhd, snoop_mode),
                  uxen_do_hypercall, uhd, vmis, user_access_opaque,
                  privileged);
        uxen_exec_dom0_end();

        if (ret == -ECONTINUATION)
            continue;

        break;
    }

    return ret;
}

intptr_t
uxen_dom0_hypercall(struct vm_info_shared *vmis, void *user_access_opaque,
                    uint32_t privileged, uint64_t op, ...)
{
    struct uxen_hypercall_desc uhd;
    int idx, n_arg;
    int snoop_mode;
    va_list ap;
    intptr_t ret;

    switch (op) {
    case __HYPERVISOR_domctl:
        n_arg = 1;
        break;
    case __HYPERVISOR_event_channel_op:
        n_arg = 2;
        break;
    case __HYPERVISOR_memory_op:
        n_arg = 2;
        break;
    case __HYPERVISOR_sysctl:
        n_arg = 1;
        break;
    case __HYPERVISOR_v4v_op:
        n_arg = 6;
        break;
    default:
        fail_msg("unknown hypercall op: %Id", op);
        return EINVAL;
    }

    snoop_mode = (privileged & UXEN_UNRESTRICTED_ACCESS_HYPERCALL) ?
        SNOOP_KERNEL : SNOOP_USER;

    memset(&uhd, 0, sizeof(struct uxen_hypercall_desc));

    uhd.uhd_op = op;
    va_start(ap, op);
    for (idx = 0; idx < n_arg; idx++)
        uhd.uhd_arg[idx] = va_arg(ap, uintptr_t);
    va_end(ap);

    ret = uxen_hypercall(&uhd, snoop_mode, vmis, user_access_opaque,
                         privileged);
    ret = -ret;

    return ret;
}

int32_t
_uxen_snoop_hypercall(void *udata, int mode)
{
    int ret;
    uint32_t pages = 0;
    struct uxen_hypercall_desc *uhd = udata;
    int (*copy)(const void *, void *, size_t);

    switch (mode) {
    case SNOOP_USER:
        copy = copyin;
        break;
    case SNOOP_KERNEL:
        copy = copyin_kernel;
        break;
    default:
        fail_msg("unknown mode %d", mode);
        return -EINVAL;
    }

    switch(uhd->uhd_op) {
    case __HYPERVISOR_memory_op:
        switch (uhd->uhd_arg[0]) {
        case XENMEM_populate_physmap: {
            xen_memory_reservation_t res;

            ret = copy((void *)uhd->uhd_arg[1], &res, sizeof(res));
            if (ret)
                return -ret;
            if (res.mem_flags & XENMEMF_populate_on_demand)
                break;
            if (((1ULL << res.extent_order) * res.nr_extents) >= (1ULL << 31)) {
                fail_msg("size assert: %Ix",
                         (1ULL << res.extent_order) * res.nr_extents);
                return -ENOMEM;
            }
            pages += (1 << res.extent_order) * (uint32_t)res.nr_extents;
            mm_dprintk("snooped populate_physmap: %d [%lld (%d:%x)]\n", pages,
                       res.nr_extents, res.extent_order, res.mem_flags);
            break;
        }
        case XENMEM_translate_gpfn_list_for_map: {
            xen_translate_gpfn_list_for_map_t list;

            ret = copy((void *)uhd->uhd_arg[1], &list, sizeof(list));
            if (ret)
                return -ret;
            if (list.nr_gpfns > 1024)
                return -EINVAL;
            pages += list.nr_gpfns;
            if (pages > 1)
                mm_dprintk("snooped translate gpfn list for map: %d\n", pages);
            break;
        }
        }
        break;
    case __HYPERVISOR_hvm_op:
        switch (uhd->uhd_arg[0]) {
        case HVMOP_set_mem_type: {
            struct xen_hvm_set_mem_type a;
            ret = copy((void *)uhd->uhd_arg[1], &a, sizeof(a));
            if (ret)
                return -ret;
            if (a.nr > 1024)
                return -EINVAL;
            pages += a.nr;
            if (pages > 1)
                mm_dprintk("snooped hvm_op set_mem_type: %d\n", pages);
            break;
        }
        }
        break;
    case __HYPERVISOR_v4v_op: {
        switch (uhd->uhd_arg[0]) {
	    case V4VOP_register_ring: {
		uint64_t mem_needed;

            	v4v_pfn_list_t pl;
            	ret = copy((void *)uhd->uhd_arg[2], &pl, sizeof(pl));
            	if (ret)
                	return -ret;

		mem_needed = (sizeof(mfn_t) + sizeof(uint8_t *) ) * pl.npage;
		mem_needed += 4096; /*v4v_ring_info and other non public structures */

		mem_needed +=PAGE_SIZE - 1 ;
		pages += mem_needed >> PAGE_SHIFT;

		pages *=2;

		DbgPrint("snooped %d extra pages for v4v\n",pages);
	
	    }
            break;
        }
        break;
    }
    default:
        break;
    }

    return pages + HYPERCALL_RESERVE;
}
