/*
 * Copyright 2018, Bromium, Inc.
 * SPDX-License-Identifier: ISC
 */

#include <xen/config.h>
#include <xen/ctype.h>
#include <xen/init.h>
#include <xen/lib.h>
#include <xen/trace.h>
#include <xen/sched.h>
#include <xen/irq.h>
#include <xen/softirq.h>
#include <xen/domain.h>
#include <xen/domain_page.h>
#include <xen/hypercall.h>
#include <xen/guest_access.h>
#include <xen/event.h>
#include <xen/paging.h>
#include <xen/cpu.h>
#include <asm/atomic.h>



static int __init xmas_clusterfuck_misery(void)
{
#ifdef __x86_64__

    uint64_t cr3 = read_cr3();
    uint64_t l4_base = cr3 & PAGE_MASK;
    uint64_t *l4, l4e;
    unsigned xcfm_1, xcfm_2h, xcfm_2l;

    /* Test 1, check low bits of cr3 */
    xcfm_1 = (unsigned) (cr3 & ~PAGE_MASK);
    printk("XCFM.1: %x\n",xcfm_1);

    l4 = mapcache_map_page(l4_base >> PAGE_SHIFT);

    l4e = atomic_read64(l4);

    xcfm_2h = (l4e >> 32) & 0xffffffffULL;
    xcfm_2l = l4e & 0xffffffffULL;

    mapcache_unmap_page_va(l4);

    printk("XCFM.2: %08x %08x\n",xcfm_2h, xcfm_2l);

#else
    printk("XCFM: 32bit\n");
#endif
    return 0;
}

__initcall(xmas_clusterfuck_misery);
