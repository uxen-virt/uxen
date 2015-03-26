/*
 * Copyright 2012-2015, Bromium, Inc.
 * Author: Julian Pidancet <julian@pidancet.net>
 * SPDX-License-Identifier: ISC
 */

#include "uxen.h"
#include <libkern/libkern.h>

#ifndef DEBUG
static
#endif
       uint64_t physmap_base;
static uint64_t physmap_max;

int
physmap_init(void)
{

    physmap_base = xnu_physmap_base();
    physmap_max = xnu_physmap_max();
    dprintk("physmap found at 0x%llx-0x%llx\n", physmap_base,
            physmap_base + physmap_max);

#if 0
    /* Check if it works */
    pml4 = (void *)((uintptr_t)(res + cr3));

    dprintk("PML4 = %p\n", pml4);
    dprintk("PML4[KERNEL_PHYSMAP_PML4_INDEX] = %16llx\n", pml4[KERNEL_PHYSMAP_PML4_INDEX]);
#endif

    return 0;
}

void *
physmap_pfn_to_va(uint32_t pfn)
{
    uint64_t vaddr = ((uint64_t)pfn << 12);

    if (vaddr >= physmap_max)
        return NULL;

    return (void *)(vaddr + physmap_base);
}

uint32_t
physmap_va_to_pfn(const void *va)
{
    uint64_t vaddr = (uint64_t)va;

    if ((vaddr >= physmap_base) && (vaddr < physmap_max))
        return (vaddr - physmap_base) >> 12;

    return pmap_find_phys(kernel_pmap, vaddr);
}
