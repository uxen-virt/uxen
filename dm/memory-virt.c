/*
 * Copyright 2013-2015, Bromium, Inc.
 * SPDX-License-Identifier: ISC
 */

#include "config.h"
#include <err.h>
#include <stdint.h>
#include "dm.h"
#include "xen.h"
#include <xenctrl.h>
#include <xen/hvm/save.h>
#include <dm/memory.h>
#include <xc_private.h>

#define PTE_PSE 0x80

static uint64_t cached_cr3;
#ifdef __x86_64__
#define CR3_ADDRESS_MASK (~0xfffull)
#else
#define CR3_ADDRESS_MASK (~0x1full)
#endif

uint64_t set_cached_cr3(uint64_t cr3)
{
    struct hvm_hw_cpu ctx;
    if (cr3) {
        cached_cr3 = cr3&CR3_ADDRESS_MASK;
        return cached_cr3;
    }

    if (xc_domain_hvm_getcontext_partial(xc_handle, vm_id,
                                         HVM_SAVE_CODE(CPU), 0,
                                         &ctx, sizeof ctx) != 0)
        return 0;
    cached_cr3 = ctx.cr3&CR3_ADDRESS_MASK;
    return cached_cr3;
}

/* based on libxc xc_translate_foreign_address */
static unsigned long xc_translate_foreign_address_cached(uint64_t virt)
{
    uint64_t paddr = cached_cr3, mask, pte = 0;
    int size, level;
#ifdef __x86_64__
    int pt_levels = 4; /* pt_levels fixed to 4, x64 guest */
#else
    int pt_levels = 3; /* i386 PAE guest */
#endif
    void *map;
    uint64_t len;

    if (pt_levels == 4) {
        virt &= 0x0000ffffffffffffull;
        mask =  0x0000ff8000000000ull;
    } else if (pt_levels == 3) {
        virt &= 0x00000000ffffffffull;
        mask =  0x0000007fc0000000ull;
    } else {
        virt &= 0x00000000ffffffffull;
        mask =  0x00000000ffc00000ull;
    }
    size = (pt_levels == 2 ? 4 : 8);

    /* Walk the pagetables */
    for (level = pt_levels; level > 0; level--) {
        paddr += ((virt & mask) >> (xc_ffs64(mask) - 1)) * size;
        len = XC_PAGE_SIZE;
        map = vm_memory_map((paddr>> XC_PAGE_SHIFT)<<XC_PAGE_SHIFT, &len, 1, 0);
        if (!map)
            return 0;
        memcpy(&pte, map + (paddr & (XC_PAGE_SIZE - 1)), size);
        vm_memory_unmap((paddr>> XC_PAGE_SHIFT)<<XC_PAGE_SHIFT, XC_PAGE_SIZE,
            1, 0, map, XC_PAGE_SIZE);
        if (!(pte & 1))
            return 0;
        paddr = pte & 0x000ffffffffff000ull;
        if (level == 2 && (pte & PTE_PSE)) {
            mask = ((mask ^ ~-mask) >> 1); /* All bits below first set bit */
            return ((paddr & ~mask) | (virt & mask)) >> XC_PAGE_SHIFT;
        }
        mask >>= (pt_levels == 2 ? 10 : 9);
    }
    return paddr >> XC_PAGE_SHIFT;
}

static void * map_guest_page_by_va_cached(uint64_t va, uint64_t *phys)
{
    uint64_t len = XC_PAGE_SIZE;
    uint64_t gfn = xc_translate_foreign_address_cached(va);
    if (!gfn)
        return NULL;
    *phys = gfn<<XC_PAGE_SHIFT;
    return vm_memory_map(gfn<<XC_PAGE_SHIFT, &len, 1, 0);
}

int virt_read(uint64_t va, void *dest, int size)
{
    uint64_t phys;
    uint64_t curr = va;

    if (!cached_cr3)
        set_cached_cr3(0);

    while (curr < va + size) {
        char *page;
        uint64_t len = XC_PAGE_SIZE - (curr & (XC_PAGE_SIZE-1));
        uint64_t remaining = size - (curr - va);
        if (remaining < len)
            len = remaining;
        page = map_guest_page_by_va_cached(curr, &phys);
        if (!page)
            return -1;
        memcpy((char*)dest + curr - va, page + (curr & (XC_PAGE_SIZE-1)), len);
        vm_memory_unmap(phys, XC_PAGE_SIZE, 1, 0, page, XC_PAGE_SIZE);
        curr += len;
    }
    return 0;
}

