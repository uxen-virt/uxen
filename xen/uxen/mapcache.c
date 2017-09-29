/*
 *  mapcache.c
 *  uxen
 *
 * Copyright 2015-2018, Bromium, Inc.
 * Author: Christian Limpach <Christian.Limpach@gmail.com>
 * SPDX-License-Identifier: ISC
 * 
 */

#include <xen/config.h>
#include <xen/types.h>
#include <xen/init.h>
#include <xen/lib.h>
#include <xen/sched.h>
#include <xen/domain_page.h>
#include <xen/softirq.h>
#include <asm/current.h>
#include <asm/flushtlb.h>
#include <asm/mm.h>
#include <asm/page.h>

#include <uxen/uxen.h>
#include <uxen/mapcache.h>

#include <asm/hvm/ax.h>

static DEFINE_PER_CPU(uint16_t, mapcache_next);
static DEFINE_PER_CPU(uint32_t[MAPCACHE_SIZE / 32], mapcache_map);

#define map_mfn(va, mfn) UI_HOST_CALL(ui_map_mfn, va, mfn)

#define HASH_ENTRIES 64
#define HASH_FN(mfn) ((mfn) & (HASH_ENTRIES - 1))

typedef struct hash_entry {
    unsigned long mfn;
    uint16_t slot;
    uint16_t refcnt;
} hash_entry_t;
static DEFINE_PER_CPU(hash_entry_t[HASH_ENTRIES], mapcache_hash);
#define SLOT_UNUSED ((uint16_t)-1)

void __init
mapcache_init(void)
{
    int cpu, i;

    for_each_present_cpu(cpu) {
        printk("%s: cpu %d va %p-%p\n", __FUNCTION__, cpu,
               (void *)_uxen_info.ui_mapcache_va[cpu],
               (void *)(_uxen_info.ui_mapcache_va[cpu] +
                        (_uxen_info.ui_mapcache_size << PAGE_SHIFT)));
        for (i = 0; i < HASH_ENTRIES; i++)
            per_cpu(mapcache_hash, cpu)[i].slot = SLOT_UNUSED;
    }
}

void *
mapcache_map_page(xen_pfn_t mfn)
{
    int cpu = smp_processor_id();
    uint16_t slot, first;
    uintptr_t va;
    struct hash_entry *entry;

    if (AX_ON_AMD_PRESENT() && ax_l1_invlpg_intercept)
        return uxen_map_page_global(mfn);

    entry = &this_cpu(mapcache_hash)[HASH_FN(mfn)];
    if (entry->mfn == mfn) {
        slot = entry->slot;
        entry->refcnt++;
        perfc_incr(mapcache_hash_hit);
        return (void *)(_uxen_info.ui_mapcache_va[cpu] + (slot << PAGE_SHIFT));
    }

    perfc_incr(mapcache_hash_miss);

    first = this_cpu(mapcache_next);
    do {
        slot = this_cpu(mapcache_next)++;
        if (this_cpu(mapcache_next) == _uxen_info.ui_mapcache_size)
            this_cpu(mapcache_next) = 0;
        if (this_cpu(mapcache_next) == first)
            return uxen_map_page_global(mfn);
    } while (__test_and_set_bit(slot, this_cpu(mapcache_map)));

    va = _uxen_info.ui_mapcache_va[cpu] + (slot << PAGE_SHIFT);
    /* printk("%s: mfn %"PRI_xen_pfn" va %p slot %d\n", __FUNCTION__, */
    /*        mfn, (void *)va, slot); */

    map_mfn(va, mfn);

    flush_tlb_one_local(va);

    return (void *)va;
}

uint64_t
mapcache_unmap_page_va(const void *va)
{
    int cpu = smp_processor_id();
    uint64_t pte;
    unsigned long mfn;
    uint16_t slot;
    struct hash_entry *entry;

    if ((uintptr_t)va < _uxen_info.ui_mapcache_va[cpu] ||
        (uintptr_t)va >= _uxen_info.ui_mapcache_va[cpu] +
        (_uxen_info.ui_mapcache_size << PAGE_SHIFT))
        return (uxen_unmap_page_global(va), 0);

    slot = ((uintptr_t)va - _uxen_info.ui_mapcache_va[cpu]) >> PAGE_SHIFT;
    ASSERT(slot < _uxen_info.ui_mapcache_size);

    pte = map_mfn((uintptr_t)va, ~0ULL);
    if (!(pte & _PAGE_PRESENT)) {
        mfn = INVALID_MFN;
        goto out;
    }

    mfn = (pte & ~0x8000000000000fff) >> PAGE_SHIFT;
    entry = &this_cpu(mapcache_hash)[HASH_FN(mfn)];
    if (entry->slot == slot) {
        ASSERT(entry->refcnt);
        ASSERT(entry->mfn == mfn);
        entry->refcnt--;
    } else if (entry->refcnt == 0) {
        if (entry->slot != SLOT_UNUSED)
            __clear_bit(entry->slot, this_cpu(mapcache_map));
        entry->mfn = mfn;
        entry->slot = slot;
    } else
      out:
        __clear_bit(slot, this_cpu(mapcache_map));

    return mfn;
}

uint64_t
mapcache_mapped_va_mfn(const void *va)
{
    int cpu = smp_processor_id();
    uint64_t pte;
    uint16_t slot;

    if ((uintptr_t)va < _uxen_info.ui_mapcache_va[cpu] ||
        (uintptr_t)va >= _uxen_info.ui_mapcache_va[cpu] +
        (_uxen_info.ui_mapcache_size << PAGE_SHIFT))
        return virt_to_mfn(va);

    slot = ((uintptr_t)va - _uxen_info.ui_mapcache_va[cpu]) >> PAGE_SHIFT;
    ASSERT(slot < _uxen_info.ui_mapcache_size);

    pte = map_mfn((uintptr_t)va, ~0ULL);

    return (pte & _PAGE_PRESENT) ?
        (pte & ~0x8000000000000fff) >> PAGE_SHIFT : INVALID_MFN;
}
