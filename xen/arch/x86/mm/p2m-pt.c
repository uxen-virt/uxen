/******************************************************************************
 * arch/x86/mm/p2m-pt.c
 *
 * Implementation of p2m datastructures as pagetables, for use by 
 * NPT and shadow-pagetable code
 *
 * Parts of this code are Copyright (c) 2009-2011 by Citrix Systems, Inc.
 * Parts of this code are Copyright (c) 2007 by Advanced Micro Devices.
 * Parts of this code are Copyright (c) 2006-2007 by XenSource Inc.
 * Parts of this code are Copyright (c) 2006 by Michael A Fetterman
 * Parts based on earlier work by Michael A Fetterman, Ian Pratt et al.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */
/*
 * uXen changes:
 *
 * Copyright 2011-2019, Bromium, Inc.
 * Author: Christian Limpach <Christian.Limpach@gmail.com>
 * SPDX-License-Identifier: ISC
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
 * SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION
 * OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
 * CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include <asm/domain.h>
#include <asm/page.h>
#include <asm/paging.h>
#include <asm/p2m.h>
#include <xen/iommu.h>
#ifndef __UXEN__
#include <asm/mem_event.h>
#include <public/mem_event.h>
#include <asm/mem_sharing.h>
#endif  /* __UXEN__ */
#include <xen/event.h>
#include <xen/trace.h>
#include <asm/hvm/nestedhvm.h>
#include <asm/hvm/svm/amd-iommu-proto.h>
#include <asm/hvm/pv.h>

#include "mm-locks.h"

/* Override macros from asm/page.h to make them work with mfn_t */
#undef mfn_to_page
#define mfn_to_page(_m) __mfn_to_page(mfn_x(_m))
#undef mfn_valid
#define mfn_valid(_mfn) __mfn_valid(mfn_x(_mfn))
#undef mfn_valid_page
#define mfn_valid_page(_mfn) __mfn_valid_page(mfn_x(_mfn))
#undef mfn_valid_page_or_vframe
#define mfn_valid_page_or_vframe(_mfn) __mfn_valid_page_or_vframe(mfn_x(_mfn))
#undef page_to_mfn
#define page_to_mfn(_pg) _mfn(__page_to_mfn(_pg))


#ifdef __UXEN__
#define PGT_l1_page_table 1
#define PGT_l2_page_table 2
#define PGT_l3_page_table 3
#define PGT_l4_page_table 4
#endif  /* __UXEN__ */

/* PTE flags for the various types of p2m entry */
#define P2M_BASE_FLAGS \
        (_PAGE_PRESENT | _PAGE_USER | _PAGE_DIRTY | _PAGE_ACCESSED)

static unsigned long p2m_type_to_flags(p2m_type_t t, mfn_t mfn)
{
    unsigned long flags;
#ifdef __x86_64__
    /*
     * AMD IOMMU: When we share p2m table with iommu, bit 9 - bit 11 will be
     * used for iommu hardware to encode next io page level. Bit 59 - bit 62
     * are used for iommu flags, We could not use these bits to store p2m types.
     */
    flags = (unsigned long)(t & 0x7f) << 12;
#else
    flags = (t & 0x7UL) << 9;
#endif

    switch(t)
    {
    case p2m_invalid:
    case p2m_mmio_dm:
    default:
        return flags;
    case p2m_ram_ro:
#ifndef __UXEN__
    case p2m_grant_map_ro:
#endif  /* __UXEN__ */
    case p2m_ram_logdirty:
#ifndef __UXEN__
    case p2m_ram_shared:
#endif  /* __UXEN__ */
    case p2m_ram_immutable:
        return flags | P2M_BASE_FLAGS;
    case p2m_ram_rw:
#ifndef __UXEN__
    case p2m_grant_map_rw:
#endif  /* __UXEN__ */
        return flags | P2M_BASE_FLAGS | _PAGE_RW;
    case p2m_mmio_direct:
        if ( !rangeset_contains_singleton(mmio_ro_ranges, mfn_x(mfn)) )
            flags |= _PAGE_RW;
        return flags | P2M_BASE_FLAGS | _PAGE_PCD;
    case p2m_populate_on_demand:
        return flags | (mfn_valid_page(mfn) ? P2M_BASE_FLAGS : 0);
    }
}


#define GUEST_TABLE_MAP_FAILED  0
#define GUEST_TABLE_NORMAL_PAGE 1
#define GUEST_TABLE_SUPER_PAGE  2
#define GUEST_TABLE_POD_PAGE    3

static int
p2m_next_level(struct p2m_domain *p2m, bool_t read_only, void **table,
               unsigned long gfn, uint32_t type);

static pt_entry_t *
pt_map_asr_ptp(struct p2m_domain *p2m)
{
    struct domain *d = p2m->domain;

    if (p2m->pt_page_next) {
        /* asr is always page with index 0, if any pt pages have been
         * allocated from vmi_pt_pages */
        ASSERT(pt_page(d, 0).mfn == pagetable_get_pfn(p2m_get_pagetable(p2m)));
        perfc_incr(p2m_map_ptp);
        return (pt_entry_t *)pt_page_va(d, 0);
    }

    perfc_incr(p2m_map_ptp_fallback);
    return map_domain_page(pagetable_get_pfn(p2m_get_pagetable(p2m)));
}

static pt_entry_t *
pt_map_ptp(struct p2m_domain *p2m, pt_entry_t *e)
{
    struct domain *d = p2m->domain;

    do {
        uint16_t idx = e->ptp_idx;

        if (!idx)
            break;

        while (idx < pt_nr_pages(d)) {
            if (pt_page(d, idx).mfn == e->mfn)
                break;
#ifdef __x86_64__
            idx += (1 << PTP_IDX_BITS) - 1;
#else  /* __x86_64__ */
            idx += (1 << PTP_IDX_BITS_amd_x86) - 1;
#endif  /* __x86_64__ */
        }

        /* ensure PTP_IDX_BITS fits in pt_entry */
#ifdef __x86_64__
        BUILD_BUG_ON(PTP_IDX_BITS > 10);
#else  /* __x86_64__ */
        BUILD_BUG_ON(PTP_IDX_BITS_amd_x86 > 3);
#endif  /* __x86_64__ */

        /* - in debug builds, trigger assert here since map_domain_page
         *   will also trigger an assert in debug builds
         * - in release builds, fallback to map_domain_page */
        ASSERT(idx < pt_nr_pages(d));
        if (idx >= pt_nr_pages(d))
            break;

        perfc_incr(p2m_map_ptp);
        return (pt_entry_t *)pt_page_va(d, idx);
    } while (0);

    perfc_incr(p2m_map_ptp_fallback);
    return map_domain_page(e->mfn);
}

static int
pt_map_ptp_gfn(struct p2m_domain *p2m, bool_t read_only,
               pt_entry_t **_table, unsigned long gfn, int *_target)
{
    struct domain *d = p2m->domain;
    pt_entry_t *table, *entry;
    uint16_t idx;
    unsigned int i;
    int ret = GUEST_TABLE_MAP_FAILED;

    idx = pt_gfn_idx(p2m, gfn, (*_target) + 1);
    if (idx < pt_nr_pages(d) && pt_page(d, idx).present) {
        *_table = (pt_entry_t *)pt_page_va(d, idx);
        return GUEST_TABLE_NORMAL_PAGE;
    }

    idx = pt_gfn_idx(p2m, gfn, (*_target) + 2);
    if (idx < pt_nr_pages(d) && pt_page(d, idx).present) {
        table = (pt_entry_t *)pt_page_va(d, idx);
        entry = table + pt_level_index(gfn, (*_target) + 1);

        if (p2m_is_pod(p2m_flags_to_type(
                           l2e_get_flags(*(l2_pgentry_t *)entry)))) {
            ASSERT(*_target == 0);
            *_table = table;
            *_target = 1;
            return GUEST_TABLE_POD_PAGE;
        }

        if (get_pte_flags(entry->e) & _PAGE_PRESENT) {
            *_table = pt_map_ptp(p2m, entry);
            return GUEST_TABLE_NORMAL_PAGE;
        }

        ASSERT(!entry->e);

        if (read_only) {
            *_table = table;
            (*_target)++;
            return GUEST_TABLE_MAP_FAILED;
        }
    }

    if (!read_only)
        printk(XENLOG_DEBUG "%s: vm%u: top down fill gfn %lx level %d\n",
               __FUNCTION__, d->domain_id, gfn, (*_target) + 1);

    table = pt_map_asr_ptp(p2m);
    for (i = PT_WL - 1
#if CONFIG_PAGING_LEVELS == 3
             - 1
#endif
             ; i > *_target; i--) {
        ret = p2m_next_level(p2m, read_only, (void **)&table, gfn, i);
        if (ret != GUEST_TABLE_NORMAL_PAGE)
            break;
    }

    *_target = i;
    *_table = table;
    return ret;
}

#define pt_ptp_mapped(p2m, va) (({                                      \
                ((uintptr_t)(va) >= pt_page_va((p2m)->domain, 0) &&     \
                 (uintptr_t)(va) < pt_page_va((p2m)->domain,            \
                                              pt_nr_pages((p2m)->domain))); \
            }))

static void
pt_unmap_ptp(struct p2m_domain *p2m, const void *va)
{

    if (!pt_ptp_mapped(p2m, va))
        unmap_domain_page(va);
}

// Find the next level's P2M entry, checking for out-of-range gfn's...
// Returns NULL on error.
//
static l1_pgentry_t *
p2m_find_entry(struct p2m_domain *p2m, void *table, unsigned long gfn,
               uint32_t level)
{
    uint32_t index;
    uint32_t max;

    max =
#if CONFIG_PAGING_LEVELS >= 4
        (level == PGT_l4_page_table) ? L4_PAGETABLE_ENTRIES :
#endif
        (level == PGT_l3_page_table) ? (
#if CONFIG_PAGING_LEVELS == 3
            (hap_enabled(p2m->domain) ? 4 : 8)
#else
            L3_PAGETABLE_ENTRIES
#endif
            ) :
        (level == PGT_l2_page_table) ? L2_PAGETABLE_ENTRIES :
        L1_PAGETABLE_ENTRIES;

    ASSERT(level > 0);
    index = pt_level_index(gfn, level - 1);
    if ( index >= max )
    {
        P2M_DEBUG("gfn=0x%lx out of range (level=%d index=0x%x max=0x%x)\n",
                  gfn, level, index, max);
        return NULL;
    }
    return (l1_pgentry_t *)table + index;
}

/* Free intermediate tables from a p2m sub-tree */
static void
p2m_free_entry(struct p2m_domain *p2m, l1_pgentry_t *p2m_entry, int page_order)
{
    /* End if the entry is a leaf entry. */
    if ( page_order == PAGE_ORDER_4K 
         || !(l1e_get_flags(*p2m_entry) & _PAGE_PRESENT)
         || (l1e_get_flags(*p2m_entry) & _PAGE_PSE) )
        return;

    if ( page_order > PAGE_ORDER_2M )
    {
        l1_pgentry_t *l3_table =
            (l1_pgentry_t *)pt_map_ptp(p2m, &p2m_entry->pte);
        for ( int i = 0; i < L3_PAGETABLE_ENTRIES; i++ )
            p2m_free_entry(p2m, l3_table + i, page_order - 9);
        pt_unmap_ptp(p2m, l3_table);
    }

    p2m_free_ptp(p2m, l1e_get_pfn(*p2m_entry), p2m_entry->pte.ptp_idx);
}

/* */
static void
write_p2m_entry(struct p2m_domain *p2m, unsigned long gfn,
                l1_pgentry_t *p, l1_pgentry_t new,
                unsigned int level, int *_needs_sync)
{
    struct domain *d = p2m->domain;
    uint32_t old_flags;
    int needs_sync = (level <= 2) ? 1 : 0;

    if (_needs_sync)
        needs_sync = *_needs_sync;

    /* No need to flush if the old entry wasn't valid */
    old_flags = l1e_get_flags(*p);
    if (!(old_flags & _PAGE_PRESENT))
        needs_sync = 0;

    safe_write_pte(p, new);
    pv_ept_write(p2m, level - 1, gfn, l1e_get_intpte(new), needs_sync);
    /* call pt_sync_domain here for callers not using the
     * needs_sync argument -- recheck needs_sync in case
     * *_pv_ept_writes cleared it above */
    if (!_needs_sync && needs_sync &&
        (level == 1 || (level == 2 && (old_flags & _PAGE_PSE))))
        pt_sync_domain(d);

    if (_needs_sync)
        *_needs_sync = needs_sync;
}

// Walk one level of the P2M table, allocating a new table if required.
// Returns 0 on error.
//

/* AMD IOMMU: Convert next level bits and r/w bits into 24 bits p2m flags */
#define iommu_nlevel_to_flags(nl, f) ((((nl) & 0x7) << 9 )|(((f) & 0x3) << 21))

static void p2m_add_iommu_flags(l1_pgentry_t *p2m_entry,
                                unsigned int nlevel, unsigned int flags)
{
#if CONFIG_PAGING_LEVELS == 4
#ifndef __UXEN__
    if ( iommu_hap_pt_share )
        l1e_add_flags(*p2m_entry, iommu_nlevel_to_flags(nlevel, flags));
#endif  /* __UXEN__ */
#endif
}

static int
npt_split_super_page(struct p2m_domain *p2m, l1_pgentry_t *p2m_entry,
                     unsigned long gpfn, unsigned long type)
{
    l1_pgentry_t *l1_entry;
    l1_pgentry_t new_entry, split_entry;
    int i, rv;

    switch (type) {
    case PGT_l1_page_table: {
        unsigned long flags, pfn;
        unsigned long mfn;
        uint16_t idx;

        mfn = p2m_alloc_ptp(p2m, gpfn, type, &idx);
        if (!__mfn_valid(mfn))
            return 0;

        new_entry = l1e_from_pfn(mfn, __PAGE_HYPERVISOR|_PAGE_USER);
        new_entry.pte.ptp_idx = idx;

        if (p2m->domain->clone_of &&
            !(p2m->domain->arch.hvm_domain.params[HVM_PARAM_CLONE_L1] &
              (HVM_PARAM_CLONE_L1_lazy_populate |
               HVM_PARAM_CLONE_L1_dynamic))) {
            struct p2m_domain *op2m = p2m_get_hostp2m(p2m->domain->clone_of);
            rv = !p2m_clone_l1(op2m, p2m, pt_level_mask(gpfn, 1),
                               &new_entry, 0);
            if (rv)
                goto out;
        }

        flags = l1e_get_flags(*p2m_entry);
        if (p2m_is_pod(p2m_flags_to_type(flags))) {
            /* when populating a populate on demand superpage, don't
             * "split" the mfn value since it's in most cases 0 or some
             * pod specific value, but not an actual mfn */
#ifndef NDEBUG
            pfn = l1e_get_pfn(*p2m_entry);
            if (pfn)
                WARN_ONCE();
#else  /* NDEBUG */
            pfn = 0;
#endif /* NDEBUG */
            /* split_entry is constant */
            split_entry = l1e_from_pfn(pfn, flags);
            p2m_add_iommu_flags(&split_entry, 0, 0);
        } else {
            /* New splintered mappings inherit the flags of the old superpage,
             * with a little reorganisation for the _PAGE_PSE_PAT bit. */
            pfn = l1e_get_pfn(*p2m_entry);
            if ( pfn & 1 )           /* ==> _PAGE_PSE_PAT was set */
                pfn -= 1;            /* Clear it; _PAGE_PSE becomes _PAGE_PAT */
            else
                flags &= ~_PAGE_PSE; /* Clear _PAGE_PSE (== _PAGE_PAT) */
        }
        l1_entry = (l1_pgentry_t *)pt_map_ptp(p2m, &new_entry.pte);
        for ( i = 0; i < L1_PAGETABLE_ENTRIES; i++ )
        {
            if (!p2m_is_pod(p2m_flags_to_type(flags))) {
                split_entry = l1e_from_pfn(pfn + i, flags);
                p2m_add_iommu_flags(&split_entry, 0, 0);
            }
            write_p2m_entry(p2m, -1, l1_entry + i, split_entry, 1, NULL);
        }
        pt_unmap_ptp(p2m, l1_entry);

        if (p2m_is_pod(p2m_flags_to_type(flags))) {
            ASSERT(!is_template_domain(p2m->domain));
            atomic_dec(&p2m->domain->clone.l1_pod_pages);
            atomic_add(1 << PAGE_ORDER_2M, &p2m->domain->pod_pages);
        }

      out:
        p2m_add_iommu_flags(&new_entry, 1, IOMMUF_readable|IOMMUF_writable);
        write_p2m_entry(p2m, -1, p2m_entry, new_entry, 2, NULL);

        return 1;
    }
    default:
        return 0;
    }
}

static int
p2m_next_level(struct p2m_domain *p2m, bool_t read_only, void **table,
               unsigned long gfn, uint32_t type)
{
    l1_pgentry_t *p2m_entry;
    l1_pgentry_t new_entry;
    void *next;

    if ( !(p2m_entry = p2m_find_entry(p2m, *table, gfn, type + 1)) )
        return GUEST_TABLE_MAP_FAILED;

    /* PoD: Not present doesn't imply empty. */
    if ( !(l1e_get_flags(*p2m_entry) & _PAGE_PRESENT) )
    {
        unsigned long mfn;
        uint16_t idx;

        if (p2m_flags_to_type(l1e_get_flags(*p2m_entry)) ==
            p2m_populate_on_demand)
            return GUEST_TABLE_POD_PAGE;

        if (read_only)
            return GUEST_TABLE_MAP_FAILED;

        mfn = p2m_alloc_ptp(p2m, gfn, type, &idx);
        if (!__mfn_valid(mfn))
            return GUEST_TABLE_MAP_FAILED;

        new_entry = l1e_from_pfn(mfn, __PAGE_HYPERVISOR | _PAGE_USER);
        new_entry.pte.ptp_idx = idx;

        switch ( type ) {
        case PGT_l3_page_table:
            p2m_add_iommu_flags(&new_entry, 3, IOMMUF_readable|IOMMUF_writable);
            write_p2m_entry(p2m, -1, p2m_entry, new_entry, 4, NULL);
            break;
        case PGT_l2_page_table:
#if CONFIG_PAGING_LEVELS == 3
            /* for PAE mode, PDPE only has PCD/PWT/P bits available */
            new_entry = l1e_from_pfn(mfn, _PAGE_PRESENT);
#endif
            p2m_add_iommu_flags(&new_entry, 2, IOMMUF_readable|IOMMUF_writable);
            write_p2m_entry(p2m, -1, p2m_entry, new_entry, 3, NULL);
            break;
        case PGT_l1_page_table:
            p2m_add_iommu_flags(&new_entry, 1, IOMMUF_readable|IOMMUF_writable);
            write_p2m_entry(p2m, -1, p2m_entry, new_entry, 2, NULL);
            break;
        default:
            BUG();
            break;
        }
    }

    ASSERT(l1e_get_flags(*p2m_entry) & (_PAGE_PRESENT|_PAGE_PSE));

    if (l1e_get_flags(*p2m_entry) & _PAGE_PSE)
        return GUEST_TABLE_SUPER_PAGE;

    next = pt_map_ptp(p2m, &p2m_entry->pte);
    pt_unmap_ptp(p2m, *table);
    *table = next;

    return GUEST_TABLE_NORMAL_PAGE;
}

static int
npt_split_super_page_one(struct p2m_domain *p2m, void *entry,
                         unsigned long gpfn, int order)
{
    l1_pgentry_t *l1e = (l1_pgentry_t *)entry;
    int level;

    level = order / PAGETABLE_ORDER;
    if (!level)
        return 1;
    return !npt_split_super_page(p2m, l1e, gpfn, level);
}

int
npt_write_entry(struct p2m_domain *p2m, void *table, unsigned long gfn,
                mfn_t mfn, int target, p2m_type_t p2mt, p2m_access_t p2ma,
                int *needs_sync)
{
    struct domain *d = p2m->domain;
    unsigned long index = pt_level_index(gfn, target);
    l1_pgentry_t *p2m_entry = (l1_pgentry_t *)table + index;
    l1_pgentry_t old_entry = l1e_empty();
    l1_pgentry_t entry_content;
    unsigned int iommu_pte_flags = p2m_is_ram_rw(p2mt) ?
                                   IOMMUF_readable|IOMMUF_writable :
                                   0;

    /* Read-then-write is OK because we hold the p2m lock. */
    old_entry = *p2m_entry;

    if (mfn_valid_page(mfn) ||
        p2m_is_mmio(p2mt) || p2m_is_pod(p2mt))
        entry_content = l1e_from_pfn(mfn_x(mfn),
                                     p2m_type_to_flags(p2mt, mfn));
    else
        entry_content = l1e_empty();

    if ( entry_content.l1 != 0 )
        p2m_add_iommu_flags(&entry_content, 0, iommu_pte_flags);

    /* level 1 entry */
    write_p2m_entry(p2m, gfn, p2m_entry, entry_content, 1, needs_sync);

    if (l1e_get_pfn(old_entry) != mfn_x(mfn)) {
        if (mfn_valid_page_or_vframe(mfn) &&
            mfn_x(mfn) != mfn_x(shared_zero_page))
            get_page_fast(mfn_to_page(mfn), NULL);
        if (__mfn_valid_page_or_vframe(l1e_get_pfn(old_entry)) &&
            l1e_get_pfn(old_entry) != mfn_x(shared_zero_page)) {
            if (p2m_flags_to_type(l1e_get_flags(old_entry)) ==
                p2m_populate_on_demand)
                put_page_destructor(__mfn_to_page(l1e_get_pfn(old_entry)),
                                    p2m_pod_free_page, p2m->domain, gfn);
            else
                put_page(__mfn_to_page(l1e_get_pfn(old_entry)));
        }
    }
    if (old_entry.l1 != entry_content.l1)
        p2m_update_pod_counts(
            d, l1e_get_pfn(old_entry),
            p2m_flags_to_type(l1e_get_flags(old_entry)),
            l1e_get_pfn(entry_content),
            p2m_flags_to_type(l1e_get_flags(entry_content)));

    /* Track the highest gfn for which we have ever had a valid mapping */
    if ( mfn_x(mfn) != INVALID_MFN &&
         (gfn + (1UL << (target * NPT_TABLE_ORDER)) - 1 > p2m->max_mapped_pfn) )
        p2m->max_mapped_pfn = gfn + (1UL << (target * NPT_TABLE_ORDER)) - 1;

    return 0;
}

// Returns 0 on error (out of memory)
static int
p2m_set_entry(struct p2m_domain *p2m, unsigned long gfn, mfn_t mfn, 
              unsigned int page_order, p2m_type_t p2mt, p2m_access_t p2ma)
{
    // XXX -- this might be able to be faster iff current->domain == d
    void *table;
    l1_pgentry_t *pt_entry, old_entry = { .l1 = 0 };
    int i, target = page_order / PAGETABLE_ORDER;
    int rv = 0;
    int ret = 0;
#ifndef __UXEN__
    unsigned long old_mfn = 0;
#endif  /* __UXEN__ */
    union p2m_l1_cache *l1c = &this_cpu(p2m_l1_cache);
    int needs_sync = 1;

    if ( tb_init_done )
    {
        struct {
            u64 gfn, mfn;
            int p2mt;
            int d:16,order:16;
        } t;

        t.gfn = gfn;
        t.mfn = mfn_x(mfn);
        t.p2mt = p2mt;
        t.d = p2m->domain->domain_id;
        t.order = page_order;

        __trace_var(TRC_MEM_SET_P2M_ENTRY, 0, sizeof(t), &t);
    }

    if (target || !l1c->se_l1.va ||
        p2m_l1_prefix(gfn, p2m) != l1c->se_l1_prefix) {
        l1c->se_l1.va = NULL;

        perfc_incr(p2m_set_entry_walk);
        i = target;
        ret = pt_map_ptp_gfn(p2m, 0, (void *)&table, gfn, &i);
        if (!target && !i && ret == GUEST_TABLE_NORMAL_PAGE) {
            int mapped = pt_ptp_mapped(p2m, table);
            l1c->se_l1_prefix = p2m_l1_prefix(gfn, p2m);
            if (mapped)
                l1c->se_l1.va = table;
            else {
                l1c->se_l1.mfn = mapped_domain_page_va_pfn(table);
                l1c->se_l1.is_mfn = 1;
            }
        }
    } else {
        perfc_incr(p2m_set_entry_cached);
        if (!l1c->se_l1.is_mfn) {
            table = l1c->se_l1.va;
            perfc_incr(p2m_map_ptp);
        } else {
            /* use map_domain_page here since we don't have an
             * l1_pgentry_t, but we also know that pt_map_ptp will
             * fallback to it anyway, and OK to free via pt_unmap_ptp
             * below */
            table = map_domain_page(l1c->se_l1.mfn);
            perfc_incr(p2m_map_ptp_fallback);
        }
        i = 0;
        ret = GUEST_TABLE_NORMAL_PAGE;
    }

    ASSERT(ret != GUEST_TABLE_POD_PAGE || i != target);

    pt_entry = (l1_pgentry_t *)table + pt_level_index(gfn, i);

    /* Non-l1 update -- invalidate the get_entry cache */
    if (target && l1e_get_flags(*pt_entry) & _PAGE_PRESENT)
        p2m_ge_l1_cache_invalidate(p2m, gfn, page_order);

    if (i > target) {
        /* If we're here with i > target, we must be at a leaf node, and
         * we need to break up the superpage. */
        if (!npt_split_super_page(p2m, pt_entry, gfn, i))
            goto out;

        /* then move to the level we want to make real changes */
        for ( ; i > target; i-- )
            p2m_next_level(p2m, 0, &table, gfn, i);

        ASSERT(i == target);

        pt_entry = table + pt_level_index(gfn, i);
    }

    /* We reached the target level. */

    /* If we're here with target > 0, we need to check to see
     * if we're replacing a non-leaf entry (i.e., pointing to an N-1 table)
     * with a leaf entry (a 1GiB or 2MiB page), and handle things appropriately.
     */
    /* If we're replacing a non-leaf entry with a leaf entry (1GiB or 2MiB),
     * the intermediate tables will be freed below after the ept flush */
    if (target)
        old_entry = *pt_entry;

    /* No need to flush if new type is logdirty */
    /* XXX Could also skip if old type is logdirty, w/ check that mfn
     * is same, or check in pt_write_entry that only R->W changed */
    if (!target && p2m_is_logdirty(p2mt))
        needs_sync = 0;

    npt_write_entry(p2m, table, gfn, mfn, target, p2mt, p2ma, &needs_sync);

    /* Success */
    rv = 1;

  out:
    pt_unmap_ptp(p2m, table);

    if (needs_sync)
        pt_sync_domain(p2m->domain);

#ifndef __UXEN__
    if ( rv && iommu_enabled && need_iommu(p2m->domain) )
    {
        if ( iommu_hap_pt_share )
        {
            if ( old_mfn && (old_mfn != mfn_x(mfn)) )
                amd_iommu_flush_pages(p2m->domain, gfn, page_order);
        }
        else
        {
            if (p2m_is_ram_rw(p2mt))
                for ( i = 0; i < (1UL << page_order); i++ )
                    iommu_map_page(p2m->domain, gfn+i, mfn_x(mfn)+i,
                                   IOMMUF_readable|IOMMUF_writable);
            else
                for ( int i = 0; i < (1UL << page_order); i++ )
                    iommu_unmap_page(p2m->domain, gfn+i);
        }
    }
#endif  /* __UXEN__ */

    /* Release the old intermediate tables, if any.  This has to be the
       last thing we do, after the ept_sync_domain() and removal
       from the iommu tables, so as to avoid a potential
       use-after-free. */
    if (l1e_get_flags(old_entry) & _PAGE_PRESENT) {
        ASSERT(target);
        p2m_free_entry(p2m, &old_entry, page_order);
    }

    return rv;
}

static int
pt_ro_update_l2_entry(struct p2m_domain *p2m, unsigned long gfn,
                      int read_only, int *_need_sync)
{
    void *table = NULL;
    l1_pgentry_t *p2m_entry;
    unsigned long mfn;
    int rv = 0;
    int need_sync = 0;

    table = pt_map_asr_ptp(p2m);

    /* have p2m_next_level populate (2nd argument == 0) when
     * setting entries read only, i.e. read_only ? 0 : 1,
     * i.e. !read_only */
#if CONFIG_PAGING_LEVELS >= 4
    if ( !p2m_next_level(p2m, !read_only, &table, gfn, PGT_l3_page_table) )
        goto out;
#endif
    if ( !p2m_next_level(p2m, !read_only, &table, gfn, PGT_l2_page_table) )
        goto out;

    p2m_entry = p2m_find_entry(p2m, table, gfn, PGT_l2_page_table);
    ASSERT(p2m_entry);

    mfn = l1e_get_pfn(*p2m_entry);
    if (__mfn_valid_page(mfn)) {
        int flags;

        flags = l1e_get_flags(*p2m_entry);

        if (((flags & _PAGE_RW) ? 0 : 1) != read_only) {
            l1_pgentry_t new_entry;

            flags ^= _PAGE_RW;

            new_entry = l1e_from_pfn(mfn, flags);

            need_sync = *_need_sync && read_only;
            write_p2m_entry(p2m, gfn, p2m_entry, new_entry, 2, &need_sync);
        }

        /* Success */
        rv = 1;
    }

  out:
    *_need_sync = need_sync;
    if (table)
        pt_unmap_ptp(p2m, table);

    return rv;
}

#ifndef __UXEN__
/* Read the current domain's p2m table (through the linear mapping). */
static mfn_t p2m_gfn_to_mfn_current(struct p2m_domain *p2m, 
                                    unsigned long gfn, p2m_type_t *t, 
                                    p2m_access_t *a, p2m_query_t q,
                                    unsigned int *page_order)
{
    mfn_t mfn = _mfn(0);
    p2m_type_t p2mt = p2m_mmio_dm;
    paddr_t addr = ((paddr_t)gfn) << PAGE_SHIFT;
    /* XXX This is for compatibility with the old model, where anything not 
     * XXX marked as RAM was considered to be emulated MMIO space.
     * XXX Once we start explicitly registering MMIO regions in the p2m 
     * XXX we will return p2m_invalid for unmapped gfns */

    l1_pgentry_t l1e = l1e_empty(), *p2m_entry;
    l2_pgentry_t l2e = l2e_empty();
    int ret;
#if CONFIG_PAGING_LEVELS >= 4
    l3_pgentry_t l3e = l3e_empty();
#endif

    ASSERT(gfn < (RO_MPT_VIRT_END - RO_MPT_VIRT_START) 
           / sizeof(l1_pgentry_t));

#if CONFIG_PAGING_LEVELS >= 4
    /*
     * Read & process L3
     */
    p2m_entry = (l1_pgentry_t *)
        &__linear_l2_table[l2_linear_offset(RO_MPT_VIRT_START)
                           + l3_linear_offset(addr)];
pod_retry_l3:
    ret = __copy_from_user(&l3e, p2m_entry, sizeof(l3e));

    if ( ret != 0 || !(l3e_get_flags(l3e) & _PAGE_PRESENT) )
    {
        if ((l3e_get_flags(l3e) & _PAGE_PSE) &&
            p2m_is_pod(p2m_flags_to_type(l3e_get_flags(l3e)))) {
            /* The read has succeeded, so we know that mapping exists */
            if ( q != p2m_query )
            {
                mfn = p2m_pod_demand_populate(p2m, gfn, PAGE_ORDER_1G, q,
                                              p2m_entry);
                if (!mfn_x(mfn))
                    goto pod_retry_l3;
                p2mt = p2m_invalid;
                printk("%s: Allocate 1GB failed!\n", __func__);
                goto out;
            }
            else
            {
                p2mt = p2m_populate_on_demand;
                goto out;
            }
        }
        goto pod_retry_l2;
    }

    if ( l3e_get_flags(l3e) & _PAGE_PSE )
    {
        p2mt = p2m_flags_to_type(l3e_get_flags(l3e));
        ASSERT(l3e_get_pfn(l3e) != INVALID_MFN || !p2m_is_ram(p2mt));
        if (p2m_is_valid(p2mt) )
            mfn = _mfn(l3e_get_pfn(l3e) + 
                       l2_table_offset(addr) * L1_PAGETABLE_ENTRIES + 
                       l1_table_offset(addr));
        else
            p2mt = p2m_mmio_dm;
            
        if ( page_order )
            *page_order = PAGE_ORDER_1G;
        goto out;
    }
#endif
    /*
     * Read & process L2
     */
    p2m_entry = &__linear_l1_table[l1_linear_offset(RO_MPT_VIRT_START)
                                   + l2_linear_offset(addr)];

pod_retry_l2:
    ret = __copy_from_user(&l2e,
                           p2m_entry,
                           sizeof(l2e));
    if ( ret != 0
         || !(l2e_get_flags(l2e) & _PAGE_PRESENT) )
    {
        if ((l2e_get_flags(l2e) & _PAGE_PSE) &&
            p2m_is_pod(p2m_flags_to_type(l2e_get_flags(l2e)))) {
            /* The read has succeeded, so we know that the mapping
             * exits at this point.  */
            if ( q != p2m_query )
            {
                mfn = p2m_pod_demand_populate(p2m, gfn, PAGE_ORDER_2M, q,
                                              p2m_entry);
                if (!mfn_x(mfn))
                    goto pod_retry_l2;

                /* Allocate failed. */
                p2mt = p2m_invalid;
                printk("%s: Allocate failed!\n", __func__);
                goto out;
            }
            else
            {
                p2mt = p2m_populate_on_demand;
                goto out;
            }
        }

        goto pod_retry_l1;
    }
        
    if (l2e_get_flags(l2e) & _PAGE_PSE)
    {
        p2mt = p2m_flags_to_type(l2e_get_flags(l2e));
        ASSERT(l2e_get_pfn(l2e) != INVALID_MFN || !p2m_is_ram(p2mt));

        if ( p2m_is_valid(p2mt) )
            mfn = _mfn(l2e_get_pfn(l2e) + l1_table_offset(addr));
        else
            p2mt = p2m_mmio_dm;

        if ( page_order )
            *page_order = PAGE_ORDER_2M;
        goto out;
    }

    /*
     * Read and process L1
     */

    /* Need to __copy_from_user because the p2m is sparse and this
     * part might not exist */
pod_retry_l1:
    p2m_entry = &phys_to_machine_mapping[gfn];

    ret = __copy_from_user(&l1e,
                           p2m_entry,
                           sizeof(l1e));
            
    if ( ret == 0 ) {
        p2mt = p2m_flags_to_type(l1e_get_flags(l1e));
        ASSERT(l1e_get_pfn(l1e) != INVALID_MFN || !p2m_is_ram(p2mt));

        if (p2m_is_pod(p2m_flags_to_type(l1e_get_flags(l1e)))) {
            /* The read has succeeded, so we know that the mapping
             * exits at this point.  */
            if ( q != p2m_query )
            {
                mfn = p2m_pod_demand_populate(p2m, gfn, PAGE_ORDER_4K, q,
                                              p2m_entry);
                if (!mfn_x(mfn))
                    goto pod_retry_l1;

                /* Allocate failed. */
                p2mt = p2m_invalid;
                goto out;
            }
            else
            {
                p2mt = p2m_populate_on_demand;
                goto out;
            }
        }

        if (p2m_is_valid(p2mt)
#ifndef __UXEN__
            || p2m_is_grant(p2mt)
#endif  /* __UXEN__ */
            )
            mfn = _mfn(l1e_get_pfn(l1e));
        else 
            /* XXX see above */
            p2mt = p2m_mmio_dm;
    }
    
    if ( page_order )
        *page_order = PAGE_ORDER_4K;
out:
    *t = p2mt;
    return mfn_x(mfn) ? mfn : _mfn(INVALID_MFN);
}
#endif  /* __UXEN__ */

static void *
npt_map_l1_table(struct p2m_domain *p2m, unsigned long gpfn,
                 unsigned int *page_order)
{
    pt_entry_t *table = NULL;
    int i;

    if (page_order)
        *page_order = PAGE_ORDER_4K;

    /* This pfn is higher than the highest the p2m map currently holds */
    if (gpfn > p2m->max_mapped_pfn)
        return NULL;

    i = 0;
    pt_map_ptp_gfn(p2m, 1, &table, gpfn, &i);

    if (page_order)
        *page_order = i * PAGETABLE_ORDER;
    if (i) {
        pt_unmap_ptp(p2m, table);
        table = NULL;
    }
    return table;
}

static void *
npt_map_entry_table(struct p2m_domain *p2m, void *_entry)
{
    l1_pgentry_t *entry = (l1_pgentry_t *)_entry;

    if (!p2m_is_valid(p2m_flags_to_type(l1e_get_flags(*entry))) ||
        !__mfn_valid_page(entry->pte.mfn))
        return NULL;

    return pt_map_ptp(p2m, &entry->pte);
}

static mfn_t
npt_parse_entry(void *table, unsigned long index,
                p2m_type_t *t, p2m_access_t *a)
{
    mfn_t mfn;
    l1_pgentry_t *l1e = (l1_pgentry_t *)table + index;

    if (p2m_is_valid(p2m_flags_to_type(l1e_get_flags(*l1e)))) {
        *t = p2m_flags_to_type(l1e_get_flags(*l1e));
        /* Not implemented except with EPT */
        *a = p2m_access_rwx;
        mfn = _mfn(l1e_get_pfn(*l1e));
    } else {
        *t = p2m_mmio_dm;
        /* Not implemented except with EPT */
        *a = p2m_access_n;
        mfn = _mfn(INVALID_MFN);
    }

    return mfn;
}

static mfn_t
p2m_gfn_to_mfn(struct p2m_domain *p2m, unsigned long gfn, 
               p2m_type_t *t, p2m_access_t *a, p2m_query_t q,
               unsigned int *page_order)
{
    mfn_t mfn = _mfn(0);
    l2_pgentry_t *l2e;
    l1_pgentry_t *l1e;
    pt_entry_t *table;
    int ge_l1_cache_slot = ge_l1_cache_hash(gfn, p2m);
    union p2m_l1_cache *l1c = &this_cpu(p2m_l1_cache);
    int mapped;
    int i = 0;
    int ret;

    ASSERT(paging_mode_translate(p2m->domain));

    /* XXX This is for compatibility with the old model, where anything not 
     * XXX marked as RAM was considered to be emulated MMIO space.
     * XXX Once we start explicitly registering MMIO regions in the p2m 
     * XXX we will return p2m_invalid for unmapped gfns */
    *t = p2m_mmio_dm;
    /* Not implemented except with EPT */
    *a = p2m_access_rwx;
    if (page_order)
        *page_order = PAGE_ORDER_4K;

    if ( gfn > p2m->max_mapped_pfn )
        /* This pfn is higher than the highest the p2m map currently holds */
        return _mfn(INVALID_MFN);

#ifndef __UXEN__
    /* Use the fast path with the linear mapping if we can */
    if ( p2m == p2m_get_hostp2m(current->domain) )
        return p2m_gfn_to_mfn_current(p2m, gfn, t, a, q, page_order);
#endif  /* __UXEN__ */

    if (!l1c->ge_l1[ge_l1_cache_slot].va ||
        p2m_l1_prefix(gfn, p2m) != l1c->ge_l1_prefix[ge_l1_cache_slot]) {
        l1c->ge_l1[ge_l1_cache_slot].va = NULL;

        perfc_incr(p2m_get_entry_walk);
      retry:
        i = 0;
        ret = pt_map_ptp_gfn(p2m, 1, &table, gfn, &i);
        if (!ret) {
            if (page_order)
                *page_order = i * PAGETABLE_ORDER;
            goto out;
        } else if (ret == GUEST_TABLE_POD_PAGE) {
            l2e = (l2_pgentry_t *)table + pt_level_index(gfn, i);

            if (q == p2m_query) {
                *t = p2m_populate_on_demand;
                mfn = _mfn(l2e_get_pfn(*l2e));
                goto out;
            }

            /* Populate this superpage */
            ASSERT(i == 1);

            mfn = p2m_pod_demand_populate(p2m, gfn, PAGE_ORDER_2M, q, l2e);
            if (mfn_x(mfn))
                goto out;
            goto retry;
        }

        if (!i && ret == GUEST_TABLE_NORMAL_PAGE) {
            mapped = pt_ptp_mapped(p2m, table);
            l1c->ge_l1_prefix[ge_l1_cache_slot] = p2m_l1_prefix(gfn, p2m);
            if (mapped)
                l1c->ge_l1[ge_l1_cache_slot].va = table;
            else {
                l1c->ge_l1[ge_l1_cache_slot].mfn =
                    mapped_domain_page_va_pfn(table);
                l1c->ge_l1[ge_l1_cache_slot].is_mfn = 1;
            }
        }
    } else {
        perfc_incr(p2m_get_entry_cached);
        if (!l1c->ge_l1[ge_l1_cache_slot].is_mfn) {
            table = l1c->ge_l1[ge_l1_cache_slot].va;
            perfc_incr(p2m_map_ptp);
        } else {
            /* use map_domain_page here since we don't have an
             * l1_pgentry_t, but we also know that pt_map_ptp will
             * fallback to it anyway, and OK to free via pt_unmap_ptp
             * below */
            table = map_domain_page(l1c->ge_l1[ge_l1_cache_slot].mfn);
            perfc_incr(p2m_map_ptp_fallback);
        }
        i = 0;
        ret = GUEST_TABLE_NORMAL_PAGE;
    }

    l1e = (l1_pgentry_t *)table + pt_level_index(gfn, i);

    mfn = _mfn(INVALID_MFN);

    if (is_p2m_zeroing_any(q)) {
        if (p2m_pod_zero_share(p2m, gfn, q, l1e))
            goto out;
        /* set t/mfn below */

    } else if (p2m_is_pod(p2m_flags_to_type(l1e_get_flags(*l1e))) &&
               q != p2m_query) {
        /* PoD: Try to populate */

        if (q == p2m_alloc_r &&
            (p2m->domain->clone_of || mfn_zero_page(l1e_get_pfn(*l1e)))) {
            *t = p2m_populate_on_demand;
            goto out;
        }

        mfn = p2m_pod_demand_populate(p2m, gfn, PAGE_ORDER_4K, q, l1e);
        if (mfn_x(mfn))
            goto out;
    }

    if (p2m_is_valid(p2m_flags_to_type(l1e_get_flags(*l1e)))) {
        *t = p2m_flags_to_type(l1e_get_flags(*l1e));
        mfn = _mfn(l1e_get_pfn(*l1e));
        if (page_order)
            *page_order = i * PAGETABLE_ORDER;
    }

  out:
    pt_unmap_ptp(p2m, table);
    return mfn_x(mfn) ? mfn : _mfn(INVALID_MFN);
}

/* Walk the whole p2m table, changing any entries of the old type
 * to the new type.  This is used in hardware-assisted paging to 
 * quickly enable or diable log-dirty tracking */
static void p2m_change_type_global(struct p2m_domain *p2m,
                                   p2m_type_t ot, p2m_type_t nt)
{
    unsigned long mfn, gfn, flags;
    l1_pgentry_t l1e_content;
    l1_pgentry_t *l1e;
    l2_pgentry_t *l2e;
    unsigned long i1, i2, i3;
    l3_pgentry_t *l3e;
#if CONFIG_PAGING_LEVELS == 4
    l4_pgentry_t *l4e;
    unsigned long i4;
#endif /* CONFIG_PAGING_LEVELS == 4 */

DEBUG();
#ifndef __UXEN__
    BUG_ON(p2m_is_grant(ot) || p2m_is_grant(nt));
#endif  /* __UXEN__ */
    BUG_ON(ot != nt && (p2m_is_mmio_direct(ot) || p2m_is_mmio_direct(nt)));

    if ( !paging_mode_translate(p2m->domain) )
        return;

    if ( pagetable_get_pfn(p2m_get_pagetable(p2m)) == 0 )
        return;

    ASSERT(p2m_locked_by_me(p2m));

#if CONFIG_PAGING_LEVELS == 4
    l4e = (l4_pgentry_t *)pt_map_asr_ptp(p2m);
#else /* CONFIG_PAGING_LEVELS == 3 */
    l3e = (l3_pgentry_t *)pt_map_asr_ptp(p2m);
#endif

#if CONFIG_PAGING_LEVELS >= 4
    for ( i4 = 0; i4 < L4_PAGETABLE_ENTRIES; i4++ )
    {
        if ( !(l4e_get_flags(l4e[i4]) & _PAGE_PRESENT) )
        {
            continue;
        }
        l3e = (l3_pgentry_t *)pt_map_ptp(p2m, &l4e[i4].pte);
#endif
        for ( i3 = 0;
              i3 < ((CONFIG_PAGING_LEVELS==4) ? L3_PAGETABLE_ENTRIES : 8);
              i3++ )
        {
            if ( !(l3e_get_flags(l3e[i3]) & _PAGE_PRESENT) )
            {
                continue;
            }
            if ( (l3e_get_flags(l3e[i3]) & _PAGE_PSE) )
            {
                flags = l3e_get_flags(l3e[i3]);
                if ( p2m_flags_to_type(flags) != ot )
                    continue;
                mfn = l3e_get_pfn(l3e[i3]);
#ifndef __UXEN__
                gfn = get_gpfn_from_mfn(mfn);
#else  /* __UXEN__ */
                gfn = ((i3
#if CONFIG_PAGING_LEVELS >= 4
                    + (i4 * L3_PAGETABLE_ENTRIES)
#endif
                    )
                    * L2_PAGETABLE_ENTRIES) * L1_PAGETABLE_ENTRIES;
#endif  /* __UXEN__ */
                flags = p2m_type_to_flags(nt, _mfn(mfn));
                l1e_content = l1e_from_pfn(mfn, flags | _PAGE_PSE);
                write_p2m_entry(p2m, -1, (l1_pgentry_t *)&l3e[i3],
                                l1e_content, 3, NULL);
                continue;
            }

            l2e = (l2_pgentry_t *)pt_map_ptp(p2m, &l3e[i3].pte);
            for ( i2 = 0; i2 < L2_PAGETABLE_ENTRIES; i2++ )
            {
                if ( !(l2e_get_flags(l2e[i2]) & _PAGE_PRESENT) )
                {
                    continue;
                }

                if ( (l2e_get_flags(l2e[i2]) & _PAGE_PSE) )
                {
                    flags = l2e_get_flags(l2e[i2]);
                    if ( p2m_flags_to_type(flags) != ot )
                        continue;
                    mfn = l2e_get_pfn(l2e[i2]);
                    /* Do not use get_gpfn_from_mfn because it may return 
                       SHARED_M2P_ENTRY */
                    gfn = (i2 + (i3
#if CONFIG_PAGING_LEVELS >= 4
				   + (i4 * L3_PAGETABLE_ENTRIES)
#endif
				)
                           * L2_PAGETABLE_ENTRIES) * L1_PAGETABLE_ENTRIES; 
                    flags = p2m_type_to_flags(nt, _mfn(mfn));
                    l1e_content = l1e_from_pfn(mfn, flags | _PAGE_PSE);
                    write_p2m_entry(p2m, -1, (l1_pgentry_t *)&l2e[i2],
                                    l1e_content, 2, NULL);
                    continue;
                }

                l1e = (l1_pgentry_t *)pt_map_ptp(p2m, &l2e[i2].pte);

                for ( i1 = 0; i1 < L1_PAGETABLE_ENTRIES; i1++, gfn++ )
                {
                    flags = l1e_get_flags(l1e[i1]);
                    if ( p2m_flags_to_type(flags) != ot )
                        continue;
                    mfn = l1e_get_pfn(l1e[i1]);
                    gfn = i1 + (i2 + (i3
#if CONFIG_PAGING_LEVELS >= 4
					+ (i4 * L3_PAGETABLE_ENTRIES)
#endif
				     )
                           * L2_PAGETABLE_ENTRIES) * L1_PAGETABLE_ENTRIES; 
                    /* create a new 1le entry with the new type */
                    flags = p2m_type_to_flags(nt, _mfn(mfn));
                    l1e_content = l1e_from_pfn(mfn, flags);
                    write_p2m_entry(p2m, -1, &l1e[i1], l1e_content, 1, NULL);
                }
                pt_unmap_ptp(p2m, l1e);
            }
            pt_unmap_ptp(p2m, l2e);
        }
#if CONFIG_PAGING_LEVELS >= 4
        pt_unmap_ptp(p2m, l3e);
    }
#endif

#if CONFIG_PAGING_LEVELS == 4
    pt_unmap_ptp(p2m, l4e);
#else /* CONFIG_PAGING_LEVELS == 3 */
    pt_unmap_ptp(p2m, l3e);
#endif

}

/* Set up the p2m function pointers for pagetable format */
void p2m_pt_init(struct p2m_domain *p2m)
{
    p2m->set_entry = p2m_set_entry;
    p2m->get_entry = p2m_gfn_to_mfn;
    p2m->map_l1_table = npt_map_l1_table;
    p2m->map_entry_table= npt_map_entry_table;
    p2m->unmap_table = pt_unmap_ptp;
    p2m->parse_entry = npt_parse_entry;
    p2m->write_entry = npt_write_entry;
    p2m->change_entry_type_global = p2m_change_type_global;
    p2m->split_super_page_one = npt_split_super_page_one;
#ifndef __UXEN__
    p2m->write_p2m_entry = paging_write_p2m_entry;
#endif  /* __UXEN__ */
    p2m->ro_update_l2_entry = pt_ro_update_l2_entry;

    p2m->p2m_l1_cache_id = p2m->domain->domain_id;
    open_softirq(P2M_L1_CACHE_CPU_SOFTIRQ, p2m_l1_cache_flush_softirq);

#ifdef __x86_64__
    p2m->ptp_idx_bits = PTP_IDX_BITS;
#else  /* __x86_64__ */
    p2m->ptp_idx_bits = PTP_IDX_BITS_amd_x86;
#endif  /* __x86_64__ */

    p2m->virgin = 1;
}


#if P2M_AUDIT
/* strict_m2p == 0 allows m2p mappings that don'#t match the p2m. 
 * It's intended for add_to_physmap, when the domain has just been allocated 
 * new mfns that might have stale m2p entries from previous owners */
void audit_p2m(struct p2m_domain *p2m, int strict_m2p)
{
    struct page_info *page;
    struct domain *od;
    unsigned long mfn, gfn, m2pfn, lp2mfn = 0;
    int entry_count = 0;
    mfn_t p2mfn;
    unsigned long orphans_d = 0, orphans_i = 0, mpbad = 0, pmbad = 0;
    int test_linear;
    p2m_type_t type;
    struct domain *d = p2m->domain;

    if ( !paging_mode_translate(d) )
        return;

    //P2M_PRINTK("p2m audit starts\n");

    test_linear = ( (d == current->domain)
                    && !pagetable_is_null(current->arch.monitor_table) );
    if ( test_linear )
        flush_tlb_local();

    spin_lock(&d->page_alloc_lock);

    /* Audit part one: walk the domain's page allocation list, checking
     * the m2p entries. */
    page_list_for_each ( page, &d->page_list )
    {
        mfn = __page_to_mfn(page);

        // P2M_PRINTK("auditing guest page, mfn=%#lx\n", mfn);

        od = page_get_owner(page);

        if ( od != d )
        {
            P2M_PRINTK("wrong owner %#lx -> %p(vm%d) != %p(vm%u)\n",
                       mfn, od, (od?od->domain_id:-1), d, d->domain_id);
            continue;
        }

        gfn = get_gpfn_from_mfn(mfn);
        if ( gfn == INVALID_M2P_ENTRY )
        {
            orphans_i++;
            //P2M_PRINTK("orphaned guest page: mfn=%#lx has invalid gfn\n",
            //               mfn);
            continue;
        }

        if ( gfn == 0x55555555 || gfn == 0x5555555555555555 )
        {
            orphans_d++;
            //P2M_PRINTK("orphaned guest page: mfn=%#lx has debug gfn\n",
            //               mfn);
            continue;
        }

        if ( gfn == SHARED_M2P_ENTRY )
        {
            P2M_PRINTK("shared mfn (%lx) on domain page list!\n",
                    mfn);
            continue;
        }

        p2mfn = gfn_to_mfn_type_p2m(p2m, gfn, &type, p2m_query);
        if ( strict_m2p && mfn_x(p2mfn) != mfn )
        {
            mpbad++;
            P2M_PRINTK("map mismatch mfn %#lx -> gfn %#lx -> mfn %#lx"
                       " (-> gfn %#lx)\n",
                       mfn, gfn, mfn_x(p2mfn),
                       (mfn_valid(p2mfn)
                        ? get_gpfn_from_mfn(mfn_x(p2mfn))
                        : -1u));
            /* This m2p entry is stale: the domain has another frame in
             * this physical slot.  No great disaster, but for neatness,
             * blow away the m2p entry. */
            set_gpfn_from_mfn(mfn, INVALID_M2P_ENTRY);
        }

        if ( test_linear && (gfn <= p2m->max_mapped_pfn) )
        {
            lp2mfn = mfn_x(gfn_to_mfn_type_p2m(p2m, gfn, &type, p2m_query));
            if ( lp2mfn != mfn_x(p2mfn) )
            {
                P2M_PRINTK("linear mismatch gfn %#lx -> mfn %#lx "
                           "(!= mfn %#lx)\n", gfn, lp2mfn, mfn_x(p2mfn));
            }
        }

        // P2M_PRINTK("OK: mfn=%#lx, gfn=%#lx, p2mfn=%#lx, lp2mfn=%#lx\n",
        //                mfn, gfn, mfn_x(p2mfn), lp2mfn);
    }

    spin_unlock(&d->page_alloc_lock);

    /* Audit part two: walk the domain's p2m table, checking the entries. */
    if ( pagetable_get_pfn(p2m_get_pagetable(p2m)) != 0 )
    {
        l2_pgentry_t *l2e;
        l1_pgentry_t *l1e;
        int i1, i2;

#if CONFIG_PAGING_LEVELS == 4
        l4_pgentry_t *l4e;
        l3_pgentry_t *l3e;
        int i4, i3;
        l4e = (l4_pgentry_t *)pt_map_asr_ptp(p2m);
#else /* CONFIG_PAGING_LEVELS == 3 */
        l3_pgentry_t *l3e;
        int i3;
        l3e = (l3_pgentry_t *)pt_map_asr_ptp(p2m);
#endif

        gfn = 0;
#if CONFIG_PAGING_LEVELS >= 4
        for ( i4 = 0; i4 < L4_PAGETABLE_ENTRIES; i4++ )
        {
            if ( !(l4e_get_flags(l4e[i4]) & _PAGE_PRESENT) )
            {
                gfn += 1 << (L4_PAGETABLE_SHIFT - PAGE_SHIFT);
                continue;
            }
            l3e = (l3_pgentry_t *)pt_map_ptp(p2m, &l4e[i4].pte);
#endif
            for ( i3 = 0;
                  i3 < ((CONFIG_PAGING_LEVELS==4) ? L3_PAGETABLE_ENTRIES : 8);
                  i3++ )
            {
                if ( !(l3e_get_flags(l3e[i3]) & _PAGE_PRESENT) )
                {
                    gfn += 1 << (L3_PAGETABLE_SHIFT - PAGE_SHIFT);
                    continue;
                }

                /* check for 1GB super page */
                if ( l3e_get_flags(l3e[i3]) & _PAGE_PSE )
                {
                    mfn = l3e_get_pfn(l3e[i3]);
                    ASSERT(__mfn_valid(mfn));
                    /* we have to cover 512x512 4K pages */
                    for ( i2 = 0; 
                          i2 < (L2_PAGETABLE_ENTRIES * L1_PAGETABLE_ENTRIES);
                          i2++)
                    {
                        m2pfn = get_gpfn_from_mfn(mfn+i2);
                        if ( m2pfn != (gfn + i2) )
                        {
                            pmbad++;
                            P2M_PRINTK("mismatch: gfn %#lx -> mfn %#lx"
                                       " -> gfn %#lx\n", gfn+i2, mfn+i2,
                                       m2pfn);
                            BUG();
                        }
                        gfn += 1 << (L3_PAGETABLE_SHIFT - PAGE_SHIFT);
                        continue;
                    }
                }

                l2e = (l2_pgentry_t *)pt_map_ptp(p2m, &l3e[i3].pte);
                for ( i2 = 0; i2 < L2_PAGETABLE_ENTRIES; i2++ )
                {
                    if ( !(l2e_get_flags(l2e[i2]) & _PAGE_PRESENT) )
                    {
                        if ((l2e_get_flags(l2e[i2]) & _PAGE_PSE) &&
                            p2m_is_pod(
                                p2m_flags_to_type(l2e_get_flags(l2e[i2]))))
                            entry_count+=SUPERPAGE_PAGES;
                        gfn += 1 << (L2_PAGETABLE_SHIFT - PAGE_SHIFT);
                        continue;
                    }
                    
                    /* check for super page */
                    if ( l2e_get_flags(l2e[i2]) & _PAGE_PSE )
                    {
                        mfn = l2e_get_pfn(l2e[i2]);
                        ASSERT(__mfn_valid(mfn));
                        for ( i1 = 0; i1 < L1_PAGETABLE_ENTRIES; i1++)
                        {
                            m2pfn = get_gpfn_from_mfn(mfn+i1);
                            /* Allow shared M2Ps */
                            if ( (m2pfn != (gfn + i1)) &&
                                 (m2pfn != SHARED_M2P_ENTRY) )
                            {
                                pmbad++;
                                P2M_PRINTK("mismatch: gfn %#lx -> mfn %#lx"
                                           " -> gfn %#lx\n", gfn+i1, mfn+i1,
                                           m2pfn);
                                BUG();
                            }
                        }
                        gfn += 1 << (L2_PAGETABLE_SHIFT - PAGE_SHIFT);
                        continue;
                    }

                    l1e = (l1_pgentry_t *)pt_map_ptp(p2m, &l2e[i2].pte);

                    for ( i1 = 0; i1 < L1_PAGETABLE_ENTRIES; i1++, gfn++ )
                    {
                        p2m_type_t type;

                        type = p2m_flags_to_type(l1e_get_flags(l1e[i1]));
                        if ( !(l1e_get_flags(l1e[i1]) & _PAGE_PRESENT) )
                        {
                            if (p2m_is_pod(type))
                                entry_count++;
                            continue;
                        }
                        mfn = l1e_get_pfn(l1e[i1]);
                        ASSERT(__mfn_valid(mfn));
                        m2pfn = get_gpfn_from_mfn(mfn);
                        if ( m2pfn != gfn &&
                             !p2m_is_mmio_direct(type)
#ifndef __UXEN__
                             &&
                             !p2m_is_grant(type) &&
                             !p2m_is_shared(type)
#endif  /* __UXEN__ */
                            )
                        {
                            pmbad++;
                            printk("mismatch: gfn %#lx -> mfn %#lx"
                                   " -> gfn %#lx\n", gfn, mfn, m2pfn);
                            P2M_PRINTK("mismatch: gfn %#lx -> mfn %#lx"
                                       " -> gfn %#lx\n", gfn, mfn, m2pfn);
                            BUG();
                        }
                    }
                    pt_unmap_ptp(p2m, l1e);
                }
                pt_unmap_ptp(p2m, l2e);
            }
#if CONFIG_PAGING_LEVELS >= 4
            pt_unmap_ptp(p2m, l3e);
        }
#endif

#if CONFIG_PAGING_LEVELS == 4
        pt_unmap_ptp(p2m, l4e);
#else /* CONFIG_PAGING_LEVELS == 3 */
        pt_unmap_ptp(p2m, l3e);
#endif

    }

    if ( entry_count != atomic_read(&d->pod_pages) )
    {
        printk("%s: refcounted entry count %d, audit count %d!\n",
               __func__,
               atomic_read(&d->pod_pages),
               entry_count);
        BUG();
    }
        
    //P2M_PRINTK("p2m audit complete\n");
    //if ( orphans_i | orphans_d | mpbad | pmbad )
    //    P2M_PRINTK("p2m audit found %lu orphans (%lu inval %lu debug)\n",
    //                   orphans_i + orphans_d, orphans_i, orphans_d);
    if ( mpbad | pmbad )
    {
        P2M_PRINTK("p2m audit found %lu odd p2m, %lu bad m2p entries\n",
                   pmbad, mpbad);
        WARN();
    }
}
#endif /* P2M_AUDIT */

