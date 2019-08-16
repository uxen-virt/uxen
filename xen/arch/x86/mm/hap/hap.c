/******************************************************************************
 * arch/x86/mm/hap/hap.c
 *
 * hardware assisted paging
 * Copyright (c) 2007 Advanced Micro Devices (Wei Huang)
 * Parts of this code are Copyright (c) 2007 by XenSource Inc.
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

#include <xen/config.h>
#include <xen/types.h>
#include <xen/mm.h>
#include <xen/trace.h>
#include <xen/sched.h>
#include <xen/perfc.h>
#include <xen/irq.h>
#include <xen/domain_page.h>
#include <xen/guest_access.h>
#include <xen/keyhandler.h>
#include <asm/event.h>
#include <asm/page.h>
#include <asm/current.h>
#include <asm/flushtlb.h>
#include <asm/shared.h>
#include <asm/hap.h>
#include <asm/paging.h>
#include <asm/p2m.h>
#include <asm/domain.h>
#include <xen/numa.h>
#include <asm/hvm/vmx/vmx.h>

#include "private.h"

/* Override macros from asm/page.h to make them work with mfn_t */
#undef mfn_to_page
#define mfn_to_page(_m) __mfn_to_page(mfn_x(_m))
#undef mfn_valid
#define mfn_valid(_mfn) __mfn_valid(mfn_x(_mfn))
#undef page_to_mfn
#define page_to_mfn(_pg) _mfn(__page_to_mfn(_pg))

/************************************************/
/*          HAP VRAM TRACKING SUPPORT           */
/************************************************/

static int hap_enable_vram_tracking(struct domain *d)
{
    struct sh_dirty_vram *dirty_vram = d->arch.hvm_domain.dirty_vram;

    if ( !dirty_vram )
        return -EINVAL;

    /* turn on PG_log_dirty bit in paging mode */
    paging_lock(d);
    d->arch.paging.mode |= PG_log_dirty;
    paging_unlock(d);

    /* set l1e entries of P2M table to be read-only. */
    p2m_change_type_range(d, dirty_vram->begin_pfn, dirty_vram->end_pfn, 
                          p2m_ram_rw, p2m_ram_logdirty);

    return 0;
}

static int hap_disable_vram_tracking(struct domain *d)
{
    struct sh_dirty_vram *dirty_vram = d->arch.hvm_domain.dirty_vram;

    if ( !dirty_vram )
        return -EINVAL;

    paging_lock(d);
    d->arch.paging.mode &= ~PG_log_dirty;
    paging_unlock(d);

    /* set l1e entries of P2M table with normal mode */
    p2m_change_type_range(d, dirty_vram->begin_pfn, dirty_vram->end_pfn, 
                          p2m_ram_logdirty, p2m_ram_rw);

    return 0;
}

static void hap_clean_vram_tracking(struct domain *d)
{
    struct sh_dirty_vram *dirty_vram = d->arch.hvm_domain.dirty_vram;

    if ( !dirty_vram )
        return;

    /* set l1e entries of P2M table to be read-only. */
    p2m_change_type_range(d, dirty_vram->begin_pfn, dirty_vram->end_pfn, 
                          p2m_ram_rw, p2m_ram_logdirty);
}

static int hap_enable_vram_tracking_l2(struct domain *d)
{
    struct sh_dirty_vram *dirty_vram = d->arch.hvm_domain.dirty_vram;

    if ( !dirty_vram )
        return -EINVAL;

    /* turn on PG_log_dirty bit in paging mode */
    paging_lock(d);
    d->arch.paging.mode |= PG_log_dirty;
    paging_unlock(d);

    /* set l2e entries of P2M table to be read-only. */
    p2m_change_type_range_l2(d, dirty_vram->begin_pfn, dirty_vram->end_pfn, 
                             p2m_ram_rw, p2m_ram_logdirty);

    return 0;
}

static int hap_disable_vram_tracking_l2(struct domain *d)
{
    struct sh_dirty_vram *dirty_vram = d->arch.hvm_domain.dirty_vram;

    if ( !dirty_vram )
        return -EINVAL;

    paging_lock(d);
    d->arch.paging.mode &= ~PG_log_dirty;
    paging_unlock(d);

    /* set l1e entries of P2M table with normal mode */
    p2m_change_type_range_l2(d, dirty_vram->begin_pfn, dirty_vram->end_pfn, 
                             p2m_ram_logdirty, p2m_ram_rw);

    return 0;
}

static void hap_clean_vram_tracking_l2(struct domain *d)
{
    struct sh_dirty_vram *dirty_vram = d->arch.hvm_domain.dirty_vram;

    if ( !dirty_vram )
        return;

    /* set l1e entries of P2M table to be read-only. */
    p2m_change_type_range_l2(d, dirty_vram->begin_pfn, dirty_vram->end_pfn, 
                             p2m_ram_rw, p2m_ram_logdirty);
}

static void hap_vram_tracking_init(struct domain *d)
{
    struct sh_dirty_vram *dirty_vram = d->arch.hvm_domain.dirty_vram;

    if ( !dirty_vram )
        return;

    /* XXX add dirty_vram->max_end_pfn to indicate upto where the gpfn
     * space is safe to ro protect, then enable 2nd condition below */
    if (!(dirty_vram->begin_pfn & ((1ul << PAGE_ORDER_2M) - 1)) &&
        /* !(dirty_vram->end_pfn & ((1ul << PAGE_ORDER_2M) - 1)) && */
        p2m_get_hostp2m(d)->ro_update_l2_entry)
        paging_log_dirty_init(d, hap_enable_vram_tracking_l2,
                              hap_disable_vram_tracking_l2,
                              hap_clean_vram_tracking_l2);
    else
        paging_log_dirty_init(d, hap_enable_vram_tracking,
                              hap_disable_vram_tracking,
                              hap_clean_vram_tracking);
}

int hap_track_dirty_vram(struct domain *d,
                         unsigned long begin_pfn,
                         unsigned long nr,
                         XEN_GUEST_HANDLE_64(uint8) dirty_bitmap,
                         unsigned long want_events)
{
    long rc = 0;
    struct sh_dirty_vram *dirty_vram = d->arch.hvm_domain.dirty_vram;

    if ( nr )
    {
        if ( paging_mode_log_dirty(d) && dirty_vram )
        {
            if ( begin_pfn != dirty_vram->begin_pfn ||
                 begin_pfn + nr != dirty_vram->end_pfn )
            {
                paging_log_dirty_disable(d);
                dirty_vram->begin_pfn = begin_pfn;
                dirty_vram->end_pfn = begin_pfn + nr;
                rc = paging_log_dirty_enable(d);
                if (rc != 0)
                    goto param_fail;
            }
        }
        else if ( !paging_mode_log_dirty(d) && !dirty_vram )
        {
            dirty_vram =
                (struct sh_dirty_vram *)d->extra_1->hvm_domain_dirty_vram;

            dirty_vram->begin_pfn = begin_pfn;
            dirty_vram->end_pfn = begin_pfn + nr;
            d->arch.hvm_domain.dirty_vram = dirty_vram;
            hap_vram_tracking_init(d);
            rc = paging_log_dirty_enable(d);
            if (rc != 0)
                goto param_fail;
        }
        else
        {
            if ( !paging_mode_log_dirty(d) && dirty_vram )
                rc = -EINVAL;
            else
                rc = -ENXIO;
            goto param_fail;
        }
        dirty_vram->want_events = want_events;
        /* get the bitmap */
        rc = paging_log_dirty_range(d, begin_pfn, nr, dirty_bitmap);
    }
    else
    {
        if ( paging_mode_log_dirty(d) && dirty_vram ) {
            rc = paging_log_dirty_disable(d);
            dirty_vram = d->arch.hvm_domain.dirty_vram = NULL;
        } else
            rc = 0;
    }

    return rc;

param_fail:
    if ( dirty_vram )
    {
        dirty_vram = d->arch.hvm_domain.dirty_vram = NULL;
    }
    return rc;
}

/************************************************/
/*            HAP LOG DIRTY SUPPORT             */
/************************************************/

/* hap code to call when log_dirty is enable. return 0 if no problem found. */
static int hap_enable_log_dirty(struct domain *d)
{
    /* turn on PG_log_dirty bit in paging mode */
    paging_lock(d);
    d->arch.paging.mode |= PG_log_dirty;
    paging_unlock(d);

    /* set l1e entries of P2M table to be read-only. */
    p2m_change_entry_type_global(d, p2m_ram_rw, p2m_ram_logdirty);

    return 0;
}

static int hap_disable_log_dirty(struct domain *d)
{
    paging_lock(d);
    d->arch.paging.mode &= ~PG_log_dirty;
    paging_unlock(d);

    /* set l1e entries of P2M table with normal mode */
    p2m_change_entry_type_global(d, p2m_ram_logdirty, p2m_ram_rw);

    return 0;
}

static void hap_clean_dirty_bitmap(struct domain *d)
{
    /* set l1e entries of P2M table to be read-only. */
    p2m_change_entry_type_global(d, p2m_ram_rw, p2m_ram_logdirty);
}

void hap_logdirty_init(struct domain *d)
{
    struct sh_dirty_vram *dirty_vram = d->arch.hvm_domain.dirty_vram;
    if ( paging_mode_log_dirty(d) && dirty_vram )
    {
        paging_log_dirty_disable(d);
        dirty_vram = d->arch.hvm_domain.dirty_vram = NULL;
    }

    /* Reinitialize logdirty mechanism */
    paging_log_dirty_init(d, hap_enable_log_dirty,
                          hap_disable_log_dirty,
                          hap_clean_dirty_bitmap);
}

static struct page_info *
hap_alloc_p2m_page(struct domain *d)
{
    struct page_info *pg;
    void *p;

    pg = alloc_domheap_page(NULL, MEMF_host_page);
    if (!pg)
        return NULL;

    page_set_owner(pg, d);
    ASSERT(!(pg->count_info & PGC_count_mask));
    pg->count_info |= 1;

    p = __map_domain_page(pg);
    ASSERT(p != NULL);
    clear_page(p);
    unmap_domain_page(p);

    return pg;
}
static void
hap_free_p2m_page(struct domain *d, struct page_info *pg)
{

    ASSERT((pg->count_info & PGC_count_mask) == 1);
    pg->count_info &= ~PGC_count_mask;
    /* Free should not decrement domain's total allocation, since
     * these pages were allocated without an owner. */
    page_set_owner(pg, NULL);
    free_domheap_page(pg);
}

/************************************************/
/*          HAP DOMAIN LEVEL FUNCTIONS          */
/************************************************/
void hap_domain_init(struct domain *d)
{

    hap_logdirty_init(d);
}

/* return 0 for success, -errno for failure */
int hap_enable(struct domain *d, u32 mode)
{
    int rv = 0;

    domain_pause(d);

    /* error check */
    if ( (d == current->domain) )
    {
        rv = -EINVAL;
        goto out;
    }

    /* Allow p2m and log-dirty code to borrow our memory */
    d->arch.paging.alloc_page = hap_alloc_p2m_page;
    d->arch.paging.free_page = hap_free_p2m_page;

    /* allocate P2m table */
    if ( mode & PG_translate )
    {
        rv = p2m_alloc_table(p2m_get_hostp2m(d));
        if ( rv != 0 )
            goto out;
    }

    /* Now let other users see the new mode */
    d->arch.paging.mode = mode | PG_HAP_enable;

 out:
    domain_unpause(d);
    return rv;
}

void hap_final_teardown(struct domain *d)
{

    p2m_teardown(p2m_get_hostp2m(d));
}

void hap_teardown(struct domain *d)
{

    ASSERT(d->is_dying);
    ASSERT(d != current->domain);

    if ( !paging_locked_by_me(d) )
        paging_lock(d); /* Keep various asserts happy */

    d->arch.paging.mode &= ~PG_log_dirty;

    paging_unlock(d);
}

static const struct paging_mode hap_paging_real_mode;
static const struct paging_mode hap_paging_protected_mode;
static const struct paging_mode hap_paging_pae_mode;
#if CONFIG_PAGING_LEVELS == 4
static const struct paging_mode hap_paging_long_mode;
#endif

void hap_vcpu_init(struct vcpu *v)
{
    v->arch.paging.mode = &hap_paging_real_mode;
}

/************************************************/
/*          HAP PAGING MODE FUNCTIONS           */
/************************************************/
/*
 * HAP guests can handle page faults (in the guest page tables) without
 * needing any action from Xen, so we should not be intercepting them.
 */
static int hap_page_fault(struct vcpu *v, unsigned long va,
                          struct cpu_user_regs *regs)
{
    struct domain *d = v->domain;

DEBUG();
    HAP_ERROR("Intercepted a guest #PF (vm%u.%u) with HAP enabled.\n",
              d->domain_id, v->vcpu_id);
    domain_crash(d);
    return 0;
}

/*
 * HAP guests can handle invlpg without needing any action from Xen, so
 * should not be intercepting it.
 */
static int hap_invlpg(struct vcpu *v, unsigned long va)
{
DEBUG();

    HAP_ERROR("Intercepted a guest INVLPG (vm%u.%u) with HAP enabled.\n",
              v->domain->domain_id, v->vcpu_id);
    domain_crash(v->domain);
    return 0;
}

static int hap_update_cr3(struct vcpu *v, int do_locking)
{
    v->arch.hvm_vcpu.hw_cr[3] = v->arch.hvm_vcpu.guest_cr[3];
    return hvm_update_guest_cr(v, 3);
}

const struct paging_mode *
hap_paging_get_mode(struct vcpu *v)
{
    return !hvm_paging_enabled(v)   ? &hap_paging_real_mode :
#if CONFIG_PAGING_LEVELS == 4
        hvm_long_mode_enabled(v) ? &hap_paging_long_mode :
#endif
        hvm_pae_enabled(v)       ? &hap_paging_pae_mode  :
                                   &hap_paging_protected_mode;
}

static int hap_update_paging_modes(struct vcpu *v)
{
    struct domain *d = v->domain;
    uint64_t cr3;

    paging_lock(d);

    v->arch.paging.mode = hap_paging_get_mode(v);

    cr3 = read_cr3();
    if (v->arch.cr3 != cr3) {
        make_cr3(v, cr3);
        hvm_update_host_cr3(v);
    }

    paging_unlock(d);

    /* CR3 is effectively updated by a mode change. Flush ASIDs, etc. */
    return hap_update_cr3(v, 0);
}

static unsigned long hap_gva_to_gfn_real_mode(
    struct vcpu *v, struct p2m_domain *p2m, unsigned long gva,
    paging_g2g_query_t q, uint32_t *pfec)
{
    return ((paddr_t)gva >> PAGE_SHIFT);
}

static unsigned long hap_p2m_ga_to_gfn_real_mode(
    struct vcpu *v, struct p2m_domain *p2m, unsigned long cr3,
    paddr_t ga, paging_g2g_query_t q, uint32_t *pfec, unsigned int *page_order)
{
DEBUG();
    if ( page_order )
        *page_order = PAGE_ORDER_4K;
    return (ga >> PAGE_SHIFT);
}

/* Entry points into this mode of the hap code. */
static const struct paging_mode hap_paging_real_mode = {
    .page_fault             = hap_page_fault,
    .invlpg                 = hap_invlpg,
    .gva_to_gfn             = hap_gva_to_gfn_real_mode,
    .p2m_ga_to_gfn          = hap_p2m_ga_to_gfn_real_mode,
    .update_cr3             = hap_update_cr3,
    .update_paging_modes    = hap_update_paging_modes,
    .guest_levels           = 1
};

static const struct paging_mode hap_paging_protected_mode = {
    .page_fault             = hap_page_fault,
    .invlpg                 = hap_invlpg,
    .gva_to_gfn             = hap_gva_to_gfn_2_levels,
    .p2m_ga_to_gfn          = hap_p2m_ga_to_gfn_2_levels,
    .update_cr3             = hap_update_cr3,
    .update_paging_modes    = hap_update_paging_modes,
    .guest_levels           = 2
};

static const struct paging_mode hap_paging_pae_mode = {
    .page_fault             = hap_page_fault,
    .invlpg                 = hap_invlpg,
    .gva_to_gfn             = hap_gva_to_gfn_3_levels,
    .p2m_ga_to_gfn          = hap_p2m_ga_to_gfn_3_levels,
    .update_cr3             = hap_update_cr3,
    .update_paging_modes    = hap_update_paging_modes,
    .guest_levels           = 3
};

#if CONFIG_PAGING_LEVELS == 4
static const struct paging_mode hap_paging_long_mode = {
    .page_fault             = hap_page_fault,
    .invlpg                 = hap_invlpg,
    .gva_to_gfn             = hap_gva_to_gfn_4_levels,
    .p2m_ga_to_gfn          = hap_p2m_ga_to_gfn_4_levels,
    .update_cr3             = hap_update_cr3,
    .update_paging_modes    = hap_update_paging_modes,
    .guest_levels           = 4
};
#endif

/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
