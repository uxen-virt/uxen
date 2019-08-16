/******************************************************************************
 * arch/x86/mm/p2m.c
 *
 * physical-to-machine mappings for automatically-translated domains.
 *
 * Parts of this code are Copyright (c) 2009 by Citrix Systems, Inc. (Patrick Colp)
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
#include <asm/hvm/vmx/vmx.h> /* ept_p2m_init() */
#include <xen/event.h>
#include <asm/hvm/pv.h>

#include "mm-locks.h"

int p2m_debug_more = 0;

/* turn on/off 1GB host page table support for hap, default on */
static bool_t __read_mostly opt_hap_1gb = 1;
boolean_param("hap_1gb", opt_hap_1gb);

static bool_t __read_mostly opt_hap_2mb = 1;
boolean_param("hap_2mb", opt_hap_2mb);

/* Printouts */
#define P2M_PRINTK(_f, _a...)                                \
    debugtrace_printk("p2m: %s(): " _f, __func__, ##_a)
#define P2M_ERROR(_f, _a...)                                 \
    printk("pg error: %s(): " _f, __func__, ##_a)
#if P2M_DEBUGGING
#define P2M_DEBUG(_f, _a...)                                 \
    debugtrace_printk("p2mdebug: %s(): " _f, __func__, ##_a)
#else
#define P2M_DEBUG(_f, _a...) do { (void)(_f); } while(0)
#endif


/* Override macros from asm/page.h to make them work with mfn_t */
#undef mfn_to_page
#define mfn_to_page(_m) __mfn_to_page(mfn_x(_m))
#undef mfn_valid
#define mfn_valid(_mfn) __mfn_valid(mfn_x(_mfn))
#undef mfn_valid_page
#define mfn_valid_page(_mfn) __mfn_valid_page(mfn_x(_mfn))
#undef mfn_valid_vframe
#define mfn_valid_vframe(_mfn) __mfn_valid_vframe(mfn_x(_mfn))
#undef page_to_mfn
#define page_to_mfn(_pg) _mfn(__page_to_mfn(_pg))


static void p2m_l1_cache_flush(void);


/* Init the datastructures for later use by the p2m code */
static void p2m_initialise(struct domain *d, struct p2m_domain *p2m)
{
    mm_lock_init(&p2m->lock);
    mm_lock_init(&p2m->logdirty_lock);
    INIT_PAGE_LIST_HEAD(&p2m->pages);

    p2m->domain = d;
    p2m->default_access = p2m_access_rwx;

    printk("vm%u: hap %sabled boot_cpu_data.x86_vendor %s\n",
           d->domain_id, hap_enabled(d) ? "en" : "dis",
           (boot_cpu_data.x86_vendor ==  X86_VENDOR_INTEL) ? "intel" :
           ((boot_cpu_data.x86_vendor ==  X86_VENDOR_AMD) ? "amd" :
            "unsupported"));

    if (!hap_enabled(d)) {
        if (d->domain_id && d->domain_id < DOMID_FIRST_RESERVED)
            printk(XENLOG_ERR "%s: vm%u: VM without hap\n",
                   __FUNCTION__, d->domain_id);
        return;
    }

    if (boot_cpu_data.x86_vendor == X86_VENDOR_INTEL)
        ept_p2m_init(p2m);
    else if (boot_cpu_data.x86_vendor == X86_VENDOR_AMD)
        p2m_pt_init(p2m);

    if (is_template_domain(d)) {
        init_timer(&p2m->template.gc_timer,
                   p2m_pod_gc_template_pages_work, d, 0);
        set_timer(&p2m->template.gc_timer, NOW() + SECONDS(10));
    }

    return;
}

int p2m_init(struct domain *d)
{
    struct p2m_domain *p2m;
    int rc;

    p2m_get_hostp2m(d) = p2m = (struct p2m_domain *)d->extra_1->p2m;
    if ( !zalloc_cpumask_var(&p2m->dirty_cpumask) )
        return -ENOMEM;
    p2m_initialise(d, p2m);

    rc = 0;
    return rc;
}

int
p2m_alive(struct domain *d)
{

    p2m_get_hostp2m(d)->is_alive = 1;

    return 0;
}

void p2m_change_entry_type_global(struct domain *d,
                                  p2m_type_t ot, p2m_type_t nt)
{
    struct p2m_domain *p2m = p2m_get_hostp2m(d);

    p2m_lock(p2m);
    p2m->change_entry_type_global(p2m, ot, nt);
    p2m_unlock(p2m);

    if (p2m_is_logdirty(nt))
        pt_sync_domain(d);
}

mfn_t get_gfn_type_access(struct p2m_domain *p2m, unsigned long gfn,
                    p2m_type_t *t, p2m_access_t *a, p2m_query_t q,
                    unsigned int *page_order)
{
    mfn_t mfn;

    if ( !p2m || !paging_mode_translate(p2m->domain) )
    {
        /* Not necessarily true, but for non-translated guests, we claim
         * it's the most generic kind of memory */
        *t = p2m_ram_rw;
        return _mfn(gfn);
    }

    mfn = p2m->get_entry(p2m, gfn, t, a, q, page_order);

    return mfn;
}

mfn_t
get_gfn_contents(struct domain *d, unsigned long gpfn, p2m_type_t *t,
                 uint8_t *buffer, uint32_t *size, int remove)
{
    struct p2m_domain *p2m = p2m_get_hostp2m(d);
    p2m_access_t a;
    unsigned int page_order;
    mfn_t mfn;
    struct page_info *page;
    void *s;
    uint8_t *data = NULL;
    uint16_t data_size = 0;
    int rc;

    *size = 0;

    rc = p2m_gfn_check_limit(d, gpfn, PAGE_ORDER_4K);
    if (rc)
        return _mfn(ERROR_MFN);

    p2m_lock(p2m);
    mfn = p2m->get_entry(p2m, gpfn, t, &a, p2m_query, &page_order);
    if (mfn_zero_page(mfn_x(mfn)) || is_xen_mfn(mfn_x(mfn)) ||
        is_host_mfn(mfn_x(mfn)))
        goto out;
    while (mfn_valid_page(mfn)) {
        page = mfn_to_page(mfn);
        if (unlikely(page_get_owner(mfn_to_page(mfn)) != d ||
                     !get_page(page, d)))
            /* if the page doesn't belong to this VM, then we don't
             * provide the contents */
            break;

        if (remove)
            guest_physmap_mark_pod_locked(d, gpfn, PAGE_ORDER_4K,
                                          _mfn(SHARED_ZERO_MFN));

        s = map_domain_page(mfn_x(mfn));
        memcpy(buffer, s, PAGE_SIZE);
        unmap_domain_page(s);
        *size = PAGE_SIZE;

        put_page(page);
        goto out;
    }
    while (p2m_is_pod(*t) && p2m_mfn_is_page_data(mfn)) {
        uint16_t offset;

        p2m_get_page_data(p2m, &mfn, &data, &data_size, &offset);

        page = mfn_to_page(mfn);
        if (unlikely(page_get_owner(mfn_to_page(mfn)) != d ||
                     !get_page(page, d)))
            /* if the page storing the compressed data doesn't belong
             * to this VM, then we don't provide the contents */
            break;

        *(uint16_t *)buffer = PAGE_SIZE - sizeof(uint16_t);
        if (!p2m_get_compressed_page_data(
                d, mfn, data, offset,
                &buffer[sizeof(uint16_t)], (uint16_t *)buffer)) {
            mfn = _mfn(ERROR_MFN);
            put_page(page);
            goto out;
        }

        *size = sizeof(uint16_t) + *(uint16_t *)buffer;
        mfn = _mfn(COMPRESSED_MFN);

        put_page(page);
        goto out;
    }
    if (p2m_is_pod(*t)) {
        mfn = _mfn(INVALID_MFN);
        goto out;
    }
    mfn = _mfn(INVALID_MFN);

  out:
    if (data)
        p2m_put_page_data(p2m, data, data_size);
    p2m_unlock(p2m);
    return mfn;
}

int set_p2m_entry(struct p2m_domain *p2m, unsigned long gfn, mfn_t mfn, 
                  unsigned int page_order, p2m_type_t p2mt, p2m_access_t p2ma)
{
    struct domain *d = p2m->domain;
    unsigned long todo = 1ul << page_order;
    unsigned int order;
    int rc = 1;

    ASSERT(p2m_locked_by_me(p2m));

    while ( todo )
    {
        if ( hap_enabled(d) )
            order = ( (((gfn | mfn_x(mfn) | todo) & ((1ul << PAGE_ORDER_1G) - 1)) == 0) &&
                      hvm_hap_has_1gb(d) && opt_hap_1gb ) ? PAGE_ORDER_1G :
                      ((((gfn | mfn_x(mfn) | todo) & ((1ul << PAGE_ORDER_2M) - 1)) == 0) &&
                      hvm_hap_has_2mb(d) && opt_hap_2mb) ? PAGE_ORDER_2M : PAGE_ORDER_4K;
        else
            order = 0;

        if ( !p2m->set_entry(p2m, gfn, mfn, order, p2mt, p2ma) )
            rc = 0;
        gfn += 1ul << order;
        if (mfn_valid_page(mfn))
            mfn = _mfn(mfn_x(mfn) + (1ul << order));
        todo -= 1ul << order;
    }

    return rc;
}

unsigned long
p2m_alloc_ptp(struct p2m_domain *p2m, unsigned long gfn, int level,
              uint16_t *_idx)
{
    struct page_info *pg;
    struct domain *d = p2m->domain;
    uint16_t idx;

    ASSERT(p2m);
    ASSERT(p2m_locked_by_me(p2m));
    ASSERT(p2m->domain);

    idx = pt_gfn_idx(p2m, gfn, level);

    printk(XENLOG_DEBUG "%s: vm%u gfn %lx level %d -> idx %d\n", __FUNCTION__,
           d->domain_id, gfn, level, idx);

    if (_idx && idx < pt_nr_pages(d)) {
        *_idx = idx;

        /* make _idx fit in 1..(1<<p2m->ptp_idx_bits), i.e. leave 0 reserved */
        while (*(_idx) >= (1 << p2m->ptp_idx_bits))
            *(_idx) -= (1 << p2m->ptp_idx_bits) - 1;

        pt_page(d, idx).present = 1;
        return pt_page(d, idx).mfn;
    }

    if (_idx)
        *_idx = 0;

    ASSERT(p2m->domain->arch.paging.alloc_page);
    pg = p2m->domain->arch.paging.alloc_page(p2m->domain);
    if (pg == NULL)
        return INVALID_MFN;

    page_list_add_tail(pg, &p2m->pages);

    return __page_to_mfn(pg);
}

void p2m_free_ptp(struct p2m_domain *p2m, unsigned long mfn, uint16_t idx)
{
    struct domain *d = p2m->domain;
    struct page_info *pg = __mfn_to_page(mfn);
    ASSERT(pg);
    ASSERT(p2m);
    ASSERT(p2m_locked_by_me(p2m));
    ASSERT(d);
    ASSERT(d->arch.paging.free_page);

    if (idx) {
        while (idx < pt_nr_pages(d)) {
            if (pt_page(d, idx).mfn == mfn)
                break;
            idx += (1 << p2m->ptp_idx_bits) - 1;
        }

        ASSERT(idx < pt_nr_pages(d));

        memset((void *)pt_page_va(d, idx), 0, PAGE_SIZE);

        pt_page(d, idx).present = 0;

        return;
    }

    page_list_del(pg, &p2m->pages);

    d->arch.paging.free_page(d, pg);

    return;
}

// Allocate a new p2m table for a domain.
//
// The structure of the p2m table is that of a pagetable for xen (i.e. it is
// controlled by CONFIG_PAGING_LEVELS).
//
// Returns 0 for success or -errno.
//
int p2m_alloc_table(struct p2m_domain *p2m)
{
    unsigned long p2m_top;
    uint16_t p2m_top_idx;
    struct domain *d = p2m->domain;

    p2m_lock(p2m);

    if ( pagetable_get_pfn(p2m_get_pagetable(p2m)) != 0 )
    {
        P2M_ERROR("p2m already allocated for this domain\n");
        p2m_unlock(p2m);
        return -EINVAL;
    }

    printk(XENLOG_INFO "%s: nr_pages %x pt_pages %p nr_pt_pages %x mfns %p\n",
           __FUNCTION__, d->vm_info_shared->vmi_nr_pages_hint,
           (void *)pt_page_va(d, 0), pt_nr_pages(d), &pt_page(d, 0));

    P2M_PRINTK("allocating p2m table\n");

    p2m_top = p2m_alloc_ptp(p2m, 0, PT_WL, &p2m_top_idx);
    if (!__mfn_valid(p2m_top)) {
        p2m_unlock(p2m);
        return -ENOMEM;
    }
    ASSERT(p2m_top_idx == 0);

    p2m->phys_table = pagetable_from_pfn(p2m_top);
    d->arch.hvm_domain.vmx.ept_control.asr  =
        pagetable_get_pfn(p2m_get_pagetable(p2m));

    pv_ept_flush(p2m);

    P2M_PRINTK("populating p2m table\n");

    /* Initialise physmap tables for slot zero. Other code assumes this. */
    /* For Intel, see comments at ept_get_wl() -- this needs
     * ept_get_wl() before ept_wl is set */
    if ( !set_p2m_entry(p2m, 0, _mfn(INVALID_MFN), PAGE_ORDER_4K,
                        p2m_invalid, p2m->default_access) ) {
        p2m_unlock(p2m);
        P2M_PRINTK("failed to initialize p2m table gfn 0\n");
        return -ENOMEM;
    }

    p2m_unlock(p2m);

    P2M_PRINTK("p2m table initialised\n");
    return 0;
}

void p2m_teardown(struct p2m_domain *p2m)
/* Return all the p2m pages to Xen.
 * We know we don't have any extra mappings to these pages */
{
    struct page_info *pg;
    struct domain *d = p2m->domain;

    if (p2m == NULL)
        return;

    p2m_lock(p2m);

    p2m_l1_cache_flush();

    p2m->phys_table = pagetable_null();

    while ( (pg = page_list_remove_head(&p2m->pages)) )
        d->arch.paging.free_page(d, pg);
    p2m_unlock(p2m);

    dsps_release(d);
}

void p2m_final_teardown(struct domain *d)
{
    /* Iterate over all p2m tables per domain */
    if ( d->arch.p2m )
    {
        free_cpumask_var(d->arch.p2m->dirty_cpumask);
        d->arch.p2m = NULL;
    }

}


static void
p2m_remove_page(struct p2m_domain *p2m, unsigned long gfn, unsigned long mfn)
{

    if ( !paging_mode_translate(p2m->domain) )
    {
        return;
    }

    if (p2m_debug_more)
    P2M_DEBUG("removing gfn=%#lx mfn=%#lx\n", gfn, mfn);

    set_p2m_entry(p2m, gfn, _mfn(INVALID_MFN), PAGE_ORDER_4K, p2m_invalid,
                  p2m->default_access);
}

void
guest_physmap_remove_page(struct domain *d, unsigned long gfn,
                          unsigned long mfn)
{
    struct p2m_domain *p2m = p2m_get_hostp2m(d);
    p2m_lock(p2m);
    audit_p2m(p2m, 1);
    p2m_remove_page(p2m, gfn, mfn);
    audit_p2m(p2m, 1);
    p2m_unlock(p2m);
}

int
guest_physmap_add_entry(struct domain *d, unsigned long gfn,
                        unsigned long mfn, p2m_type_t t)
{
    struct p2m_domain *p2m = p2m_get_hostp2m(d);
    int rc = 0;

    if ( !paging_mode_translate(d) )
    {
        return 0;
    }

    rc = p2m_gfn_check_limit(d, gfn, PAGE_ORDER_4K);
    if ( rc != 0 )
        return rc;

    p2m_lock(p2m);
    audit_p2m(p2m, 0);

    if (p2m_debug_more)
    P2M_DEBUG("adding gfn=%#lx mfn=%#lx\n", gfn, mfn);

    if ( __mfn_valid(mfn) )
    {
        if ( !set_p2m_entry(p2m, gfn, _mfn(mfn), PAGE_ORDER_4K, t,
                            p2m->default_access) )
        {
            rc = -EINVAL;
            goto out; /* Failed to update p2m, bail without updating m2p. */
        }
    }
    else
    {
        gdprintk(XENLOG_WARNING, "Adding bad mfn to p2m map (%#lx -> %#lx)\n",
                 gfn, mfn);
        if ( !set_p2m_entry(p2m, gfn, _mfn(INVALID_MFN), PAGE_ORDER_4K,
                            p2m_invalid, p2m->default_access) )
            rc = -EINVAL;
    }

out:
    audit_p2m(p2m, 1);
    p2m_unlock(p2m);

    return rc;
}


/* Modify the p2m type of a single gfn from ot to nt, returning the 
 * entry's previous type.  Resets the access permissions. */
p2m_type_t p2m_change_type(struct domain *d, unsigned long gfn, 
                           p2m_type_t ot, p2m_type_t nt)
{
    p2m_access_t a;
    p2m_type_t pt;
    mfn_t mfn;
    struct p2m_domain *p2m = p2m_get_hostp2m(d);

    p2m_lock(p2m);

    mfn = p2m->get_entry(p2m, gfn, &pt, &a, p2m_query, NULL);
    if ( pt == ot )
        set_p2m_entry(p2m, gfn, mfn, PAGE_ORDER_4K, nt, p2m->default_access);

    p2m_unlock(p2m);

    return pt;
}

/* Modify the p2m type of a range of gfns from ot to nt.
 * Resets the access permissions. */
void p2m_change_type_range(struct domain *d, 
                           unsigned long start, unsigned long end,
                           p2m_type_t ot, p2m_type_t nt)
{
    p2m_access_t a;
    p2m_type_t pt;
    unsigned long gfn;
    mfn_t mfn;
    struct p2m_domain *p2m = p2m_get_hostp2m(d);

    p2m_lock(p2m);

    for ( gfn = start; gfn < end; gfn++ )
    {
        mfn = p2m->get_entry(p2m, gfn, &pt, &a, p2m_query, NULL);
        if ( pt == ot )
            set_p2m_entry(p2m, gfn, mfn, PAGE_ORDER_4K, nt, p2m->default_access);
    }

    p2m_unlock(p2m);

    if (p2m_is_logdirty(nt))
        pt_sync_domain(d);
}

/* Modify the p2m type of a range of gfns from ot to nt.
 * Resets the access permissions. */
void p2m_change_type_range_l2(struct domain *d, 
                              unsigned long start, unsigned long end,
                              p2m_type_t ot, p2m_type_t nt)
{
    unsigned long gfn;
    struct p2m_domain *p2m = p2m_get_hostp2m(d);
    int need_sync = 0;

    p2m_lock(p2m);

    for ( gfn = start; gfn < end; gfn += (1ul << PAGE_ORDER_2M) ) {
        int ns = 1;
        p2m->ro_update_l2_entry(p2m, gfn, p2m_is_logdirty(nt), &ns);
        if (ns)
            need_sync = 1;
    }

    if (need_sync)
        pt_sync_domain(p2m->domain);

    p2m_unlock(p2m);
}



int
set_mmio_dm_p2m_entry(struct domain *d, unsigned long gfn, mfn_t mfn)
{
    int rc = 0;
    p2m_access_t a;
    p2m_type_t ot;
    /* mfn_t omfn; */
    struct p2m_domain *p2m = p2m_get_hostp2m(d);

    if ( !paging_mode_translate(d) )
        return 0;

    p2m_lock(p2m);
    /* omfn = */ p2m->get_entry(p2m, gfn, &ot, &a, p2m_query, NULL);

    P2M_DEBUG("set mmio %lx %lx\n", gfn, mfn_x(mfn));
    rc = set_p2m_entry(p2m, gfn, mfn, PAGE_ORDER_4K, p2m_mmio_dm,
                       p2m->default_access);
    audit_p2m(p2m, 1);
    p2m_unlock(p2m);
    if ( 0 == rc )
        gdprintk(XENLOG_ERR,
            "set_mmio_dm_p2m_entry: set_p2m_entry failed! mfn=%08lx\n",
            mfn_x(get_gfn_query_unlocked(p2m->domain, gfn, &ot)));
    return rc;
}

int
set_mmio_p2m_entry(struct domain *d, unsigned long gfn, mfn_t mfn)
{
    int rc = 0;
    p2m_access_t a;
    p2m_type_t ot;
    /* mfn_t omfn; */
    struct p2m_domain *p2m = p2m_get_hostp2m(d);

    if ( !paging_mode_translate(d) )
        return 0;

    p2m_lock(p2m);
    /* omfn = */ p2m->get_entry(p2m, gfn, &ot, &a, p2m_query, NULL);

    P2M_DEBUG("set mmio %lx %lx\n", gfn, mfn_x(mfn));
    rc = set_p2m_entry(p2m, gfn, mfn, PAGE_ORDER_4K, p2m_mmio_direct, p2m->default_access);
    audit_p2m(p2m, 1);
    p2m_unlock(p2m);
    if ( 0 == rc )
        gdprintk(XENLOG_ERR,
            "set_mmio_p2m_entry: set_p2m_entry failed! mfn=%08lx\n",
            mfn_x(get_gfn_query_unlocked(p2m->domain, gfn, &ot)));
    return rc;
}

int
clear_mmio_p2m_entry(struct domain *d, unsigned long gfn)
{
    int rc = 0;
    mfn_t mfn;
    p2m_access_t a;
    p2m_type_t t;
    struct p2m_domain *p2m = p2m_get_hostp2m(d);

    if ( !paging_mode_translate(d) )
        return 0;

    p2m_lock(p2m);
    mfn = p2m->get_entry(p2m, gfn, &t, &a, p2m_query, NULL);

    /* Do not use mfn_valid() here as it will usually fail for MMIO pages. */
    if ((INVALID_MFN == mfn_x(mfn)) || (!p2m_is_mmio_direct(t))) {
        gdprintk(XENLOG_ERR,
            "clear_mmio_p2m_entry: gfn_to_mfn failed! gfn=%08lx\n", gfn);
        goto out;
    }
    rc = set_p2m_entry(p2m, gfn, _mfn(INVALID_MFN), PAGE_ORDER_4K, p2m_invalid, p2m->default_access);
    audit_p2m(p2m, 1);

out:
    p2m_unlock(p2m);

    return rc;
}

struct p2m_domain *
p2m_get_p2m(struct vcpu *v)
{

    return p2m_get_hostp2m(v->domain);
}

unsigned long paging_gva_to_gfn(struct vcpu *v,
                                unsigned long va,
                                paging_g2g_query_t q,
                                uint32_t *pfec)
{
    struct p2m_domain *hostp2m = p2m_get_hostp2m(v->domain);
    const struct paging_mode *hostmode = paging_get_hostmode(v);

    if (!hostmode) {
        *pfec = 0;
        return INVALID_GFN;
    }

    return hostmode->gva_to_gfn(v, hostp2m, va, q, pfec);
}

int
p2m_translate(struct domain *d, xen_pfn_t *arr, int nr, int write)
{
    struct p2m_domain *p2m;
    p2m_type_t pt;
    mfn_t mfn;
    int j;
    int rc;

    p2m = p2m_get_hostp2m(d);

    p2m_lock(p2m);
    for ( j = 0; j < nr; j++ ) {
        switch (write) {
        case 0:
            /* p2m_alloc_r, fill pod mappings, leave cow mappings as is */
            mfn = get_gfn_type(d, arr[j], &pt, p2m_alloc_r);
            break;
        case 1:
            /* p2m_unshare implies p2m_alloc, break pod/cow mappings */
            mfn = get_gfn_unshare(d, arr[j], &pt);
            break;
        default:
            rc = -EINVAL;
            goto out;
        }
        if (unlikely(is_xen_mfn(mfn_x(mfn))) ||
            unlikely(is_host_mfn(mfn_x(mfn))) ||
            unlikely(mfn_zero_page(mfn_x(mfn))))
            /* don't allow p2m_translate access to xen pages or host pages */
            mfn = _mfn(INVALID_MFN);
        else if (mfn_valid(mfn))  {
            if (!write && p2m_is_pod(pt)) {
                /* Populate on demand: cloned shared page. */
                struct page_info *page = mfn_to_page(mfn);
                ASSERT(d->clone_of == page_get_owner(page));
                if (!get_page(page, page_get_owner(page)))
                    DEBUG();
            } else if (!get_page(mfn_to_page(mfn), d))
                DEBUG();
        }
        put_gfn(d, arr[j]);
        arr[j] = mfn_x(mfn);
    }
    rc = j;
 out:
    p2m_unlock(p2m);
    return rc;
}

DEFINE_PER_CPU(union p2m_l1_cache, p2m_l1_cache);
atomic_t p2m_l1_cache_gen = ATOMIC_INIT(0);

static void
_p2m_l1_cache_flush(union p2m_l1_cache *l1c)
{
    int j;

    l1c->se_l1.va = NULL;
    for (j = 0; j < NR_GE_L1_CACHE; j++)
        l1c->ge_l1[j].va = NULL;
}

static void
p2m_l1_cache_flush(void)
{
    uint16_t oldgen;

    oldgen = atomic_read(&p2m_l1_cache_gen);
    atomic_inc(&p2m_l1_cache_gen);
    if ((oldgen ^ _atomic_read(p2m_l1_cache_gen)) &
        ((P2M_L1_CACHE_GEN_MASK + 1) >> 1))
        cpumask_raise_softirq(&cpu_online_map, P2M_L1_CACHE_CPU_SOFTIRQ);
}

void
p2m_l1_cache_flush_softirq(void)
{

    _p2m_l1_cache_flush(&this_cpu(p2m_l1_cache));
}

/* Non-l1 update -- invalidate the get_entry cache */
void
p2m_ge_l1_cache_invalidate(struct p2m_domain *p2m, unsigned long gfn,
                           unsigned int page_order)
{
    /* flush all per-cpu caches unconditionally */
    p2m_l1_cache_flush();

    perfc_incr(p2m_get_entry_invalidate);
}

/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
