/******************************************************************************
 * arch/x86/mm/p2m-pod.c
 *
 * Populate-on-demand p2m entries. 
 *
 * Copyright (c) 2009-2011 Citrix Systems, Inc.
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
 * Copyright 2011-2018, Bromium, Inc.
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
#ifndef __UXEN__
#include <asm/hvm/nestedhvm.h>
#include <asm/hvm/svm/amd-iommu-proto.h>
#endif  /* __UXEN__ */
#include <xen/guest_access.h>
#include <xen/trace.h>
#include <lz4.h>
#include <xen/keyhandler.h>

#include "mm-locks.h"

/* XSA-246/247: set_p2m_entry() can fail if it needs to shatter a superpage and 
 * cannot allocate a new page directory to map the 4k pages. The upstream 
 * patches are not simple to apply, but crashing the world seems strictly  
 * better than silently failing to map (or unmap) as this can lead to hang, 
 * infinite loop, or information leaks. -- KAF */
#define SET_P2M_UNEXPECTED_FAIL() BUG()
static inline void set_p2m_entry_unchecked(
    struct p2m_domain *p2m, unsigned long gfn, mfn_t mfn, 
    unsigned int page_order, p2m_type_t p2mt, p2m_access_t p2ma)
{
    if (!set_p2m_entry(p2m, gfn, mfn, page_order, p2mt, p2ma))
        SET_P2M_UNEXPECTED_FAIL();
}

/* Override macros from asm/page.h to make them work with mfn_t */
#undef mfn_to_page
#define mfn_to_page(_m) __mfn_to_page(mfn_x(_m))
#undef mfn_valid
#define mfn_valid(_mfn) __mfn_valid(mfn_x(_mfn))
#undef mfn_valid_page
#define mfn_valid_page(_mfn) __mfn_valid_page(mfn_x(_mfn))
#undef mfn_valid_vframe
#define mfn_valid_vframe(_mfn) __mfn_valid_vframe(mfn_x(_mfn))
#undef mfn_valid_page_or_vframe
#define mfn_valid_page_or_vframe(_mfn) __mfn_valid_page_or_vframe(mfn_x(_mfn))
#undef mfn_zero_page
#define mfn_zero_page(_mfn) __mfn_zero_page(mfn_x(_mfn))
#undef page_to_mfn
#define page_to_mfn(_pg) _mfn(__page_to_mfn(_pg))

#ifndef __UXEN__
#define superpage_aligned(_x)  (((_x)&(SUPERPAGE_PAGES-1))==0)
#endif  /* __UXEN__ */

/* Enforce lock ordering when grabbing the "external" page_alloc lock */
static inline void lock_page_alloc(struct p2m_domain *p2m)
{
    page_alloc_mm_pre_lock();
    spin_lock(&(p2m->domain->page_alloc_lock));
    page_alloc_mm_post_lock(p2m->domain->arch.page_alloc_unlock_level);
}

static inline void unlock_page_alloc(struct p2m_domain *p2m)
{
    page_alloc_mm_unlock(p2m->domain->arch.page_alloc_unlock_level);
    spin_unlock(&(p2m->domain->page_alloc_lock));
}

/*
 * Populate-on-demand functionality
 */

static void check_immutable(p2m_query_t q, struct domain *d, unsigned long gfn)
{
    struct domain *template = d->clone_of;
    struct p2m_domain *p2m;
    p2m_type_t t;
    p2m_access_t a;
    mfn_t mfn;

/* The "!is_p2m_guest_query(q)" check is a bit fragile. It is supposed to mean:
   I was called by  hvm_hap_nested_page_fault, via
   1295     mfn = get_gfn_type_access(p2m, gfn, &p2mt, &p2ma, p2m_guest, NULL);
   line. It is the only occurence of rvalue p2m_guest, though */
    if (!is_p2m_guest_query(q))
        return;
    if (!template || !(current->domain->introspection_features & XEN_DOMCTL_INTROSPECTION_FEATURE_IMMUTABLE_MEMORY))
        return;
    p2m = p2m_get_hostp2m(template);
    mfn = p2m->get_entry(p2m, gfn, &t, &a, p2m_query, NULL);
    if (mfn_x(mfn) == INVALID_MFN)
       gdprintk(XENLOG_WARNING, "INVALID_MFN for gfn 0x%lx in the template?\n", gfn);
    else if (p2m_is_immutable(t)) {
        gdprintk(XENLOG_WARNING, "write to immutable gfn 0x%lx\n", gfn);
        hvm_dump_vcpu(current, "immutable_memory");
        send_introspection_ioreq_detailed(
            XEN_DOMCTL_INTROSPECTION_FEATURE_IMMUTABLE_MEMORY,
            guest_cpu_user_regs()->eip,
            hvm_exit_info(current, EXIT_INFO_guest_linear_address));
    }
}

#ifndef NDEBUG
// #define P2M_POD_STAT_UPDATE 1
#endif  /* NDEBUG */

#ifdef P2M_POD_STAT_UPDATE
static uint64_t host_memory_saved = 0;
static DEFINE_SPINLOCK(host_memory_saved_lock);

static void
update_host_memory_saved(int64_t delta)
{
    spin_lock(&host_memory_saved_lock);
    host_memory_saved += delta;
    spin_unlock(&host_memory_saved_lock);
}

#define TEMPLATE_STAT_RATE MILLISECS(200)
#define VM_STAT_RATE MILLISECS(1000)

static void
p2m_pod_stat_update(struct domain *d)
{
    static int have_clone = 0;
    s_time_t n;
    uint64_t memory_saved;
    char m[256];

    if (is_template_domain(d) && !have_clone)
        return;
    have_clone = 1;

    spin_lock(&host_memory_saved_lock);
    memory_saved = host_memory_saved >> PAGE_SHIFT;
    spin_unlock(&host_memory_saved_lock);

    spin_lock(&d->p2m_stat_lock);

    n = NOW() - d->p2m_stat_last;
    if (/* ((d->p2m_stat_ops++ > 100) && (n > MILLISECS(20))) || */
        (n > (is_template_domain(d) ? TEMPLATE_STAT_RATE : VM_STAT_RATE))) {
        int id = 1 + ((d->domain_id - 1) % 52);
        if (id > 26)
            id += 6;
        id += 64;
        d->p2m_stat_last = NOW();
        d->p2m_stat_ops = 0;
        if (!is_template_domain(d))
            snprintf(m, sizeof(m) - 1,
                     "p2m_pod_stat %"PRId64" %"PRId64" %d %c %d %"PRId64
                     " %d %d %d\n",
                     (u64)((d->p2m_stat_last - d->start_time) / 1000000UL),
                     (u64)(d->p2m_stat_last / 1000000UL),
                     d->domain_id, id,
#ifdef __i386__
                     atomic_read(&hidden_pages_allocated) +
#endif  /* __i386__ */
                     atomic_read(&host_pages_allocated), memory_saved,
                     d->tot_pages,
                     atomic_read(&d->tmpl_shared_pages),
                     atomic_read(&d->zero_shared_pages)
                );
        else
            snprintf(m, sizeof(m) - 1,
                     "p2m_pod_stat %"PRId64" %"PRId64" %d %c %d %"PRId64
                     " %d %d %d %d %d %d\n",
                     (u64)((d->p2m_stat_last - d->start_time) / 1000000UL),
                     (u64)(d->p2m_stat_last / 1000000UL),
                     d->domain_id, id,
#ifdef __i386__
                     atomic_read(&hidden_pages_allocated) +
#endif  /* __i386__ */
                     atomic_read(&host_pages_allocated), memory_saved,
                     d->tot_pages,
                     atomic_read(&d->tmpl_shared_pages),
                     atomic_read(&d->zero_shared_pages),
                     atomic_read(&d->template.compressed_pages),
                     atomic_read(&d->template.compressed_pdata),
                     atomic_read(&d->template.decompressed_shared)
                );
        UI_HOST_CALL(ui_printf, NULL, "%s", m);
    }

    spin_unlock(&d->p2m_stat_lock);
}
#else  /* P2M_POD_STAT_UPDATE */
#define p2m_pod_stat_update(d) do { (void)(d); } while (/* CONSTCOND */0)
#define update_host_memory_saved(delta)                 \
    do { (void)(delta); } while (/* CONSTCOND */0)
#endif /* P2M_POD_STAT_UPDATE */

struct page_data_info {
    uxen_mfn_t mfn;             /* protected by page store write lock */
    uint16_t size;
    uint8_t data[];
} __attribute__ ((packed));

static DEFINE_PER_CPU(uint8_t *, decompress_buffer);

static always_inline int
check_decompress_buffer(void)
{

    if (unlikely(!this_cpu(decompress_buffer))) {
        this_cpu(decompress_buffer) = alloc_xenheap_page();
        if (unlikely(!this_cpu(decompress_buffer)))
            return 0;
    }
    return 1;
}

#define CSIZE_MAX                                                       \
    (PAGE_STORE_MAX - DSPS_slot_data_offset - sizeof(struct page_data_info))

static mfn_t
p2m_pod_add_compressed_page(struct p2m_domain *p2m, unsigned long gpfn,
                            uint8_t *c_data, uint16_t c_size,
                            struct page_info *new_page)
{
    struct domain *d = p2m->domain;
    mfn_t mfn;
    struct page_data_info _pdi = { };
    struct page_info *page, *vpage;
    uint16_t offset;

    ASSERT(c_size <= CSIZE_MAX);

    if (!p2m->dsps)
        dsps_init(d);

    vpage = alloc_vframe(d);
    if (!vpage)
        BUG();
    mfn = page_to_mfn(vpage);

    BUILD_BUG_ON(sizeof(struct page_data_info) !=
                 offsetof(struct page_data_info, data));
    _pdi.size = c_size;
    // _pdi.mfn = _mfn(0);
    dsps_add(d, mfn_x(mfn), &_pdi, sizeof(_pdi), c_data, c_size,
             &page, &offset, &new_page);

    vpage->page_data.page = page_to_pdx(page);
    vpage->page_data.offset = offset;

    set_p2m_entry_unchecked(p2m, gpfn, mfn, 0, p2m_populate_on_demand,
                            p2m->default_access);
    put_page(vpage);

    ASSERT(p2m_locked_by_me(p2m));

    /* page was not used? */
    if (new_page)
        put_allocated_page(d, new_page);
    else
        atomic_inc(&d->template.compressed_pdata);
    atomic_inc(&d->template.compressed_pages);
    update_host_memory_saved(
        PAGE_SIZE -
        (DSPS_DSIZE_bytes_used(sizeof(struct page_data_info) + c_size)));
    p2m_pod_stat_update(d);

    return mfn;
}

#ifndef NDEBUG
static int
p2m_pod_compress_page(struct p2m_domain *p2m, unsigned long gfn_aligned,
                      mfn_t mfn, void *target, int refs)
{
    struct domain *d = p2m->domain;
    struct page_info *new_page = NULL;
    mfn_t checkmfn;
    uint16_t c_size;
    p2m_type_t t;
    p2m_access_t a;

    /* in case of failures, leave page uncompressed */

    if (unlikely(!check_decompress_buffer()))
        return 1;

    c_size = LZ4_compress_limitedOutput(
        target, (char *)this_cpu(decompress_buffer), PAGE_SIZE, CSIZE_MAX);
    if (c_size) {
        /* compress successful, allocate page to store compressed data */
        new_page = alloc_domheap_page(d, PAGE_ORDER_4K);
        if (!new_page)
            return 1;
    } else
        return 1;

    p2m_lock(p2m);

    /* Check page is not compressed/replaced yet */
    checkmfn = p2m->get_entry(p2m, gfn_aligned, &t, &a, p2m_query, NULL);
    if (mfn_x(mfn) != mfn_x(checkmfn) ||
        (refs && (mfn_to_page(mfn)->count_info & PGC_count_mask) != refs)) {
        p2m_unlock(p2m);
        if (new_page)
            put_page(new_page);
        return 1;
    }

    p2m_pod_add_compressed_page(p2m, gfn_aligned, this_cpu(decompress_buffer),
                                c_size, new_page);
    p2m_unlock(p2m);

    p2m_pod_stat_update(d);
    perfc_incr(compressed_pages);
    return 1;
}
#endif  /* NDEBUG */

int
p2m_get_compressed_page_data(struct domain *d, mfn_t mfn, uint8_t *data,
                             uint16_t offset, void *target, uint16_t *c_size)
{
    mfn_t p_cont;
    uint8_t *data_cont = NULL;
    uint16_t size;
    int uc_size;
    struct page_data_info *pdi;
    void *source;
    int ret = 1;

    pdi = (struct page_data_info *)&data[offset];
    size = pdi->size;
    offset += sizeof(struct page_data_info);
    if (offset == PAGE_STORE_MAX) {
        perfc_incr(decompressed_pages_detached);
        p_cont = page_to_mfn(dsps_next(d, sizeof(struct page_data_info) + size,
                                       mfn_to_page(mfn)));
        ASSERT(mfn_x(p_cont));
        data_cont = map_domain_page_direct(mfn_x(p_cont));
        source = data_cont;
    } else if (offset + size > PAGE_STORE_MAX) {
        perfc_incr(decompressed_pages_split);
        if (unlikely(!check_decompress_buffer())) {
            ret = 0;
            goto out;
        }
        memcpy(this_cpu(decompress_buffer), &data[offset],
               PAGE_STORE_MAX - offset);
        p_cont = page_to_mfn(dsps_next(d, sizeof(struct page_data_info) + size,
                                       mfn_to_page(mfn)));
        ASSERT(mfn_x(p_cont));
        data_cont = map_domain_page_direct(mfn_x(p_cont));
        memcpy(this_cpu(decompress_buffer) + PAGE_STORE_MAX - offset,
               data_cont, size - (PAGE_STORE_MAX - offset));
        source = this_cpu(decompress_buffer);
    } else
        source = pdi->data;

    if (!c_size) {
        uc_size = LZ4_decompress_safe((const char *)source, target, size,
                                      PAGE_SIZE);
        if (uc_size != PAGE_SIZE) {
            ret = 0;
            goto out;
        }
    } else {
        if (size > *c_size) {
            ret = 0;
            goto out;
        }
        memcpy(target, source, size);
        *c_size = size;
    }

  out:
    if (data_cont)
        unmap_domain_page_direct(data_cont);
    return ret;
}

int
_p2m_get_page_data(struct p2m_domain *p2m, mfn_t *mfn, uint8_t **data,
                   uint16_t *data_size, uint16_t *offset, int write_lock)
{
    struct page_info *vpage = mfn_to_page(*mfn);
    struct page_data_info *pdi;

    *offset = vpage->page_data.offset;
    *mfn = _mfn(pdx_to_pfn(vpage->page_data.page));
    *data = map_domain_page_direct(mfn_x(*mfn));

    pdi = (struct page_data_info *)&(*data)[*offset];
    *data_size = sizeof(struct page_data_info) + pdi->size;

    dsps_lock(p2m->domain, *data_size, write_lock);

    return 0;
}

void
_p2m_put_page_data(struct p2m_domain *p2m, uint8_t *data, uint16_t data_size,
                   int write_lock)
{

    unmap_domain_page_direct(data);
    dsps_unlock(p2m->domain, data_size, write_lock);
}

static int
p2m_pod_get_decompressed_page(struct p2m_domain *p2m, mfn_t mfn, mfn_t *tmfn,
                              struct domain *page_owner)
{
    struct domain *d = p2m->domain;
    uint8_t *data = NULL;
    uint16_t data_size = 0;
    int wr_lock = 0;
    struct page_data_info *pdi;
    uint16_t offset;
    int ret = 1;

    p2m_lock_recursive(p2m);
    if (p2m_get_page_data(p2m, &mfn, &data, &data_size, &offset)) {
        ret = 0;
        p2m_unlock(p2m);
        goto out;
    }

    pdi = (struct page_data_info *)&data[offset];

    /* check if decompressed page exists */
    if (page_owner == d && pdi->mfn &&
        get_page(__mfn_to_page(pdi->mfn), page_owner)) {
        *tmfn = _mfn(pdi->mfn);
        p2m_unlock(p2m);
        perfc_incr(decompressed_shared);
        goto out;
    }
    p2m_unlock(p2m);
    ret = 0;
  out:
    if (data)
        _p2m_put_page_data(p2m, data, data_size, wr_lock);
    return ret;
}

static int
p2m_pod_decompress_page(struct p2m_domain *p2m, mfn_t mfn, mfn_t *tmfn,
                        struct domain *page_owner, int share)
{
    struct domain *d = p2m->domain;
    struct page_info *p = NULL;
    mfn_t pmfn = mfn;
    uint8_t *data = NULL;
    uint16_t data_size = 0;
    int wr_lock = 0;
    struct page_data_info *pdi;
    uint16_t offset;
    void *target = NULL;
    int ret = 1;

    p2m_lock_recursive(p2m);
    if (p2m_get_page_data(p2m, &mfn, &data, &data_size, &offset)) {
        ret = 0;
        p2m_unlock(p2m);
        goto out;
    }

    pdi = (struct page_data_info *)&data[offset];

    /* check if decompressed page exists */
    if (share && page_owner == d && pdi->mfn &&
        get_page(__mfn_to_page(pdi->mfn), page_owner)) {
        *tmfn = _mfn(pdi->mfn);
        p2m_unlock(p2m);
        perfc_incr(decompressed_shared);
        goto out;
    }
    p2m_unlock(p2m);

    p = alloc_domheap_page(page_owner, 0);
    if (!p) {
        ret = 0;
        goto out;
    }
    *tmfn = page_to_mfn(p);

    target = map_domain_page_direct(mfn_x(*tmfn));
    ret = p2m_get_compressed_page_data(d, mfn, data, offset, target, NULL);
    if (!ret)
        goto out;

    if (share && page_owner == d) {
        p2m_put_page_data(p2m, data, data_size);
        data = NULL;
        p2m_lock_recursive(p2m);
        mfn = pmfn;
        if (p2m_get_page_data_and_write_lock(p2m, &mfn, &data, &data_size,
                                             &offset)) {
            ret = 0;
            p2m_unlock(p2m);
            goto out;
        }
        wr_lock = 1;
        pdi = (struct page_data_info *)&data[offset];
        if (pdi->mfn && get_page(__mfn_to_page(pdi->mfn), page_owner)) {
            /* page was decompressed concurrently, share it and free
             * our page via goto out w/ p != NULL */
            *tmfn = _mfn(pdi->mfn);
            p2m_unlock(p2m);
            perfc_incr(decompressed_in_vain);
            goto out;
        }
        pdi->mfn = mfn_x(*tmfn);
        atomic_inc(&d->template.decompressed_shared);
        if (!(page_owner->arch.hvm_domain.params[HVM_PARAM_COMPRESSED_GC] &
              HVM_PARAM_COMPRESSED_GC_decompressed))
            get_page_fast(p, page_owner);
        p2m_unlock(p2m);
        perfc_incr(decompressed_shareable);
        update_host_memory_saved(-PAGE_SIZE);
        p2m_pod_stat_update(d);
    }

    perfc_incr(decompressed_pages);

    p2m_pod_stat_update(d);
    p = NULL;                   /* sucess -- don't free the page */
  out:
    if (target)
        unmap_domain_page_direct(target);
    if (data)
        _p2m_put_page_data(p2m, data, data_size, wr_lock);
    if (p)
        put_allocated_page(page_owner, p);
    return ret;
}

static int
p2m_teardown_compressed_one_cb(void *_pdi, uint16_t size, struct domain *d,
                               void *opaque)
{
    struct page_data_info *pdi = _pdi;
    int *decomp = opaque;

    /* if GC_decompressed is enabled, then no reference is held on the
     * page for pdi->mfn */
    if (d->arch.hvm_domain.params[HVM_PARAM_COMPRESSED_GC] &
        HVM_PARAM_COMPRESSED_GC_decompressed)
        return 0;

    if (pdi->mfn && get_page(__mfn_to_page(pdi->mfn), d)) {
        uxen_mfn_t mfn = pdi->mfn;
        pdi->mfn = 0;
        (*decomp)++;
        put_allocated_page(d, __mfn_to_page(mfn));
        put_page(__mfn_to_page(mfn));
        update_host_memory_saved(PAGE_SIZE);
    }

    return 0;
}

void
p2m_teardown_compressed(struct p2m_domain *p2m)
{
    struct domain *d = p2m->domain;
    int n = 0, comp = 0, decomp = 0;

    if (!p2m->dsps)
        return;

    n = dsps_teardown(d, p2m_teardown_compressed_one_cb, &comp, &decomp);
    if (n < 0) {
        printk(XENLOG_ERR "%s: dsps_teardown failed ret %d\n", __FUNCTION__, n);
        return;
    }

    printk(XENLOG_INFO "%s: vm%d %d pages freed (%d comp and %d decomp)\n",
           __FUNCTION__, d->domain_id, n + decomp, comp, decomp);
}

mfn_t
p2m_pod_demand_populate(struct p2m_domain *p2m, unsigned long gfn,
                        unsigned int order, p2m_query_t q, void *entry)
{
    struct domain *d = p2m->domain;
    struct page_info *p = NULL; /* Compiler warnings */
    unsigned long gfn_aligned;
    mfn_t mfn, smfn;
    p2m_type_t t, pod_p2mt = p2m_ram_rw;
    p2m_access_t a;
    void *source, *target;
    mfn_t put_page_parent = _mfn(0);
    struct p2m_domain *op2m = d->clone_of ? p2m_get_hostp2m(d->clone_of) : NULL;
    bool_t op2m_locked = 0;
    long ret;

#define out_fail() (({                                          \
                if (mfn_x(put_page_parent))                     \
                    put_page(mfn_to_page(put_page_parent));     \
                if (op2m_locked)                                \
                    p2m_unlock(op2m);                           \
                p2m_unlock(p2m);                                \
                domain_crash(d);                                \
                _mfn(INVALID_MFN);                              \
            }))

#define out_of_memory() (({                                             \
                printk(XENLOG_ERR "%s: out of memory --"                \
                       " tot_pages %u max_pages %u\n",                  \
                       __FUNCTION__, d->tot_pages, d->max_pages);       \
                out_fail();                                             \
            }))

    /* This is called from the p2m lookups, which can happen with or 
     * without the lock hed. */
    p2m_lock_recursive(p2m);

    /* This check is done with the p2m lock held.  This will make sure that
     * even if d->is_dying changes under our feet, p2m_pod_empty_cache() 
     * won't start until we're done. */
    if (unlikely(d->is_dying)) {
        if (op2m_locked)
            p2m_unlock(op2m);
        p2m_unlock(p2m);
        return _mfn(INVALID_MFN);
    }

    gfn_aligned = (gfn >> order) << order;

    /* parse entry with lock held */
    smfn = p2m->parse_entry(entry, 0, &t, &a);

    /* Check to make sure this is still PoD, also check for spurious
     * read accesses to entries already populated from other vcpus. */
    if (!p2m_is_pod(t) || ((q == p2m_guest_r || q == p2m_alloc_r) &&
                           mfn_valid_page(smfn))) {
        p2m_unlock(p2m);
        return _mfn(0);
    }

    switch (order) {
    case PAGE_ORDER_1G:
        /* Because PoD does not have cache list for 1GB pages, it has to remap
         * 1GB region to 2MB chunks for a retry. */
        /* Note that we are supposed to call set_p2m_entry() 512 times to 
         * split 1GB into 512 2MB pages here. But We only do once here because
         * set_p2m_entry() should automatically shatter the 1GB page into 
         * 512 2MB pages. The rest of 511 calls are unnecessary.
         */
        set_p2m_entry_unchecked(p2m, gfn_aligned, _mfn(0), PAGE_ORDER_2M,
                                p2m_populate_on_demand, p2m->default_access);
        audit_p2m(p2m, 1);
        p2m_unlock(p2m);
        return _mfn(0);
    case PAGE_ORDER_2M:
        if (!d->clone_of) {
            gdprintk(XENLOG_ERR, "PAGE_ORDER_2M pod in non-clone VM\n");
            return out_fail();
        }

        ret = p2m_clone_l1(p2m_get_hostp2m(d->clone_of), p2m, gfn_aligned,
                           entry, 1);
        p2m_unlock(p2m);
        return ret ? _mfn(INVALID_MFN) : _mfn(0);
    }

    ASSERT(order == 0);
    ASSERT(mfn_x(smfn) != INVALID_MFN);

    if (mfn_x(smfn) == 0) {
        p2m_lock_recursive(op2m);
        op2m_locked = 1;

        smfn = op2m->get_entry(op2m, gfn_aligned, &t, &a, p2m_query, NULL);
        /* templates only have SHARED_ZERO_MFN */
        ASSERT(mfn_x(smfn) != mfn_x(shared_zero_page));
        if (mfn_x(smfn) == INVALID_MFN) {
            p2m_unlock(op2m);
            op2m_locked = 0;
            /* clear this ept entry since it's not present in the
             * template p2m -- this happens if the l1 is accessed/used
             * between when it's allocated and filled with pod entries
             * (xpt_split_super_page), and when its entries are copied
             * from the template (clone_l1_table), or more often in
             * the case where the l1 table is populated lazily
             * (HVM_PARAM_CLONE_L1_lazy_populate) */
            set_p2m_entry_unchecked(p2m, gfn_aligned, _mfn(0), 0, 0, 0);
            ret = 0;
            goto out;
        }
        if ((d->arch.hvm_domain.params[HVM_PARAM_CLONE_L1] &
             HVM_PARAM_CLONE_L1_dynamic) && p2m_is_ram_rw(t)) {
            /* mark regular pages pod in template, so that they are
             * populated in clone_l1_table */
            ASSERT(mfn_valid_page(smfn));
            set_p2m_entry_unchecked(op2m, gfn_aligned, smfn, 0,
                                    p2m_populate_on_demand,
                                    op2m->default_access);
            p2m_pod_stat_update(d->clone_of);
        }
        if (mfn_valid_page_or_vframe(smfn)) {
            ASSERT(mfn_x(smfn) != mfn_x(shared_zero_page));
            get_page_fast(mfn_to_page(smfn), d->clone_of);
            put_page_parent = smfn;
        }
        if ((q == p2m_guest_r || q == p2m_alloc_r) &&
            (mfn_valid_page(smfn) || mfn_x(smfn) == SHARED_ZERO_MFN)) {
            p2m_unlock(op2m);
            op2m_locked = 0;
            /* read-acces -- add pod entry, i.e. make the gpfn shared */
            ASSERT((!mfn_x(put_page_parent) &&
                    mfn_x(smfn) == SHARED_ZERO_MFN) ||
                   (mfn_x(put_page_parent) == mfn_x(smfn)));
            /* read-access to zero page, use shared zero page */
            if (mfn_x(smfn) == SHARED_ZERO_MFN)
                smfn = shared_zero_page;
            /* install smfn in clone p2m */
            set_p2m_entry_unchecked(p2m, gfn_aligned, smfn, 0,
                                    p2m_populate_on_demand,
                                    p2m->default_access);
            if (mfn_x(smfn) != mfn_x(shared_zero_page)) {
                ASSERT(mfn_x(smfn) == mfn_x(put_page_parent));
                put_page(mfn_to_page(smfn));
                put_page_parent = _mfn(0);
            }
            ret = 0;
            goto out;
        }
        ASSERT(p2m_locked_by_me(op2m));
    }

    if (mfn_retry(smfn)) {
        struct dmreq *dmreq;
        void *dmreq_vcpu_page = NULL;
        uint32_t dmreq_gpfn;

        if (current->target_vmis)
            dmreq = current->target_vmis->vmi_dmreq;
        else
            dmreq = get_dmreq(current);
        dmreq_gpfn = dmreq->dmreq_gpfn;
        dmreq->dmreq_gpfn = DMREQ_GPFN_UNUSED;
        if (!dmreq || dmreq_gpfn_error(dmreq->dmreq_gpfn_loaded))
            return out_fail();

        if (gfn_aligned != dmreq_gpfn ||
            !dmreq_gpfn_valid(dmreq->dmreq_gpfn_loaded) ||
            dmreq_gpfn != dmreq->dmreq_gpfn_loaded) {
            if (gfn_aligned == dmreq_gpfn) {
                gdprintk(
                    XENLOG_DEBUG, "%s: vm%u.%s%u dmreq gpfn %lx %s "
                    "(dmreq_gpfn %x dmreq_gpfn_loaded %x)\n",
                    __FUNCTION__,
                    current->target_vmis ? current->target_vmis->vmi_domid :
                    current->domain->domain_id,
                    current->target_vmis ? "dom" : "",
                    current->target_vmis ? 0 : current->vcpu_id, gfn_aligned,
                    !dmreq_gpfn_valid(dmreq->dmreq_gpfn_loaded) ? "spurious" :
                    "mismatch", dmreq_gpfn, dmreq->dmreq_gpfn_loaded);
                /* DEBUG(); */
            }

            if (op2m_locked) {
                p2m_unlock(op2m);
                op2m_locked = 0;
            }

            dmreq->dmreq_gpfn_loaded = DMREQ_GPFN_UNUSED;
            dmreq->dmreq_gpfn = gfn_aligned;
            dmreq->dmreq_gpfn_access =
                (q != p2m_guest_r && q != p2m_alloc_r) ?
                DMREQ_GPFN_ACCESS_WRITE : DMREQ_GPFN_ACCESS_READ;

            if (current->target_vmis) {
                ((struct domain *)current->target_vmis->vmi_domain)
                    ->arch.hvm_domain.dmreq_query = q;
                hvm_send_dom0_dmreq(current->target_vmis->vmi_domain);
            } else {
                current->arch.hvm_vcpu.dmreq_gpfn = gfn_aligned;
                current->arch.hvm_vcpu.dmreq_query = q;
                hvm_send_dmreq(current);
            }
            ret = DMREQ_MFN;
            goto out;
        }

        ASSERT(dmreq_gpfn == dmreq->dmreq_gpfn_loaded);
        dmreq->dmreq_gpfn_loaded = DMREQ_GPFN_UNUSED;
        if (current->target_vmis)
            dmreq_vcpu_page = current->target_vmis->vmi_dmreq_vcpu_page_va;
        else
            dmreq_vcpu_page = current->arch.hvm_vcpu.dmreq_vcpu_page_va;

        if (!d->arch.hvm_domain.params[HVM_PARAM_TEMPLATE_LAZY_LOAD] ||
            !d->clone_of) {
          dead_template:
            if (op2m_locked) {
                p2m_unlock(op2m);
                op2m_locked = 0;
            }

            p = alloc_domheap_page(d, PAGE_ORDER_4K);
            if (!p)
                return out_of_memory();
            mfn = page_to_mfn(p);

            target = map_domain_page_direct(mfn_x(mfn));
            if (dmreq->dmreq_gpfn_size > PAGE_SIZE)
                return out_fail();
            if (dmreq->dmreq_gpfn_size != PAGE_SIZE) {
                int uc_size;
                uc_size = LZ4_decompress_safe(dmreq_vcpu_page, target,
                                              dmreq->dmreq_gpfn_size,
                                              PAGE_SIZE);
                if (uc_size != PAGE_SIZE) {
                    unmap_domain_page_direct(target);
                    return out_fail();
                }
                perfc_incr(pc18);
            } else
                memcpy(target, dmreq_vcpu_page, PAGE_SIZE);
            perfc_incr(pc16);
            check_immutable(q, d, gfn_aligned);
            unmap_domain_page_direct(target);
            perfc_incr(dmreq_populated);

            goto out_reassigned;
        } else {
            struct domain *tmpl = d->clone_of;
            p2m_query_t orig_q;

            if (current->target_vmis)
                orig_q = ((struct domain *)current->target_vmis->vmi_domain)
                    ->arch.hvm_domain.dmreq_query;
            else
                orig_q = current->arch.hvm_vcpu.dmreq_query;

            p = alloc_domheap_page(tmpl, PAGE_ORDER_4K);
            if (!p) {
                if (tmpl->is_dying) {
                    d->arch.hvm_domain.params[HVM_PARAM_TEMPLATE_LAZY_LOAD] = 0;
                    goto dead_template;
                }
                return out_of_memory();
            }
            mfn = page_to_mfn(p);

            if (!op2m_locked) {
                p2m_lock_recursive(op2m);
                op2m_locked = 1;
            }

            smfn = op2m->get_entry(op2m, gfn_aligned, &t, &a, p2m_query, NULL);
            if (mfn_retry(smfn)) {
                if (dmreq->dmreq_gpfn_size > PAGE_SIZE) {
                    put_allocated_page(tmpl, p);
                    return out_fail();
                }

                /* compressed + write -> add compressed to template,
                   then decompress into VM via cow below */
                if (dmreq->dmreq_gpfn_size <= CSIZE_MAX &&
                    (orig_q != p2m_guest_r && orig_q != p2m_alloc_r)) {
                    smfn = p2m_pod_add_compressed_page(
                        op2m, gfn_aligned, dmreq_vcpu_page,
                        dmreq->dmreq_gpfn_size, p);
                } else {
                    /* compressed + read -> decompress */
                    if (dmreq->dmreq_gpfn_size != PAGE_SIZE) {
                        int uc_size;

                        ASSERT(orig_q == p2m_guest_r || orig_q == p2m_alloc_r);
                        target = map_domain_page_direct(mfn_x(mfn));
                        uc_size = LZ4_decompress_safe(dmreq_vcpu_page, target,
                                                      dmreq->dmreq_gpfn_size,
                                                      PAGE_SIZE);
                        if (uc_size != PAGE_SIZE) {
                            unmap_domain_page_direct(target);
                            put_allocated_page(tmpl, p);
                            return out_fail();
                        }
                    } else {
                        /* uncompressed */
                        target = map_domain_page_direct(mfn_x(mfn));
                        memcpy(target, dmreq_vcpu_page, PAGE_SIZE);
                    }

                    /* add uncompressed or decompressed to template */
                    set_p2m_entry_unchecked(op2m, gfn_aligned, mfn, 0,
                                            p2m_populate_on_demand,
                                            op2m->default_access);

                    unmap_domain_page_direct(target);

                    p2m_pod_stat_update(tmpl);

                    /* read -> share template with VM */
                    if (orig_q == p2m_guest_r || orig_q == p2m_alloc_r) {
                        p2m_unlock(op2m);
                        op2m_locked = 0;
                        set_p2m_entry_unchecked(p2m, gfn_aligned, mfn, 0,
                                                p2m_populate_on_demand,
                                                p2m->default_access);
                        put_page(p);
                        perfc_incr(dmreq_populated_template_shared);
                        ret = 0;
                        goto out;
                    }

                    /* write -> cow into VM */
                    smfn = mfn;
                }

                ASSERT(!mfn_x(put_page_parent));
                put_page_parent = mfn;

                perfc_incr(dmreq_populated_template);
            } else
                put_allocated_page(tmpl, p);
            ASSERT(p2m_locked_by_me(op2m));
        }
    }

    if (mfn_zero_page(smfn)) {
        if (op2m_locked) {
            p2m_unlock(op2m);
            op2m_locked = 0;
        }
        p = alloc_domheap_page(d, PAGE_ORDER_4K);
        if (!p)
            return out_of_memory();
        mfn = page_to_mfn(p);
        target = map_domain_page_direct(mfn_x(mfn));
        clear_page(target);
        perfc_incr(populated_zero_pages);
        unmap_domain_page_direct(target);
    } else if (p2m_mfn_is_page_data(smfn)) {
        struct domain *page_owner = d;

        if (!d->clone_of)
            atomic_inc(&d->template.decompressed_permanent);
        else if (d->arch.hvm_domain.params[HVM_PARAM_CLONE_DECOMPRESSED] &&
                 (q == p2m_guest_r || q == p2m_alloc_r)) {
            /* on read access -- map page pod */
            pod_p2mt = p2m_populate_on_demand;
            if (d->arch.hvm_domain.params[HVM_PARAM_CLONE_DECOMPRESSED] &
                HVM_PARAM_CLONE_DECOMPRESSED_shared)
                page_owner = d->clone_of;
            /* else decompressed page not owned by template, but read-only */
        }
      redo_decompress:
        if (!p2m_pod_decompress_page(
                d->clone_of ? p2m_get_hostp2m(d->clone_of) : p2m, smfn, &mfn,
                page_owner, page_owner == d->clone_of)) {
            if (page_owner == d->clone_of && d->clone_of->is_dying) {
                /* template vm was destroyed, redo decompress without
                 * sharing */
                gdprintk(XENLOG_INFO, "template vm%u destroyed,"
                         " not sharing decompressed pages\n",
                         d->clone_of->domain_id);
                page_owner = d;
                d->arch.hvm_domain.params[HVM_PARAM_CLONE_DECOMPRESSED] &=
                    ~HVM_PARAM_CLONE_DECOMPRESSED_shared;
                if (!d->arch.hvm_domain.params[HVM_PARAM_CLONE_DECOMPRESSED])
                    pod_p2mt = p2m_ram_rw;
                goto redo_decompress;
            }
            return out_fail();
        }
        if (op2m_locked) {
            p2m_unlock(op2m);
            op2m_locked = 0;
        }
        check_immutable(q, d, gfn_aligned);
    } else if (/* d->arch.hvm_domain.params[HVM_PARAM_CLONE_DECOMPRESSED] && */
               page_get_owner(mfn_to_page(smfn)) == d) {
        /* read-only mapped page already belonging to the VM - write
           access to previously decompressed page which was mapped
           read-only */
        mfn = smfn;
        if (op2m_locked) {
            p2m_unlock(op2m);
            op2m_locked = 0;
        }
    } else {
        /* check if template page is a decompressed page, only shared
         * in one clone */
#define ONE_CLONE_COUNT 1
        while ((d->arch.hvm_domain.params[HVM_PARAM_CLONE_DECOMPRESSED] &
                HVM_PARAM_CLONE_DECOMPRESSED_gift) &&
               page_get_owner(mfn_to_page(smfn)) == d->clone_of &&
               (mfn_to_page(smfn)->count_info & PGC_count_mask) <=
               ONE_CLONE_COUNT) {
            struct page_data_info *pdi;
            uint8_t *data;
            uint16_t data_size;
            uint16_t offset;
            mfn_t omfn;

            ASSERT(!op2m_locked);
            p2m_lock_recursive(op2m);
            omfn = op2m->get_entry(op2m, gfn_aligned, &t, &a, p2m_query, NULL);
            if (!p2m_mfn_is_page_data(omfn)) {
                p2m_unlock(op2m);
                break;
            }
            if (p2m_get_page_data_and_write_lock(op2m, &omfn, &data,
                                                 &data_size, &offset)) {
                p2m_unlock(op2m);
                break;
            }
            pdi = (struct page_data_info *)&data[offset];
            if (pdi->mfn == mfn_x(smfn)) {
                ret = change_page_owner(__mfn_to_page(pdi->mfn), d,
                                        d->clone_of, ONE_CLONE_COUNT);
                if (ret != -1)
                    /* page was assigned (ret == 0), or failed to
                     * assign page (ret == 1, and page freed) */
                    pdi->mfn = 0;
            } else
                ret = -1;
            if (ret) {
                p2m_put_page_data_with_write_lock(op2m, data, data_size);
                p2m_unlock(op2m);
                break;
            }
            mfn = smfn;
            get_page_fast(mfn_to_page(smfn), d);
            p2m_put_page_data_with_write_lock(op2m, data, data_size);
            atomic_dec(&d->clone_of->template.decompressed_shared);
            p2m_unlock(op2m);
            perfc_incr(decompressed_unshared);
            update_host_memory_saved(PAGE_SIZE);
            p2m_pod_stat_update(d->clone_of);
            goto out_reassigned;
        }

        if (op2m_locked) {
            p2m_unlock(op2m);
            op2m_locked = 0;
        }

        p = alloc_domheap_page(d, PAGE_ORDER_4K);
        if (!p)
            return out_of_memory();
        mfn = page_to_mfn(p);
        target = map_domain_page_direct(mfn_x(mfn));
        source = map_domain_page(mfn_x(smfn));
        memcpy(target, source, PAGE_SIZE);
        unmap_domain_page(source);
        perfc_incr(populated_clone_pages);
	check_immutable(q, d, gfn_aligned);
        unmap_domain_page_direct(target);
    }

  out_reassigned:
    set_p2m_entry_unchecked(p2m, gfn_aligned, mfn, PAGE_ORDER_4K, pod_p2mt,
                            p2m->default_access);

    if (mfn_valid_page_or_vframe(mfn) &&
        mfn_x(mfn) != mfn_x(shared_zero_page))
        put_page(mfn_to_page(mfn));

#ifndef __UXEN__
    paging_mark_dirty(d, gfn_aligned);
#endif  /* __UXEN__ */

    if ( tb_init_done )
    {
        struct {
            u64 gfn, mfn;
            int d:16,order:16;
        } t;

        t.gfn = gfn;
        t.mfn = mfn_x(mfn);
        t.d = d->domain_id;
        t.order = order;
        
        __trace_var(TRC_MEM_POD_POPULATE, 0, sizeof(t), &t);
    }

    ret = 0;
  out:
    if (mfn_x(put_page_parent))
        put_page(mfn_to_page(put_page_parent));
    if (op2m_locked)
        p2m_unlock(op2m);
    if (!ret)
        p2m_pod_stat_update(d);
    p2m_unlock(p2m);
    return _mfn(ret);
}

static int
clone_l1_table(struct p2m_domain *op2m, struct p2m_domain *p2m,
               unsigned long *_gpfn, void *otable, void *table,
               int _needs_sync)
{
    struct domain *od = op2m->domain;
    struct domain *d = p2m->domain;
    unsigned long gpfn = *_gpfn;
    unsigned long index = gpfn & ((1UL << PAGETABLE_ORDER) - 1);
    mfn_t mfn;
    p2m_type_t t;
    p2m_access_t a;
    bool_t clone_l1_dynamic = !!(d->arch.hvm_domain.params[HVM_PARAM_CLONE_L1] &
                                 HVM_PARAM_CLONE_L1_dynamic);
    int ret = 0;
    int needs_sync_any = 0;

    while (index < L1_PAGETABLE_ENTRIES) {
        mfn = op2m->parse_entry(otable, index, &t, &a);
        if (table && (p2m_is_pod(t) || p2m_is_ram(t))) {
            p2m_type_t _t;
            p2m_access_t _a;
            p2m->parse_entry(table, index, &_t, &_a);
        }
        if (p2m_is_pod(t)) {
            if (mfn_valid_vframe(mfn)) {
                if (!(d->arch.hvm_domain.params[HVM_PARAM_CLONE_L1] &
                      HVM_PARAM_CLONE_L1_decompressed) ||
                    !p2m_pod_get_decompressed_page(op2m, mfn, &mfn, od))
                    mfn = _mfn(0);
            } else if (mfn_valid_page(mfn) &&
                       unlikely(!get_page_fast(mfn_to_page(mfn), od))) {
                gdprintk(XENLOG_ERR, "%s: get_page failed mfn=%08lx\n",
                         __FUNCTION__, mfn_x(mfn));
                mfn = _mfn(0);
            }
            if (table) {
                int needs_sync = _needs_sync;
                ret = p2m->write_entry(p2m, table, gpfn, mfn, 0,
                                       p2m_populate_on_demand,
                                       p2m->default_access, &needs_sync);
                if (needs_sync)
                    needs_sync_any = 1;
            } else
                ret = !set_p2m_entry(p2m, gpfn, mfn, 0, p2m_populate_on_demand,
                                     p2m->default_access);
            if (mfn_valid_page(mfn))
                put_page(mfn_to_page(mfn));
            if (ret) {
                gdprintk(XENLOG_ERR, "%s: set_p2m_entry "
                         "copy_on_write failed gpfn=%08lx\n",
                         __FUNCTION__, gpfn);
                goto out;
            }
        } else if (p2m_is_ram(t)) {
            if (clone_l1_dynamic && !p2m_is_immutable(t))
                mfn = _mfn(0);
            if (mfn_valid_page(mfn) &&
                unlikely(!get_page_fast(mfn_to_page(mfn), od))) {
                gdprintk(XENLOG_ERR, "%s: get_page failed mfn=%08lx\n",
                         __FUNCTION__, mfn_x(mfn));
                mfn = _mfn(0);
            }
            if (table) {
                int needs_sync = _needs_sync;
                ret = p2m->write_entry(p2m, table, gpfn, mfn, 0,
                                       p2m_populate_on_demand,
                                       p2m->default_access, &needs_sync);
                if (needs_sync)
                    needs_sync_any = 1;
            } else
                ret = !set_p2m_entry(p2m, gpfn, mfn, 0, p2m_populate_on_demand,
                                     p2m->default_access);
            if (mfn_valid_page(mfn))
                put_page(mfn_to_page(mfn));
            if (ret) {
                gdprintk(XENLOG_ERR, "%s: set_p2m_entry failed gpfn=%08lx\n",
                         __FUNCTION__, gpfn);
                goto out;
            }
        }
        index++;
        gpfn++;
    }

  out:
    if (needs_sync_any)
        pt_sync_domain(p2m->domain);
    *_gpfn = gpfn;
    return ret;
}

int
p2m_clone_l1(struct p2m_domain *op2m, struct p2m_domain *p2m,
             unsigned long gpfn, void *entry, int needs_sync)
{
    void *otable = NULL, *table = NULL;
    mfn_t mfn;
    p2m_type_t t;
    p2m_access_t a;
    int ret = 0;

    ASSERT(p2m_locked_by_me(p2m));

    if ((p2m->domain->arch.hvm_domain.params[HVM_PARAM_CLONE_L1] &
         HVM_PARAM_CLONE_L1_lazy_populate) && p2m->split_super_page_one &&
        !p2m->split_super_page_one(p2m, entry, gpfn, PAGE_ORDER_2M))
        return 0;

    mfn = op2m->get_l1_table(op2m, gpfn, NULL);
    if (!mfn_valid_page(mfn))
        return 0;
    otable = map_domain_page(mfn_x(mfn));

    mfn = p2m->parse_entry(entry, 0, &t, &a);
    if (mfn_valid_page(mfn))
        table = map_domain_page(mfn_x(mfn));

    ret = clone_l1_table(op2m, p2m, &gpfn, otable, table, needs_sync);

    if (table)
        unmap_domain_page(table);
    unmap_domain_page(otable);
    return ret;
}

int
p2m_clone(struct p2m_domain *p2m, struct domain *nd)
{
    struct p2m_domain *np2m = p2m_get_hostp2m(nd);
    unsigned long gpfn;
    mfn_t mfn = _mfn(0);        /* compiler */
    mfn_t nmfn = _mfn(0);
    unsigned int page_order;
    void *table = NULL, *ntable = NULL;
    int ret = 0;
    s64 ct;

    p2m_lock(np2m);
    ct = -NOW();
    for (gpfn = np2m->clone_gpfn; !ret && gpfn <= p2m->max_mapped_pfn; ) {
        if (hypercall_needs_checks() || UI_HOST_CALL(ui_host_needs_preempt)) {
            ret = -EAGAIN;
            break;
        }
        if (!(gpfn & ((1UL << PAGETABLE_ORDER) - 1))) {
            mfn = p2m->get_l1_table(p2m, gpfn, &page_order);
            if (!mfn_valid_page(mfn)) {
                gpfn |= ((1 << page_order) - 1);
                gpfn++;
                continue;
            }
            nmfn = np2m->get_l1_table(np2m, gpfn, NULL);
        }
        if (hvm_hap_has_2mb(d) &&
            (p2m->domain->arch.hvm_domain.params[HVM_PARAM_CLONE_L1] &
             HVM_PARAM_CLONE_L1_lazy_mask)) {
            /* if l1 exists already in clone, clone the rest of the l1
             * immediately */
            if (mfn_valid_page(nmfn))
                goto clone_now;
            ret = !set_p2m_entry(np2m, gpfn, _mfn(0), PAGE_ORDER_2M,
                                 p2m_populate_on_demand, np2m->default_access);
            if (ret) {
                gdprintk(XENLOG_ERR, "%s: set_p2m_entry "
                         "shared l1 failed gpfn=%08lx\n",
                         __FUNCTION__, gpfn);
                continue;
            }
            gpfn += (1 << PAGE_ORDER_2M);
            atomic_inc(&nd->clone.l1_pod_pages);
            continue;
        }
      clone_now:
        if (!(gpfn & ((1UL << PAGETABLE_ORDER) - 1))) {
            if (ntable) {
                unmap_domain_page(ntable);
                ntable = NULL;
            }
            if (table)
                unmap_domain_page(table);
            table = map_domain_page(mfn_x(mfn));
            if (mfn_valid_page(nmfn))
                ntable = map_domain_page(mfn_x(nmfn));
        }
        ret = clone_l1_table(p2m, np2m, &gpfn, table, ntable, 1);
    }
    if (ntable)
        unmap_domain_page(ntable);
    if (table)
        unmap_domain_page(table);
    ct += NOW();
    np2m->clone_time += ct;
    p2m_unlock(np2m);

    np2m->clone_gpfn = gpfn;
    if (gpfn > p2m->max_mapped_pfn) {
        printk("%s: vm%u took %"PRIu64".%06"PRIu64"ms\n",
               __FUNCTION__, nd->domain_id,
               np2m->clone_time / 1000000UL, np2m->clone_time % 1000000UL);
        printk("vm%u: pod_pages=%d zero_shared=%d tmpl_shared=%d\n",
               nd->domain_id, atomic_read(&nd->pod_pages),
               atomic_read(&nd->zero_shared_pages),
               atomic_read(&nd->tmpl_shared_pages));
        if (atomic_read(&nd->clone.l1_pod_pages))
            printk("vm%u: l1_pod_pages=%d\n",
                   nd->domain_id, atomic_read(&nd->clone.l1_pod_pages));
    }
    return ret;
}

void
p2m_pod_free_page(struct page_info *page, va_list ap)
{
    unsigned long gpfn;
    struct domain *d, *owner;
    struct p2m_domain *p2m;
    mfn_t mfn;
    p2m_type_t t;
    p2m_access_t a;
    uint8_t *data = NULL;
    uint16_t data_size;
    uint16_t offset;
    struct page_data_info *pdi;

    d = va_arg(ap, struct domain *);
    gpfn = va_arg(ap, unsigned long);

    owner = page_get_owner(page);
    p2m = p2m_get_hostp2m(owner);

    if (d->clone_of != owner)
        goto out_no_lock;

    p2m_lock(p2m);

    mfn = p2m->get_entry(p2m, gpfn, &t, &a, p2m_query, NULL);
    if (!p2m_mfn_is_page_data(mfn))
        goto out;

    if (p2m_get_page_data_and_write_lock(p2m, &mfn, &data, &data_size,
                                         &offset))
        goto out;

    pdi = (struct page_data_info *)&data[offset];
    if (pdi->mfn != __page_to_mfn(page))
        goto out;

    pdi->mfn = 0;

    atomic_dec(&owner->template.decompressed_shared);
    perfc_incr(decompressed_removed);
    update_host_memory_saved(PAGE_SIZE);
    p2m_pod_stat_update(owner);

  out:
    if (data)
        p2m_put_page_data_with_write_lock(p2m, data, data_size);
    p2m_unlock(p2m);

  out_no_lock:
    free_domheap_page(page);
}

int
p2m_shared_teardown(struct p2m_domain *p2m)
{
    struct domain *d = p2m->domain, *owner;
    unsigned long gpfn;
    mfn_t mfn, l1mfn;
    void *l1table = NULL;
    p2m_type_t t;
    p2m_access_t a;
    unsigned int page_order;
    struct page_info *page;
    int p2m_count = 0, domain_count = 0, vframe_count = 0;
    int shared_count = 0, zero_count = 0, host_count = 0, xen_count = 0;

    for (gpfn = 0; gpfn <= p2m->max_mapped_pfn; gpfn++) {
        if (!(gpfn & ((1UL << PAGETABLE_ORDER) - 1))) {
            l1mfn = p2m->get_l1_table(p2m, gpfn, &page_order);
            if (!mfn_valid_page(l1mfn)) {
                gpfn |= ((1 << page_order) - 1);
                continue;
            }
            if (l1table)
                unmap_domain_page(l1table);
            l1table = map_domain_page(mfn_x(l1mfn));
        }
        mfn = p2m->parse_entry(l1table, gpfn & ((1UL << PAGETABLE_ORDER) - 1),
                               &t, &a);
        if (!mfn_valid_page_or_vframe(mfn))
            continue;
        if (mfn_x(mfn) == mfn_x(shared_zero_page)) {
            zero_count++;
            continue;
        }
        page = mfn_to_page(mfn);
        if (test_bit(_PGC_host_page, &page->count_info)) {
            put_page(page);
            host_count++;
            continue;
        }
        owner = page_get_owner(page);
        if (p2m_mfn_is_vframe(mfn)) {
            put_page(page);
            vframe_count++;
        } else if (p2m_is_pod(t)) {
            put_page_destructor(page, p2m_pod_free_page, d, gpfn);
            shared_count++;
        } else if (is_xen_page(page) && owner == d) {
            put_page(page);
            xen_count++;
        } else if (p2m_is_ram(t) && owner == d) {
            put_allocated_page(d, page);
            domain_count++;
        } else
            BUG();
        p2m_count++;
    }
    if (l1table)
        unmap_domain_page(l1table);

    printk(XENLOG_INFO "%s: vm%u cleared %d p2m entries --"
           " domain=%d shared=%d zero=%d host=%d xen=%d vframe=%d\n",
           __FUNCTION__, d->domain_id, p2m_count, domain_count, shared_count,
           zero_count, host_count, xen_count, vframe_count);
    return 1;
}

int
p2m_pod_zero_share(struct p2m_domain *p2m, unsigned long gfn,
                   p2m_query_t q, void *entry)
{
    struct domain *d = p2m->domain;
    mfn_t smfn;
    p2m_type_t p2mt;
    p2m_access_t p2ma;
    int ret = -1;

    /* This is called from the p2m lookups, which can happen with or 
     * without the lock hed. */
    p2m_lock_recursive(p2m);

    /* This check is done with the p2m lock held.  This will make sure that
     * even if d->is_dying changes under our feet, p2m_pod_empty_cache() 
     * won't start until we're done. */
    if (unlikely(d->is_dying))
        goto out;

    /* parse entry with lock held */
    smfn = p2m->parse_entry(entry, 0, &p2mt, &p2ma);

    if (p2m_is_pod(p2mt))
        check_immutable(q, d, gfn);

    if (is_p2m_zeropop(q) && !p2m_is_ram(p2mt)) {
        struct page_info *p = alloc_domheap_page(d, PAGE_ORDER_4K);
        if (!p) {
            printk(XENLOG_ERR "%s: out of memory --"
                   " tot_pages %u max_pages %u\n",
                   __FUNCTION__, d->tot_pages, d->max_pages);
            domain_crash(d);
            goto out;
        }

        smfn = page_to_mfn(p);
        p2mt = p2m_ram_rw;
        set_p2m_entry_unchecked(p2m, gfn, smfn, PAGE_ORDER_4K, p2mt,
                                p2m->default_access);
        put_page(p);
        /* page zeroed below in p2m_is_ram(p2mt) */
    }

    if (p2m_is_ram(p2mt)) {
        ASSERT(mfn_valid_page(smfn));
        if (is_p2m_zeropop(q) ||
            (mfn_to_page(smfn)->count_info & PGC_count_mask) > 1) {
            char *b = map_domain_page(mfn_x(smfn));
            clear_page(b);
            unmap_domain_page(b);
            ret = 0;
            goto out;
        }
    }

    if (mfn_zero_page(smfn)) {
        if (mfn_x(smfn) == mfn_x(shared_zero_page))
            set_p2m_entry_unchecked(p2m, gfn, _mfn(SHARED_ZERO_MFN),
                                    PAGE_ORDER_4K,
                                    p2m_populate_on_demand,
                                    p2m->default_access);
        ret = 0;
        goto out;
    }

    set_p2m_entry_unchecked(p2m, gfn, _mfn(SHARED_ZERO_MFN), PAGE_ORDER_4K,
                            p2m_populate_on_demand, p2m->default_access);

    ret = 0;

    if ( tb_init_done )
    {
        struct {
            u64 gfn, mfn;
            int d:16,order:16;
        } t;

        t.gfn = gfn;
        t.mfn = mfn_x(smfn);
        t.d = d->domain_id;
        t.order = PAGE_ORDER_4K;
        
        __trace_var(TRC_MEM_POD_ZERO_RECLAIM, 0, sizeof(t), &t);
    }

  out:
    p2m_unlock(p2m);
    return ret;
}


int
guest_physmap_mark_pod_locked(struct domain *d, unsigned long gfn,
                              unsigned int order, mfn_t mfn)
{
    struct p2m_domain *p2m = p2m_get_hostp2m(d);
    unsigned long i;
    p2m_type_t ot;
    mfn_t omfn;
    int rc = 0;

    // P2M_DEBUG("mark pod gfn=%#lx\n", gfn);

    /* this interface is not for setting p2m entries to actual pages */
    ASSERT(!mfn_valid_page_or_vframe(mfn) ||
           mfn_x(mfn) == mfn_x(shared_zero_page));

    /* Make sure all gpfns are unused */
    for ( i = 0; i < (1UL << order); i++ )
    {
        p2m_access_t a;
        omfn = p2m->get_entry(p2m, gfn + i, &ot, &a, p2m_query, NULL);

        if (unlikely(mfn_zero_page(omfn)) && p2m_is_pod(ot) && !order)
            goto out;

        if ( p2m_is_ram(ot) )
        {
            ASSERT(mfn_valid(omfn));

            if (order) {
                dprintk(XENLOG_WARNING, "%s: vm%u: unsupported order != 0\n",
                    __func__, d->domain_id);
                rc = -EINVAL;
                goto out;
            }
        }
    }

    /* Now, actually do the two-way mapping */
    if ( !set_p2m_entry(p2m, gfn, order ? _mfn(0) : mfn,
                        order, p2m_populate_on_demand, p2m->default_access) ) {
        rc = -EINVAL;
        goto out;
    }

  out:
    return rc;
}

int
guest_physmap_mark_populate_on_demand(struct domain *d, unsigned long gfn,
                                      unsigned int order, mfn_t mfn)
{
    struct p2m_domain *p2m = p2m_get_hostp2m(d);
    int rc = 0;

    BUG_ON(!paging_mode_translate(d));

    rc = p2m_gfn_check_limit(d, gfn, order);
    if ( rc != 0 )
        return rc;

    p2m_lock(p2m);
    audit_p2m(p2m, 1);

    rc = guest_physmap_mark_pod_locked(d, gfn, order, mfn);

    audit_p2m(p2m, 1);
    p2m_unlock(p2m);

    return rc;
}

int
guest_physmap_mark_populate_on_demand_contents(
    struct domain *d, unsigned long gpfn, XEN_GUEST_HANDLE(uint8) buffer,
    unsigned int *pos)
{
    struct p2m_domain *p2m = p2m_get_hostp2m(d);
    struct page_info *new_page;
    void *va;
    uint16_t c_size;
    int uc_size;
    mfn_t mfn;

    if (unlikely(!check_decompress_buffer()))
        return -1;

    if (unlikely(__copy_from_guest_offset((void *)&c_size, buffer, *pos,
                                          sizeof(c_size))))
        return -1;
    *pos += sizeof(c_size);

    if (c_size > PAGE_SIZE) {
        printk("%s: gpfn %lx invalid compressed size %d\n", __FUNCTION__,
               gpfn, c_size);
        return -1;
    }

    if (unlikely(__copy_from_guest_offset(this_cpu(decompress_buffer),
                                          buffer, *pos, c_size)))
        return -1;
    *pos += c_size;

    new_page = alloc_domheap_page(d, PAGE_ORDER_4K);
    if (!new_page)
        return -1;

    if (c_size > CSIZE_MAX) {
        /* page data can't be stored compressed -- uncompress and
         * install uncompressed page in p2m */
        mfn = page_to_mfn(new_page);
        va = map_domain_page(mfn_x(mfn));
        if (c_size < PAGE_SIZE)
            uc_size = LZ4_decompress_safe(
                (const char *)this_cpu(decompress_buffer), va, c_size,
                PAGE_SIZE);
        else {
            memcpy(va, this_cpu(decompress_buffer), PAGE_SIZE);
            uc_size = PAGE_SIZE;
        }
        unmap_domain_page(va);
        if (uc_size != PAGE_SIZE) {
            printk("%s: gpfn %lx invalid compressed data\n", __FUNCTION__,
                   gpfn);
            free_domheap_page(new_page);
            return -1;
        }
        guest_physmap_add_page(d, gpfn, mfn_x(mfn));
        put_page(new_page);
        return 0;
    }

    p2m_lock(p2m);
    p2m_pod_add_compressed_page(p2m, gpfn, this_cpu(decompress_buffer),
                                c_size, new_page);
    p2m_unlock(p2m);
    p2m_pod_stat_update(d);

    return 0;
}

#ifndef NDEBUG
static struct timer p2m_pod_compress_template_timer;

static void
p2m_pod_compress_template_work(void *_d)
{
    struct domain *d = (struct domain *)_d;
    struct p2m_domain *p2m = p2m_get_hostp2m(d);
    unsigned long gpfn;
    mfn_t mfn;
    p2m_type_t t;
    p2m_access_t a;
    unsigned int page_order;
    struct page_info *page;
    void *target;
    bool_t unshared_only = !!d->arch.hvm_domain.params[
        HVM_PARAM_CLONE_PAGE_WRITE_COMPRESS_UNSHARED_ONLY];
    int nr_comp_unused = 0;
    int nr_comp_used = 0;
    int nr_shared = 0;
    int nr_compressed = 0;
    s64 ct;

    ct = -NOW();
    for (gpfn = p2m->compress_gpfn; gpfn <= p2m->max_mapped_pfn; gpfn++) {
        if (UI_HOST_CALL(ui_host_needs_preempt))
            break;
        mfn = p2m->get_entry(p2m, gpfn, &t, &a, p2m_query, &page_order);
        if (!mfn_valid_page(mfn)) {
            gpfn |= ((1 << page_order) - 1);
            continue;
        }
        if (mfn_x(mfn) == mfn_x(shared_zero_page))
            continue;
        page = mfn_to_page(mfn);
        if (p2m_is_ram(t))
            nr_comp_unused++;
        else if (p2m_is_pod(t)) {
            if ((page->count_info & PGC_count_mask) > 2)
                nr_shared++;
            else
                nr_comp_used++;
        }
        if (p2m_is_ram(t) &&
            (!unshared_only || (page->count_info & PGC_count_mask) == 2)) {
            p2m_lock(p2m);
            mfn = p2m->get_entry(p2m, gpfn, &t, &a, p2m_query, &page_order);
            if (mfn_valid_page(mfn) &&
                get_page(page = mfn_to_page(mfn), d)) {
                p2m_unlock(p2m);
                target = map_domain_page_direct(mfn_x(mfn));
                (void)p2m_pod_compress_page(p2m, gpfn, mfn, target,
                                            unshared_only ? 2 + 1 : 0);
                unmap_domain_page_direct(target);
                nr_compressed++;
                put_page(page);
            } else
                p2m_unlock(p2m);
        }
    }
    p2m->compress_gpfn = gpfn;
    ct += NOW();
    if (0)
        printk("%s: vm%u: comp unused %d used %d -- shared %d"
               " -- compressed %d -- took %"PRIu64".%"PRIu64"ms\n",
               __FUNCTION__, d->domain_id,
               nr_comp_unused, nr_comp_used, nr_shared, nr_compressed,
               ct / 1000000UL, ct % 1000000UL);
    if (p2m->compress_gpfn > p2m->max_mapped_pfn) {
        p2m->compress_gpfn = 0;
        printk("%s: vm%u: comp_pages=%d comp_pdata=%d\n",
               __FUNCTION__, d->domain_id,
               atomic_read(&d->template.compressed_pages),
               atomic_read(&d->template.compressed_pdata));
    } else
        set_timer(&p2m_pod_compress_template_timer, NOW() + MILLISECS(10));
}

static void
p2m_pod_compress_template(struct domain *d)
{
    static int once = 0;

    if (!once) {
        init_timer(&p2m_pod_compress_template_timer,
                   p2m_pod_compress_template_work, d, 0);
        once = 1;
    }
    set_timer(&p2m_pod_compress_template_timer, NOW() + MILLISECS(10));
}

static void
p2m_audit_pod_counts(struct domain *d)
{
    struct p2m_domain *p2m = p2m_get_hostp2m(d);
    unsigned long gpfn;
    mfn_t mfn;
    p2m_type_t t;
    p2m_access_t a;
    unsigned int page_order;
    int nr_pages = 0, nr_xen = 0, nr_pod = 0, nr_zero = 0;
    int nr_zero_mapped = 0, nr_tmpl = 0, nr_retry = 0, nr_empty = 0;
    int nr_immutable = 0;
    void *l1table = NULL;
    mfn_t l1mfn;

    p2m_lock(p2m);
    for (gpfn = 0; gpfn <= p2m->max_mapped_pfn; gpfn++) {
        if (!(gpfn & ((1UL << PAGETABLE_ORDER) - 1))) {
            l1mfn = p2m->get_l1_table(p2m, gpfn, &page_order);
            if (!mfn_valid_page(l1mfn)) {
                gpfn |= ((1 << page_order) - 1);
                continue;
            }
            if (l1table)
                unmap_domain_page(l1table);
            l1table = map_domain_page(mfn_x(l1mfn));
        }
        mfn = p2m->parse_entry(l1table, gpfn & ((1UL << PAGETABLE_ORDER) - 1),
                               &t, &a);
        if (mfn_x(mfn) == INVALID_MFN /* !mfn_valid(mfn) */) {
            continue;
        }
        if (p2m_is_immutable(t))
            nr_immutable++;
        if (p2m_is_pod(t)) {
            nr_pod++;
            if (mfn_x(mfn) == mfn_x(shared_zero_page))
                nr_zero_mapped++;
            else if (mfn_x(mfn) == SHARED_ZERO_MFN)
                nr_zero++;
            else if (mfn_retry(mfn))
                nr_retry++;
            else if (mfn_x(mfn))
                nr_tmpl++;
            else
                nr_empty++;
            continue;
        }
        if (p2m_is_ram(t)) {
            if (!is_xen_mfn(mfn_x(mfn)))
                nr_pages++;
            else
                nr_xen++;
            continue;
        }
    }
    if (l1table)
        unmap_domain_page(l1table);
    printk("vm%d: pages %d/%d pod %d zero %d/%d tmpl %d retry %d\n",
           d->domain_id, nr_pages, nr_xen, nr_pod,
           nr_zero, nr_zero_mapped, nr_tmpl, nr_retry);
    printk("vm%d: empty %d immutable %d\n", d->domain_id, nr_empty,
           nr_immutable);
    printk("vm%d: nr=%d pod=%d zero=%d tmpl=%d retry=%d\n",
           d->domain_id, d->tot_pages,
           atomic_read(&d->pod_pages),
           atomic_read(&d->zero_shared_pages),
           atomic_read(&d->tmpl_shared_pages),
           atomic_read(&d->retry_pages));
    p2m_unlock(p2m);
}

static void
p2m_pod_keyhandler_fn(unsigned char key)
{
    struct domain *d;

    rcu_read_lock(&domlist_read_lock);
    switch (key) {
    case 't':
        for_each_domain(d) {
            if (!is_template_domain(d))
                continue;
            p2m_pod_compress_template(d);
            break;
        }
        break;
    case 'C':
        for_each_domain(d) {
            if (!is_hvm_domain(d))
                continue;
            p2m_audit_pod_counts(d);
        }
        break;
    }
    rcu_read_unlock(&domlist_read_lock);
}

static struct keyhandler
p2m_pod_compress_templates_keyhandler = {
    .diagnostic = 1,
    .u.fn = p2m_pod_keyhandler_fn,
    .desc = "compress templates"
};

static struct keyhandler
p2m_pod_audit_counts_keyhandler = {
    .diagnostic = 1,
    .u.fn = p2m_pod_keyhandler_fn,
    .desc = "audit pod counts"
};

static __init int
p2m_pod_compress_templates_keyhandler_init(void)
{
    register_keyhandler('t', &p2m_pod_compress_templates_keyhandler);
    register_keyhandler('C', &p2m_pod_audit_counts_keyhandler);
    return 0;
}
__initcall(p2m_pod_compress_templates_keyhandler_init);
#endif  /* NDEBUG */
