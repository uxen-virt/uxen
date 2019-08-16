/******************************************************************************
 * arch/x86/mm.c
 * 
 * Copyright (c) 2002-2005 K A Fraser
 * Copyright (c) 2004 Christian Limpach
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

/*
 * A description of the x86 page table API:
 * 
 * Domains trap to do_mmu_update with a list of update requests.
 * This is a list of (ptr, val) pairs, where the requested operation
 * is *ptr = val.
 * 
 * Reference counting of pages:
 * ----------------------------
 * Each page has two refcounts: tot_count and type_count.
 * 
 * TOT_COUNT is the obvious reference count. It counts all uses of a
 * physical page frame by a domain, including uses as a page directory,
 * a page table, or simple mappings via a PTE. This count prevents a
 * domain from releasing a frame back to the free pool when it still holds
 * a reference to it.
 * 
 * TYPE_COUNT is more subtle. A frame can be put to one of three
 * mutually-exclusive uses: it might be used as a page directory, or a
 * page table, or it may be mapped writable by the domain [of course, a
 * frame may not be used in any of these three ways!].
 * So, type_count is a count of the number of times a frame is being 
 * referred to in its current incarnation. Therefore, a page can only
 * change its type when its type count is zero.
 * 
 * Pinning the page type:
 * ----------------------
 * The type of a page can be pinned/unpinned with the commands
 * MMUEXT_[UN]PIN_L?_TABLE. Each page can be pinned exactly once (that is,
 * pinning is not reference counted, so it can't be nested).
 * This is useful to prevent a page's type count falling to zero, at which
 * point safety checks would need to be carried out next time the count
 * is increased again.
 * 
 * A further note on writable page mappings:
 * -----------------------------------------
 * For simplicity, the count of writable mappings for a page may not
 * correspond to reality. The 'writable count' is incremented for every
 * PTE which maps the page with the _PAGE_RW flag set. However, for
 * write access to be possible the page directory entry must also have
 * its _PAGE_RW bit set. We do not check this as it complicates the 
 * reference counting considerably [consider the case of multiple
 * directory entries referencing a single page table, some with the RW
 * bit set, others not -- it starts getting a bit messy].
 * In normal use, this simplification shouldn't be a problem.
 * However, the logic can be added if required.
 * 
 * One more note on read-only page mappings:
 * -----------------------------------------
 * We want domains to be able to map pages for read-only access. The
 * main reason is that page tables and directories should be readable
 * by a domain, but it would not be safe for them to be writable.
 * However, domains have free access to rings 1 & 2 of the Intel
 * privilege model. In terms of page protection, these are considered
 * to be part of 'supervisor mode'. The WP bit in CR0 controls whether
 * read-only restrictions are respected in supervisor mode -- if the 
 * bit is clear then any mapped page is writable.
 * 
 * We get round this by always setting the WP bit and disallowing 
 * updates to it. This is very unlikely to cause a problem for guest
 * OS's, which will generally use the WP bit to simplify copy-on-write
 * implementation (in that case, OS wants a fault when it writes to
 * an application-supplied buffer).
 */

#include <xen/config.h>
#include <xen/init.h>
#include <xen/kernel.h>
#include <xen/lib.h>
#include <xen/mm.h>
#include <xen/domain.h>
#include <xen/sched.h>
#include <xen/errno.h>
#include <xen/perfc.h>
#include <xen/irq.h>
#include <xen/softirq.h>
#include <xen/domain_page.h>
#include <xen/event.h>
#include <xen/iocap.h>
#include <xen/guest_access.h>
#include <xen/pfn.h>
#include <xen/xmalloc.h>
#include <xen/efi.h>
#include <xen/grant_table.h>
#include <asm/paging.h>
#include <asm/shadow.h>
#include <asm/page.h>
#include <asm/flushtlb.h>
#include <asm/io.h>
#include <asm/ldt.h>
#include <asm/x86_emulate.h>
#include <asm/e820.h>
#include <asm/hypercall.h>
#include <asm/shared.h>
#include <public/memory.h>
#include <public/sched.h>
#include <xsm/xsm.h>
#include <xen/trace.h>
#include <asm/setup.h>
#include <asm/fixmap.h>

#define MEM_LOG(_f, _a...) gdprintk(XENLOG_WARNING , _f "\n" , ## _a)

/* Private domain structs for DOMID_XEN and DOMID_IO. */
struct domain *dom_xen, *dom_io, *dom_cow;

mfn_t shared_zero_page;

struct page_info *frame_table;
uint32_t *_machine_to_phys_mapping;
/* Frame table size in pages. */
unsigned long max_page;
unsigned long max_vframe;

bool_t __read_mostly machine_to_phys_mapping_valid = 0;

#define PAGE_CACHE_ATTRS (_PAGE_PAT|_PAGE_PCD|_PAGE_PWT)

bool_t __read_mostly opt_allow_superpage = 0;

static uint32_t base_disallow_mask;

void __init init_frametable(void)
{
    unsigned long nr_pages;

    frame_table = (struct page_info *)_uxen_info.ui_frametable;
    nr_pages = PFN_UP(_uxen_info.ui_max_page * sizeof(*frame_table));
    printk("frametable: %p - %lx\n", frame_table,
           (vaddr_t)frame_table + (nr_pages << PAGE_SHIFT));

    machine_to_phys_mapping_valid = 1;
}

void __init arch_init_memory(void)
{
    struct page_info *pg;
    void *va;

    /* Basic guest-accessible flags: PRESENT, R/W, USER, A/D, AVAIL[0,1,2] */
    base_disallow_mask = ~(_PAGE_PRESENT|_PAGE_RW|_PAGE_USER|
                           _PAGE_ACCESSED|_PAGE_DIRTY|_PAGE_AVAIL);
    /* Allow guest access to the NX flag if hardware supports it. */
    if ( cpu_has_nx )
        base_disallow_mask &= ~_PAGE_NX_BIT;
    /* On x86/64, range [62:52] is available for guest software use. */
    if ( CONFIG_PAGING_LEVELS == 4 )
        base_disallow_mask &= ~get_pte_flags((intpte_t)0x7ff << 52);

    /*
     * Initialise our DOMID_XEN domain.
     * Any Xen-heap pages that we will allow to be mapped will have
     * their domain field set to dom_xen.
     */
    dom_xen = domain_create_internal(DOMID_XEN, DOMCRF_dummy, 0, NULL);
    BUG_ON(dom_xen == NULL);

    /*
     * Initialise our DOMID_IO domain.
     * This domain owns I/O pages that are within the range of the page_info
     * array. Mappings occur at the priv of the caller.
     */
    dom_io = domain_create_internal(DOMID_IO, DOMCRF_dummy, 0, NULL);
    BUG_ON(dom_io == NULL);
    
    /*
     * Initialise our DOMID_COW domain.
     * This domain owns sharable pages.
     */
    dom_cow = domain_create_internal(DOMID_COW, DOMCRF_dummy, 0, NULL);
    BUG_ON(dom_cow == NULL);

    pg = alloc_host_page(1);
    BUG_ON(!pg);
    shared_zero_page = _mfn(page_to_mfn(pg));
    va = map_xen_page(mfn_x(shared_zero_page));
    BUG_ON(!va);
    clear_page(va);
    unmap_xen_page(va);
}

unsigned long domain_get_maximum_gpfn(struct domain *d)
{
    if ( is_hvm_domain(d) )
        return p2m_get_hostp2m(d)->max_mapped_pfn;
    BUG();
    /* NB. PV guests specify nr_pfns rather than max_pfn so we adjust here. */
    return arch_get_max_pfn(d) - 1;
}

void share_xen_page_with_guest(
    struct page_info *page, struct domain *d, int readonly)
{
    unsigned long flags;

    if ( page_get_owner(page) == d )
        return;

    spin_lock(&d->page_alloc_lock);

    page_set_owner(page, d);
    wmb(); /* install valid domain ptr before updating refcnt. */
    ASSERT((page->count_info & ~PGC_xen_page) == PGC_state_inuse);

    /* Only add to the allocation list if the domain isn't dying. */
    if ( !d->is_dying )
    {
        if ( is_xen_page(page) ) {
            spin_lock_irqsave(&host_page_list_lock, flags);
            page_list_del(page, &host_page_list);
            spin_unlock_irqrestore(&host_page_list_lock, flags);
        }
        page->count_info |= 1;
        if ( unlikely(d->xenheap_pages++ == 0) )
            get_knownalive_domain(d);
    }

    spin_unlock(&d->page_alloc_lock);
}

void make_cr3(struct vcpu *v, uint64_t cr3)
{
    v->arch.cr3 = cr3;
}

void write_ptbase(struct vcpu *v)
{
    BUG();
}

/*
 * Should be called after CR3 is updated.
 * 
 * Uses values found in vcpu->arch.(guest_table and guest_table_user), and
 * for HVM guests, arch.monitor_table and hvm's guest CR3.
 *
 * Update ref counts to shadow tables appropriately.
 */
void update_cr3(struct vcpu *v)
{

    if ( paging_mode_enabled(v->domain) )
    {
        paging_update_cr3(v);
        return;
    }

    make_cr3(v, read_cr3());
}


static int get_page_from_pagenr(unsigned long page_nr, struct domain *d)
{
    struct page_info *page = mfn_to_page(page_nr);

    if ( unlikely(!mfn_valid(page_nr)) || unlikely(!get_page(page, d)) )
    {
        MEM_LOG("Could not get page ref for pfn %lx", page_nr);
        return 0;
    }

    return 1;
}


int is_iomem_page(unsigned long mfn)
{
    struct page_info *page;

DEBUG();
    if ( !mfn_valid(mfn) )
        return 1;

    /* Caller must know that it is an iomem page, or a reference is held. */
    page = mfn_to_page(mfn);
    ASSERT((page->count_info & PGC_count_mask) != 0);

    return (page_get_owner(page) == dom_io);
}

static int cleanup_page_cacheattr(struct page_info *page)
{
    uint32_t cacheattr =
        (page->count_info & PGC_cacheattr_mask) >> PGC_cacheattr_base;

    if ( likely(cacheattr == 0) )
        return 0;

    BUG(); return 0;
}

static uint32_t always_inline _put_page(struct page_info *page)
{
    uint32_t nx, x, y = page->count_info;

    do {
        ASSERT((y & PGC_count_mask) != 0);
        x  = y;
        nx = x - 1;
    }
    while ( unlikely((y = cmpxchg(&page->count_info, x, nx)) != x) );

    return nx & PGC_count_mask;
}

void put_page(struct page_info *page)
{
    uint32_t count = _put_page(page);

    if ( unlikely(count == 0) )
    {
        if ( cleanup_page_cacheattr(page) == 0 )
            free_domheap_page(page);
        else
            MEM_LOG("Leaking pfn %lx", page_to_mfn(page));
    }
}


static int always_inline
_get_page(struct page_info *page)
{
    uint32_t x, y = page->count_info;

    do {
        x = y;
        /*
         * Count ==  0: Page is not allocated, so we cannot take a reference.
         * Count == -1: Reference count would wrap, which is invalid. 
         * Count == -2: Remaining unused ref is reserved for get_page_light().
         */
        if ( unlikely(((x + 2) & PGC_count_mask) <= 2) )
            return 0;
    }
    while ( (y = cmpxchg(&page->count_info, x, x + 1)) != x );

    return 1;
}

struct domain *page_get_owner_and_reference(struct page_info *page)
{

    if (!_get_page(page))
        return NULL;
    return page_get_owner(page);
}

/* fast get page -- used when the caller is already holding a reference
 * to the page, and also probably knows the page owner */
#ifndef NDEBUG
int
_get_page_fast(struct page_info *page, struct domain *domain)
{
    struct domain *owner;
    int ret;

    ret = _get_page(page);
    if (!ret || !domain)
        return ret;
    owner = page_get_owner(page);
    if (unlikely(domain != owner)) {
        printk("%s: page %lx owner is %p/vm%d, expected %p/vm%d\n",
               __FUNCTION__, page_to_mfn(page),
               owner, owner ? owner->domain_id : -1,
               domain, domain ? domain->domain_id : -1);
        DEBUG();
    }
    return 1;
}
#else  /* NDEBUG */
int
_get_page_fast(struct page_info *page)
{

    return _get_page(page);
}
#endif  /* NDEBUG */

int get_page(struct page_info *page, struct domain *domain)
{
    struct domain *owner = page_get_owner_and_reference(page);

    if ( likely(owner == domain) )
        return 1;

    if ( owner != NULL )
        put_page(page);

    if ( !domain->is_dying ) {
        gdprintk(XENLOG_INFO,
                 "Error mfn %lx: rd=%p, od=%p, caf=%08x\n",
                 page_to_mfn(page), domain, owner,
                 page->count_info);
    }
    return 0;
}

#ifdef __UXEN_todo__
/*
 * Special version of get_page() to be used exclusively when
 * - a page is known to already have a non-zero reference count
 * - the page does not need its owner to be checked
 * - it will not be called more than once without dropping the thus
 *   acquired reference again.
 * Due to get_page() reserving one reference, this call cannot fail.
 */
static void get_page_light(struct page_info *page)
{
    unsigned long x, nx, y = page->count_info;

    do {
        x  = y;
        nx = x + 1;
        BUG_ON(!(x & PGC_count_mask)); /* Not allocated? */
        BUG_ON(!(nx & PGC_count_mask)); /* Overflow? */
        y = cmpxchg(&page->count_info, x, nx);
    }
    while ( unlikely(y != x) );
}
#endif  /* __UXEN_todo__ */

void
put_page_destructor(struct page_info *page,
                    void (*destructor)(struct page_info *, va_list), ...)
{
    uint32_t count = _put_page(page);
    va_list ap;

    if (unlikely(count == 0)) {
        if (cleanup_page_cacheattr(page) == 0) {
            va_start(ap, destructor);
            destructor(page, ap);
            va_end(ap);
        } else
            MEM_LOG("Leaking pfn %lx", page_to_mfn(page));
    }
}

/* put page after dropping refs many references */
static int always_inline
put_page_last_ref(struct page_info *page, struct domain *d, int refs)
{
    uint32_t nx, x, y;
    struct domain *owner = page_get_owner_and_reference(page);
    int drop_dom_ref;

    if (!owner)
        return 0;
    if (owner != d) {
        put_page(page);
        return 0;
    }

    /* also drop the ref taken above */
    refs++;
    y = page->count_info;
    do {
        if ((y & PGC_count_mask) < refs) {
            put_page(page);
            return 0;
        }
        ASSERT((y & PGC_count_mask) >= refs);
        x  = y;
        nx = (x - refs);
        if (nx & PGC_count_mask) {
            put_page(page);
            return 0;
        }
    } while (unlikely((y = cmpxchg(&page->count_info, x, nx)) != x));

    spin_lock_recursive(&d->page_alloc_lock);
    d->tot_pages -= 1;
    drop_dom_ref = (d->tot_pages == 0);
    spin_unlock_recursive(&d->page_alloc_lock);
    if (drop_dom_ref)
        put_domain(d);

    return 1;
}

/* change page owner, if there are refs many references to it --
 * returns 0 on success, -1 when unable to drop references, and 1 if
 * page was lost when failing to assign the page to the to domain,
 * either because the domain is dying or because it is beyond it's
 * allowed memory usage */
int
change_page_owner(struct page_info *page, struct domain *to,
                  struct domain *from, int refs)
{
    int ret;

    if (!put_page_last_ref(page, from, refs))
        return -1;

    ASSERT(page->count_info == PGC_state_host);
    page->count_info = PGC_state_inuse;
    page_set_owner(page, NULL);
    ret = assign_pages(to, page, 0, 0);
    if (ret)
        free_domheap_page(page);
    return ret ? 1 : 0;
}


int free_page_type(struct page_info *page, unsigned long type,
                   int preemptible)
{
    BUG(); return 0;
}


static int xenmem_add_to_physmap_once(
    struct domain *d,
    const struct xen_add_to_physmap *xatp)
{
    struct page_info *page;
    unsigned long gfn = 0; /* gcc ... */
    unsigned long prev_mfn, mfn = 0, idx;
    p2m_type_t pt;
    int rc;

    switch ( xatp->space )
    {
        case XENMAPSPACE_shared_info:
            if ( xatp->idx == 0 )
                mfn = virt_to_mfn(d->shared_info);
            break;
        case XENMAPSPACE_gmfn_range:
        case XENMAPSPACE_gmfn:
        {
            p2m_type_t p2mt;
            gfn = xatp->idx;

            if (xatp->idx == INVALID_GFN) {
                mfn = INVALID_MFN;
                break;
            }

            if (hypercall_needs_checks())
                return -EAGAIN;
            idx = mfn_x(get_gfn_unshare(d, xatp->idx, &p2mt));
            if (idx == INVALID_MFN) {
                put_gfn(d, gfn);
                return -EINVAL;
            }
            if ( !get_page_from_pagenr(idx, d) )
                break;
            mfn = idx;
            break;
        }
        case XENMAPSPACE_host_mfn:
        {
            if (!IS_PRIV_SYS())
                return -EPERM;
            mfn = xatp->idx;
            break;
        }
        default:
            break;
    }

    domain_lock(d);

    switch ( xatp->space )
    {
        case XENMAPSPACE_host_mfn:
        {
            /* invalid mfn passed in to clear/unhook mapping at gfn */
            if (!mfn_valid(mfn))
                break;
            if (page_get_owner(__mfn_to_page(mfn)) == dom0)
                break;
            if (is_host_page(__mfn_to_page(mfn))) {
                gdprintk(XENLOG_ERR, "mfn %lx for gpfn %"PRI_xen_pfn
                         " already host page\n", mfn, xatp->gpfn);
                rc = -EINVAL;
                goto out;
            }
            if (!get_page_from_pagenr(mfn, d)) {
                gdprintk(XENLOG_ERR, "unexpected owner for gpfn %"PRI_xen_pfn
                         ": host mfn %lx has owner vm%u\n",
                         xatp->gpfn, mfn,
                         page_get_owner(__mfn_to_page(mfn))->domain_id);
            } else {
                put_page(mfn_to_page(mfn));
                gdprintk(XENLOG_ERR, "attempt to map already mapped host "
                         "mfn %lx at gpfn %"PRI_xen_pfn"\n", mfn, xatp->gpfn);
            }
            rc = -EINVAL;
            goto out;
        }
    }

    if ( !paging_mode_translate(d) || (mfn == 0) )
    {
        if ( xatp->space == XENMAPSPACE_gmfn ||
             xatp->space == XENMAPSPACE_gmfn_range )
            put_gfn(d, gfn);
        rc = -EINVAL;
        goto out;
    }

    if (d->is_dying) {
        /* silently don't add page to p2m when domain is exiting, and
         * don't remove previous entries from the p2m since it is/has
         * already being torn down */
        put_gfn(d, xatp->gpfn);
        rc = 0;
        if ( xatp->space == XENMAPSPACE_gmfn ||
             xatp->space == XENMAPSPACE_gmfn_range )
            put_gfn(d, gfn);
        goto out;
    }

    /* Remove previously mapped page if it was present. */
    prev_mfn = mfn_x(get_gfn_query(d, xatp->gpfn, &pt));
    if ( mfn_valid_page(prev_mfn) )
    {
        if ( is_xen_mfn(prev_mfn) )
            /* Xen heap frames are simply unhooked from this phys slot. */
            guest_physmap_remove_page(d, xatp->gpfn, prev_mfn);
        else if ( is_host_mfn(prev_mfn) ) {
            /* Host frames are unhooked from this phys slot and have
             * their PGC_host_page flag cleared. */
            guest_physmap_remove_page(d, xatp->gpfn, prev_mfn);
        } else if ( p2m_is_ram(pt) )
            /* Normal domain memory is freed, to avoid leaking memory. */
            guest_remove_page(d, xatp->gpfn);
        else if (p2m_is_pod(pt))
            /* pod pages are simply unhooked from this phys slot. */
            guest_physmap_remove_page(d, xatp->gpfn, prev_mfn);
        else {
            gdprintk(XENLOG_ERR, "unexpected type for gpfn %"PRI_xen_pfn
                     " type %x\n", xatp->gpfn, pt);
            guest_physmap_remove_page(d, xatp->gpfn, prev_mfn);
        }
    }
    put_gfn(d, xatp->gpfn);

    switch (xatp->space) {
    case XENMAPSPACE_host_mfn:
        /* invalid mfn passed in to clear/unhook mapping at gfn */
        if (!mfn_valid(mfn)) {
            rc = 0;
            goto out;
        }
        page = __mfn_to_page(mfn);
        spin_lock(&d->page_alloc_lock);
        page_set_owner(page, d);
        wmb(); /* install valid domain ptr before updating refcnt. */
        d->tot_pages++;
        page->count_info = PGC_host_page | 1;
        d->host_pages++;
        spin_unlock(&d->page_alloc_lock);
        break;
    case XENMAPSPACE_shared_info:
        if (d->shared_info_gpfn != INVALID_GFN) {
            guest_physmap_remove_page(d, d->shared_info_gpfn, mfn);
            d->shared_info_gpfn = INVALID_GFN;
        }
        get_page_fast(mfn_to_page(mfn), NULL);
        break;
    case XENMAPSPACE_gmfn:
    case XENMAPSPACE_gmfn_range:
        if (xatp->idx == INVALID_GFN) {
            rc = 0;
            put_gfn(d, gfn);
            goto out;
        }
        guest_physmap_remove_page(d, xatp->idx, mfn);
        /* ref on mfn taken above */
        break;
    default:
        break;
    }

    /* Map at new location. */
    rc = guest_physmap_add_page(d, xatp->gpfn, mfn);
    put_page(__mfn_to_page(mfn));

    /* In the XENMAPSPACE_gmfn, we took a ref and locked the p2m at the top */
    if ( xatp->space == XENMAPSPACE_gmfn ||
         xatp->space == XENMAPSPACE_gmfn_range )
        put_gfn(d, gfn);
    /* XENMAPSPACE_shared_info case: update shared_info_gpfn on success */
    else if (!rc && xatp->space == XENMAPSPACE_shared_info)
        d->shared_info_gpfn = xatp->gpfn;
  out:
    domain_unlock(d);

    return rc;
}

static int xenmem_add_to_physmap(struct domain *d,
                                 struct xen_add_to_physmap *xatp)
{
    int rc = 0;

    if ( xatp->space == XENMAPSPACE_gmfn_range )
    {
        while ( xatp->size > 0 )
        {
            rc = xenmem_add_to_physmap_once(d, xatp);
            if ( rc < 0 )
                return rc;

            if (xatp->idx != INVALID_GFN)
                xatp->idx++;
            xatp->gpfn++;
            xatp->size--;

            /* Check for continuation if it's not the last interation */
            if ( xatp->size > 0 && hypercall_preempt_check() )
            {
                rc = -EAGAIN;
                break;
            }
        }

        return rc;
    }

    return xenmem_add_to_physmap_once(d, xatp);
}

long arch_memory_op(int op, XEN_GUEST_HANDLE(void) arg)
{
    int rc;

    switch ( op )
    {
    case XENMEM_add_to_physmap:
    {
        struct xen_add_to_physmap xatp;
        struct domain *d;

        if ( copy_from_guest(&xatp, arg, 1) )
            return -EFAULT;

        if (current->domain->domain_id != 0) {
            switch (xatp.space) {
            case XENMAPSPACE_shared_info:
            case XENMAPSPACE_gmfn_range:
            case XENMAPSPACE_gmfn:
                break;
            default:
                return -EPERM;
            }
        }

        rc = rcu_lock_target_domain_by_id(xatp.domid, &d);
        if ( rc != 0 )
            return rc;

        if ( xsm_add_to_physmap(current->domain, d) )
        {
            rcu_unlock_domain(d);
            return -EPERM;
        }

        rc = xenmem_add_to_physmap(d, &xatp);

        rcu_unlock_domain(d);

        if ( xatp.space == XENMAPSPACE_gmfn_range )
        {
            if ( rc && copy_to_guest(arg, &xatp, 1) )
                rc = -EFAULT;

            if ( rc == -EAGAIN )
                rc = hypercall_create_continuation(
                        __HYPERVISOR_memory_op, "ih", op, arg);
        }

        return rc;
    }

    case XENMEM_translate_gpfn_list_for_map:
    {
        xen_translate_gpfn_list_for_map_t list;
        struct domain *d;
        struct page_info *page = NULL;
        xen_pfn_t *arr = NULL;
        unsigned int k, n, i;

        if (!IS_PRIV_SYS())
            return -EPERM;

        if ( copy_from_guest(&list, arg, 1) )
            return -EFAULT;

        rc = rcu_lock_target_domain_by_id(list.domid, &d);
        if ( rc != 0 )
            return rc;
        
        if (list.gpfns_end > 1024) {
            rc = -E2BIG;
            goto translate_gpfn_list_for_map_out;
        }

        page = alloc_domheap_page(NULL, 0);
        if ( !page ) {
            rc = -ENOMEM;
            goto translate_gpfn_list_for_map_out;
        }

        arr = __map_domain_page(page);

        for (n = list.gpfns_start; n < list.gpfns_end; ) {
            k = min_t(unsigned int, list.gpfns_end - n,
                      PAGE_SIZE / sizeof(*arr));
            switch (list.map_mode) {
            default:
                rc = -EINVAL;
                goto translate_gpfn_list_for_map_out;
            case XENMEM_TRANSLATE_RELEASE:
                if ( copy_from_guest_offset(arr, list.mfn_list, n, k) ) {
                    rc = -EFAULT;
                    goto translate_gpfn_list_for_map_out;
                }
                for (i = 0; i < k; i++)
                    if (__mfn_valid(arr[i]))
                        put_page(__mfn_to_page(arr[i]));
                break;
            case XENMEM_TRANSLATE_MAP:
                if ( copy_from_guest_offset(arr, list.gpfn_list, n, k) ) {
                    rc = -EFAULT;
                    goto translate_gpfn_list_for_map_out;
                }
                rc = p2m_translate(d, arr, k,
                                   list.prot == XENMEM_TRANSLATE_PROT_WRITE);
                if (rc < 0)
                    goto translate_gpfn_list_for_map_out;
                if (copy_to_guest_offset(list.mfn_list, n, arr, rc)) {
                    rc = -EFAULT;
                    goto translate_gpfn_list_for_map_out;
                }
                if (rc != k) {
                    list.gpfns_start = n + rc;
                    if (copy_to_guest(arg, &list, 1)) {
                        rc = -EFAULT;
                        goto translate_gpfn_list_for_map_out;
                    }
                    rc = hypercall_create_continuation(
                        __HYPERVISOR_memory_op, "ih",
                        XENMEM_translate_gpfn_list_for_map, arg);
                    goto translate_gpfn_list_for_map_out;
                }
                break;
            }
            n += k;
        }
        rc = 0;

    translate_gpfn_list_for_map_out:
        if (arr)
            unmap_domain_page(arr);
        if (page)
            free_domheap_page(page);
        rcu_unlock_domain(d);
        return rc;
    }

    case XENMEM_share_zero_pages:
    {
        xen_memory_share_zero_pages_t list;
        struct domain *d;
        xen_pfn_t *gpfns;
        mfn_t mfn;
        p2m_type_t pt;
        unsigned int n;

        if ( copy_from_guest(&list, arg, 1) )
            return -EFAULT;

        d = rcu_lock_current_domain();
        
        if ( !is_hvm_domain(d) )
        {
            rc = -EPERM;
            goto share_zero_pages_out;
        }

        if (list.nr_gpfns > (PAGE_SIZE / sizeof(gpfns[0]))) {
            rc = -E2BIG;
            goto share_zero_pages_out;
        }

        mfn = get_gfn_unshare(d, list.gpfn_list_gpfn, &pt);
        if (!p2m_is_ram(pt)) {
            put_gfn(d, list.gpfn_list_gpfn);
            rc = -EFAULT;
            goto share_zero_pages_out;
        }
        ASSERT(mfn_valid(mfn_x(mfn)));

        gpfns = map_domain_page(mfn_x(mfn));

        rc = 0;
        for (n = 0; n < list.nr_gpfns; n++) {
            get_gfn_type(d, gpfns[n], &pt, p2m_zeroshare);
            put_gfn(d, gpfns[n]);
        }

        unmap_domain_page(gpfns);
        put_gfn(d, list.gpfn_list_gpfn);

    share_zero_pages_out:
        rcu_unlock_domain(d);
        return rc;
    }

    case XENMEM_set_zero_page_ctxt:
    {
        struct domain *d;
        xen_memory_set_zero_page_ctxt_t zp_arg;
        uint32_t nr;

        d = rcu_lock_current_domain();

        if (copy_from_guest(&zp_arg, arg, 1))
            return -EFAULT;

        if (d->zp_nr) {
            MEM_LOG("zp: vm zero page ctxt already set");
            goto set_zero_page_ctxt_out;
        }

        if (!(d->arch.hvm_domain.params[HVM_PARAM_ZERO_PAGE] &
              HVM_PARAM_ZERO_PAGE_enable_setup)) {
            MEM_LOG("zp: vm zero page disabled");
            goto set_zero_page_ctxt_out;
        }

        for (nr = 0; nr < zp_arg.nr_desc; nr++) {
            if (nr >= XEN_MEMORY_SET_ZERO_PAGE_DESC_MAX)
                break;
            if (!zp_arg.zp[nr].entry)
                continue;
            d->zp_ctxt[d->zp_nr].entry = zp_arg.zp[nr].entry;
            d->zp_ctxt[d->zp_nr].ret = zp_arg.zp[nr].ret;
            d->zp_ctxt[d->zp_nr].nr_gpfns_mode = zp_arg.zp[nr].nr_gpfns_mode;
            d->zp_ctxt[d->zp_nr].gva_mode = zp_arg.zp[nr].gva_mode;
            d->zp_ctxt[d->zp_nr].prologue_mode = zp_arg.zp[nr].prologue_mode;
            d->zp_ctxt[d->zp_nr].zero_thread_mode =
                zp_arg.zp[nr].zero_thread_mode;
            switch (d->zp_ctxt[d->zp_nr].zero_thread_mode) {
            case XEN_MEMORY_SET_ZERO_PAGE_ZERO_THREAD_MODE_gs_pcr_188:
            case XEN_MEMORY_SET_ZERO_PAGE_ZERO_THREAD_MODE_fs_pcr_124:
                d->zp_ctxt[d->zp_nr].zero_thread_addr =
                    zp_arg.zp[nr].zero_thread_addr;
                break;
            case XEN_MEMORY_SET_ZERO_PAGE_ZERO_THREAD_MODE_cr3:
                d->zp_ctxt[d->zp_nr].zero_thread_paging_base =
                    zp_arg.zp[nr].zero_thread_paging_base;
                break;
            }
            MEM_LOG("zp: vm zero page fn @ %"PRIxPTR" - %"PRIxPTR
                    " nr_gpfns %d gva %d prologue %d"
                    " -- zero thread addr/cr3 %"PRIxPTR" mode %d",
                    d->zp_ctxt[d->zp_nr].entry, d->zp_ctxt[d->zp_nr].ret,
                    d->zp_ctxt[d->zp_nr].nr_gpfns_mode,
                    d->zp_ctxt[d->zp_nr].gva_mode,
                    d->zp_ctxt[d->zp_nr].prologue_mode,
                    d->zp_ctxt[d->zp_nr].zero_thread_addr,
                    d->zp_ctxt[d->zp_nr].zero_thread_mode);
            d->zp_nr++;
        }

        hvm_set_zp_prefix(d);

      set_zero_page_ctxt_out:
        rcu_unlock_domain(d);

        return 0;
    }

    default:
        rc = -ENOSYS;
        return rc;
    }

    return 0;
}


/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
