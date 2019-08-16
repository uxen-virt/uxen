/******************************************************************************
 * page_alloc.c
 * 
 * Simple buddy heap allocator for Xen.
 * 
 * Copyright (c) 2002-2004 K A Fraser
 * Copyright (c) 2006 IBM Ryan Harper <ryanh@us.ibm.com>
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
#include <xen/init.h>
#include <xen/types.h>
#include <xen/lib.h>
#include <xen/sched.h>
#include <xen/spinlock.h>
#include <xen/mm.h>
#include <xen/irq.h>
#include <xen/softirq.h>
#include <xen/domain_page.h>
#include <xen/keyhandler.h>
#include <xen/perfc.h>
#include <xen/numa.h>
#include <xen/nodemask.h>
#include <public/sysctl.h>
#include <public/sched.h>
#include <asm/page.h>
#include <asm/numa.h>
#include <asm/flushtlb.h>
#ifdef CONFIG_X86
#include <asm/p2m.h>
#else
#define p2m_pod_offline_or_broken_hit(pg) 0
#define p2m_pod_offline_or_broken_replace(pg) BUG_ON(pg != NULL)
#endif

// #define UXEN_ALLOC_DEBUG
// #define UXEN_ALLOC_HIDDEN_DEBUG
#include <xen/symbols.h>

#ifdef __i386__
/*
 * no-bootscrub -> Free pages are not zeroed during boot.
 */
static bool_t opt_bootscrub __initdata = 1;
boolean_param("bootscrub", opt_bootscrub);
#endif  /* __i386__ */

#ifdef __i386__
#define round_pgdown(_p)  ((_p)&PAGE_MASK)
#define round_pgup(_p)    (((_p)+(PAGE_SIZE-1))&PAGE_MASK)
#endif  /* __i386__ */



#ifdef __i386__
/*************************
 * hidden memory allocator
 */

#define HIDDEN_MEMORY_BASE 0x100000
#define is_hidden_page(pg) (page_to_mfn(pg) >= HIDDEN_MEMORY_BASE)

PAGE_LIST_HEAD(hidden_pages_free_list);
DEFINE_SPINLOCK(hidden_pages_free_list_lock);

static void
free_hidden_page(struct page_info *pg)
{
    unsigned long flags;

    pg->domain = DOMID_0;
    pg->count_info = PGC_state_free;

    atomic_dec(&hidden_pages_allocated);
    ASSERT(atomic_read(&hidden_pages_allocated) >= 0);

    spin_lock_irqsave(&hidden_pages_free_list_lock, flags);
    page_list_add(pg, &hidden_pages_free_list);
    spin_unlock_irqrestore(&hidden_pages_free_list_lock, flags);
}

void
init_hidden_pages(paddr_t ps, paddr_t pe)
{
    struct page_info *pg;
    unsigned long nr_pages;
    unsigned long i;
    unsigned long flags;

    pg = mfn_to_page(ps >> PAGE_SHIFT);
    nr_pages = (pe >> PAGE_SHIFT) - (ps >> PAGE_SHIFT);

    atomic_add(nr_pages, &hidden_pages_available);

    for (i = 0; i < nr_pages; i++) {
        if (opt_bootscrub) {
            scrub_one_page(pg);
            pg->count_info = PGC_state_free;
        } else
            pg->count_info = PGC_state_dirty;

        pg->domain = DOMID_0;

        spin_lock_irqsave(&hidden_pages_free_list_lock, flags);
        page_list_add_tail(pg, &hidden_pages_free_list);
        spin_unlock_irqrestore(&hidden_pages_free_list_lock, flags);

        pg++;
    }
}

static struct page_info *
alloc_hidden_page(unsigned int memflags, struct domain *d)
{
    struct page_info *pg;
    unsigned long flags;

    spin_lock_irqsave(&hidden_pages_free_list_lock, flags);
    pg = page_list_remove_head(&hidden_pages_free_list);
    spin_unlock_irqrestore(&hidden_pages_free_list_lock, flags);

    if (pg) {
        if (pg->count_info == PGC_state_dirty) {
            scrub_one_page(pg);
            pg->count_info = PGC_state_free;
        }
        BUG_ON(pg->count_info != PGC_state_free);
        pg->count_info = PGC_state_inuse;

        pg->domain = DOMID_ANON;

        atomic_inc(&hidden_pages_allocated);
        ASSERT(atomic_read(&hidden_pages_allocated) <=
               atomic_read(&hidden_pages_available));

#ifdef UXEN_ALLOC_HIDDEN_DEBUG
        printk("alloc hidden page: %lx pg %p\n", page_to_mfn(pg), pg);
#endif  /* UXEN_ALLOC_HIDDEN_DEBUG */
    }

    return pg;
}
#endif  /* __i386__ */



/*************************
 * Host allocator
 */

atomic_t host_pages_allocated = ATOMIC_INIT(0);
#ifdef __i386__
atomic_t hidden_pages_allocated = ATOMIC_INIT(0);
atomic_t hidden_pages_available = ATOMIC_INIT(0);
#endif

struct page_info *
alloc_host_page(int is_xen_page)
{
    struct page_info *pg;
    int cpu = smp_processor_id();

    if (!_uxen_info.ui_free_pages[cpu].count) {
        printk(XENLOG_ERR "%s: no pages on cpu %d from %S\n", __FUNCTION__,
               cpu, (printk_symbol)__builtin_return_address(0));
        return NULL;
    }

    pg = mfn_to_page(_uxen_info.ui_free_pages[cpu].list);
    _uxen_info.ui_free_pages[cpu].list = pg->list.next;
    pg->list.next = 0;
    _uxen_info.ui_free_pages[cpu].count--;
    atomic_inc(&host_pages_allocated);

    BUG_ON(pg->count_info != PGC_state_host);
    pg->count_info = PGC_state_inuse;

    /* Initialise fields which have other uses for free pages. */
    BUG_ON(pg->domain != DOMID_0);
    pg->domain = DOMID_ANON;

    if (is_xen_page) {
        unsigned long flags;

        pg->count_info |= PGC_xen_page;
        spin_lock_irqsave(&host_page_list_lock, flags);
        page_list_add_tail(pg, &host_page_list);
        spin_unlock_irqrestore(&host_page_list_lock, flags);
    }

#ifdef DEBUG_STRAY_PAGES
    pg->alloc0 = __builtin_return_address(0);
#endif  /* DEBUG_STRAY_PAGES */

    return pg;
}

static void
free_host_page(struct page_info *pg)
{
    int cpu = smp_processor_id();

    /* This page is not a guest frame any more. */
    pg->domain = DOMID_ANON;

    /*
     * Cannot assume that count_info == 0, as there are some corner cases
     * where it isn't the case and yet it isn't a bug:
     *  1. page_get_owner() is NULL
     *  2. page_get_owner() is a domain that was never accessible by
     *     its domid (e.g., failed to fully construct the domain).
     *  3. page was never addressable by the guest (e.g., it's an
     *     auto-translate-physmap guest and the page was never included
     *     in its pseudophysical address space).
     * In all the above cases there can be no guest mappings of this page.
     */
    pg->count_info = PGC_state_host;
    BUG_ON(pg->domain != DOMID_ANON);
    pg->domain = DOMID_0;
#ifdef DEBUG_MAPCACHE
    if (atomic_read(&pg->mapped) > 1) {
        printk("%s: mfn %lx still mapped from %S and %S\n", __FUNCTION__,
               page_to_mfn(pg), (printk_symbol)pg->lastmap,
               (printk_symbol)pg->lastmap0);
    }
    if (atomic_read(&pg->mapped)) {
        atomic_set(&pg->mapped, 0);
        pg->lastmap = NULL;
        pg->lastmap0 = NULL;
    }
#endif  /* DEBUG_MAPCACHE */

    pg->list.next = _uxen_info.ui_free_pages[cpu].list;
    pg->list.prev = 0;
    _uxen_info.ui_free_pages[cpu].list = page_to_mfn(pg);
    _uxen_info.ui_free_pages[cpu].count++;
    atomic_dec(&host_pages_allocated);
    ASSERT(atomic_read(&host_pages_allocated) >= 0);
}

void
free_host_heap_page(struct domain *d, struct page_info *pg)
{

#ifdef __i386__
#ifdef UXEN_ALLOC_HIDDEN_DEBUG
    printk("%s: %lx pg %p %s\n", __FUNCTION__, page_to_mfn(pg), pg,
           is_hidden_page(pg) ? "is hidden" : "not hidden");
#endif  /* UXEN_ALLOC_HIDDEN_DEBUG */
    if (is_hidden_page(pg)) {
        if (d)                  /* ASSERT(d) */
            atomic_dec(&d->hidden_pages);
        free_hidden_page(pg);
    } else
#endif
        free_host_page(pg);
}


/*************************
 * vframe allocator
 */

atomic_t vframes_allocated = ATOMIC_INIT(0);

struct page_info *
alloc_vframe(struct domain *d)
{
    uint32_t f;
    struct page_info *pg;

    BUILD_BUG_ON(sizeof(_uxen_info.ui_vframes.count) != sizeof(atomic_t));

    if (!_uxen_info.ui_vframes.count) {
        printk(XENLOG_ERR "%s: no vframes from %S", __FUNCTION__,
               (printk_symbol)__builtin_return_address(0));
        return NULL;
    }

    do {
        f = _uxen_info.ui_vframes.list;
        pg = mfn_to_page(f);
    } while (cmpxchg(&_uxen_info.ui_vframes.list, f, pg->list.next) != f);

    BUG_ON(!is_vframe_page(pg));
    BUG_ON(pg->count_info != PGC_state_host);

    pg->list.next = 0;
    atomic_dec((atomic_t *)&_uxen_info.ui_vframes.count);
    atomic_inc(&vframes_allocated);

    pg->count_info = PGC_state_inuse | 1;
    page_set_owner(pg, d);

    if (d) {
        spin_lock(&d->page_alloc_lock);
        if (unlikely(d->vframes == 0))
            get_knownalive_domain(d);
        d->vframes++;
        spin_unlock(&d->page_alloc_lock);
    }

    return pg;
}

void
free_vframe(struct page_info *pg)
{
    uint32_t f = page_to_mfn(pg);

    pg->domain = DOMID_0;

    BUG_ON(pg->count_info != PGC_state_inuse);
    pg->count_info = PGC_state_host;

    pg->list.prev = 0;
    do {
        pg->list.next = _uxen_info.ui_vframes.list;
    } while (cmpxchg(&_uxen_info.ui_vframes.list, pg->list.next, f) !=
             pg->list.next);
    atomic_inc((atomic_t *)&_uxen_info.ui_vframes.count);
    atomic_dec(&vframes_allocated);
    ASSERT(atomic_read(&vframes_allocated) >= 0);
}


/*************************
 * XEN-HEAP SUB-ALLOCATOR
 */

void
init_host_pages(void)
{

}

PAGE_LIST_HEAD(host_page_list);
DEFINE_SPINLOCK(host_page_list_lock);

void *
alloc_host_pages(unsigned int pages, unsigned int memflags)
{
    uxen_pfn_t pfns[_uxen_info.ui_map_page_range_max_nr];
    unsigned int i;
    struct page_info *pg;
    void *v;
    unsigned long flags;

    ASSERT(!in_irq());

    if (pages > 1 && !(memflags & (MEMF_xmalloc | MEMF_multiok))) {
        printk("%s: non-xmalloc/multiok alloc %d pages from %S\n", __FUNCTION__,
               pages, (printk_symbol)__builtin_return_address(0));
        BUG();
        return NULL;
    }

    if (pages > _uxen_info.ui_map_page_range_max_nr) {
        printk("%s: alloc pages %d > %d pages from %S\n", __FUNCTION__,
               pages, _uxen_info.ui_map_page_range_max_nr,
               (printk_symbol)__builtin_return_address(0));
        BUG();
        return NULL;
    }

    for ( i = 0; i < pages; i++ ) {
        pg = alloc_host_page(1);
        if (pg == NULL)
            break;
#ifdef DEBUG_STRAY_PAGES
        pg->alloc1 = __builtin_return_address(0);
#endif  /* DEBUG_STRAY_PAGES */
        pfns[i] = page_to_mfn(pg);
#ifdef UXEN_ALLOC_DEBUG
        printk("alloc host pages %d/%d: %x\n", i, pages, pfns[i]);
#endif  /* UXEN_ALLOC_DEBUG */
    }

    if (i != pages)
        goto free_out;

    if (pages > 1) {
        v = UI_HOST_CALL(ui_map_page_range, current->vm_vcpu_info_shared, i,
                         pfns);
#ifdef DEBUG_MAPCACHE
        if (v)
            for (i = 0; i < pages; i++) {
                atomic_inc(&mfn_to_page(pfns[i])->mapped);
                mfn_to_page(pfns[i])->lastmap = current_text_addr();
                mfn_to_page(pfns[i])->lastmap0 = __builtin_return_address(0);
            }
#endif  /* DEBUG_MAPCACHE */
    } else
        v = map_xen_page(pfns[0]);

#ifdef UXEN_ALLOC_DEBUG
    printk("%S: alloc host pages %d -> %p\n",
           (printk_symbol)__builtin_return_address(0), pages, v);
#endif  /* UXEN_ALLOC_DEBUG */

    if (v)
        return v;

  free_out:
    /* free i-1 .. 0 */
    while (i-- > 0) {
        pg = mfn_to_page(pfns[i]);
        pg->count_info &= ~PGC_xen_page;
        pg->domain = DOMID_ANON;
        spin_lock_irqsave(&host_page_list_lock, flags);
        page_list_del(pg, &host_page_list);
        spin_unlock_irqrestore(&host_page_list_lock, flags);
        free_host_page(pg);
    }

    return NULL;
}

void free_host_pages(void *v, unsigned int pages)
{
    uxen_pfn_t pfns[64];
    struct page_info *pg;
    unsigned long flags;
    int ret;

    ASSERT(!in_irq());

    if ( v == NULL )
        return;

#ifdef UXEN_ALLOC_DEBUG
    printk("free_host_pages(%p,%d) from %S\n", v, pages,
           (printk_symbol)__builtin_return_address(0));
#endif  /* UXEN_ALLOC_DEBUG */

    if (pages > 1) {
        BUG_ON(((unsigned long)v & (PAGE_SIZE - 1)));

        ret = UI_HOST_CALL(ui_unmap_page_range, current->vm_vcpu_info_shared,
                           v, pages, pfns);
        if (ret) {
            gdprintk(XENLOG_INFO, "Error free_xenheap_pages(%p,%d) ret %d\n",
                     v, pages, ret);
            return;
        }
#ifdef DEBUG_MAPCACHE
        {
            int i;
            for (i = 0; i < pages; i++)
                atomic_dec(&mfn_to_page(pfns[i])->mapped);
        }
#endif  /* DEBUG_MAPCACHE */
    } else
        pfns[0] = unmap_xen_page(v);

    /* free pages-1 .. 0 */
    while (pages-- > 0) {
        pg = mfn_to_page(pfns[pages]);
        pg->count_info &= ~PGC_xen_page;
        pg->domain = DOMID_ANON;
        spin_lock_irqsave(&host_page_list_lock, flags);
        page_list_del(pg, &host_page_list);
        spin_unlock_irqrestore(&host_page_list_lock, flags);
        free_host_page(pg);
    }
}

void
free_all_host_pages(void)
{
    struct page_info *pg;
    unsigned long flags;

    spin_lock_irqsave(&host_page_list_lock, flags);
    while ((pg = page_list_remove_head(&host_page_list))) {
        spin_unlock_irqrestore(&host_page_list_lock, flags);
#ifdef UXEN_ALLOC_DEBUG
        printk("%s: page %lx\n", __FUNCTION__, page_to_mfn(pg));
#endif  /* UXEN_ALLOC_DEBUG */
        pg->count_info &= ~PGC_xen_page;
        pg->domain = DOMID_ANON;
        free_host_page(pg);
        spin_lock_irqsave(&host_page_list_lock, flags);
    }
    spin_unlock_irqrestore(&host_page_list_lock, flags);
}



/*************************
 * DOMAIN-HEAP SUB-ALLOCATOR
 */


int assign_pages(
    struct domain *d,
    struct page_info *pg,
    unsigned int order,
    unsigned int memflags)
{
    unsigned long i;

    ASSERT(order == 0);
    spin_lock(&d->page_alloc_lock);

    if ( unlikely(d->is_dying) )
    {
        gdprintk(XENLOG_INFO, "Cannot assign page to vm%u -- dying.\n",
                d->domain_id);
        goto fail;
    }

    if ( !(memflags & MEMF_no_refcount) )
    {
        if ( unlikely((d->tot_pages + (1 << order)) > d->max_pages) )
        {
                gdprintk(XENLOG_INFO, "Over-allocation for vm%u: "
                         "%u > %u\n", d->domain_id,
                         d->tot_pages + (1 << order), d->max_pages);
            goto fail;
        }

        if ( unlikely(d->tot_pages == 0) )
            get_knownalive_domain(d);

        d->tot_pages += 1 << order;
    }

    for ( i = 0; i < (1 << order); i++ )
    {
        ASSERT(page_get_owner(&pg[i]) == NULL);
        ASSERT((pg[i].count_info & ~1) == PGC_state_inuse);
        page_set_owner(&pg[i], d);
        wmb(); /* Domain pointer must be visible before updating refcnt. */
        pg[i].count_info = 1;
    }

    spin_unlock(&d->page_alloc_lock);
    return 0;

 fail:
    spin_unlock(&d->page_alloc_lock);
    return -1;
}


struct page_info *alloc_domheap_pages(
    struct domain *d, unsigned int order, unsigned int memflags)
{
    struct page_info *pg = NULL;

    ASSERT(order == 0);

#ifdef __i386__
    if (!d || !d->use_hidden_mem)
        memflags |= MEMF_host_page;
    if (!(memflags & MEMF_host_page)) {
        pg = alloc_hidden_page(memflags, d);
        if (d && pg)
            atomic_inc(&d->hidden_pages);
    }
    if (!pg)
#endif
        pg = alloc_host_page(0);
    if (!pg) {
        printk(XENLOG_ERR "%s: alloc_host_page failed from %S\n", __FUNCTION__,
               (printk_symbol)__builtin_return_address(0));
        return NULL;
    }

#ifdef DEBUG_STRAY_PAGES
    pg->alloc1 = __builtin_return_address(0);
#endif  /* DEBUG_STRAY_PAGES */

    if ( (d != NULL) && assign_pages(d, pg, order, memflags) )
    {
        printk(XENLOG_ERR "%s: assign_pages vm%u failed from %S\n",
               __FUNCTION__, d->domain_id,
               (printk_symbol)__builtin_return_address(0));
        free_host_heap_page(d, pg);
        return NULL;
    }

    return pg;
}

void free_domheap_pages(struct page_info *pg, unsigned int order)
{
    int            i, drop_dom_ref;
    struct domain *d = page_get_owner(pg);
    unsigned long flags;

    ASSERT(!in_irq());

    if (unlikely(is_vframe_page(pg))) {
        drop_dom_ref = 0;
        if (d) {
            spin_lock_recursive(&d->page_alloc_lock);
            d->vframes--;
            if (unlikely(d->vframes == 0))
                drop_dom_ref = 1;
            spin_unlock_recursive(&d->page_alloc_lock);
        }
        free_vframe(pg);
    } else

    if (unlikely(is_host_page(pg))) {
        /* This doesn't actually free the page since the page is only
         * shared with the domain */
        ASSERT(d != NULL);

        ASSERT(order == 0);

        spin_lock_recursive(&d->page_alloc_lock);

        pg->count_info &= ~PGC_host_page;
        d->host_pages--;

        pg->domain = DOMID_0;

        d->tot_pages -= 1 << order;
        drop_dom_ref = (d->tot_pages == 0);

        spin_unlock_recursive(&d->page_alloc_lock);
    } else

    if ( unlikely(is_xen_page(pg)) )
    {
        /* This doesn't actually free the page since the page is only
         * shared with the domain */
        ASSERT(d != NULL);
#ifdef UXEN_ALLOC_DEBUG
        printk("%s: free xen domheap page mfn %lx from %S\n", __FUNCTION__,
               page_to_mfn(pg), (printk_symbol)__builtin_return_address(0));
#endif  /* UXEN_ALLOC_DEBUG */

        ASSERT(order == 0);
        /* NB. May recursively lock from relinquish_memory(). */
        spin_lock_recursive(&d->page_alloc_lock);

        for ( i = 0; i < (1 << order); i++ ) {
            spin_lock_irqsave(&host_page_list_lock, flags);
            page_list_add_tail(&pg[i], &host_page_list);
            spin_unlock_irqrestore(&host_page_list_lock, flags);
        }

        d->xenheap_pages -= 1 << order;
        drop_dom_ref = (d->xenheap_pages == 0);

        spin_unlock_recursive(&d->page_alloc_lock);
    }
    else if ( likely(d != NULL) && likely(d != dom_cow) )
    {
        ASSERT(order == 0);
        /* NB. May recursively lock from relinquish_memory(). */
        spin_lock_recursive(&d->page_alloc_lock);

#ifndef NDEBUG
        for ( i = 0; i < (1 << order); i++ )
        {

            if (pg[i].count_info & PGC_count_mask) {
                printk("%s: mfn %lx count %x\n", __FUNCTION__,
                       page_to_mfn(&pg[i]), pg[i].count_info);
                DEBUG();
            }
        }
#endif

        d->tot_pages -= 1 << order;
        drop_dom_ref = (d->tot_pages == 0);

        spin_unlock_recursive(&d->page_alloc_lock);

#ifdef __UXEN_todo__
        /*
         * Normally we expect a domain to clear pages before freeing them, if 
         * it cares about the secrecy of their contents. However, after a 
         * domain has died we assume responsibility for erasure.
         */
        if ( unlikely(d->is_dying) )
            for ( i = 0; i < (1 << order); i++ )
                scrub_one_page(&pg[i]);
#endif  /* __UXEN_todo__ */

        free_host_heap_page(d, pg);
    }
    else if ( unlikely(d == dom_cow) )
    {
DEBUG();
        ASSERT(order == 0); 
        scrub_one_page(pg);
        ASSERT(order == 0); 
        free_host_heap_page(NULL, pg);
        drop_dom_ref = 0;
    }
    else
    {
        /* Freeing anonymous domain-heap pages. */
        ASSERT(order == 0); 
        free_host_heap_page(NULL, pg);
        drop_dom_ref = 0;
    }

    if ( drop_dom_ref )
        put_domain(d);
}


void scrub_one_page(struct page_info *pg)
{
    void *p = __map_domain_page(pg);

#ifndef NDEBUG
    /* Avoid callers relying on allocations returning zeroed pages. */
    memset(p, 0xc2, PAGE_SIZE);
#else
    /* For a production build, clear_page() is the fastest way to scrub. */
    clear_page(p);
#endif

    unmap_domain_page(p);
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
