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
 * Copyright 2011-2016, Bromium, Inc.
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
#ifndef __UXEN__
#include <xen/tmem.h>
#include <xen/tmem_xen.h>
#endif  /* __UXEN__ */
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

#ifndef __UXEN__
/*
 * Comma-separated list of hexadecimal page numbers containing bad bytes.
 * e.g. 'badpage=0x3f45,0x8a321'.
 */
static char __initdata opt_badpage[100] = "";
string_param("badpage", opt_badpage);
#endif  /* __UXEN__ */

#if defined(__UXEN__) && defined(__i386__)
/*
 * no-bootscrub -> Free pages are not zeroed during boot.
 */
static bool_t opt_bootscrub __initdata = 1;
boolean_param("bootscrub", opt_bootscrub);
#endif  /* defined(__UXEN__) && defined(__i386__) */

#ifndef __UXEN__
/*
 * Bit width of the DMA heap -- used to override NUMA-node-first.
 * allocation strategy, which can otherwise exhaust low memory.
 */
static unsigned int dma_bitsize;
integer_param("dma_bits", dma_bitsize);
#endif  /* __UXEN__ */

#if defined(__UXEN__) && defined(__i386__)
#define round_pgdown(_p)  ((_p)&PAGE_MASK)
#define round_pgup(_p)    (((_p)+(PAGE_SIZE-1))&PAGE_MASK)
#endif  /* defined(__UXEN__) && defined(__i386__) */

#ifndef __UXEN__
/* Offlined page list, protected by heap_lock. */
PAGE_LIST_HEAD(page_offlined_list);
/* Broken page list, protected by heap_lock. */
PAGE_LIST_HEAD(page_broken_list);

/*************************
 * BOOT-TIME ALLOCATOR
 */

static unsigned long __initdata first_valid_mfn = ~0UL;

static struct bootmem_region {
    unsigned long s, e; /* MFNs @s through @e-1 inclusive are free */
} *__initdata bootmem_region_list;
static unsigned int __initdata nr_bootmem_regions;

static void __init boot_bug(int line)
{
    panic("Boot BUG at %s:%d\n", __FILE__, line);
}
#define BOOT_BUG_ON(p) if ( p ) boot_bug(__LINE__);

static void __init bootmem_region_add(unsigned long s, unsigned long e)
{
    unsigned int i;

    if ( (bootmem_region_list == NULL) && (s < e) )
        bootmem_region_list = mfn_to_virt(s++);

    if ( s >= e )
        return;

    for ( i = 0; i < nr_bootmem_regions; i++ )
        if ( s < bootmem_region_list[i].e )
            break;

    BOOT_BUG_ON((i < nr_bootmem_regions) && (e > bootmem_region_list[i].s));
    BOOT_BUG_ON(nr_bootmem_regions ==
                (PAGE_SIZE / sizeof(struct bootmem_region)));

    memmove(&bootmem_region_list[i+1], &bootmem_region_list[i],
            (nr_bootmem_regions - i) * sizeof(*bootmem_region_list));
    bootmem_region_list[i] = (struct bootmem_region) { s, e };
    nr_bootmem_regions++;
}

static void __init bootmem_region_zap(unsigned long s, unsigned long e)
{
    unsigned int i;

    for ( i = 0; i < nr_bootmem_regions; i++ )
    {
        struct bootmem_region *r = &bootmem_region_list[i];
        if ( e <= r->s )
            break;
        if ( s >= r->e )
            continue;
        if ( s <= r->s )
        {
            r->s = min(e, r->e);
        }
        else if ( e >= r->e )
        {
            r->e = s;
        }
        else
        {
            unsigned long _e = r->e;
            r->e = s;
            bootmem_region_add(e, _e);
        }
    }
}

void __init init_boot_pages(paddr_t ps, paddr_t pe)
{
    unsigned long bad_spfn, bad_epfn;
    const char *p;

    ps = round_pgup(ps);
    pe = round_pgdown(pe);
    if ( pe <= ps )
        return;

    first_valid_mfn = min_t(unsigned long, ps >> PAGE_SHIFT, first_valid_mfn);

    bootmem_region_add(ps >> PAGE_SHIFT, pe >> PAGE_SHIFT);

    /* Check new pages against the bad-page list. */
    p = opt_badpage;
    while ( *p != '\0' )
    {
        bad_spfn = simple_strtoul(p, &p, 0);
        bad_epfn = bad_spfn;

        if ( *p == '-' )
        {
            p++;
            bad_epfn = simple_strtoul(p, &p, 0);
            if ( bad_epfn < bad_spfn )
                bad_epfn = bad_spfn;
        }

        if ( *p == ',' )
            p++;
        else if ( *p != '\0' )
            break;

        if ( bad_epfn == bad_spfn )
            printk("Marking page %lx as bad\n", bad_spfn);
        else
            printk("Marking pages %lx through %lx as bad\n",
                   bad_spfn, bad_epfn);

        bootmem_region_zap(bad_spfn, bad_epfn+1);
    }
}

unsigned long __init alloc_boot_pages(
    unsigned long nr_pfns, unsigned long pfn_align)
{
    unsigned long pg, _e;
    int i;

    for ( i = nr_bootmem_regions - 1; i >= 0; i-- )
    {
        struct bootmem_region *r = &bootmem_region_list[i];
        pg = (r->e - nr_pfns) & ~(pfn_align - 1);
        if ( pg < r->s )
            continue;
        _e = r->e;
        r->e = pg;
        bootmem_region_add(pg + nr_pfns, _e);
        return pg;
    }

    BOOT_BUG_ON(1);
    return 0;
}
#endif  /* __UXEN__ */



#if defined(__UXEN__) && defined(__i386__)
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

    page_set_owner(pg, NULL);
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

        page_set_owner(pg, NULL);

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

        page_set_owner(pg, NULL);

        atomic_inc(&hidden_pages_allocated);
        ASSERT(atomic_read(&hidden_pages_allocated) <=
               atomic_read(&hidden_pages_available));

#ifdef UXEN_ALLOC_HIDDEN_DEBUG
        printk("alloc hidden page: %lx pg %p\n", page_to_mfn(pg), pg);
#endif  /* UXEN_ALLOC_HIDDEN_DEBUG */
    }

    return pg;
}
#endif  /* defined(__UXEN__) && defined(__i386__) */

#ifndef __UXEN__
/*************************
 * BINARY BUDDY ALLOCATOR
 */

#define NR_ZONES    (PADDR_BITS - 32)

// #define bits_to_zone(b) ((b) - 32)
#define page_to_zone(pg) (fls(page_to_mfn(pg)) - 1 - (32 - PAGE_SHIFT))

typedef struct page_list_head heap_by_zone_and_order_t[NR_ZONES][MAX_ORDER+1];
static heap_by_zone_and_order_t *_heap[MAX_NUMNODES];
#define heap(node, zone, order) ((*_heap[node])[zone][order])

#define is_heap_page(pg) (page_to_mfn(pg) >= 0x100000)

static unsigned long *avail[MAX_NUMNODES];
static long total_avail_pages;

#ifndef __UXEN__
/* TMEM: Reserve a fraction of memory for mid-size (0<order<9) allocations.*/
static long midsize_alloc_zone_pages;
#define MIDSIZE_ALLOC_FRAC 128
#endif  /* __UXEN__ */

static DEFINE_SPINLOCK(heap_lock);

static unsigned long init_node_heap(int node, unsigned long mfn,
                                    unsigned long nr, bool_t *use_tail)
{
    /* First node to be discovered has its heap metadata statically alloced. */
    static heap_by_zone_and_order_t _heap_static;
    static unsigned long avail_static[NR_ZONES];
    static int first_node_initialised;
    unsigned long needed = (sizeof(**_heap) +
                            sizeof(**avail) * NR_ZONES +
                            PAGE_SIZE - 1) >> PAGE_SHIFT;
    int i, j;

    if ( !first_node_initialised )
    {
        _heap[node] = &_heap_static;
        avail[node] = avail_static;
        first_node_initialised = 1;
        needed = 0;
    }
#ifdef DIRECTMAP_VIRT_END
    else if ( *use_tail && nr >= needed &&
              (mfn + nr) <= (virt_to_mfn(DIRECTMAP_VIRT_END - 1) + 1) )
    {
        _heap[node] = mfn_to_virt(mfn + nr - needed);
        avail[node] = mfn_to_virt(mfn + nr - 1) +
                      PAGE_SIZE - sizeof(**avail) * NR_ZONES;
    }
    else if ( nr >= needed &&
              (mfn + needed) <= (virt_to_mfn(DIRECTMAP_VIRT_END - 1) + 1) )
    {
        _heap[node] = mfn_to_virt(mfn);
        avail[node] = mfn_to_virt(mfn + needed - 1) +
                      PAGE_SIZE - sizeof(**avail) * NR_ZONES;
        *use_tail = 0;
    }
#endif
    else if ( get_order_from_bytes(sizeof(**_heap)) ==
              get_order_from_pages(needed) )
    {
        _heap[node] = alloc_xenheap_pages(get_order_from_pages(needed), 0);
        BUG_ON(!_heap[node]);
        avail[node] = (void *)_heap[node] + (needed << PAGE_SHIFT) -
                      sizeof(**avail) * NR_ZONES;
        needed = 0;
    }
    else
    {
        _heap[node] = xmalloc(heap_by_zone_and_order_t);
        avail[node] = xmalloc_array(unsigned long, NR_ZONES);
        BUG_ON(!_heap[node] || !avail[node]);
        needed = 0;
    }

    memset(avail[node], 0, NR_ZONES * sizeof(long));

    for ( i = 0; i < NR_ZONES; i++ )
        for ( j = 0; j <= MAX_ORDER; j++ )
            INIT_PAGE_LIST_HEAD(&(*_heap[node])[i][j]);

    return needed;
}

/* Allocate 2^@order contiguous pages. */
static struct page_info *alloc_heap_pages(
    unsigned int zone_lo, unsigned int zone_hi,
    unsigned int order, unsigned int memflags,
    struct domain *d)
{
    unsigned int first_node, i, j, zone = 0, nodemask_retry = 0;
#ifndef __UXEN__
    unsigned int node = (uint8_t)((memflags >> _MEMF_node) - 1);
#else  /* __UXEN__ */
    unsigned int node = 0;
#endif  /* __UXEN__ */
    unsigned long request = 1UL << order;
#ifndef __UXEN__
    cpumask_t mask;
#endif  /* __UXEN__ */
    struct page_info *pg;
#ifndef __UXEN__
    nodemask_t nodemask = (d != NULL ) ? d->node_affinity : node_online_map;
#else  /* __UXEN__ */
    nodemask_t nodemask = node_online_map;
#endif  /* __UXEN__ */

#ifndef __UXEN__
    if ( node == NUMA_NO_NODE )
    {
        memflags &= ~MEMF_exact_node;
        if ( d != NULL )
        {
            node = next_node(d->last_alloc_node, nodemask);
            if ( node >= MAX_NUMNODES )
                node = first_node(nodemask);
        }
        if ( node >= MAX_NUMNODES )
            node = cpu_to_node(smp_processor_id());
    }
#endif  /* __UXEN__ */
    first_node = node;

    ASSERT(node >= 0);
    ASSERT(zone_lo <= zone_hi);
    ASSERT(zone_hi < NR_ZONES);

    if ( unlikely(order > MAX_ORDER) )
        return NULL;

    spin_lock(&heap_lock);

#ifndef __UXEN__
    /*
     * TMEM: When available memory is scarce due to tmem absorbing it, allow
     * only mid-size allocations to avoid worst of fragmentation issues.
     * Others try tmem pools then fail.  This is a workaround until all
     * post-dom0-creation-multi-page allocations can be eliminated.
     */
    if ( opt_tmem && ((order == 0) || (order >= 9)) &&
         (total_avail_pages <= midsize_alloc_zone_pages) &&
         tmem_freeable_pages() )
        goto try_tmem;
#endif  /* __UXEN__ */

    /*
     * Start with requested node, but exhaust all node memory in requested 
     * zone before failing, only calc new node value if we fail to find memory 
     * in target node, this avoids needless computation on fast-path.
     */
    for ( ; ; )
    {
        zone = zone_hi;
        do {
            /* Check if target node can support the allocation. */
            if ( !avail[node] || (avail[node][zone] < request) )
                continue;

            /* Find smallest order which can satisfy the request. */
            for ( j = order; j <= MAX_ORDER; j++ )
                if ( (pg = page_list_remove_head(&heap(node, zone, j))) )
                    goto found;
        } while ( zone-- > zone_lo ); /* careful: unsigned zone may wrap */

#ifndef __UXEN__
        if ( memflags & MEMF_exact_node )
            goto not_found;
#endif  /* __UXEN__ */

        /* Pick next node. */
        if ( !node_isset(node, nodemask) )
        {
            /* Very first node may be caller-specified and outside nodemask. */
            ASSERT(!nodemask_retry);
            first_node = node = first_node(nodemask);
            if ( node < MAX_NUMNODES )
                continue;
        }
        else if ( (node = next_node(node, nodemask)) >= MAX_NUMNODES )
            node = first_node(nodemask);
        if ( node == first_node )
        {
            /* When we have tried all in nodemask, we fall back to others. */
            if ( nodemask_retry++ )
                goto not_found;
            nodes_andnot(nodemask, node_online_map, nodemask);
            first_node = node = first_node(nodemask);
            if ( node >= MAX_NUMNODES )
                goto not_found;
        }
    }

#ifndef __UXEN__
 try_tmem:
    /* Try to free memory from tmem */
    if ( (pg = tmem_relinquish_pages(order, memflags)) != NULL )
    {
        /* reassigning an already allocated anonymous heap page */
        spin_unlock(&heap_lock);
        return pg;
    }
#endif  /* __UXEN__ */

 not_found:
    /* No suitable memory blocks. Fail the request. */
    spin_unlock(&heap_lock);
    return NULL;

 found: 
    /* We may have to halve the chunk a number of times. */
    while ( j != order )
    {
        PFN_ORDER(pg) = --j;
        page_list_add_tail(pg, &heap(node, zone, j));
        pg += 1 << j;
    }

    ASSERT(avail[node][zone] >= request);
    avail[node][zone] -= request;
    total_avail_pages -= request;
    ASSERT(total_avail_pages >= 0);
    atomic_add(request, &hidden_pages_allocated);

#ifndef __UXEN__
    if ( d != NULL )
        d->last_alloc_node = node;
#endif  /* __UXEN__ */

#ifndef __UXEN__
    cpumask_clear(&mask);
#endif  /* __UXEN__ */

    for ( i = 0; i < (1 << order); i++ )
    {
#ifndef __UXEN__
        if (pg[i].count_info & PGC_count_mask)
        {
            /* Add in extra CPUs that need flushing because of this page. */
            static cpumask_t extra_cpus_mask;

            cpumask_andnot(&extra_cpus_mask, &cpu_online_map, &mask);
            tlbflush_filter(extra_cpus_mask, pg[i].count_info & PGC_count_mask);
            cpumask_or(&mask, &mask, &extra_cpus_mask);
            pg[i].count_info &= ~PGC_count_mask;
        }
#endif  /* __UXEN__ */

        /* Reference count must continuously be zero for free pages. */
        BUG_ON(pg[i].count_info != PGC_state_free);
        pg[i].count_info = PGC_state_inuse;

        /* Initialise fields which have other uses for free pages. */
#ifndef __UXEN__
        pg[i].u.inuse.type_info = 0;
#endif  /* __UXEN__ */
        page_set_owner(&pg[i], NULL);
    }

    spin_unlock(&heap_lock);

#ifndef __UXEN__
    if ( unlikely(!cpumask_empty(&mask)) )
    {
        perfc_incr(need_flush_tlb_flush);
        flush_tlb_mask(&mask);
    }
#endif  /* __UXEN__ */

#ifdef UXEN_ALLOC_HEAP_DEBUG
    printk("alloc heap page: %lx pg %p\n", page_to_mfn(pg), pg);
#endif  /* UXEN_ALLOC_HEAP_DEBUG */

    return pg;
}
#endif  /* __UXEN__ */

#ifndef __UXEN__
/* Remove any offlined page in the buddy pointed to by head. */
static int reserve_offlined_page(struct page_info *head)
{
    unsigned int node = phys_to_nid(page_to_maddr(head));
    int zone = page_to_zone(head), i, head_order = PFN_ORDER(head), count = 0;
    struct page_info *cur_head;
    int cur_order;

    ASSERT(spin_is_locked(&heap_lock));

    cur_head = head;

    page_list_del(head, &heap(node, zone, head_order));

    while ( cur_head < (head + (1 << head_order)) )
    {
        struct page_info *pg;
        int next_order;

        if ( page_state_is(cur_head, offlined) )
        {
            cur_head++;
            continue;
        }

        next_order = cur_order = 0;

        while ( cur_order < head_order )
        {
            next_order = cur_order + 1;

            if ( (cur_head + (1 << next_order)) >= (head + ( 1 << head_order)) )
                goto merge;

            for ( i = (1 << cur_order), pg = cur_head + (1 << cur_order );
                  i < (1 << next_order);
                  i++, pg++ )
                if ( page_state_is(pg, offlined) )
                    break;
            if ( i == ( 1 << next_order) )
            {
                cur_order = next_order;
                continue;
            }
            else
            {
            merge:
                /* We don't consider merging outside the head_order. */
                page_list_add_tail(cur_head, &heap(node, zone, cur_order));
                PFN_ORDER(cur_head) = cur_order;
                cur_head += (1 << cur_order);
                break;
            }
        }
    }

    for ( cur_head = head; cur_head < head + ( 1UL << head_order); cur_head++ )
    {
        if ( !page_state_is(cur_head, offlined) )
            continue;

        avail[node][zone]--;
        total_avail_pages--;
        ASSERT(total_avail_pages >= 0);
        atomic_inc(&hidden_pages_allocated);

        page_list_add_tail(cur_head,
                           test_bit(_PGC_broken, &cur_head->count_info) ?
                           &page_broken_list : &page_offlined_list);

        count++;
    }

    return count;
}
#endif  /* __UXEN__ */

#ifndef __UXEN__
/* Free 2^@order set of pages. */
static void free_heap_pages(
    struct page_info *pg, unsigned int order)
{
    unsigned long mask;
#ifndef __UXEN__
    unsigned long mfn = page_to_mfn(pg);
#endif  /* __UXEN__ */
    unsigned int i, node = phys_to_nid(page_to_maddr(pg));
#ifndef __UXEN__
    unsigned int tainted = 0;
#endif  /* __UXEN__ */
    unsigned int zone = page_to_zone(pg);

    ASSERT(order <= MAX_ORDER);
    ASSERT(node >= 0);

    spin_lock(&heap_lock);

    for ( i = 0; i < (1 << order); i++ )
    {
#ifndef __UXEN__
        struct domain *d = page_get_owner(&pg[i]);
#endif  /* __UXEN__ */

        /* This page is not a guest frame any more. */
        page_set_owner(&pg[i], NULL); /* set_gpfn_from_mfn snoops pg owner */
#ifndef __UXEN__
        set_gpfn_from_mfn(mfn + i, INVALID_M2P_ENTRY);
#endif  /* __UXEN__ */

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
#ifndef __UXEN__
        ASSERT(!page_state_is(&pg[i], offlined));
        pg[i].count_info =
            ((pg[i].count_info & PGC_broken) |
             (page_state_is(&pg[i], offlining)
              ? PGC_state_offlined : PGC_state_free));
        if ( page_state_is(&pg[i], offlined) )
            tainted = 1;

        /* If a page has no owner it will need no safety TLB flush. */
        if (d)
            pg[i].count_info |= tlbflush_current_time();
#else  /* __UXEN__ */
        pg[i].count_info = PGC_state_free;
#endif  /* __UXEN__ */
    }

    avail[node][zone] += 1 << order;
    total_avail_pages += 1 << order;
    atomic_sub(1 << order, &hidden_pages_allocated);
    ASSERT(atomic_read(&hidden_pages_allocated) >= 0);

#ifndef __UXEN__
    if ( opt_tmem )
        midsize_alloc_zone_pages = max(
            midsize_alloc_zone_pages, total_avail_pages / MIDSIZE_ALLOC_FRAC);
#endif  /* __UXEN__ */

    /* Merge chunks as far as possible. */
    while ( order < MAX_ORDER )
    {
        mask = 1UL << order;

        if ( (page_to_mfn(pg) & mask) )
        {
            /* Merge with predecessor block? */
            if ( !mfn_valid(page_to_mfn(pg-mask)) ||
                 !page_state_is(pg-mask, free) ||
                 (PFN_ORDER(pg-mask) != order) ||
                 (phys_to_nid(page_to_maddr(pg-mask)) != node) )
                break;
            pg -= mask;
            page_list_del(pg, &heap(node, zone, order));
        }
        else
        {
            /* Merge with successor block? */
            if ( !mfn_valid(page_to_mfn(pg+mask)) ||
                 !page_state_is(pg+mask, free) ||
                 (PFN_ORDER(pg+mask) != order) ||
                 (phys_to_nid(page_to_maddr(pg+mask)) != node) )
                break;
            page_list_del(pg + mask, &heap(node, zone, order));
        }

        order++;
    }

    PFN_ORDER(pg) = order;
    page_list_add_tail(pg, &heap(node, zone, order));

#ifndef __UXEN__
    if ( tainted )
        reserve_offlined_page(pg);
#endif  /* __UXEN__ */

    spin_unlock(&heap_lock);
}
#endif  /* __UXEN__ */


#ifndef __UXEN__
/*
 * Following rules applied for page offline:
 * Once a page is broken, it can't be assigned anymore
 * A page will be offlined only if it is free
 * return original count_info
 */
static unsigned long mark_page_offline(struct page_info *pg, int broken)
{
    unsigned long nx, x, y = pg->count_info;

    ASSERT(page_is_ram_type(page_to_mfn(pg), RAM_TYPE_CONVENTIONAL));
    ASSERT(spin_is_locked(&heap_lock));

    do {
        nx = x = y;

        if ( ((x & PGC_state) != PGC_state_offlined) &&
             ((x & PGC_state) != PGC_state_offlining) )
        {
            nx &= ~PGC_state;
            nx |= (((x & PGC_state) == PGC_state_free)
                   ? PGC_state_offlined : PGC_state_offlining);
        }

        if ( broken )
            nx |= PGC_broken;

        if ( x == nx )
            break;
    } while ( (y = cmpxchg(&pg->count_info, x, nx)) != x );

    return y;
}

static int reserve_heap_page(struct page_info *pg)
{
    struct page_info *head = NULL;
    unsigned int i, node = phys_to_nid(page_to_maddr(pg));
    unsigned int zone = page_to_zone(pg);

    for ( i = 0; i <= MAX_ORDER; i++ )
    {
        struct page_info *tmp;

        if ( page_list_empty(&heap(node, zone, i)) )
            continue;

        page_list_for_each_safe ( head, tmp, &heap(node, zone, i) )
        {
            if ( (head <= pg) &&
                 (head + (1UL << i) > pg) )
                return reserve_offlined_page(head);
        }
    }

    return -EINVAL;

}

int offline_page(unsigned long mfn, int broken, uint32_t *status)
{
    unsigned long old_info = 0;
    struct domain *owner;
    int ret = 0;
    struct page_info *pg;

    if ( !mfn_valid(mfn) )
    {
        dprintk(XENLOG_WARNING,
                "try to offline page out of range %lx\n", mfn);
        return -EINVAL;
    }

    *status = 0;
    pg = mfn_to_page(mfn);

    if ( is_xen_fixed_mfn(mfn) )
    {
        *status = PG_OFFLINE_XENPAGE | PG_OFFLINE_FAILED |
          (DOMID_XEN << PG_OFFLINE_OWNER_SHIFT);
        return -EPERM;
    }

    /*
     * N.B. xen's txt in x86_64 is marked reserved and handled already.
     * Also kexec range is reserved.
     */
    if ( !page_is_ram_type(mfn, RAM_TYPE_CONVENTIONAL) )
    {
        *status = PG_OFFLINE_FAILED | PG_OFFLINE_NOT_CONV_RAM;
        return -EINVAL;
    }

    /*
     * NB. When broken page belong to guest, usually hypervisor will
     * notify the guest to handle the broken page. However, hypervisor
     * need to prevent malicious guest access the broken page again.
     * Under such case, hypervisor shutdown guest, preventing recursive mce.
     */
    if ( (pg->count_info & PGC_broken) && (owner = page_get_owner(pg)) )
    {
        *status = PG_OFFLINE_AGAIN;
        domain_shutdown(owner, SHUTDOWN_crash);
        return 0;
    }

    spin_lock(&heap_lock);

    old_info = mark_page_offline(pg, broken);

    if ( page_state_is(pg, offlined) )
    {
        reserve_heap_page(pg);
        *status = PG_OFFLINE_OFFLINED;
    }
    else if ( (owner = page_get_owner_and_reference(pg)) )
    {
        if ( p2m_pod_offline_or_broken_hit(pg) )
            goto pod_replace;
        else
        {
            *status = PG_OFFLINE_OWNED | PG_OFFLINE_PENDING |
              (owner->domain_id << PG_OFFLINE_OWNER_SHIFT);
            /* Release the reference since it will not be allocated anymore */
            put_page(pg);
        }
    }
    else if ( old_info & PGC_xen_heap )
    {
        *status = PG_OFFLINE_XENPAGE | PG_OFFLINE_PENDING |
          (DOMID_XEN << PG_OFFLINE_OWNER_SHIFT);
    }
    else
    {
        /*
         * assign_pages does not hold heap_lock, so small window that the owner
         * may be set later, but please notice owner will only change from
         * NULL to be set, not verse, since page is offlining now.
         * No windows If called from #MC handler, since all CPU are in softirq
         * If called from user space like CE handling, tools can wait some time
         * before call again.
         */
        *status = PG_OFFLINE_ANONYMOUS | PG_OFFLINE_FAILED |
                  (DOMID_INVALID << PG_OFFLINE_OWNER_SHIFT );
    }

    if ( broken )
        *status |= PG_OFFLINE_BROKEN;

    spin_unlock(&heap_lock);

    return ret;

pod_replace:
    put_page(pg);
    spin_unlock(&heap_lock);

    p2m_pod_offline_or_broken_replace(pg);
    *status = PG_OFFLINE_OFFLINED;

    if ( broken )
        *status |= PG_OFFLINE_BROKEN;

    return ret;
}

/*
 * Online the memory.
 *   The caller should make sure end_pfn <= max_page,
 *   if not, expand_pages() should be called prior to online_page().
 */
unsigned int online_page(unsigned long mfn, uint32_t *status)
{
    unsigned long x, nx, y;
    struct page_info *pg;
    int ret;

    if ( !mfn_valid(mfn) )
    {
        dprintk(XENLOG_WARNING, "call expand_pages() first\n");
        return -EINVAL;
    }

    pg = mfn_to_page(mfn);

    spin_lock(&heap_lock);

    y = pg->count_info;
    do {
        ret = *status = 0;

        if ( y & PGC_broken )
        {
            ret = -EINVAL;
            *status = PG_ONLINE_FAILED |PG_ONLINE_BROKEN;
            break;
        }

        if ( (y & PGC_state) == PGC_state_offlined )
        {
            page_list_del(pg, &page_offlined_list);
            *status = PG_ONLINE_ONLINED;
        }
        else if ( (y & PGC_state) == PGC_state_offlining )
        {
            *status = PG_ONLINE_ONLINED;
        }
        else
        {
            break;
        }

        x = y;
        nx = (x & ~PGC_state) | PGC_state_inuse;
    } while ( (y = cmpxchg(&pg->count_info, x, nx)) != x );

    spin_unlock(&heap_lock);

    if ( (y & PGC_state) == PGC_state_offlined )
        free_heap_pages(pg, 0);

    return ret;
}

int query_page_offline(unsigned long mfn, uint32_t *status)
{
    struct page_info *pg;

    if ( !mfn_valid(mfn) || !page_is_ram_type(mfn, RAM_TYPE_CONVENTIONAL) )
    {
        dprintk(XENLOG_WARNING, "call expand_pages() first\n");
        return -EINVAL;
    }

    *status = 0;
    spin_lock(&heap_lock);

    pg = mfn_to_page(mfn);

    if ( page_state_is(pg, offlining) )
        *status |= PG_OFFLINE_STATUS_OFFLINE_PENDING;
    if ( pg->count_info & PGC_broken )
        *status |= PG_OFFLINE_STATUS_BROKEN;
    if ( page_state_is(pg, offlined) )
        *status |= PG_OFFLINE_STATUS_OFFLINED;

    spin_unlock(&heap_lock);

    return 0;
}
#endif  /* __UXEN__ */

#ifndef __UXEN__
/*
 * Hand the specified arbitrary page range to the specified heap zone
 * checking the node_id of the previous page.  If they differ and the
 * latter is not on a MAX_ORDER boundary, then we reserve the page by
 * not freeing it to the buddy allocator.
 */
static void init_heap_pages(
    struct page_info *pg, unsigned long nr_pages)
{
    unsigned long i;

    atomic_add(nr_pages, &hidden_pages_available);
    atomic_add(nr_pages, &hidden_pages_allocated);
    for ( i = 0; i < nr_pages; i++ )
    {
        unsigned int nid = phys_to_nid(page_to_maddr(pg+i));

        if ( unlikely(!avail[nid]) )
        {
            unsigned long s = page_to_mfn(pg + i);
            unsigned long e = page_to_mfn(pg + nr_pages - 1) + 1;
            bool_t use_tail = (nid == phys_to_nid(pfn_to_paddr(e - 1))) &&
                              !(s & ((1UL << MAX_ORDER) - 1)) &&
                              (find_first_set_bit(e) <= find_first_set_bit(s));
            unsigned long n;

            n = init_node_heap(nid, page_to_mfn(pg+i), nr_pages - i,
                               &use_tail);
            BUG_ON(i + n > nr_pages);
            if ( n && !use_tail )
            {
                i += n - 1;
                continue;
            }
            if ( i + n == nr_pages )
                break;
            nr_pages -= n;
        }

        free_heap_pages(pg+i, 0);
    }
}

static unsigned long avail_heap_pages(
    unsigned int zone_lo, unsigned int zone_hi, unsigned int node)
{
    unsigned int i, zone;
    unsigned long free_pages = 0;

    if ( zone_hi >= NR_ZONES )
        zone_hi = NR_ZONES - 1;

    for_each_online_node(i)
    {
        if ( !avail[i] )
            continue;
        for ( zone = zone_lo; zone <= zone_hi; zone++ )
            if ( (node == -1) || (node == i) )
                free_pages += avail[i][zone];
    }

    return free_pages;
}

unsigned long total_free_pages(void)
{
    return total_avail_pages
#ifndef __UXEN__
        - midsize_alloc_zone_pages
#endif  /* __UXEN__ */
        ;
}
#endif  /* __UXEN__ */

#ifndef __UXEN__
void __init end_boot_allocator(void)
{
    unsigned int i;

    /* Pages that are free now go to the domain sub-allocator. */
    for ( i = 0; i < nr_bootmem_regions; i++ )
    {
        struct bootmem_region *r = &bootmem_region_list[i];
        if ( (r->s < r->e) &&
             (phys_to_nid(pfn_to_paddr(r->s)) == cpu_to_node(0)) )
        {
            init_heap_pages(mfn_to_page(r->s), r->e - r->s);
            r->e = r->s;
            break;
        }
    }
    for ( i = nr_bootmem_regions; i-- > 0; )
    {
        struct bootmem_region *r = &bootmem_region_list[i];
        if ( r->s < r->e )
            init_heap_pages(mfn_to_page(r->s), r->e - r->s);
    }
    init_heap_pages(virt_to_page(bootmem_region_list), 1);

    if ( !dma_bitsize && (num_online_nodes() > 1) )
    {
#ifdef CONFIG_X86
        dma_bitsize = min_t(unsigned int,
                            fls(NODE_DATA(0)->node_spanned_pages) - 1
                            + PAGE_SHIFT - 2,
                            32);
#else
        dma_bitsize = 32;
#endif
    }

    printk("Domain heap initialised");
    if ( dma_bitsize )
        printk(" DMA width %u bits", dma_bitsize);
    printk("\n");
}
#endif  /* __UXEN__ */

#ifndef __UXEN__
#ifdef __UXEN__
/* Scrub pages above 4GB */
#define first_valid_mfn 0x100000ULL
#endif  /* __UXEN__ */

/*
 * Scrub all unallocated pages in all heap zones. This function is more
 * convoluted than appears necessary because we do not want to continuously
 * hold the lock while scrubbing very large memory areas.
 */
void __init scrub_heap_pages(void)
{
    unsigned long mfn;
    struct page_info *pg;

    if ( !opt_bootscrub )
        return;

    printk("Scrubbing Free RAM: ");

    for ( mfn = first_valid_mfn; mfn < max_page; mfn++ )
    {
#ifndef __UXEN__
        process_pending_softirqs();
#endif  /* __UXEN__ */

        pg = mfn_to_page(mfn);

        /* Quick lock-free check. */
        if ( !mfn_valid(mfn) || !page_state_is(pg, free) )
            continue;

        /* Every 100MB, print a progress dot. */
        if ( (mfn % ((100*1024*1024)/PAGE_SIZE)) == 0 )
            printk(".");

        spin_lock(&heap_lock);

        /* Re-check page status with lock held. */
        if ( page_state_is(pg, free) )
            scrub_one_page(pg);

        spin_unlock(&heap_lock);
    }

    printk("done.\n");
}
#endif  /* __UXEN__ */



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
        printk("%s: no pages on cpu %d from %S\n", __FUNCTION__, cpu,
               (printk_symbol)__builtin_return_address(0));
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
    page_set_owner(pg, NULL);

    if (is_xen_page) {
        unsigned long flags;

        pg->count_info |= PGC_xen_page;
        spin_lock_irqsave(&host_page_list_lock, flags);
        page_list_add_tail(pg, &host_page_list);
        spin_unlock_irqrestore(&host_page_list_lock, flags);
    }

    return pg;
}

static void
free_host_page(struct page_info *pg)
{
    int cpu = smp_processor_id();

    /* This page is not a guest frame any more. */
    page_set_owner(pg, NULL); /* set_gpfn_from_mfn snoops pg owner */
#ifndef __UXEN__
    set_gpfn_from_mfn(page_to_mfn(pg), INVALID_M2P_ENTRY);
#endif  /* __UXEN__ */

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
#ifndef __UXEN__
    ASSERT(!page_state_is(pg, offlined));
    pg->count_info =
        ((pg->count_info & PGC_broken) |
         (page_state_is(pg, offlining)
          ? PGC_state_offlined : PGC_state_free));
    /* if ( page_state_is(pg, offlined) ) */
    /*     tainted = 1; */
#else  /* __UXEN__ */
    pg->count_info = PGC_state_host;
#endif  /* __UXEN__ */
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
 * XEN-HEAP SUB-ALLOCATOR
 */

#ifndef __UXEN__

#if !defined(__x86_64__) && !defined(__ia64__)

void init_xenheap_pages(paddr_t ps, paddr_t pe)
{
    ps = round_pgup(ps);
    pe = round_pgdown(pe);
    if ( pe <= ps )
        return;

    /*
     * Yuk! Ensure there is a one-page buffer between Xen and Dom zones, to
     * prevent merging of power-of-two blocks across the zone boundary.
     */
    if ( ps && !is_xen_heap_mfn(paddr_to_pfn(ps)-1) )
        ps += PAGE_SIZE;
    if ( !is_xen_heap_mfn(paddr_to_pfn(pe)) )
        pe -= PAGE_SIZE;

    memguard_guard_range(maddr_to_virt(ps), pe - ps);

    init_heap_pages(maddr_to_page(ps), (pe - ps) >> PAGE_SHIFT);
}


void *alloc_xenheap_pages(unsigned int order, unsigned int memflags)
{
    struct page_info *pg;

    ASSERT(!in_irq());

    pg = alloc_heap_pages(MEMZONE_XEN, MEMZONE_XEN,
                          order, memflags, NULL);
    if ( unlikely(pg == NULL) )
        return NULL;

    memguard_unguard_range(page_to_virt(pg), 1 << (order + PAGE_SHIFT));

    return page_to_virt(pg);
}


void free_xenheap_pages(void *v, unsigned int order)
{
    ASSERT(!in_irq());

    if ( v == NULL )
        return;

    memguard_guard_range(v, 1 << (order + PAGE_SHIFT));

    free_heap_pages(virt_to_page(v), order);
}

#else

void init_xenheap_pages(paddr_t ps, paddr_t pe)
{
    init_domheap_pages(ps, pe);
}

void *alloc_xenheap_pages(unsigned int order, unsigned int memflags)
{
    struct page_info *pg;
    unsigned int i;

    ASSERT(!in_irq());

    pg = alloc_domheap_pages(NULL, order, memflags);
    if ( unlikely(pg == NULL) )
        return NULL;

    for ( i = 0; i < (1u << order); i++ )
        pg[i].count_info |= PGC_xen_heap;

    return page_to_virt(pg);
}

void free_xenheap_pages(void *v, unsigned int order)
{
    struct page_info *pg;
    unsigned int i;

    ASSERT(!in_irq());

    if ( v == NULL )
        return;

    pg = virt_to_page(v);

    for ( i = 0; i < (1u << order); i++ ) {
        ASSERT(pg[i].count_info & PGC_xen_heap);
        pg[i].count_info &= ~PGC_xen_heap;
    }

    free_heap_pages(pg, order);
}

#endif

#else  /* __UXEN__ */

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
        pg->domain = 0;
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
        pg->domain = 0;
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
        pg->domain = 0;
        free_host_page(pg);
        spin_lock_irqsave(&host_page_list_lock, flags);
    }
    spin_unlock_irqrestore(&host_page_list_lock, flags);
}

#endif  /* __UXEN__ */



/*************************
 * DOMAIN-HEAP SUB-ALLOCATOR
 */

#ifndef __UXEN__
void init_domheap_pages(paddr_t ps, paddr_t pe)
{
    unsigned long smfn, emfn;

    ASSERT(!in_irq());

    smfn = round_pgup(ps) >> PAGE_SHIFT;
    emfn = round_pgdown(pe) >> PAGE_SHIFT;

    init_heap_pages(mfn_to_page(smfn), emfn - smfn);
}
#endif  /* __UXEN__ */


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
#ifndef __UXEN__
            if ( !opt_tmem || order != 0 || d->tot_pages != d->max_pages )
#endif  /* __UXEN__ */
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
#ifndef __UXEN__
    struct page_info *pg = NULL;
    unsigned int bits = memflags >> _MEMF_bits, zone_hi = NR_ZONES - 1;
    unsigned int dma_zone;

    ASSERT(!in_irq());

    bits = domain_clamp_alloc_bitsize(d, bits ? : (BITS_PER_LONG+PAGE_SHIFT));
    if ( (zone_hi = min_t(unsigned int, bits_to_zone(bits), zone_hi)) == 0 )
        return NULL;

    if ( dma_bitsize && ((dma_zone = bits_to_zone(dma_bitsize)) < zone_hi) )
        pg = alloc_heap_pages(dma_zone + 1, zone_hi, order, memflags, d);

    if ( (pg == NULL) &&
         ((memflags & MEMF_no_dma) ||
          ((pg = alloc_heap_pages(MEMZONE_XEN + 1, zone_hi, order,
                                  memflags, d)) == NULL)) )
         return NULL;

    if ( (d != NULL) && assign_pages(d, pg, order, memflags) )
    {
        free_heap_pages(pg, order);
        return NULL;
    }
    
    return pg;
#else   /* __UXEN__ */
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
    if (!pg)
        return NULL;

    if ( (d != NULL) && assign_pages(d, pg, order, memflags) )
    {
        free_host_heap_page(d, pg);
        return NULL;
    }

    return pg;
#endif  /* __UXEN__ */
}

void free_domheap_pages(struct page_info *pg, unsigned int order)
{
    int            i, drop_dom_ref;
    struct domain *d = page_get_owner(pg);
    unsigned long flags;

    ASSERT(!in_irq());

#ifndef __UXEN__
    if ( unlikely(is_xen_heap_page(pg)) )
    {
        /* NB. May recursively lock from relinquish_memory(). */
        spin_lock_recursive(&d->page_alloc_lock);

        for ( i = 0; i < (1 << order); i++ )
            page_list_del2(&pg[i], &d->xenpage_list, &d->arch.relmem_list);

        d->xenheap_pages -= 1 << order;
        drop_dom_ref = (d->xenheap_pages == 0);

        spin_unlock_recursive(&d->page_alloc_lock);
    }
#else  /* __UXEN__ */
    if (unlikely(is_host_page(pg))) {
        /* This doesn't actually free the page since the page is only
         * shared with the domain */
        ASSERT(d != NULL);

        ASSERT(order == 0);

        spin_lock_recursive(&d->page_alloc_lock);

        pg->count_info &= ~PGC_host_page;
        d->host_pages--;

        page_set_owner(pg, NULL);

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
#endif  /* __UXEN__ */
    else if ( likely(d != NULL) && likely(d != dom_cow) )
    {
#ifdef __UXEN__
        ASSERT(order == 0);
#endif  /* __UXEN__ */
        /* NB. May recursively lock from relinquish_memory(). */
        spin_lock_recursive(&d->page_alloc_lock);

#ifndef NDEBUG
        for ( i = 0; i < (1 << order); i++ )
        {
#ifndef __UXEN__
            BUG_ON((pg[i].u.inuse.type_info & PGT_count_mask) != 0);
#endif  /* __UXEN__ */

            if (pg[i].count_info & PGC_count_mask) {
                printk("%s: mfn %lx count %lx\n", __FUNCTION__,
                       page_to_mfn(&pg[i]), pg[i].count_info);
                DEBUG();
            }
        }
#endif

        d->tot_pages -= 1 << order;
        drop_dom_ref = (d->tot_pages == 0);

        spin_unlock_recursive(&d->page_alloc_lock);

#ifndef __UXEN_NOT_YET__
        /*
         * Normally we expect a domain to clear pages before freeing them, if 
         * it cares about the secrecy of their contents. However, after a 
         * domain has died we assume responsibility for erasure.
         */
        if ( unlikely(d->is_dying) )
            for ( i = 0; i < (1 << order); i++ )
                scrub_one_page(&pg[i]);
#endif  /* __UXEN_NOT_YET__ */

#ifndef __UXEN__
        free_heap_pages(pg, order);
#else   /* __UXEN__ */
        free_host_heap_page(d, pg);
#endif  /* __UXEN__ */
    }
    else if ( unlikely(d == dom_cow) )
    {
DEBUG();
        ASSERT(order == 0); 
        scrub_one_page(pg);
#ifndef __UXEN__
        free_heap_pages(pg, 0);
#else   /* __UXEN__ */
        ASSERT(order == 0); 
        free_host_heap_page(NULL, pg);
#endif  /* __UXEN__ */
        drop_dom_ref = 0;
    }
    else
    {
        /* Freeing anonymous domain-heap pages. */
#ifndef __UXEN__
        free_heap_pages(pg, order);
#else   /* __UXEN__ */
        ASSERT(order == 0); 
        free_host_heap_page(NULL, pg);
#endif  /* __UXEN__ */
        drop_dom_ref = 0;
    }

    if ( drop_dom_ref )
        put_domain(d);
}

#ifndef __UXEN__
unsigned long avail_domheap_pages_region(
    unsigned int node, unsigned int min_width, unsigned int max_width)
{
    int zone_lo, zone_hi;

    zone_lo = min_width ? bits_to_zone(min_width) : (MEMZONE_XEN + 1);
    zone_lo = max_t(int, MEMZONE_XEN + 1, min_t(int, NR_ZONES - 1, zone_lo));

    zone_hi = max_width ? bits_to_zone(max_width) : (NR_ZONES - 1);
    zone_hi = max_t(int, MEMZONE_XEN + 1, min_t(int, NR_ZONES - 1, zone_hi));

    return avail_heap_pages(zone_lo, zone_hi, node);
}

unsigned long avail_domheap_pages(void)
{
    return avail_heap_pages(MEMZONE_XEN + 1,
                            NR_ZONES - 1,
                            -1);
}

unsigned long avail_node_heap_pages(unsigned int nodeid)
{
    return avail_heap_pages(MEMZONE_XEN, NR_ZONES -1, nodeid);
}
#endif  /* __UXEN__ */


#ifndef __UXEN__
static void pagealloc_info(unsigned char key)
{
    unsigned int zone = 0;
    unsigned long n, total = 0;

    printk("Physical memory information:\n");

    while ( zone < NR_ZONES )
    {
        if ( (n = avail_heap_pages(zone, zone, -1)) != 0 )
        {
            total += n;
            printk("    heap[%02u]: %lukB free\n", zone, n << (PAGE_SHIFT-10));
        }

        zone++;
    }

    printk("    Dom heap: %lukB free\n", total << (PAGE_SHIFT-10));
}

static struct keyhandler pagealloc_info_keyhandler = {
    .diagnostic = 1,
    .u.fn = pagealloc_info,
    .desc = "memory info"
};

static __init int pagealloc_keyhandler_init(void)
{
    register_keyhandler('m', &pagealloc_info_keyhandler);
    return 0;
}
__initcall(pagealloc_keyhandler_init);
#endif  /* __UXEN__ */


void scrub_one_page(struct page_info *pg)
{
    void *p = __map_domain_page(pg);

#ifndef __UXEN__
    if ( unlikely(pg->count_info & PGC_broken) )
        return;
#endif  /* __UXEN__ */

#ifndef NDEBUG
    /* Avoid callers relying on allocations returning zeroed pages. */
    memset(p, 0xc2, PAGE_SIZE);
#else
    /* For a production build, clear_page() is the fastest way to scrub. */
    clear_page(p);
#endif

    unmap_domain_page(p);
}

#ifndef __UXEN__
static void dump_heap(unsigned char key)
{
    s_time_t      now = NOW();
    int           i, j;

    printk("'%c' pressed -> dumping heap info (now-0x%X:%08X)\n", key,
           (u32)(now>>32), (u32)now);

    for ( i = 0; i < MAX_NUMNODES; i++ )
    {
        if ( !avail[i] )
            continue;
        for ( j = 0; j < NR_ZONES; j++ )
            printk("heap[node=%d][zone=%d] -> %lu pages\n",
                   i, j, avail[i][j]);
    }
}

static struct keyhandler dump_heap_keyhandler = {
    .diagnostic = 1,
    .u.fn = dump_heap,
    .desc = "dump heap info"
};

static __init int register_heap_trigger(void)
{
    register_keyhandler('H', &dump_heap_keyhandler);
    return 0;
}
__initcall(register_heap_trigger);
#endif  /* __UXEN__ */

/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
