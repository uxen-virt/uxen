/*
 * Copyright 2012-2018, Bromium, Inc.
 * Author: Christian Limpach <Christian.Limpach@gmail.com>
 * SPDX-License-Identifier: ISC
 */

#include "config.h"

#include <err.h>
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>

#include "aio.h"
#include "dm.h"
#include "mapcache.h"
#include "monitor.h"
#include "os.h"
#include "queue.h"
#include "uxen.h"
#include "rbtree.h"

#include <uxenctllib.h>
#include <xenctrl.h>

#include <uxen/uxen_memcache_dm.h>
#include <xen/hvm/e820.h>

static uint32_t mapcache_end_low_pfn = 0;
static uint32_t mapcache_start_high_pfn = 0;
static uint32_t mapcache_end_high_pfn = 0;
static uint8_t *memcache_va;
static mdm_mfn_entry_t *memcache_mfn_to_entry;

uint64_t use_simple_mapping = 1;
uint64_t simple_map_size = XC_PAGE_SIZE;
static void simple_init(void);

static critical_section cs;

int
mapcache_init(uint64_t mem_mb)
{

    critical_section_init(&cs);

    if (use_simple_mapping)
	simple_init();

    mapcache_end_low_pfn = mem_mb << (20 - UXEN_PAGE_SHIFT);
    if (mapcache_end_low_pfn <= PCI_HOLE_START >> UXEN_PAGE_SHIFT) {
        mapcache_start_high_pfn = mapcache_end_low_pfn;
        mapcache_end_high_pfn = mapcache_start_high_pfn;
    } else {
        mapcache_start_high_pfn = PCI_HOLE_END >> UXEN_PAGE_SHIFT;
        mapcache_end_high_pfn = mapcache_start_high_pfn +
            mapcache_end_low_pfn - (PCI_HOLE_START >> UXEN_PAGE_SHIFT);
        mapcache_end_low_pfn = PCI_HOLE_START >> UXEN_PAGE_SHIFT;
    }

    return uxen_memcacheinit(uxen_handle, mapcache_end_low_pfn,
                             mapcache_start_high_pfn,
                             mapcache_end_high_pfn, &memcache_va,
                             &memcache_mfn_to_entry);
}

int
mapcache_init_restore(uint32_t end_low_pfn,
                      uint32_t start_high_pfn,
                      uint32_t end_high_pfn)
{

    critical_section_init(&cs);

    if (use_simple_mapping)
	simple_init();

    mapcache_end_low_pfn = end_low_pfn;
    mapcache_start_high_pfn = start_high_pfn;
    mapcache_end_high_pfn = end_high_pfn;

    return uxen_memcacheinit(uxen_handle, mapcache_end_low_pfn,
                             mapcache_start_high_pfn,
                             mapcache_end_high_pfn, &memcache_va,
                             &memcache_mfn_to_entry);
}

void
mapcache_get_params(uint32_t *end_low_pfn,
                    uint32_t *start_high_pfn,
                    uint32_t *end_high_pfn)
{
    if (end_low_pfn)
        *end_low_pfn = mapcache_end_low_pfn;
    if (start_high_pfn)
        *start_high_pfn = mapcache_start_high_pfn;
    if (end_high_pfn)
        *end_high_pfn = mapcache_end_high_pfn;
}

/****************************************** SIMPLE MAPPER **********************************************/

typedef uint64_t Simple_mapping_key;

typedef struct simple_mapping {
    /* This needs to be first otherwise the tests for NULL/Sentinel node don't work */
    struct rb_node simple_mapping_rbnode; 
    Simple_mapping_key start_pa;
    uint64_t end_pa;
    void *base;
} Simple_mapping;

static int
simple_mapping_compare_key(void *ctx, const void *_node, const void *_key)
{
    const Simple_mapping * const node = _node;
    const Simple_mapping_key * const key = _key;

    if (node->start_pa  < *key) 
	return -1;
    if (node->start_pa  > *key) 
	return 1;

    return 0;
}

static int
simple_mapping_compare_nodes(void *ctx, const void *_parent, const void *_node)
{
    const Simple_mapping * const node = _node;

    return simple_mapping_compare_key(ctx, _parent, &node->start_pa);
}

static rb_tree_t simple_mapping_rbtree;

static const rb_tree_ops_t simple_mapping_rbtree_ops = {
    .rbto_compare_nodes = simple_mapping_compare_nodes,
    .rbto_compare_key = simple_mapping_compare_key,
    .rbto_node_offset = offsetof(struct simple_mapping, simple_mapping_rbnode),
    .rbto_context = NULL
};

static Simple_mapping *simple_make_mapping (uint64_t start, uint64_t end)
{
    Simple_mapping *ret;
    xen_pfn_t pfn = start >> XC_PAGE_SHIFT;
    uint8_t *va;

    va = xc_map_foreign_range (xc_handle, vm_id, end - start, 
                               PROT_READ | PROT_WRITE, pfn);

    if (!va)
        return NULL;

    ret = malloc(sizeof(*ret));

    if (!ret) //FIXME unmap on out of memory.
	return NULL;

    ret->base = va;
    ret->start_pa = start;
    ret->end_pa = end;

    return ret;
}

static Simple_mapping *simple_find_mapping (uint64_t start, uint64_t end)
{
    Simple_mapping *ret;
    Simple_mapping_key key = start;

    critical_section_enter(&cs);

    ret=(Simple_mapping *) rb_tree_find_node_leq(&simple_mapping_rbtree, &key);

    /* The above claims that ret->start_pa <= start, so check the end */
    if (ret && (ret->end_pa < end))
	ret = NULL;

    critical_section_leave(&cs);

    return ret;
}


static Simple_mapping *simple_find_or_make_mapping (uint64_t _start, uint64_t _end)
{
    Simple_mapping *ret;
    uint64_t start, end, size;

    ret = simple_find_mapping(_start, _end);

    if (ret)
        return ret;

    for (size = simple_map_size; size >= XC_PAGE_SIZE; size >>= 1)
    {
        start = _start & ~(size - 1);
        end = _end + (size - 1);
        end &= ~(size - 1);

        ret = simple_make_mapping(start, end);

        if (ret) break;
    }

    if (!ret)
        return ret;

    critical_section_enter(&cs);
    rb_tree_insert_node(&simple_mapping_rbtree, ret);
    critical_section_leave(&cs);

    return ret;
}

static uint8_t *
simple_mapcache_map(uint64_t pa, uint64_t *len, uint8_t lock)
{
    Simple_mapping *m;

    uint64_t end_pa = pa + *len;

    m = simple_find_or_make_mapping(pa, end_pa);

    if (m)
        return m->base + (pa - m->start_pa);

    return NULL;
}

static void simple_init(void)
{
    critical_section_enter (&cs);
    rb_tree_init(&simple_mapping_rbtree, &simple_mapping_rbtree_ops);
    critical_section_leave(&cs);
}

/*****************************************************************************************************/


int debug_memcache_global_count = 0;
int debug_memcache_concurrent_count = 0;
int debug_memcache_max_count = 0;
int debug_memcache_map_count = 0;
int debug_memcache_cache_count = 0;


static uint32_t
memcache_entry_update(uint32_t pfn, int get, uint32_t lock)
{
    mdm_mfn_entry_t *entry;
    uint32_t y, x, nx;
    int count;

    if (pfn < mapcache_end_low_pfn)
        entry = &memcache_mfn_to_entry[pfn];
    else if (pfn >= mapcache_start_high_pfn && pfn < mapcache_end_high_pfn)
        entry = &memcache_mfn_to_entry[pfn - (mapcache_start_high_pfn -
                                              mapcache_end_low_pfn)];
    else
        return ~0U;

    y = *entry;

    lock <<= (MEMCACHE_ENTRY_COUNT_BITS - 1);

    do {
        if (y == ~0U)
            return ~0U;

        x = y;
        nx = (x & ~MEMCACHE_ENTRY_COUNT_MASK);
        count = (x & MEMCACHE_ENTRY_COUNT_MASK) >> MEMCACHE_ENTRY_COUNT_SHIFT;
        if (!lock && (count & (1 << (MEMCACHE_ENTRY_COUNT_BITS - 1)))) {
            debug_printf("memcache unlocked %s op on locked pfn %06x from %p\n",
                         get ? "get" : "put", pfn, __builtin_return_address(0));
            /* debug_break(); */
        }

        /* remove lock-bit */
        count &= ~(1 << (MEMCACHE_ENTRY_COUNT_BITS - 1));

        if (count != MEMCACHE_ENTRY_COUNT_MAX) {
            if (get) {
                count++;
                if (count > debug_memcache_max_count)
                    debug_memcache_max_count = count;
            } else {
                assert(count != 0);
                count--;
            }
        }

        nx |= (count | lock) << MEMCACHE_ENTRY_COUNT_SHIFT;

        if (x == nx)
            break;

    } while ((y = cmpxchg(entry, x, nx)) != x);

    return nx;
}

static uint32_t
memcache_entry_get(uint32_t pfn, int lock)
{
    uint32_t offset;

    offset = memcache_entry_update(pfn, 1, lock);
    if (!lock && offset != ~0U) {
        debug_memcache_global_count++;
        if (debug_memcache_global_count > debug_memcache_concurrent_count)
            debug_memcache_concurrent_count = debug_memcache_global_count;
    }

    return offset;
}

static void
memcache_entry_put(uint32_t pfn, int lock)
{
    if (!lock)
        debug_memcache_global_count--;
    memcache_entry_update(pfn, 0, lock);
}

uint8_t *
mapcache_map(uint64_t phys_addr, uint64_t *len, uint8_t lock)
{
    uint32_t pfn = phys_addr >> UXEN_PAGE_SHIFT;
    uint32_t end_pfn = ((phys_addr + *len - 1) >> UXEN_PAGE_SHIFT) + 1;
    uint8_t *va = NULL;
    uint64_t mapped = 0;
    uint32_t offset;
    int ret;

    if (use_simple_mapping)
        return simple_mapcache_map(phys_addr, len, lock);

    critical_section_enter(&cs);

    if (pfn < mapcache_end_low_pfn) {
        if (end_pfn >= mapcache_end_low_pfn) {
            /* ">=" because need to adjust len, if end_pfn == max_pfn */
            end_pfn = mapcache_end_low_pfn;
            *len = (end_pfn << UXEN_PAGE_SHIFT) - phys_addr;
        }
    } else if (pfn >= mapcache_start_high_pfn && pfn < mapcache_end_high_pfn) {
        if (end_pfn >= mapcache_end_high_pfn) {
            /* ">=" because need to adjust len, if end_pfn == max_pfn */
            end_pfn = mapcache_end_high_pfn;
            *len = (end_pfn << UXEN_PAGE_SHIFT) - phys_addr;
        }
    } else {
        critical_section_leave(&cs);
        return NULL;
    }

    while (mapped < *len) {
        offset = memcache_entry_get(pfn, lock); //memcache_mfn_to_entry[pfn];
        if (offset == ~0U) {
            debug_memcache_map_count++;
            ret = uxen_memcachemap(uxen_handle, vm_id, pfn, end_pfn - pfn);
            if (ret)
                goto out;
            offset = memcache_entry_get(pfn, lock); // memcache_mfn_to_entry[pfn];
            if (offset == ~0U)
                goto out;
            memcache_entry_update(pfn, 0, lock); /* drop ref taken by
                                                  * uxen_memcachemap */
        } else
            debug_memcache_cache_count++;

        offset &= MEMCACHE_ENTRY_OFFSET_MASK;
        // offset <<= (UXEN_PAGE_SHIFT - MEMCACHE_ENTRY_OFFSET_SHIFT);
        offset >>= (MEMCACHE_ENTRY_OFFSET_SHIFT - UXEN_PAGE_SHIFT);

        if (va == NULL)
            va = memcache_va + offset;
        else {
            if (va + mapped != memcache_va + offset) {
                memcache_entry_put(pfn, lock);
                goto out;
            }
        }

        mapped += UXEN_PAGE_SIZE;
        pfn++;
    }

  out:
    critical_section_leave(&cs);

    if (!va)
        return NULL;

    mapped -= (phys_addr & ~UXEN_PAGE_MASK);
    if (mapped < *len)
        *len = mapped;

    return va + (phys_addr & ~UXEN_PAGE_MASK);
}

void
mapcache_unmap(uint64_t phys_addr, uint64_t len, uint8_t lock)
{
    uint32_t pfn = phys_addr >> UXEN_PAGE_SHIFT;
    uint32_t end_pfn = ((phys_addr + len - 1) >> UXEN_PAGE_SHIFT) + 1;
    uint64_t cleared = 0;

    if (use_simple_mapping)
        return;

    if (pfn < mapcache_end_low_pfn) {
        if (end_pfn >= mapcache_end_low_pfn) {
            /* ">=" because need to adjust len, if end_pfn == max_pfn */
            end_pfn = mapcache_end_low_pfn;
            len = (end_pfn << UXEN_PAGE_SHIFT) - phys_addr;
        }
    } else if (pfn >= mapcache_start_high_pfn && pfn < mapcache_end_high_pfn) {
        if (end_pfn >= mapcache_end_high_pfn) {
            /* ">=" because need to adjust len, if end_pfn == max_pfn */
            end_pfn = mapcache_end_high_pfn;
            len = (end_pfn << UXEN_PAGE_SHIFT) - phys_addr;
        }
    } else
        return;

    while (cleared < len) {
        memcache_entry_put(pfn, lock);

        cleared += UXEN_PAGE_SIZE;
        pfn++;
    }
}

void
mapcache_invalidate(void)
{
    // int i;

    aio_flush();

#if 0
    for (i = 0; i < mapcache_max_pfn; i++) {
        if (!mapcache[i])
            continue;
        errno = xc_munmap(xc_handle, vm_id, mapcache[i], UXEN_PAGE_SIZE);
        if (errno)
            err(1, "mapcache_invalidate munmap");
        mapcache[i] = NULL;
    }
#endif
    debug_break();
}

#ifdef MONITOR
void
ic_memcache(Monitor *mon)
{
    uint32_t pfn;
    uint32_t offset;
    int count, lock, mapped = 0;

    for (pfn = 0; pfn < mapcache_end_high_pfn; pfn++) {
        if (pfn == mapcache_end_low_pfn)
            pfn = mapcache_start_high_pfn;
        if (pfn < mapcache_end_low_pfn)
            offset = memcache_mfn_to_entry[pfn];
        else
            offset = memcache_mfn_to_entry[pfn - (mapcache_start_high_pfn -
                                                  mapcache_end_low_pfn)];
        if (offset != ~0U)
            mapped++;
        if (offset != ~0U && (offset & MEMCACHE_ENTRY_COUNT_MASK)) {
            count = (offset & MEMCACHE_ENTRY_COUNT_MASK) >>
                MEMCACHE_ENTRY_COUNT_SHIFT;
            lock = count & (1 << (MEMCACHE_ENTRY_COUNT_BITS - 1));
            count &= ~(1 << (MEMCACHE_ENTRY_COUNT_BITS - 1));

            monitor_printf(mon, "memcache pfn %06x count: %d%s\n", pfn, count,
                           lock ? " locked" : "");
        }
    }

    monitor_printf(mon, "memcache     global count: %d\n",
                   debug_memcache_global_count);
    monitor_printf(mon, "memcache concurrent count: %d\n",
                   debug_memcache_concurrent_count);
    monitor_printf(mon, "memcache        max count: %d\n",
                   debug_memcache_max_count);
    monitor_printf(mon, "memcache     mapped count: %d\n", mapped);
    monitor_printf(mon, "memcache        map count: %d\n",
                   debug_memcache_map_count);
    monitor_printf(mon, "memcache      cache count: %d\n",
                   debug_memcache_cache_count);
}
#endif  /* MONITOR */
