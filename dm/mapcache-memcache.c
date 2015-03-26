/*
 * Copyright 2012-2015, Bromium, Inc.
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

#include <uxenctllib.h>
#include <xenctrl.h>

#include <uxen/uxen_memcache_dm.h>

static uint32_t mapcache_end_low_pfn, mapcache_end_high_pfn;
static uint32_t mapcache_start_high_pfn =
    (PCI_HOLE_START >> UXEN_PAGE_SHIFT);
static uint8_t *memcache_va;
static mdm_mfn_entry_t *memcache_mfn_to_entry;

static critical_section cs;

int
mapcache_init(uint64_t mem_mb)
{

    critical_section_init(&cs);

    mapcache_end_low_pfn = mem_mb << (20 - UXEN_PAGE_SHIFT);
    mapcache_end_high_pfn = 0x100000;
    if (mapcache_end_low_pfn > mapcache_start_high_pfn) {
        mapcache_end_high_pfn +=
            mapcache_end_low_pfn - mapcache_start_high_pfn;
        mapcache_end_low_pfn = mapcache_start_high_pfn;
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
