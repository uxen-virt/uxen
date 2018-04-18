/*
 * Copyright 2018, Bromium, Inc.
 * Author: Jacob Gorm Hansen <jacobgorm@gmail.com>
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

#include "block-swap/hashtable.h"
#include "block-swap/lrucache.h"

#include <uxenctllib.h>
#include <xenctrl.h>

#include <dm/qemu_glue.h>
#include <dm/whpx/whpx.h>

static HashTable ht;
static LruCache lru;
static critical_section cs;
const int lru_cache_lines = 10;

int
mapcache_init(uint64_t mem_mb)
{

    critical_section_init(&cs);
    hashtable_init(&ht, NULL, NULL);
    lru_cache_init(&lru, lru_cache_lines);

    return 0;
}

int
mapcache_init_restore(uint32_t end_low_pfn,
                      uint32_t start_high_pfn,
                      uint32_t end_high_pfn)
{

    return mapcache_init(0);
}

void
mapcache_get_params(uint32_t *end_low_pfn,
                    uint32_t *start_high_pfn,
                    uint32_t *end_high_pfn)
{

    if (end_low_pfn)
        *end_low_pfn = 0;
    if (start_high_pfn)
        *start_high_pfn = 0;
    if (end_high_pfn)
        *end_high_pfn = 0;
}

static int debug_memcache_global_count = 0;
static int debug_memcache_concurrent_count = 0;
static int debug_memcache_max_count = 0;
static int debug_memcache_map_count = 0;
static int debug_memcache_cache_count = 0;

#if 0
int
mapcache_flush(void)
{
    int i;

    for (i = 0; i < (1 << lru_cache_lines); i++) {
        LruCacheLine *cl = &lru.lines[i];
        if (cl->key) {
            if (cl->value & (UXEN_PAGE_SIZE - 1))
                continue;
            assert(!(cl->value & (UXEN_PAGE_SIZE - 1)));
            hashtable_delete(&ht, cl->key);
            xc_munmap(xc_handle, vm_id, (void *)(cl->value & UXEN_PAGE_MASK),
                      XC_PAGE_SIZE * (cl->key & (UXEN_PAGE_SIZE - 1)));
            cl->key = cl->value = 0;
        }
    }

    return 0;
}
#endif

static uint8_t *
uxen_mapcache_map(uint64_t phys_addr, uint64_t *len, uint8_t lock)
{
    uint8_t *va = NULL;
    uint8_t *mapping;
    uint32_t pfn = phys_addr >> UXEN_PAGE_SHIFT;
    uint32_t end_pfn = ((phys_addr + (*len) - 1) >> UXEN_PAGE_SHIFT) + 1;
    int num_pages = end_pfn - pfn;
    uint64_t key = (phys_addr & UXEN_PAGE_MASK) | num_pages;
    uint64_t line;
    LruCacheLine *cl;
    int i;

    assert(!lock);
    // debug_printf("%s %"PRIx64" %"PRIx64"\n", __FUNCTION__, phys_addr, *len);

    critical_section_enter(&cs);

    if (hashtable_find(&ht, key, &line)) {
        cl = lru_cache_touch_line(&lru, line);
        va = (uint8_t *)(cl->value & UXEN_PAGE_MASK) +
            (phys_addr & (UXEN_PAGE_SIZE - 1));
        cl->value++;
        debug_memcache_cache_count += num_pages;
        if ((cl->value & (UXEN_PAGE_SIZE - 1)) > debug_memcache_max_count)
            debug_memcache_max_count = cl->value & (UXEN_PAGE_SIZE - 1);
    } else {
        for (i = 0; i < (1 << lru_cache_lines); i++) {
            line = lru_cache_evict_line(&lru);
            cl = lru_cache_touch_line(&lru, line);
            if (cl->key) {
                if ((cl->value & (UXEN_PAGE_SIZE - 1)) == 0) {
                    hashtable_delete(&ht, cl->key);
                    xc_munmap(xc_handle, vm_id,
                              (void *)(cl->value & UXEN_PAGE_MASK),
                              XC_PAGE_SIZE * (cl->key & (UXEN_PAGE_SIZE - 1)));
                    break;
                }
            } else
                break;
        }
        if (i >= (1 << lru_cache_lines)) {
            warn("%s: cache too small\n", __FUNCTION__);
            goto out;
        }

        mapping = xc_map_foreign_range(xc_handle, vm_id,
                                       XC_PAGE_SIZE * num_pages,
                                       PROT_READ|PROT_WRITE, pfn);
        if (!mapping) {
            warn("%s: unable to map %"PRIx64" len %"PRIx64"\n",
                 __FUNCTION__, phys_addr, *len);
            goto out;
        }

        cl->key = key;
        cl->value = ((uintptr_t)mapping) |  1; /* initial refcount */
        debug_memcache_map_count += num_pages;

        hashtable_insert(&ht, key, line);
        va = mapping + (phys_addr & (UXEN_PAGE_SIZE - 1));
    }

    debug_memcache_global_count += num_pages;
    if (debug_memcache_global_count > debug_memcache_concurrent_count)
        debug_memcache_concurrent_count = debug_memcache_global_count;

  out:
    critical_section_leave(&cs);

    return (uint8_t *)va;
}


static void
uxen_mapcache_unmap(uint64_t phys_addr, uint64_t len, uint8_t lock)
{
    uint32_t pfn = phys_addr >> UXEN_PAGE_SHIFT;
    uint32_t end_pfn = ((phys_addr + len - 1) >> UXEN_PAGE_SHIFT) + 1;
    int num_pages = end_pfn - pfn;
    uint64_t key = (phys_addr & UXEN_PAGE_MASK) | num_pages;
    uint64_t line;
    LruCacheLine *cl;

    assert(!lock);

    critical_section_enter(&cs);

    if (hashtable_find(&ht, key, &line)) {
        cl = &lru.lines[line];
        (cl->value)--;
    } else
        warnx("%s: unmap of missing mapping: %"PRIx64" len %"PRIx64"\n",
              __FUNCTION__, phys_addr, len);

    debug_memcache_global_count -= num_pages;

    critical_section_leave(&cs);
}

uint8_t *
mapcache_map(uint64_t phys_addr, uint64_t *len, uint8_t lock)
{
    return !whpx_enable ?
        uxen_mapcache_map(phys_addr, len, lock) : whpx_ram_map(phys_addr, len);
}

void
mapcache_unmap(uint64_t phys_addr, uint64_t len, uint8_t lock)
{
    if (!whpx_enable)
        uxen_mapcache_unmap(phys_addr, len, lock);
    /* no-op on WHPX */
}

void
mapcache_invalidate(void)
{
}

#ifdef MONITOR
void
ic_memcache(Monitor *mon)
{
    int i;
    int mapped = 0;

    for (i = 0; i < (1 << lru_cache_lines); i++) {
        LruCacheLine *cl = &lru.lines[i];
        if (cl->key) {
            mapped++;
            if (cl->value & (UXEN_PAGE_SIZE - 1))
                monitor_printf(mon, "memcache pfn %06x/%x count: %d\n",
                               (uint32_t)(cl->key >> UXEN_PAGE_SHIFT),
                               (uint32_t)(cl->key & (UXEN_PAGE_SIZE - 1)),
                               (uint32_t)(cl->value & (UXEN_PAGE_SIZE - 1)));
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
#endif
