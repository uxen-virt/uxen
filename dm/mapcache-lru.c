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

int
mapcache_clear(void)
{
    int i;
    for (i = 0; i < (1 << lru_cache_lines); ++i) {
        LruCacheLine *cl = &lru.lines[i];
        if (cl->key) {
            if (cl->value & (UXEN_PAGE_SIZE-1)) {
                debug_printf("leaked %"PRIx64"\n", cl->key);
            }
            assert(!(cl->value & (UXEN_PAGE_SIZE-1)));
            hashtable_delete(&ht, cl->key);
            xc_munmap(xc_handle, vm_id, (void*) (cl->value & UXEN_PAGE_MASK),
                    XC_PAGE_SIZE * (cl->key & (UXEN_PAGE_SIZE-1)));
            cl->key = cl->value = 0;
        }
    }
    return 0;
}

uint8_t *
mapcache_map(uint64_t phys_addr, uint64_t *len, uint8_t lock)
{
    assert(!lock);
    // debug_printf("%s %"PRIx64" %"PRIx64"\n", __FUNCTION__, phys_addr, *len);

    uint8_t *va;
    uint8_t *mapping;
    uint32_t pfn = phys_addr >> UXEN_PAGE_SHIFT;
    uint32_t end_pfn = ((phys_addr + *len - 1) >> UXEN_PAGE_SHIFT) + 1;
    int num_pages = end_pfn - pfn;
    uint64_t key = (phys_addr & UXEN_PAGE_MASK) | num_pages;
    uint64_t line;
    LruCacheLine *cl;
    int i;

    critical_section_enter(&cs);

    if (hashtable_find(&ht, key, &line)) {
        cl = lru_cache_touch_line(&lru, line);
        va = (uint8_t*) (cl->value & UXEN_PAGE_MASK) + (phys_addr & (UXEN_PAGE_SIZE-1));
        cl->value++;
    } else {

        for (i = 0; i < (1 << lru_cache_lines); ++i) {
            line = lru_cache_evict_line(&lru);
            cl = lru_cache_touch_line(&lru, line);
            if (cl->key) {
                if ((cl->value & (UXEN_PAGE_SIZE-1)) == 0) {
                    hashtable_delete(&ht, cl->key);
                    xc_munmap(xc_handle, vm_id, (void*) (cl->value & UXEN_PAGE_MASK),
                            XC_PAGE_SIZE * (cl->key & (UXEN_PAGE_SIZE-1)));
                    break;
                }
            } else {
                break;
            }
        }
        assert(i < (1<<lru_cache_lines)); /* cache too small. */

        mapping = xc_map_foreign_range(xc_handle, vm_id, XC_PAGE_SIZE *
                num_pages, PROT_READ|PROT_WRITE, pfn);
        if (!mapping) {
            warn("%s: unable to map %"PRIx64" len %"PRIx64"\n",
                    __FUNCTION__, phys_addr, *len);
            assert(0);
        }
        assert(mapping);

        cl->key = key;
        cl->value = ((uintptr_t)mapping) |  1; /* initial refcount */

        hashtable_insert(&ht, key, line);
        va = mapping + (phys_addr & (UXEN_PAGE_SIZE-1));
    }
    critical_section_leave(&cs);

    return (uint8_t*) va;
}


void
mapcache_unmap(uint64_t phys_addr, uint64_t len, uint8_t lock)
{
    assert(!lock);

    uint32_t pfn = phys_addr >> UXEN_PAGE_SHIFT;
    uint32_t end_pfn = ((phys_addr + len - 1) >> UXEN_PAGE_SHIFT) + 1;
    int num_pages = end_pfn - pfn;
    uint64_t key = (phys_addr & UXEN_PAGE_MASK) | num_pages;
    uint64_t line;
    LruCacheLine *cl;

    critical_section_enter(&cs);

    if (hashtable_find(&ht, key, &line)) {
        cl = &lru.lines[line];
        --(cl->value);
    } else {
        assert(0);
    }

    critical_section_leave(&cs);
}

void
mapcache_invalidate(void)
{
}

#ifdef MONITOR
void
ic_memcache(Monitor *mon)
{
}
#endif
