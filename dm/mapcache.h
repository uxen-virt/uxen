/*
 * Copyright 2012-2019, Bromium, Inc.
 * Author: Christian Limpach <Christian.Limpach@gmail.com>
 * SPDX-License-Identifier: ISC
 */

#ifndef _MAPCACHE_H_
#define _MAPCACHE_H_

int mapcache_init(uint64_t mem_mb);
int mapcache_init_restore(uint32_t end_low_pfn,
                          uint32_t start_high_pfn,
                          uint32_t end_high_pfn);
void mapcache_get_params(uint32_t *end_low_pfn,
                         uint32_t *start_high_pfn,
                         uint32_t *end_high_pfn);
uint8_t *mapcache_map(uint64_t phys_addr, uint64_t *len, uint8_t lock);
void mapcache_unmap(uint64_t phys_addr, uint64_t len, uint8_t lock);
#ifndef __UXEN_TOOLS__
void mapcache_invalidate_entry(uint8_t *buffer);
void mapcache_invalidate(void);
#endif  /* __UXEN_TOOLS__ */

extern int mapcache_lock_cnt;

/* XXX this should be a recursive lock */
#define mapcache_lock() do { ; } while (0)
#define mapcache_unlock() do { ; } while (0)

#endif	/* _MAPCACHE_H_ */
