/*
 * Copyright 2012-2016, Bromium, Inc.
 * Author: Christian Limpach <Christian.Limpach@gmail.com>
 * SPDX-License-Identifier: ISC
 */

#ifndef _MEMCACHE_H_
#define _MEMCACHE_H_

#ifdef __x86_64__
#define MEMCACHE_MAP_FULL
#endif

typedef uint32_t mc_mfn_t;

void *memcache_lookup(mc_mfn_t mfn);
void *memcache_enter(mc_mfn_t mfn);
void memcache_ensure_space(void);
#ifndef MEMCACHE_MAP_FULL
void memcache_entry_get(mc_mfn_t mfn);
void memcache_entry_put(mc_mfn_t mfn);
mc_mfn_t memcache_get_mfn(const void *va);
#endif
void memcache_clear_batch(uint32_t nr_pages, uintptr_t *mfn_list);
int memcache_init(void);
void memcache_free(void);

#ifndef memcache_space
extern uint32_t memcache_space;
#endif

uint64_t __cdecl uxen_memcache_check(void);

#endif	/* _MEMCACHE_H_ */
