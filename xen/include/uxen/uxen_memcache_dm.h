/*
 *  uxen_memcache_dm.h
 *  uxen
 *
 * Copyright 2014-2015, Bromium, Inc.
 * Author: Christian Limpach <Christian.Limpach@gmail.com>
 * SPDX-License-Identifier: ISC
 *
 */

#ifndef _UXEN_MEMCACHE_DM_H_
#define _UXEN_MEMCACHE_DM_H_

#include "uxen_types.h"

typedef uint32_t mdm_mfn_t;
typedef volatile uint32_t mdm_mfn_entry_t;

/* low 8 bits unused */
/* top 13 bits for offset = 32MB */
/* middle 11 bits for count */

#define MEMCACHE_ENTRY_OFFSET_SHIFT 19
#define MEMCACHE_ENTRY_OFFSET_MASK ~((1 << MEMCACHE_ENTRY_OFFSET_SHIFT) - 1)

#define MEMCACHE_ENTRY_COUNT_SHIFT 8
#define MEMCACHE_ENTRY_COUNT_BITS 11
/* don't include top-bit/lock-bit in max */
#define MEMCACHE_ENTRY_COUNT_MAX ((1 << (MEMCACHE_ENTRY_COUNT_BITS - 1)) - 1)
/* include top-bit/lock-bit in mask */
#define MEMCACHE_ENTRY_COUNT_MASK				\
    (((1 << MEMCACHE_ENTRY_COUNT_BITS) - 1) << MEMCACHE_ENTRY_COUNT_SHIFT)

struct mdm_info {
    mdm_mfn_entry_t *mdm_mfn_to_entry;
    uint8_t *mdm_va;
    uint32_t mdm_map_pfns;
    uxen_pfn_t mdm_end_low_gpfn;
    uxen_pfn_t mdm_start_high_gpfn;
    uxen_pfn_t mdm_end_high_gpfn;
    uint32_t mdm_takeref;
    uxen_pfn_t mdm_undefined_mfn;
};

#endif	/* _UXEN_MEMCACHE_DM_H_ */
