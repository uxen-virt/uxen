/*
 *  mapcache.h
 *  uxen
 *
 * Copyright 2015-2016, Bromium, Inc.
 * Author: Christian Limpach <Christian.Limpach@gmail.com>
 * SPDX-License-Identifier: ISC
 * 
 */

#ifndef __MAPCACHE_H_
#define __MAPCACHE_H_

#ifdef UXEN_HOST_WINDOWS

#define MAPCACHE_SIZE (4 /* MB */ * 1024 * 1024 / PAGE_SIZE)

void mapcache_init(void);
void *mapcache_map_page(xen_pfn_t pfn);
uint64_t mapcache_unmap_page_va(const void *va);
uint64_t mapcache_mapped_va_mfn(const void *va);

#endif  /* UXEN_HOST_WINDOWS */

#endif  /* __MAPCACHE_H_ */
