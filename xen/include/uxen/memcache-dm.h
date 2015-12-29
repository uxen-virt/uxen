/*
 *  memcache-dm.h
 *  uxen
 *
 * Copyright 2014-2016, Bromium, Inc.
 * Author: Christian Limpach <Christian.Limpach@gmail.com>
 * SPDX-License-Identifier: ISC
 *
 */

#ifndef _MEMCACHE_DM_H_
#define _MEMCACHE_DM_H_

uint64_t
mdm_enter(struct domain *d, xen_pfn_t pfn, xen_pfn_t mfn);
int
mdm_clear(struct domain *d, xen_pfn_t pfn, int force);
int
mdm_clear_vm(struct domain *d);
void
mdm_destroy_vm(struct domain *d);

#endif /* _MEMCACHE_DM_H_ */
