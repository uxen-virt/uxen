/*
 * Copyright 2012-2018, Bromium, Inc.
 * Author: Christian Limpach <Christian.Limpach@gmail.com>
 * SPDX-License-Identifier: ISC
 */

#ifndef _UXEN_UTIL_H_
#define _UXEN_UTIL_H_

#define UXEN_POOL_TAG 'uxen'

#define uxen_malloc(size)                                       \
    ExAllocatePoolWithTag(NonPagedPool, (size), UXEN_POOL_TAG)

#define uxen_free(addr)                                         \
    ExFreePoolWithTag(addr, UXEN_POOL_TAG)

void *
uxen_malloc_locked_pages(unsigned int nr_pages, unsigned int *mfn_list,
			 unsigned int max_mfn);
void *
uxen_user_map_page_range(unsigned int n, unsigned int *mfn, MDL **_mdl);

void
cpuid(uint32_t idx, uint32_t *eax, uint32_t *ebx, uint32_t *ecx, uint32_t *edx);

void
wrmsr(uint32_t reg, uint64_t val);

#define PRId64 "Id"
#define PRIu64 "Iu"
#define PRIx64 "Ix"

int
uxen_DbgPrint(const char *fmt, ...);

struct shared_info *
uxen_get_shared_info(unsigned int *);

static __inline int uxen_is_whp_present_32(void) { return 0; }
int uxen_is_whp_present_64(void);

#ifdef __x86_64__
#define uxen_is_whp_present uxen_is_whp_present_64
#else
#define uxen_is_whp_present uxen_is_whp_present_32
#endif

#endif	/* _UXEN_UTIL_H_ */
