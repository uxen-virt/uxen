/*
 * Copyright 2012-2015, Bromium, Inc.
 * Author: Christian Limpach <Christian.Limpach@gmail.com>
 * SPDX-License-Identifier: ISC
 */

#include "uxen.h"
#include "memcache.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define UXEN_DEFINE_SYMBOLS_PROTO
#include <uxen/uxen_link.h>

struct memcache_desc {
    uint8_t *md_va;
#ifdef MEMCACHE_MAP_FULL
    uint32_t md_first_free_offset;
    uint64_t md_free[];
#else
    uint32_t md_next_offset;
    uint32_t mapped_pfn[];
#endif
};
#define MEMCACHE_MD_FREE_BITS 64
#define MEMCACHE_MD_FREE_BYTES 8
#define MEMCACHE_MD_FREE_SHIFT 6
#define MEMCACHE_MD_FREE_MASK ((1 << MEMCACHE_MD_FREE_SHIFT) - 1)

#ifdef MEMCACHE_MAP_FULL
typedef volatile uint32_t memcache_mfn_entry_t;
#define cmpxchg_entry cmpxchg
#else
typedef volatile uint16_t memcache_mfn_entry_t;
#define cmpxchg_entry cmpxchg16b
#endif
static memcache_mfn_entry_t *memcache_mfn_to_entry = NULL;
#define MEMCACHE_MFN_ENTRY_EMPTY (memcache_mfn_entry_t)~0U
#ifdef MEMCACHE_MAP_FULL
#define MEMCACHE_INDEX_MASK 0xffU
#define MEMCACHE_OFFSET_SHIFT 12
#define MEMCACHE_OFFSET_BITS (32 - MEMCACHE_OFFSET_SHIFT)
#else
#define MEMCACHE_INDEX_MASK 0x0U
#define MEMCACHE_OFFSET_SHIFT 3
#define MEMCACHE_OFFSET_BITS (16 - MEMCACHE_OFFSET_SHIFT)
#endif
#define MEMCACHE_OFFSET_MASK                                            \
    ((memcache_mfn_entry_t)~((1U << MEMCACHE_OFFSET_SHIFT) - 1))

#ifndef MEMCACHE_MAP_FULL
#define MEMCACHE_COUNT_SHIFT 0
#define MEMCACHE_COUNT_BITS MEMCACHE_OFFSET_SHIFT
#define MEMCACHE_COUNT_MAX ((1U << MEMCACHE_COUNT_BITS) - 1)
#define MEMCACHE_COUNT_MASK                                             \
    ((memcache_mfn_entry_t)(MEMCACHE_COUNT_MAX << MEMCACHE_COUNT_SHIFT))
#endif

#ifdef MEMCACHE_MAP_FULL
#define MEMCACHE_MAX_IDX 256
#else
#define MEMCACHE_MAX_IDX 1
#endif
static struct memcache_desc *memcaches[MEMCACHE_MAX_IDX] = { NULL, };
static uint32_t memcache_next_idx = 0;
static uint32_t memcache_pfn_per_idx;
#ifdef MEMCACHE_MAP_FULL
static uint32_t memcache_md_free_size;
#endif
#ifndef memcache_space
uint32_t memcache_space = 0;
#endif
uint32_t memcache_capacity = 0;

static MDL *memcache_map_mdl = NULL;
static KSPIN_LOCK memcache_lock;
static KGUARDED_MUTEX memcache_mutex;

static int
ffs64less1(uint64_t v)
{
    int m = 32;
    int b = 0;

    ASSERT(v);

    while (m) {
	if ((v & ((1ULL << m) - 1)) == 0) {
	    v >>= m;
	    b += m;
	}
	m >>= 1;
    }
    return b;
}

#ifndef MEMCACHE_MAP_FULL

void
memcache_entry_get(mdm_mfn_t pfn)
{
    memcache_mfn_entry_t y, x, nx;
    uint32_t count;

    y = memcache_mfn_to_entry[pfn];

    do {
        x = y;
        nx = (x & ~MEMCACHE_COUNT_MASK);
        count = (x & MEMCACHE_COUNT_MASK) >> MEMCACHE_COUNT_SHIFT;
        if (count == MEMCACHE_COUNT_MAX) {
            dprintk("%s: count for mfn %x at max\n", __FUNCTION__, pfn);
            break;
        }
        count++;

        nx |= count << MEMCACHE_COUNT_SHIFT;
        if (x == nx)
            break;
    } while ((y = cmpxchg_entry(&memcache_mfn_to_entry[pfn], x, nx)) != x);
}

void
memcache_entry_put(mc_mfn_t pfn)
{
    memcache_mfn_entry_t y, x, nx;
    uint32_t count;

    y = memcache_mfn_to_entry[pfn];

    if (y == MEMCACHE_MFN_ENTRY_EMPTY) {
        dprintk("%s: no entry for mfn %x\n", __FUNCTION__, pfn);
        return;
    }

    do {
        x = y;
        nx = (x & ~MEMCACHE_COUNT_MASK);
        count = (x & MEMCACHE_COUNT_MASK) >> MEMCACHE_COUNT_SHIFT;
        if (count == MEMCACHE_COUNT_MAX)
            return;
        BUG_ON(count == 0);
        count--;

        nx |= count << MEMCACHE_COUNT_SHIFT;
        if (x == nx)
            break;
    } while ((y = cmpxchg_entry(&memcache_mfn_to_entry[pfn], x, nx)) != x);
}

uint32_t
memcache_entry_clear(uint32_t pfn)
{
    memcache_mfn_entry_t y, x, nx;
    uint32_t count;

    if (pfn == ~0U)
        return 0;
    y = memcache_mfn_to_entry[pfn];

    do {
        x = y;
        count = (x & MEMCACHE_COUNT_MASK) >> MEMCACHE_COUNT_SHIFT;
        if (count)
            return 1;
        nx = MEMCACHE_MFN_ENTRY_EMPTY;
        if (x == nx)
            break;
    } while ((y = cmpxchg_entry(&memcache_mfn_to_entry[pfn], x, nx)) != x);

    return 0;
}

#endif

#ifndef MEMCACHE_MAP_FULL
/* on !MEMCACHE_MAP_FULL -- memcache_lookup must be called with
 * memcache_entry_get called */
static
#endif
void *
memcache_lookup(mc_mfn_t mfn)
{
    uint8_t idx;
    uint32_t offset;

    BUG_ON(mfn >= uxen_info->ui_max_page);
    offset = memcache_mfn_to_entry[mfn];
    if (offset == MEMCACHE_MFN_ENTRY_EMPTY)
	return NULL;

    idx = offset & MEMCACHE_INDEX_MASK;
    offset &= MEMCACHE_OFFSET_MASK;
#if PAGE_SHIFT >= MEMCACHE_OFFSET_SHIFT
    offset <<= (PAGE_SHIFT - MEMCACHE_OFFSET_SHIFT);
#else
    offset >>= (MEMCACHE_OFFSET_SHIFT - PAGE_SHIFT);
#endif

    MemoryBarrier();
    return memcaches[idx]->md_va + offset;
}

void *
memcache_lookup_mapped(mc_mfn_t mfn)
{
    uint8_t idx;
    uint32_t offset;

    BUG_ON(mfn >= uxen_info->ui_max_page);
    offset = memcache_mfn_to_entry[mfn];
    if (offset == MEMCACHE_MFN_ENTRY_EMPTY)
	return NULL;

#ifndef MEMCACHE_MAP_FULL
    if (((offset & MEMCACHE_COUNT_MASK) >> MEMCACHE_COUNT_SHIFT) == 0) {
        dprintk("%s: mfn %x has no referenced mapping\n", __FUNCTION__, mfn);
        return NULL;
    }
#endif

    idx = offset & MEMCACHE_INDEX_MASK;
    offset &= MEMCACHE_OFFSET_MASK;
#if PAGE_SHIFT >= MEMCACHE_OFFSET_SHIFT
    offset <<= (PAGE_SHIFT - MEMCACHE_OFFSET_SHIFT);
#else
    offset >>= (MEMCACHE_OFFSET_SHIFT - PAGE_SHIFT);
#endif

    MemoryBarrier();
    return memcaches[idx]->md_va + offset;
}

#ifdef __x86_64__
#define LINEAR_PT_VA 0xfffff68000000000
#define VA_TO_LINEAR_PTE(v)						\
    (uint64_t *)(LINEAR_PT_VA +						\
		 (((v) & ~0xffff000000000fff) >> (PAGE_SHIFT - 3)))
#else
#define LINEAR_PT_VA 0xc0000000
#define VA_TO_LINEAR_PTE(v)						\
    (uint32_t *)(LINEAR_PT_VA +						\
		 (((v) & ~0x00000fff) >> (PAGE_SHIFT - 3)))
#endif

static int
memcache_map_mfn(void *va, uint32_t offset, mc_mfn_t mfn)
{
#ifdef __x86_64__
    volatile uint64_t *pteaddr = VA_TO_LINEAR_PTE((uintptr_t)va + offset);

    ASSERT(*pteaddr == 0);
    *pteaddr = (uint64_t)mfn << UXEN_PAGE_SHIFT |
	0x963; /* -G-DA--KWEV and avail2 */
#else
    volatile uint32_t *pteaddr = VA_TO_LINEAR_PTE((uintptr_t)va + offset);

#ifdef MEMCACHE_MAP_FULL
    ASSERT(pteaddr[0] == 0 && pteaddr[1] == 0);
#else
    if (pteaddr[0] & 1) {
        pteaddr[0] = 0;
        _WriteBarrier();
    }
#endif
    pteaddr[1] = (mfn >> (32 - UXEN_PAGE_SHIFT));
    _WriteBarrier();
    pteaddr[0] = mfn << UXEN_PAGE_SHIFT |
   	0x863; /* ---DA--KWEV and avail2 */
#endif

    return 0;
}

static int
memcache_unmap_mfn(void *va, uint32_t offset, mc_mfn_t mfn)
{
#ifdef __x86_64__
    volatile uint64_t *pteaddr = VA_TO_LINEAR_PTE((uintptr_t)va + offset);

    ASSERT(*pteaddr);
    *pteaddr = 0;
#else
    volatile uint32_t *pteaddr = VA_TO_LINEAR_PTE((uintptr_t)va + offset);

    ASSERT(pteaddr[0]);
    pteaddr[0] = 0;
    _WriteBarrier();
    pteaddr[1] = 0;
#endif

    return 0;
}

void *
memcache_enter(mc_mfn_t mfn)
{
    uint8_t idx;
    uint32_t offset;
    struct memcache_desc *mc;
    void *va = NULL;

    KeAcquireSpinLockAtDpcLevel(&memcache_lock);
    if (memcache_mfn_to_entry[mfn] != MEMCACHE_MFN_ENTRY_EMPTY) {
#ifndef MEMCACHE_MAP_FULL
        memcache_entry_get(mfn);
#endif
	KeReleaseSpinLockFromDpcLevel(&memcache_lock);
        va = memcache_lookup(mfn);
        BUG_ON(!va);
        return va;
    }

#ifdef MEMCACHE_MAP_FULL
    uxen_info->ui_memcache_needs_check++;
    while (memcache_next_idx != MEMCACHE_MAX_IDX) {
	idx = memcache_next_idx;
	mc = memcaches[idx];
	ASSERT(mc);
	if (mc == NULL)
	    goto out;
	while (mc->md_first_free_offset < memcache_md_free_size &&
	       mc->md_free[mc->md_first_free_offset] == 0)
	    mc->md_first_free_offset++;
	if (mc->md_first_free_offset != memcache_md_free_size) {
	    offset = ffs64less1(mc->md_free[mc->md_first_free_offset]);
	    mc->md_free[mc->md_first_free_offset] &=
		~(1ULL << offset);
	    offset += mc->md_first_free_offset << MEMCACHE_MD_FREE_SHIFT;
	    memcache_space--;
	    if (memcache_map_mfn(mc->md_va, offset << PAGE_SHIFT, mfn))
		goto out;
	    MemoryBarrier();
	    memcache_mfn_to_entry[mfn] = idx +
		(offset << MEMCACHE_OFFSET_SHIFT);
            va = mc->md_va + (offset << PAGE_SHIFT);
            goto out;
	}
	memcache_next_idx++;
    }
#else
    idx = 0;
    mc = memcaches[idx];
    ASSERT(mc);
    if (mc == NULL)
        goto out;
    offset = mc->md_next_offset;
    if (mc->mapped_pfn[offset] != ~0U) {
        uint32_t clear_offset;
        int cleared = 0;
        while (memcache_entry_clear(mc->mapped_pfn[offset])) {
            offset++;
            if (offset >= memcache_pfn_per_idx)
                offset = 0;
            BUG_ON(offset == mc->md_next_offset);
        }
        clear_offset = offset + 1;
        if (clear_offset >= memcache_pfn_per_idx)
            clear_offset = 0;
#define WANT_CLEARED 256
        while (cleared < WANT_CLEARED && clear_offset != mc->md_next_offset) {
            if (mc->mapped_pfn[clear_offset] != ~0U &&
                !memcache_entry_clear(mc->mapped_pfn[clear_offset])) {
                memcache_unmap_mfn(mc->md_va, clear_offset << PAGE_SHIFT,
                                   mc->mapped_pfn[clear_offset]);
                mc->mapped_pfn[clear_offset] = ~0U;
                memcache_space++;
            }
            clear_offset++;
            if (clear_offset >= memcache_pfn_per_idx)
                clear_offset = 0;
            cleared++;
        }
        MemoryBarrier();
        uxen_mem_tlb_flush();
    }
    if (memcache_map_mfn(mc->md_va, offset << PAGE_SHIFT, mfn))
        goto out;
    if (mc->mapped_pfn[offset] == ~0U)
        memcache_space--;
    mc->mapped_pfn[offset] = mfn;
    MemoryBarrier();
    memcache_mfn_to_entry[mfn] = idx + (offset << MEMCACHE_OFFSET_SHIFT) +
        (1 << MEMCACHE_COUNT_SHIFT);
    va = mc->md_va + (offset << PAGE_SHIFT);
    offset++;
    if (offset >= memcache_pfn_per_idx)
        offset = 0;
    mc->md_next_offset = offset;
#endif

  out:
    KeReleaseSpinLockFromDpcLevel(&memcache_lock);
    return va;
}

#ifndef MEMCACHE_MAP_FULL
mc_mfn_t
memcache_get_mfn(const void *va)
{
    struct memcache_desc *mc;
    uint32_t offset;

    mc = memcaches[0];
    if ((uint8_t *)va < mc->md_va ||
        (uint8_t *)va >= mc->md_va + (memcache_pfn_per_idx << PAGE_SHIFT)) {
        dprintk("%s: va %p out of bounds %p - %p\n", __FUNCTION__, va,
                mc->md_va, mc->md_va + (memcache_pfn_per_idx << PAGE_SHIFT));
        return -1;
    }
    offset = ((uint8_t *)va - mc->md_va) >> PAGE_SHIFT;
    return mc->mapped_pfn[offset];
}
#endif

static void *
memcache_allocate_va(uint32_t num)
{
    PMDL mdl;
    PFN_NUMBER *pfn;
    void *va;
    unsigned int i;
    int failed = 1;

    va = MmAllocateMappingAddress(num << PAGE_SHIFT, UXEN_MAPPING_TAG);
    if (va == NULL) {
        fail_msg("MmAllocateMappingAddress failed: %d pages", num);
        return NULL;
    }

    mdl = ExAllocatePoolWithTag(
        NonPagedPool, sizeof(MDL) + sizeof(PFN_NUMBER) * num,
        UXEN_POOL_TAG);
    if (mdl == NULL) {
        fail_msg("ExAllocatePoolWithTag failed: %d pfns", num);
        goto out;
    }
    memset(mdl, 0, sizeof(*mdl));

    mdl->Size = sizeof(MDL) + sizeof(PFN_NUMBER) * num;
    mdl->ByteCount = num << PAGE_SHIFT;
    mdl->MdlFlags = MDL_PAGES_LOCKED;

    pfn = MmGetMdlPfnArray(mdl);
    for (i = 0; i < num; i++)
        pfn[i] = uxen_zero_mfn;

    if (MmMapLockedPagesWithReservedMapping(va, UXEN_MAPPING_TAG, mdl,
                                            MmCached))
        failed = 0;
    else
        fail_msg("MmMapLockedPagesWithReservedMapping failed: "
                 "%x pages at va %p", num, va);

    /* Clear va space even in failed case, since otherwise
     * MmFreeMappingAddress below can blue screen because the va space
     * is "dirty"  */
    for (i = 0; i < num; i++) {
#ifdef __x86_64__
        uint64_t *pteaddr = VA_TO_LINEAR_PTE((uintptr_t)va + (i << PAGE_SHIFT));
        *pteaddr = 0;
#else
        volatile uint32_t *pteaddr =
            VA_TO_LINEAR_PTE((uintptr_t)va + (i << PAGE_SHIFT));
        pteaddr[0] = 0;
        _WriteBarrier();
        pteaddr[1] = 0;
#endif
    }

    uxen_mem_tlb_flush();

  out:
    if (mdl)
        ExFreePoolWithTag(mdl, UXEN_POOL_TAG);
    if (failed && va) {
        MmFreeMappingAddress(va, UXEN_MAPPING_TAG);
        va = NULL;
    }
    return va;
}

uint64_t __cdecl
uxen_memcache_check(void)
{

    uxen_info->ui_memcache_needs_check = 0;
    return !memcaches[MEMCACHE_MAX_IDX - 1] && memcache_space < 2048;
}

struct memcache_desc *
alloc_mc(KIRQL *irql)
{
    struct memcache_desc *mc;

#ifdef MEMCACHE_MAP_FULL
    mc = kernel_malloc(sizeof(struct memcache_desc) + memcache_md_free_size *
                       MEMCACHE_MD_FREE_BITS);
#else
    mc = kernel_malloc(sizeof(struct memcache_desc) + sizeof(uint32_t) *
                       memcache_pfn_per_idx);
#endif
    if (mc == NULL)
        goto out;
    KeReleaseSpinLock(&memcache_lock, *irql);
    mc->md_va = memcache_allocate_va(memcache_pfn_per_idx);
    KeAcquireSpinLock(&memcache_lock, irql);
    if (mc->md_va == NULL) {
#ifdef MEMCACHE_MAP_FULL
        kernel_free(mc, sizeof(struct memcache_desc) +
                    memcache_md_free_size * MEMCACHE_MD_FREE_BITS);
#else
        kernel_free(mc, sizeof(struct memcache_desc) +
                    sizeof(uint32_t) * memcache_pfn_per_idx);
#endif
        mc = NULL;
        goto out;
    }

  out:
    return mc;
}

void
memcache_ensure_space(void)
{
    uint32_t idx;
    struct memcache_desc *mc;
    KIRQL irql;

  again:
    KeAcquireGuardedMutex(&memcache_mutex);
    KeAcquireSpinLock(&memcache_lock, &irql);

    if (memcaches[MEMCACHE_MAX_IDX - 1])
        goto out;

    for (idx = memcache_next_idx; memcache_space < 2048 &&
         idx != MEMCACHE_MAX_IDX; idx++) {
        mc = memcaches[idx];
        if (mc)
            continue;
        mc = alloc_mc(&irql);
        if (!mc) {
            LARGE_INTEGER delay;
            LONG pri;
            NTSTATUS status;
            KeReleaseSpinLock(&memcache_lock, irql);
            KeReleaseGuardedMutex(&memcache_mutex);
            mm_dprintk("memcache_ensure_space alloc failed\n");
            delay.QuadPart = -TIME_MS(50);
            pri = KeSetBasePriorityThread(KeGetCurrentThread(), LOW_VCPUTHREAD_PRI);
            status = KeDelayExecutionThread(KernelMode, FALSE, &delay);
            KeSetBasePriorityThread(KeGetCurrentThread(), pri);
            if (status != STATUS_SUCCESS)
                return;
            goto again;
        }
        memcaches[idx] = mc;
#ifdef MEMCACHE_MAP_FULL
        memset(mc->md_free, 0xff,
               memcache_md_free_size * MEMCACHE_MD_FREE_BYTES);
        mc->md_first_free_offset = 0;
#else
        memset(mc->mapped_pfn, 0xff, sizeof(uint32_t) * memcache_pfn_per_idx);
        mc->md_next_offset = 0;
#endif
        dprintk("memcache: allocated idx %d at %p\n", idx, mc->md_va);
#ifdef MEMCACHE_MAP_FULL
        memcache_space += memcache_md_free_size * MEMCACHE_MD_FREE_BITS;
        memcache_capacity += memcache_md_free_size * MEMCACHE_MD_FREE_BITS;
#else
        memcache_space += memcache_pfn_per_idx;
        memcache_capacity += memcache_pfn_per_idx;
#endif
    }

  out:
    KeReleaseSpinLock(&memcache_lock, irql);
    KeReleaseGuardedMutex(&memcache_mutex);
}

static void
memcache_clear_locked(mc_mfn_t mfn)
{
    uint8_t idx;
    uint32_t offset;
    struct memcache_desc *mc;

    BUG_ON(mfn >= uxen_info->ui_max_page);
    offset = memcache_mfn_to_entry[mfn];
    if (offset == MEMCACHE_MFN_ENTRY_EMPTY)
	return;

#ifndef MEMCACHE_MAP_FULL
    if (((offset & MEMCACHE_COUNT_MASK) >> MEMCACHE_COUNT_SHIFT) > 1)
        dprintk("%s: entry for mfn %x has count %d\n", __FUNCTION__, mfn,
                (offset & MEMCACHE_COUNT_MASK) >> MEMCACHE_COUNT_SHIFT);
#endif

    memcache_mfn_to_entry[mfn] = MEMCACHE_MFN_ENTRY_EMPTY;
    MemoryBarrier();

    idx = offset & MEMCACHE_INDEX_MASK;
    offset &= MEMCACHE_OFFSET_MASK;
#if PAGE_SHIFT >= MEMCACHE_OFFSET_SHIFT
    offset <<= (PAGE_SHIFT - MEMCACHE_OFFSET_SHIFT);
#else
    offset >>= (MEMCACHE_OFFSET_SHIFT - PAGE_SHIFT);
#endif

    mc = memcaches[idx];
    memcache_unmap_mfn(mc->md_va, offset, mfn);
    offset >>= PAGE_SHIFT;
#ifdef MEMCACHE_MAP_FULL
    mc->md_free[offset >> MEMCACHE_MD_FREE_SHIFT] |=
	(1ULL << (offset & MEMCACHE_MD_FREE_MASK));
    if ((offset >> MEMCACHE_MD_FREE_SHIFT) < mc->md_first_free_offset) {
	mc->md_first_free_offset = offset >> MEMCACHE_MD_FREE_SHIFT;
	if (idx < memcache_next_idx)
	    memcache_next_idx = idx;
    }
#else
    mc->mapped_pfn[offset] = ~0U;
#endif
    memcache_space++;
}

#if 0
static void
memcache_clear(mc_mfn_t mfn)
{
    KIRQL irql;

    KeAcquireSpinLock(&memcache_lock, &irql);

    memcache_clear_locked(mfn);

    KeReleaseSpinLock(&memcache_lock, irql);
}
#endif

void
memcache_clear_batch(uint32_t nr_pages, uintptr_t *mfn_list)
{
    uint32_t i;
    KIRQL irql;

    KeAcquireSpinLock(&memcache_lock, &irql);

    for (i = 0; i < nr_pages; i++)
        memcache_clear_locked((mc_mfn_t)mfn_list[i]);
    uxen_mem_tlb_flush();

    KeReleaseSpinLock(&memcache_lock, irql);
}

int
memcache_clear_cache(struct memcache_desc *mc)
{
#ifdef MEMCACHE_MAP_FULL
    uint8_t idx;
    uint32_t b;
#endif
    uint32_t offset;
    KIRQL irql;
    int count = 0;

    KeAcquireGuardedMutex(&memcache_mutex);
    KeAcquireSpinLock(&memcache_lock, &irql);

    offset = 0;
#ifdef MEMCACHE_MAP_FULL
    while (offset < memcache_md_free_size) {
	if (mc->md_free[offset] == ~0) {
	    offset++;
	    continue;
	}
	b = ffs64less1(~(mc->md_free[offset]));
	mc->md_free[offset] |= (1ULL << b);
	b += offset << MEMCACHE_MD_FREE_SHIFT;
	memcache_unmap_mfn(mc->md_va, b << PAGE_SHIFT, 0 /* ignored */);
	count++;
    }
#else
    while (offset < memcache_pfn_per_idx) {
        if (mc->mapped_pfn[offset] != ~0U) {
            memcache_unmap_mfn(mc->md_va, offset << PAGE_SHIFT,
                               0 /* ignored */);
            count++;
            mc->mapped_pfn[offset] = ~0U;
        }
        offset++;
    }
#endif

    uxen_mem_tlb_flush();

    KeReleaseSpinLock(&memcache_lock, irql);
    KeReleaseGuardedMutex(&memcache_mutex);

    return count;
}

int
memcache_init(void)
{
    int ret = 0;
    int nr_pages;

    KeInitializeGuardedMutex(&memcache_mutex);
    KeInitializeSpinLock(&memcache_lock);

    memset(memcaches, 0, sizeof(memcaches));

    memcache_mfn_to_entry =
	kernel_malloc(uxen_info->ui_max_page * sizeof(memcache_mfn_entry_t));
    if (memcache_mfn_to_entry == NULL) {
#ifdef DEBUG_PAGE_ALLOC
        BUG_ON(TRUE);
#endif /* DEBUG_PAGE_ALLOC */
        fail_msg("failed to allocate %x bytes",
                 uxen_info->ui_max_page * sizeof(memcache_mfn_entry_t));
	ret = -1;
	goto out;
    }
    memset((uint8_t *)memcache_mfn_to_entry, 0xff,
	   uxen_info->ui_max_page * sizeof(memcache_mfn_entry_t));

#ifdef MEMCACHE_MAP_FULL
    if (uxen_info->ui_max_page / MEMCACHE_MAX_IDX <
        (1 << MEMCACHE_OFFSET_BITS))
        memcache_pfn_per_idx = uxen_info->ui_max_page / MEMCACHE_MAX_IDX;
    else
        memcache_pfn_per_idx = (1ULL << MEMCACHE_OFFSET_BITS) - 1;
    memcache_md_free_size = memcache_pfn_per_idx / MEMCACHE_MD_FREE_BITS;
#else
    memcache_pfn_per_idx = (1ULL << MEMCACHE_OFFSET_BITS) - 1;
#endif
    dprintk("memcache: va per idx %lx\n", memcache_pfn_per_idx << PAGE_SHIFT);
    memcache_ensure_space();

    memcache_map_mdl = ExAllocatePoolWithTag(NonPagedPool, sizeof(MDL) +
					     sizeof(PFN_NUMBER) * 1,
					     UXEN_POOL_TAG);
    if (memcache_map_mdl == NULL) {
#ifdef DEBUG_PAGE_ALLOC
        BUG_ON(TRUE);
#endif /* DEBUG_PAGE_ALLOC */
        fail_msg("failed to allocate mdl");
	ret = -1;
	goto out;
    }
    memset(memcache_map_mdl, 0, sizeof(*memcache_map_mdl));
    memcache_map_mdl->Size = sizeof(MDL) + sizeof(PFN_NUMBER) * 1;
    memcache_map_mdl->ByteCount = 1 << PAGE_SHIFT;

  out:
    return ret;
}

void
memcache_free(void)
{
    uint32_t idx;
    struct memcache_desc *mc;
    int cleared = 0;

    for (idx = 0; idx != MEMCACHE_MAX_IDX; idx++) {
	if (memcaches[idx])
	    cleared += memcache_clear_cache(memcaches[idx]);
    }
    if (cleared)
	dprintk("memcache_free: cleared %d entries\n", cleared);
#if 0
    if (memcache_space + cleared != memcache_capacity)
	DbgBreakPoint();
#endif
    for (idx = 0; idx < MEMCACHE_MAX_IDX; idx++) {
	mc = memcaches[idx];
	if (mc == NULL)
	    break;
	MmFreeMappingAddress(mc->md_va, UXEN_MAPPING_TAG);
#ifdef MEMCACHE_MAP_FULL
	kernel_free(mc, sizeof(struct memcache_desc) + memcache_md_free_size *
		    MEMCACHE_MD_FREE_BITS);
#else
        kernel_free(mc, sizeof(struct memcache_desc) + sizeof(uint32_t) *
                    memcache_pfn_per_idx);
#endif
	memcaches[idx] = NULL;
    }
    if (memcache_mfn_to_entry) {
	kernel_free((uint8_t *)memcache_mfn_to_entry,
		    uxen_info->ui_max_page * sizeof(memcache_mfn_entry_t));
	memcache_mfn_to_entry = NULL;
    }
    if (memcache_map_mdl) {
	ExFreePoolWithTag(memcache_map_mdl, UXEN_POOL_TAG);
	memcache_map_mdl = NULL;
    }
}
