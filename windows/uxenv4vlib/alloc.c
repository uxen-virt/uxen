/*
 * Copyright 2016, Bromium, Inc.
 * SPDX-License-Identifier: ISC
 */

#include "uxenv4vlib_private.h"

#define USE_PREALLOCATION
//#define DEBUG_ALLOC_STATS

#define PREALLOC_BLOCKS 8
#define BLOCK_SIZE 4096
#define PREALLOC_BLK_TAG 'v4vp'

struct xenv4v_prealloc_block {
    void *data;
    uint8_t used;
};

#ifdef DEBUG_ALLOC_STATS

struct alloc_stats {
    uint32_t num_allocs;
    uint32_t num_pooled_allocs;
    uint32_t num_used;
    uint32_t peak_used;
};
static struct alloc_stats stats;
static void dump_alloc_stats();

#endif /* DEBUG_ALLOC_STATS */

static NTSTATUS
uxen_v4v_preallocate(xenv4v_extension_t *pde)
{
    int i;

    pde->prealloc_area = ExAllocatePoolWithTag(
        NonPagedPool,
        BLOCK_SIZE * PREALLOC_BLOCKS,
        PREALLOC_BLK_TAG);
    if (!pde->prealloc_area) {
        TraceError(("failed to preallocate memory\n"));
        return STATUS_NO_MEMORY;
    }

    pde->prealloc_blocks = ExAllocatePoolWithTag(
        NonPagedPool,
        sizeof(struct xenv4v_prealloc_block) * PREALLOC_BLOCKS,
        XENV4V_TAG);
    if (!pde->prealloc_blocks) {
        TraceError(("failed to preallocate memory\n"));
        ExFreePoolWithTag(pde->prealloc_area, PREALLOC_BLK_TAG);
        pde->prealloc_area = NULL;
        return STATUS_NO_MEMORY;
    }

    for (i = 0; i < PREALLOC_BLOCKS; ++i) {
        pde->prealloc_blocks[i].used = 0;
        pde->prealloc_blocks[i].data =
            (uint8_t*)pde->prealloc_area + i * BLOCK_SIZE;
    }

    return STATUS_SUCCESS;
}

void
uxen_v4v_free_preallocation(xenv4v_extension_t *pde)
{
    KIRQL irq;

    KeAcquireSpinLock(&pde->alloc_lock, &irq);
    if (pde->prealloc_blocks) {
        ExFreePoolWithTag(pde->prealloc_blocks, XENV4V_TAG);
        pde->prealloc_blocks = NULL;
    }
    if (pde->prealloc_area) {
        ExFreePoolWithTag(pde->prealloc_area, PREALLOC_BLK_TAG);
        pde->prealloc_area = NULL;
    }

    KeReleaseSpinLock(&pde->alloc_lock, irq);
}

#ifdef USE_PREALLOCATION

static struct xenv4v_prealloc_block *
find_free_block(xenv4v_extension_t *pde)
{
    int i;

    for (i = 0; i < PREALLOC_BLOCKS; ++i) {
        struct xenv4v_prealloc_block *b = &pde->prealloc_blocks[i];

        if (!b->used)
            return b;
    }

    return NULL;
}

static struct xenv4v_prealloc_block *
find_block_by_ptr(xenv4v_extension_t *pde, void *ptr)
{
    int i;

    for (i = 0; i < PREALLOC_BLOCKS; ++i) {
        struct xenv4v_prealloc_block *b = &pde->prealloc_blocks[i];

        if (b->data == ptr)
            return b;
    }

    return NULL;
}

#endif /* USE_PREALLOCATION */

void *
uxen_v4v_fast_alloc(SIZE_T nbytes)
{
#ifdef USE_PREALLOCATION
    xenv4v_extension_t *pde = uxen_v4v_get_pde();
    KIRQL irq;
    void *ptr = NULL;

    /* setup preallocation on 1st alloc */
    if (!pde->prealloc_blocks) {
        KeAcquireSpinLock(&pde->alloc_lock, &irq);
        if (!pde->prealloc_blocks)
            uxen_v4v_preallocate(pde);
        KeReleaseSpinLock(&pde->alloc_lock, irq);
    }

#ifdef DEBUG_ALLOC_STATS
    KeAcquireSpinLock(&pde->alloc_lock, &irq);
    stats.num_allocs++;
    KeReleaseSpinLock(&pde->alloc_lock, irq);
#endif

    if (nbytes <= BLOCK_SIZE) {
        struct xenv4v_prealloc_block *b;

        KeAcquireSpinLock(&pde->alloc_lock, &irq);
        b = find_free_block(pde);
        if (b) {
#ifdef DEBUG_ALLOC_STATS
            stats.num_used++;
            stats.num_pooled_allocs++;
            if (stats.num_used > stats.peak_used)
                stats.peak_used = stats.num_used;
#endif
            b->used = 1;
            ptr = b->data;
        }
        KeReleaseSpinLock(&pde->alloc_lock, irq);
    }
    uxen_v4v_put_pde(pde);

    return ptr ? ptr
               : ExAllocatePoolWithTag(NonPagedPool, nbytes, XENV4V_TAG);
#else  /* USE_PREALLOCATION */
    return ExAllocatePoolWithTag(NonPagedPool, nbytes,
                                 XENV4V_TAG);
#endif /* USE_PREALLOCATION */
}

void
uxen_v4v_fast_free(void *ptr)
{
#ifdef USE_PREALLOCATION
    xenv4v_extension_t *pde = uxen_v4v_get_pde();
    struct xenv4v_prealloc_block *b;
    KIRQL irq;

    if (!ptr)
        return;

    KeAcquireSpinLock(&pde->alloc_lock, &irq);

#ifdef DEBUG_ALLOC_STATS
    dump_alloc_stats();
#endif

    b = find_block_by_ptr(pde, ptr);
    if (b) {
        b->used = 0;
#ifdef DEBUG_ALLOC_STATS
        stats.num_used--;
#endif
    } else
        ExFreePoolWithTag(ptr, XENV4V_TAG);
    KeReleaseSpinLock(&pde->alloc_lock, irq);
    uxen_v4v_put_pde(pde);
#else /*  USE_PREALLOCATION */
    ExFreePoolWithTag(ptr, XENV4V_TAG);
#endif /* USE_PREALLOCATION */
}

/* --------- DEBUG ---------- */

#ifdef DEBUG_ALLOC_STATS

static void
dump_alloc_stats()
{
    static LARGE_INTEGER t0, t1, freq;

    t1 = KeQueryPerformanceCounter(&freq);
    if ((t1.QuadPart - t0.QuadPart) / freq.QuadPart < 1)
        return;
    t0 = t1;

    TraceWarning(("%s: alloc stats -------------\n", __FUNCTION__));
    if (stats.num_allocs) {
        int missed = stats.num_allocs - stats.num_pooled_allocs;

        TraceWarning(("%s: allocs %4d/sec (missed %4d = %2d perc), peak=%3d\n\n",
                      __FUNCTION__,
                      stats.num_allocs,
                      missed,
                      missed * 100 / stats.num_allocs,
                      stats.peak_used));

        stats.num_allocs = 0;
        stats.num_pooled_allocs = 0;
    }
}


#endif /* DEBUG_ALLOC_STATS */

