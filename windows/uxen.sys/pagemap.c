/*
 *  pagemap.c
 *  uxen
 *
 * Copyright 2016-2017, Bromium, Inc.
 * Author: Christian Limpach <Christian.Limpach@gmail.com>
 * SPDX-License-Identifier: ISC
 *
 */

#include "uxen.h"
#include "pagemap.h"

#include <stddef.h>

#include <xen/errno.h>

#define UXEN_DEFINE_SYMBOLS_PROTO
#include <uxen/uxen_link.h>

#define PAGEMAP_SPACE_SIZE (16 /* MB */ * 1024 * 1024 / PAGE_SIZE)

#define PAGEMAP_SLOTS_FREE_RESERVE 2048

// #define DEBUG_PAGEMAP

struct pagemap_space_key {
    uintptr_t va;
    uint32_t size;
};
struct pagemap_space {
    union {
        uintptr_t va;
        struct pagemap_space_key key;
    };
    struct rb_node rbnode;
#ifdef DEBUG_PAGEMAP
    int id;
#endif  /* DEBUG_PAGEMAP */
    uint32_t map[PAGEMAP_SPACE_SIZE / 32];
};

static struct pagemap_space **pagemap_spaces;
static int nr_spaces;

static uint16_t pagemap_next = 0;
static uint16_t pagemap_max = 0;
static uint16_t pagemap_slots_free = 0;

static KSPIN_LOCK pagemap_lock;

static intptr_t
space_compare_key(void *ctx, const void *b, const void *key)
{
    const struct pagemap_space * const pnp =
        (const struct pagemap_space * const)b;
    const struct pagemap_space_key * const fhp =
        (const struct pagemap_space_key * const)key;

    if (pnp->key.va >= fhp->va + fhp->size)
        return 1;
    else if (pnp->key.va + pnp->key.size <= fhp->va)
        return -1;
    return 0;
}

static intptr_t
space_compare_nodes(void *ctx, const void *parent, const void *node)
{
    const struct pagemap_space * const np =
        (const struct pagemap_space * const)node;

    return space_compare_key(ctx, parent, &np->key);
}

const rb_tree_ops_t space_rbtree_ops = {
    /* .rbto_compare_nodes = */ space_compare_nodes,
    /* .rbto_compare_key = */ space_compare_key,
    /* .rbto_node_offset = */ offsetof(struct pagemap_space, rbnode),
    /* .rbto_context = */ NULL
};

static rb_tree_t space_rbtree;

static int
alloc_next_space(void)
{
    struct pagemap_space *s;
    void *va;
    int n;
    KIRQL irql;

    s = (struct pagemap_space *)kernel_malloc(sizeof(struct pagemap_space));
    if (!s) {
        fail_msg("kernel_malloc(s) failed");
        return -ENOMEM;
    }

    va = kernel_alloc_va(PAGEMAP_SPACE_SIZE);
    if (!va) {
        kernel_free(s, sizeof(struct pagemap_space));
        fail_msg("kernel_alloc_va(s->va) failed");
        return -ENOMEM;
    }

    KeAcquireSpinLock(&pagemap_lock, &irql);

    if (pagemap_slots_free > PAGEMAP_SLOTS_FREE_RESERVE) {
        KeReleaseSpinLock(&pagemap_lock, irql);
        kernel_free_va(va, PAGEMAP_SPACE_SIZE);
        kernel_free(s, sizeof(struct pagemap_space));
        return 0;
    }

    n = pagemap_max / PAGEMAP_SPACE_SIZE;
    if (n >= nr_spaces) {
        KeReleaseSpinLock(&pagemap_lock, irql);
        kernel_free_va(va, PAGEMAP_SPACE_SIZE);
        kernel_free(s, sizeof(struct pagemap_space));
        fail_msg("all spaces allocated");
        return -EINVAL;
    }

    pagemap_spaces[n] = s;
    s->va = (uintptr_t)va;
    memset(s->map, 0, sizeof(uint32_t) * PAGEMAP_SPACE_SIZE / 32);

    s->key.size = PAGEMAP_SPACE_SIZE << PAGE_SHIFT;
    rb_tree_insert_node(&space_rbtree, s);

#ifdef DEBUG_PAGEMAP
    s->id = n;
#endif  /* DEBUG_PAGEMAP */

    pagemap_max += PAGEMAP_SPACE_SIZE;
    pagemap_slots_free += PAGEMAP_SPACE_SIZE;

    KeReleaseSpinLock(&pagemap_lock, irql);

    printk("pagemap: space %d va %p-%p\n", n, s->va,
           s->va + (PAGEMAP_SPACE_SIZE << PAGE_SHIFT));

    return 0;
}

int
pagemap_init(int max_pfn)
{
    int ret;

    BUILD_BUG_ON(PAGEMAP_SPACE_SIZE % 32);

    nr_spaces = (max_pfn + PAGEMAP_SPACE_SIZE - 1) / PAGEMAP_SPACE_SIZE;
    pagemap_spaces = (struct pagemap_space **)
        kernel_malloc(nr_spaces * sizeof(struct pagemap_space *));
    if (!pagemap_spaces) {
        fail_msg("kernel_malloc(pagemap_spaces) failed");
        return -ENOMEM;
    }

    rb_tree_init(&space_rbtree, &space_rbtree_ops);

    ret = alloc_next_space();
    if (ret)
        return ret;

    KeInitializeSpinLock(&pagemap_lock);

    return 0;
}

int
pagemap_free(void)
{
    struct pagemap_space *s;
    int n;

    n = pagemap_max / PAGEMAP_SPACE_SIZE;
    if (!n)
        return 0;

    while (n > 0) {
        n--;

        s = pagemap_spaces[n];
        if (!s)
            continue;

        if (s->va) {
            kernel_free_va((void *)s->va, PAGEMAP_SPACE_SIZE);
            s->va = 0;
        }

        kernel_free(s, sizeof(struct pagemap_space));
    }

    kernel_free(pagemap_spaces,
                nr_spaces * sizeof(struct pagemap_space *));

    return 0;
}

void *
pagemap_map_page(xen_pfn_t mfn)
{
    struct pagemap_space *s = NULL;
    uint16_t slot, first;
    uintptr_t va;

    KeAcquireSpinLockAtDpcLevel(&pagemap_lock);

    first = pagemap_next;
    /* the pagemap_next != first expression is evaluated before
     * pagemap_next is wrapped */
    if (!first)
        first = pagemap_max;
    do {
        if (pagemap_next == pagemap_max) {
            pagemap_next = 0;
            uxen_mem_tlb_flush();
        }
        if (!s || !(pagemap_next % PAGEMAP_SPACE_SIZE))
            s = pagemap_spaces[pagemap_next / PAGEMAP_SPACE_SIZE];
        slot = pagemap_next++ % PAGEMAP_SPACE_SIZE;
    } while (_interlockedbittestandset(s->map, slot) &&
             pagemap_next != first);

    if (pagemap_next == first) {
        fail_msg("out of space in host map");
        return NULL;
    }

    pagemap_slots_free--;
    if (pagemap_slots_free <= PAGEMAP_SLOTS_FREE_RESERVE)
        uxen_info->ui_pagemap_needs_check = 1;

    va = s->va + (slot << PAGE_SHIFT);
#ifdef DEBUG_PAGEMAP
    dprintk("%s: mfn %Ix va %p slot %d:%d\n", __FUNCTION__,
            (uint64_t)mfn, (void *)va, s->id, slot);
#endif  /* DEBUG_PAGEMAP */

    map_mfn(va, mfn);

    KeReleaseSpinLockFromDpcLevel(&pagemap_lock);
    return (void *)va;
}

uint64_t
pagemap_unmap_page_va(const void *va)
{
    struct pagemap_space *s;
    uint64_t pte;
    unsigned long mfn;
    uint16_t slot;

    KeAcquireSpinLockAtDpcLevel(&pagemap_lock);

    if (pagemap_max == PAGEMAP_SPACE_SIZE)
        s = pagemap_spaces[0];
    else {
        struct pagemap_space_key key;
        key.va = (uintptr_t)va;
        key.size = PAGE_SIZE;
        s = (struct pagemap_space *)
            rb_tree_find_node(&space_rbtree, &key);
        if (!s) {
            fail_msg("unmap of unknown va %p", va);
            KeReleaseSpinLockFromDpcLevel(&pagemap_lock);
            return -EINVAL;
        }
    }

    if ((uintptr_t)va < s->va ||
        (uintptr_t)va >= s->va + (PAGEMAP_SPACE_SIZE << PAGE_SHIFT)) {
        fail_msg("unmap of unknown va %p, not in %p - %p", va,
                 s->va, s->va + (PAGEMAP_SPACE_SIZE << PAGE_SHIFT));
        KeReleaseSpinLockFromDpcLevel(&pagemap_lock);
        return -EINVAL;
    }

    slot = ((uintptr_t)va - s->va) >> PAGE_SHIFT;
    ASSERT(slot < PAGEMAP_SPACE_SIZE);

    pte = map_mfn((uintptr_t)va, 0ULL);
    if (!(pte & 1/* _PAGE_PRESENT */))
        mfn = -1; /* INVALID_MFN */
    else
        mfn = (pte & ~0xffff000000000fff) >> PAGE_SHIFT;

    _bittestandreset(s->map, slot);
    pagemap_slots_free++;

#ifdef DEBUG_PAGEMAP
    dprintk("%s: mfn %Ix va %p slot %d:%d\n", __FUNCTION__,
            (uint64_t)mfn, (void *)va, s->id, slot);
#endif  /* DEBUG_PAGEMAP */
    KeReleaseSpinLockFromDpcLevel(&pagemap_lock);
    return mfn;
}

void
pagemap_check_space(void)
{

    uxen_info->ui_pagemap_needs_check = 0;
    if (pagemap_slots_free > PAGEMAP_SLOTS_FREE_RESERVE)
        return;

    alloc_next_space();
}
