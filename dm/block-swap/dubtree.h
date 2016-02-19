/*
 * Copyright 2012-2016, Bromium, Inc.
 * Author: Jacob Gorm Hansen <jacobgorm@gmail.com>
 * SPDX-License-Identifier: ISC
 */

#ifndef __DUBTREE_H__
#define __DUBTREE_H__

#if defined (QEMU_UXEN) || defined(LIBIMG)
#include <dm/config.h>
#else
#include "config.h"
#endif

#include "dubtree_constants.h"
#include "hashtable.h"
#include "lrucache.h"

#define DUBTREE_MAX_FALLBACKS 8

/* The per-instance in-memory representation of a dubtree. */

typedef struct DubTreeHeader {
    uint32_t magic, version;
    uint32_t dubtree_m;
    uint32_t dubtree_slot_size;
    uint32_t dubtree_max_levels;
    uint32_t dubtree_initialized;
    volatile uint64_t out_chunk;
    volatile uint64_t levels[DUBTREE_MAX_LEVELS];
} DubTreeHeader;

typedef void (*read_callback) (void *opaque, int result);
typedef void *(*malloc_callback) (void *opaque, size_t sz);
typedef void (*free_callback) (void *opaque, void *ptr);

typedef struct DubTree {
    critical_section write_lock;
    DubTreeHeader *header;
    volatile uint64_t *levels;

    char *fallbacks[DUBTREE_MAX_FALLBACKS + 1];
    critical_section cache_lock;
    HashTable ht;
    LruCache lru;
    int buffer_max;
    void *buffered;
    malloc_callback malloc_cb;
    free_callback free_cb;
    void *opaque;

} DubTree;

int dubtree_insert(DubTree *t, int numKeys, uint64_t* keys, uint8_t *values,
        uint32_t *sizes, int force_level);

void *dubtree_prepare_find(DubTree *t);
void dubtree_end_find(DubTree *t, void *ctx);

int dubtree_find(DubTree *t, uint64_t start, int num_keys,
        uint8_t *out, uint8_t *map, uint32_t *sizes,
        read_callback cb, void *opaque, void *ctx);

int dubtree_init(DubTree *t, char **fallbacks, malloc_callback malloc_cb,
    free_callback free_cb, void *opaque);
void dubtree_close(DubTree *t);
int dubtree_delete(DubTree *t);
void dubtree_quiesce(DubTree *t);
int dubtree_sanity_check(DubTree *t);

#endif /* __DUBTREE_H__ */
