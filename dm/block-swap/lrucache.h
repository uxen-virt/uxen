/*
 * Copyright 2014-2016, Bromium, Inc.
 * Author: Jacob Gorm Hansen <jacobgorm@gmail.com>
 * SPDX-License-Identifier: ISC
 */

#ifndef __LRUCACHE_H__
#define __LRUCACHE_H__

typedef struct LruCacheLine {
    uintptr_t key;
    uintptr_t value;
    int users;
    int delete;
    int dirty;
} LruCacheLine;

typedef struct LruCache {
    int log_lines;
    char *bits;
    LruCacheLine *lines;
} LruCache;

static inline int lru_cache_innner_nodes(LruCache *fc)
{
    return (1 << fc->log_lines) - 1;
}

static inline int lru_cache_init(LruCache *fc, int log_lines)
{
    fc->log_lines = log_lines;
    fc->bits = calloc(lru_cache_innner_nodes(fc), sizeof(char));
    if (!fc->bits) {
        return -1;
    }
    fc->lines = calloc(1 << fc->log_lines, sizeof(LruCacheLine));
    if (!fc->lines) {
        free(fc->bits);
        return -1;
    }
    return 0;
}

static inline void lruCacheClose(LruCache *fc)
{
    int i;
    for (i = 0; i < (1<<fc->log_lines); ++i) {
        LruCacheLine *cl = &fc->lines[i];
        if (cl->users) {
            printf("leaked cache line %d\n", i);
        }
    }
    free(fc->bits);
    free(fc->lines);
}

static inline void lru_cache_clear(LruCache *fc)
{
    memset(fc->bits, 0, lru_cache_innner_nodes(fc));
    memset(fc->lines, 0, (1 << fc->log_lines) * sizeof(LruCacheLine));
}

static inline
int lru_cache_evict_line(LruCache *fc)
{
    int i;
    int child;
    for (i = 0, child = 0; i < fc->log_lines; i++) {
        int parent = child;
        child = 2 * parent + 1 + fc->bits[parent];
        fc->bits[parent] ^= 1;
    }
    return child - lru_cache_innner_nodes(fc);
}

static inline
LruCacheLine *lru_cache_touch_line(LruCache *fc, int line)
{
    /* Flip the bits in the reverse path from leaf to root */
    assert(line < (1 << fc->log_lines));
    LruCacheLine *cl = &fc->lines[line];
    int inner_nodes = lru_cache_innner_nodes(fc);
    int child;
    for (child = line + inner_nodes; child != 0;) {
        int parent = (child - 1) / 2;

        fc->bits[parent] = (child == (2 * parent + 1));  /* inverse test to save xor */
        child = parent;
    }
    return cl;
}

#endif /* __LRUCACHE_H__ */
