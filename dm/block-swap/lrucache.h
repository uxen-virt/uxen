/*
 * Copyright 2014-2015, Bromium, Inc.
 * Author: Jacob Gorm Hansen <jacobgorm@gmail.com>
 * SPDX-License-Identifier: ISC
 */

#ifndef __FILECACHE_H__
#define __FILECACHE_H__

//#include "dubtree_io.h"

typedef struct LruCacheLine {
    uintptr_t key;
    uintptr_t value;
} LruCacheLine;

typedef struct LruCache {
    int log_lines;
    char *bits;
    LruCacheLine *lines;
} LruCache;

static inline int lruCacheInnerNodes(LruCache *fc)
{
    return (1 << fc->log_lines) - 1;
}

static inline int lruCacheInit(LruCache *fc, int log_lines)
{
    fc->log_lines = log_lines;
    fc->bits = calloc(lruCacheInnerNodes(fc), sizeof(char));
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
    free(fc->bits);
    free(fc->lines);
}

static inline void lruCacheClear(LruCache *fc)
{
    memset(fc->bits, 0, lruCacheInnerNodes(fc));
    memset(fc->lines, 0, (1 << fc->log_lines) * sizeof(LruCacheLine));
}

static inline
int lruCacheEvictLine(LruCache *fc)
{
    int i;
    int child;
    for (i = 0, child = 0; i < fc->log_lines; i++) {
        int parent = child;
        child = 2 * parent + 1 + fc->bits[parent];
        fc->bits[parent] ^= 1;
    }
    return child - lruCacheInnerNodes(fc);
}

static inline
LruCacheLine *lruCacheTouchLine(LruCache *fc, int line)
{
    /* Flip the bits in the reverse path from leaf to root */
    assert(line < (1 << fc->log_lines));
    LruCacheLine *cl = &fc->lines[line];
    int inner_nodes = lruCacheInnerNodes(fc);
    int child;
    for (child = line + inner_nodes; child != 0;) {
        int parent = (child - 1) / 2;

        fc->bits[parent] = (child == (2 * parent + 1));  /* inverse test to save xor */
        child = parent;
    }
    return cl;
}
#endif /* __FILECACHE_H__ */
