/*
 * Copyright 2013-2015, Bromium, Inc.
 * Author: Jacob Gorm Hansen <jacobgorm@gmail.com>
 * SPDX-License-Identifier: ISC
 */

#ifndef __FILECACHE_H__
#define __FILECACHE_H__

#include "dubtree_io.h"

typedef struct FileCacheLine {
    uintptr_t key;
    uintptr_t file;
} FileCacheLine;

typedef struct FileCache {
    int log_lines;
    char *bits;
    FileCacheLine *lines;
} FileCache;

static inline int fileCacheInnerNodes(FileCache *fc)
{
    return (1 << fc->log_lines) - 1;
}

static inline int fileCacheInit(FileCache *fc, int log_lines)
{
    fc->log_lines = log_lines;
    fc->bits = calloc(fileCacheInnerNodes(fc), sizeof(char));
    if (!fc->bits) {
        return -1;
    }
    fc->lines = calloc(1 << fc->log_lines, sizeof(FileCacheLine));
    if (!fc->lines) {
        free(fc->bits);
        return -1;
    }
    return 0;
}

static inline void fileCacheClose(FileCache *fc)
{
    free(fc->bits);
    free(fc->lines);
}

static inline
int fileCacheEvictLine(FileCache *fc)
{
    int i;
    int child;
    for (i = 0, child = 0; i < fc->log_lines; i++) {
        int parent = child;
        child = 2 * parent + 1 + fc->bits[parent];
        fc->bits[parent] ^= 1;
    }
    return child - fileCacheInnerNodes(fc);
}

static inline
FileCacheLine *fileCacheTouchLine(FileCache *fc, int line)
{
    /* Flip the bits in the reverse path from leaf to root */
    assert(line < (1 << fc->log_lines));
    FileCacheLine *cl = &fc->lines[line];
    int inner_nodes = fileCacheInnerNodes(fc);
    int child;
    for (child = line + inner_nodes; child != 0;) {
        int parent = (child - 1) / 2;

        fc->bits[parent] = (child == (2 * parent + 1));  /* inverse test to save xor */
        child = parent;
    }
    return cl;
}
#endif /* __FILECACHE_H__ */
