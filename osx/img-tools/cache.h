/*
 * Copyright 2013-2015, Bromium, Inc.
 * Author: Jacob Gorm Hansen <jacobgorm@gmail.com>
 * SPDX-License-Identifier: ISC
 */

#ifndef __CACHE_H__
#define __CACHE_H__

#include <block-swap/hashtable.h>

#define CACHE_SECTORSIZE (1<<12) /* size of disk sector to store */

typedef struct CacheEntry {
    uint64_t block;
    void *sector;
    int dirty;
} CacheEntry;

/* Cache with pseudo-LRU replacement. */

typedef struct Cache {
    HashTable ht;
    CacheEntry *lines;
    unsigned int log_lines;
    char *bits;
} Cache;

void *cachePeek(Cache *c, uint64_t block, int dirty);
void cacheStore(Cache *c, uint64_t block, const void *sector,
        int dirty, uint64_t *old, void **old_sector);
int cacheInit(Cache *c, unsigned int num_lines);
void cacheFree(Cache *c);
int cacheGetDirtyLine(Cache *c, int i, uint64_t *block, void **sector);

#endif /* __CACHE_H__ */
