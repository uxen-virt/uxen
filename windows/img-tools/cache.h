/*
 * Copyright 2011-2015, Bromium, Inc.
 * SPDX-License-Identifier: ISC
 */

#ifndef __CACHE_H__
#define __CACHE_H__

/* Cache with pseudo-LRU replacement. */
#define CACHE_SECTORSIZE (1<<14) /* size of disk sector to store */
#define CACHE_MAX_LINES 32

typedef struct CacheEntry {
    uint64_t block;
    void *sector;
} CacheEntry;

struct HashTable;
typedef struct Cache {
    struct Cache *next;
    struct HashTable *ht;
    CacheEntry *lines;
    unsigned int log_lines;
    char *bits;
    int compressAlways;
    void *buffer;
} Cache;

int cacheLookup(Cache *c, uint64_t block, void *out);
int cacheCheck(Cache *c, uint64_t block);
void cacheStore(Cache *c, uint64_t block, const void *sector);
void cacheUpdate(Cache *c, uint64_t block, const void *sector);
int cacheInit(Cache *c, unsigned int num_lines, Cache *next, int compressAlways);
void cacheFree(Cache *c);

#endif /* __CACHE_H__ */
