/*
 * Copyright 2013-2016, Bromium, Inc.
 * Author: Jacob Gorm Hansen <jacobgorm@gmail.com>
 * SPDX-License-Identifier: ISC
 */

// #define STANDALONE 1

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <assert.h>

#include "cache.h"

#define INNER_NODES(c) ((1<<c->log_lines)-1)

static inline int cacheEvictLine(Cache *c)
{
    int i;
    int child;
    for (i = 0, child = 0; i < c->log_lines; i++) {
        int parent = child;
        child = 2 * parent + 1 + c->bits[parent];
        c->bits[parent] ^= 1;
    }
    return child - INNER_NODES(c);

}

static inline void cacheTouchLine(Cache *c, int line)
{
    /* Flip the bits in the reverse path from leaf to root */

    int child;
    for (child = line + INNER_NODES(c); child != 0;) {
        int parent = (child - 1) / 2;

        c->bits[parent] = (child == (2 * parent + 1));  /* inverse test to save xor */
        child = parent;
    }
}

/* Used before shutdown to flush dirty cache lines. */
int cacheGetDirtyLine(Cache *c, int i, uint64_t *block, void **sector)
{
    CacheEntry *ce = &c->lines[i];

    if (ce->dirty && ce->sector) {
        *block = ce->block;
        *sector = ce->sector;
        return 1;
    }
    return 0;
}

void *cachePeek(Cache *c, uint64_t block, int dirty)
{
    uint64_t line;
    if (hashtable_find(&c->ht, block, &line)) {
        CacheEntry *ce = &c->lines[line];
        cacheTouchLine(c, line);
        ce->dirty |= dirty;

        return ce->sector;
    }
    return NULL;
}


void cacheStore(Cache *c, uint64_t block, const void *sector,
        int dirty, uint64_t *old, void **old_sector)
{
    uint64_t line;
    CacheEntry *ce;
    void *s;

    /* Check for previously cached values to make this idempotent. */

    if (!hashtable_find(&c->ht, block, &line)) {
        line = cacheEvictLine(c);
        ce = &c->lines[line];

        if (ce->sector != NULL) {

            if (ce->dirty) {
                *old = ce->block;
                *old_sector = ce->sector;
            } else {
                free(ce->sector);
            }
            ce->sector = NULL;
            ce->dirty = 0;
            hashtable_delete(&c->ht, ce->block);
        }

        s = malloc(CACHE_SECTORSIZE);
        assert(s);
        memcpy(s, sector, CACHE_SECTORSIZE);

        ce->block = block;
        ce->sector = s;
        ce->dirty |= dirty;

        hashtable_insert(&c->ht, block, line);
        cacheTouchLine(c, line);
    } else {
        ce = &c->lines[line];
        ce->dirty |= dirty;
        memcpy(ce->sector, sector, CACHE_SECTORSIZE);
    }
}

int cacheInit(Cache *c, unsigned int log_lines)
{
    int i;
    size_t sz;

    c->log_lines = log_lines;

    c->bits = malloc(sizeof(*c->bits) * INNER_NODES(c));
    if ( c->bits == NULL) {
        return 0;
    }

    hashtable_init(&c->ht, NULL, NULL);
    sz = (1<<c->log_lines) * sizeof(CacheEntry);
    c->lines = (CacheEntry *) malloc(sz);

    if ( c->lines == NULL ) {
        free(c->bits);
        return 0;
    }

    memset(c->bits, 0, sizeof(*c->bits) * INNER_NODES(c));
    for (i = 0; i < (1<<c->log_lines); ++i) {
        CacheEntry *ce = &c->lines[i];
        ce->block = ~0ULL;
        ce->sector = NULL;
        ce->dirty = 0;
    }

    return 1;
}

void cacheFree(Cache *c)
{
    int i;

    /* Release all cache lines contents. */
    for (i = 0; i < 1 << c->log_lines; i++) {
        CacheEntry *ce = &c->lines[i];
        if (ce->sector) {
            free(ce->sector);
        }
    }
    free(c->lines);
    free(c->bits);
    hashtable_clear(&c->ht);
}

