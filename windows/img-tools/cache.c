/*
 * Copyright 2011-2016, Bromium, Inc.
 * SPDX-License-Identifier: ISC
 */

// #define STANDALONE 1

#define _CRT_RAND_S
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <assert.h>
#include <windows.h>
#include <lz4.h>

#include <block-swap/hashtable.h>
#include "cache.h"

#define INNER_NODES(c) ((1<<c->log_lines)-1)

int cacheEvictLine(Cache *c)
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


void cacheTouchLine(Cache *c, int line)
{
    /* Flip the bits in the reverse path from leaf to root */

    int child;
    for (child = line + INNER_NODES(c); child != 0;) {
        int parent = (child - 1) / 2;

        c->bits[parent] = (child == (2 * parent + 1));  /* inverse test to save xor */
        child = parent;
    }
}


static size_t compress(void *out, const void *in)
{
    return LZ4_compress((const char *)in, (char *)out, CACHE_SECTORSIZE);
}


static void expand(void *out, const void *in)
{
    int rc = LZ4_decompress_fast((const char *)in, (char *)out,
                                 CACHE_SECTORSIZE);
    assert(rc >= 0);
}


int cacheCheck(Cache *c, uint64_t block)
{
    while (c) {
        uint64_t value;
        if (hashtable_find(c->ht, block, &value)) return 1;
        else c = c->next;
    }
    return 0;
}


int cacheLookup(Cache *c, uint64_t block, void *out)
{
    Cache *prev = NULL;
    while (c) {
        uint64_t line;
        if (hashtable_find(c->ht, block, &line)) {
            CacheEntry *ce = &c->lines[line];
            cacheTouchLine(c, line);

            if (c->compressAlways) {
                expand(out, ce->sector);
            } else {
                memcpy(out, ce->sector, CACHE_SECTORSIZE);
            }

            /* Promote to higher cache level if possible. */
            if (prev != NULL) {
                cacheStore(prev, block, out);
            }

            return 1;
        }
        prev = c;
        c = c->next;
    }
    return 0;
}


void cacheStore(Cache *c, uint64_t block, const void *sector)
{
    uint64_t line;
    CacheEntry *ce;
    void *s;

    /* Check for previously cached values to make this idempotent. */

    if (!hashtable_find(c->ht, block, &line)) {
        line = cacheEvictLine(c);
        ce = &c->lines[line];

        if (ce->sector != NULL) {

            if (c->next != NULL) {
                cacheStore(c->next, ce->block, ce->sector);
            }
            free(ce->sector);
            ce->sector = NULL;
            hashtable_delete(c->ht, ce->block);
        }

        if (c->compressAlways) {
            size_t sz;
            sz = compress(c->buffer, sector);
            s = malloc(sz);
            assert(s);
            memcpy(s, c->buffer, sz);
        } else {

            s = malloc(CACHE_SECTORSIZE);
            assert(s);
            memcpy(s, sector, CACHE_SECTORSIZE);

        }

        ce->block = block;
        ce->sector = s;

        hashtable_insert(c->ht, block, line);
        cacheTouchLine(c, line);
    }
}

int cacheInit(Cache *c, unsigned int log_lines, Cache *next, int compressAlways)
{
    int i;
    size_t sz;

    c->log_lines = log_lines;
    c->compressAlways = compressAlways;
    c->buffer = malloc(2 * CACHE_SECTORSIZE);
    c->next = next;

    c->bits = malloc(sizeof(*c->bits) * INNER_NODES(c));
    if ( c->bits == NULL) {
        return 0;
    }

    c->ht = (HashTable*) malloc(sizeof(HashTable));
    if ( c->ht == NULL) {
        return 0;
    }
    hashtable_init(c->ht, NULL, NULL);
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
    }

    return 1;
}

void cacheFree(Cache *c)
{
    while (c) {
        int i;

        /* Release all cache lines contents. */
        for (i = 0; i < 1 << c->log_lines; i++) {
            CacheEntry *ce = &c->lines[i];
            if (ce->sector) {
                free(ce->sector);
            }
        }
        free(c->lines);
        hashtable_clear(c->ht);
        free(c->ht);
        free(c->bits);

        c = c->next;
    }
}


#ifdef STANDALONE
FILE *file;

void readSector(Cache *c, uint64_t block, uint8_t *sector)
{

    void *s= cacheLookup(c, block);

    if (s) {

        /* Cache hit. */
        printf("hit\n");
        memcpy(sector, s, CACHE_SECTORSIZE);

    } else {
        /* Cache miss. */

        uint8_t sector[CACHE_SECTORSIZE];
        fseek(file, CACHE_SECTORSIZE * block, SEEK_SET);
        fread(sector, CACHE_SECTORSIZE, 1, file);

        cacheStore(c, block, sector);
    }

}

int main(int argc, char **argv)
{
    int i;
    Cache c;

    file = fopen("mft.raw", "rb");
    assert(file>=0);

    cacheInit(&c, 15);

    for (i = 0 ; i < 2; ++i) {

        int j;

        for (j = 0; j < 2000; ++j) {
            uint8_t sector[CACHE_SECTORSIZE];
            readSector(&c, j, sector);
        }
    }

    cacheFree(&c);
}
#endif
