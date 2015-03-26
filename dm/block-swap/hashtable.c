/*
 * Copyright 2013-2015, Bromium, Inc.
 * Author: Jacob Gorm Hansen <jacobgorm@gmail.com>
 * SPDX-License-Identifier: ISC
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CUCKOO_HASHES 3

#include "hashtable.h"
#include "hashtable_noise.h"

static int hashtableInsert2(HashTable *ht, HashEntry *bounce);

static inline
uint32_t getHash(uint32_t *noise, uint64_t x)
{
    int i;
    uint32_t h = 0;

    for (i = 0; i < sizeof(x); ++i) {
        h ^= noise[0x100 * i + (x&0xff)];
        x >>= 8;
    }
    return h;
}

static inline 
uint32_t HashN(HashTable *ht, uint64_t in, int level)
{
    return getHash(hashtable_noise[level],
            ht->seed ^ in) & ((1 << ht->bits) - 1);
}

static int hashtableRebuild(HashTable *ht, HashEntry bounce)
{
    int i;
    int retries = 0;

retry:
    if (5 * ht->load >= 4 * (1<<ht->bits) || retries++ > 5) {
        /* Double table size when 80% full. */
        ++(ht->bits);
        retries = 0;
        ht->table = (HashEntry*) ht->alloc(ht->table,
                sizeof(HashEntry) * (1 << ht->bits), ht->data);
        if (!ht->table) {
            return -1;
        }
    }

    /* Keep rebuilding hash table inline, until no more bounces.
       We know the table has space, so we should succeed eventually. If not
       we will hit the max retries limit and double the table size.
     */
    ht->seed = 6364136223846793005ULL * ht->seed +
        1442695040888963407ULL;

    /* Take care of previously bounced element first. */
    if (hashtableInsert2(ht, &bounce)) {
        goto retry;
    }

    /* Rebuild hash table in-place, using newly seeded hash functions. */
    for (i = 0; i < (1 << ht->bits); ++i) {
        bounce = ht->table[i];

        if (bounce.present && HashN(ht, bounce.key, bounce.level) != i) {
            ht->table[i].present = 0;
            if (hashtableInsert2(ht, &bounce)) {
                goto retry;
            }
        }

    }
    return 0;
}

static void *hashtableDefaultAlloc(void *ptr, size_t sz, void *data)
{
    uint8_t *r = (uint8_t*) realloc(ptr, sz);
    size_t *old_sz = (size_t*) data;
    if (r && sz > *old_sz) {
        memset(r + *old_sz, 0, sz - *old_sz);
    }
    *old_sz = sz;
    return r;

}

int hashtableInit(HashTable *ht, HashAllocFn alloc, void *data)
{
    ht->load = 0;
    ht->seed = 0;
    if (alloc) {
        ht->alloc = alloc;
        ht->data = data;
    } else {
        ht->alloc = hashtableDefaultAlloc;
        ht->data = &ht->alloced_size;
        ht->alloced_size = 0;
    }
    ht->bits = 0;
    ht->table = NULL;
    return 0;
}

int hashtableReinit(HashTable *ht, int bits, HashAllocFn alloc, void *data)
{
    size_t sz;
    ht->bits = bits;
    ht->alloc = alloc ? alloc : hashtableDefaultAlloc;
    ht->data = data;

    sz = sizeof(HashEntry) * (1 << ht->bits);
    ht->table = (HashEntry*) ht->alloc(NULL, sz, ht->data);
    if (!ht->table) {
        return -1;
    }
    return 0;
}

void hashtableClear(HashTable *ht)
{
    ht->alloc(ht->table, 0, ht->data);
    ht->table = NULL;
    ht->bits = 0;
}

static int hashtableInsert2(HashTable *ht, HashEntry *bounce)
{
    unsigned hash;
    bounce->level = 0;
    bounce->present = 1;
    hash = HashN(ht, bounce->key, 0);
    int i;

    /* According to the litterature, maxloop should be set as alpha * log2(n).
     * Empirically alpha=5 yields optimum throughput. */
    for (i = 0; i < 5 * ht->bits; ++i) {
        HashEntry found = ht->table[hash];
        /* Insert the new emement here, collision or not. */
        ht->table[hash] = *bounce;

        if (!found.present) {
            /* No collision, done. */
            return 0;
        }

        /* This is a three-level cuckoo hash, so we wrap
         * around after CUCKOO_HASHES-1. */

        found.level = (found.level == CUCKOO_HASHES-1) ? 0 : found.level + 1;
        hash = HashN(ht, found.key, found.level);
        *bounce = found;

        /* If we detect an infinite loop we bounce back the last pushed out
         * element to the calling function, which will rebuild the hash table.
         * */
    }
    return 1;
}

int hashtableInsert(HashTable *ht, uint64_t key, uint64_t value)
{
    HashEntry bounce;
    bounce.key = key;
    bounce.value = value;
    ++(ht->load);
    if (!ht->bits || hashtableInsert2(ht, &bounce)) {
        if (hashtableRebuild(ht, bounce) < 0) {
            return -1;
        }
    }
    return 0;
}


int hashtableFind(HashTable *ht, uint64_t key, uint64_t *value)
{
    int i;
    if (ht->bits) {
        for (i = 0; i < CUCKOO_HASHES; ++i) {
            uint32_t hash = HashN(ht, key, i);
            HashEntry found = ht->table[hash];
            if (found.key == key && found.present) {
                *value = found.value;
                return 1;
            }
        }
    }

    return 0;
}

void hashtableDelete(HashTable *ht, uint64_t key)
{
    int i;
    if (ht->bits) {
        for (i = 0; i < CUCKOO_HASHES; ++i) {
            uint32_t hash = HashN(ht, key, i);
            HashEntry *found = &ht->table[hash];
            if (found->key == key && found->present) {
                found->level = 0;
                found->present = 0;
                break;
            }
        }
    }
    if (--(ht->load) == 0) {
        hashtableClear(ht);
    }
}
