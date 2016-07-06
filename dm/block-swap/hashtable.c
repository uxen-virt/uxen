/*
 * Copyright 2013-2016, Bromium, Inc.
 * Author: Jacob Gorm Hansen <jacobgorm@gmail.com>
 * SPDX-License-Identifier: ISC
 */

#include <dm/config.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CUCKOO_HASHES 3

#include "hashtable.h"
#include "hashtable_noise.h"

static int insert(HashTable *ht, HashEntry *bounce);

static inline
uint32_t get_hash(uint32_t *noise, uint64_t x)
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
uint32_t hash_n(HashTable *ht, uint64_t in, int level)
{
    return get_hash(hashtable_noise[level],
            ht->seed ^ in) & ((1 << ht->bits) - 1);
}

static int rebuild(HashTable *ht, HashEntry bounce)
{
    int i;
    int retries = 0;

retry:
    if (5 * ht->load >= 4 * (1<<ht->bits) || retries++ > 5) {
        /* Double table size when 80% full. */
        size_t sz = sizeof(ht->table[0]) * (1 << ht->bits);
        ++(ht->bits);
        retries = 0;
        if (ht->alloc) {
            ht->table = ht->alloc(ht->table, 2 * sz, ht->data);
        } else {
            if (ht->bits <= HASHTABLE_START_BITS) {
                ht->table = ht->inline_table;
            } else if (ht->table == ht->inline_table) {
                void *t = malloc(2 * sz);
                memcpy(t, ht->table, sz);
                ht->table = t;
            } else {
                ht->table = realloc(ht->table, 2 * sz);
            }
            memset(((uint8_t *) ht->table) + sz, 0, sz);
        }
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
    if (insert(ht, &bounce)) {
        goto retry;
    }

    /* Rebuild hash table in-place, using newly seeded hash functions. */
    for (i = 0; i < (1 << ht->bits); ++i) {
        bounce = ht->table[i];

        if (bounce.present && hash_n(ht, bounce.key, bounce.level) != i) {
            ht->table[i].present = 0;
            if (insert(ht, &bounce)) {
                goto retry;
            }
        }

    }
    return 0;
}

int hashtable_init(HashTable *ht, HashAllocFn alloc, void *data)
{
    memset(ht, 0, sizeof(*ht));
    ht->alloc = alloc;
    ht->data = data;
    return 0;
}

/* You can use the reinit call with a custom allocator to fill in the hash
 * table from the start, e.g, when working over a mmap'ed table. */
int hashtable_reinit(HashTable *ht, int bits, HashAllocFn alloc, void *data)
{
    hashtable_init(ht, alloc, data);
    ht->bits = bits;
    ht->table = ht->alloc(NULL,
            sizeof(ht->table[0]) * (1 << ht->bits), ht->data);
    return ht->table ? 0 : -1;
}

void hashtable_clear(HashTable *ht)
{
    if (ht->alloc) {
        ht->alloc(ht->table, 0, ht->data);
    } else {
        if (ht->table != ht->inline_table) {
            free(ht->table);
        }
    }
    hashtable_init(ht, ht->alloc, ht->data);
}

static int insert(HashTable *ht, HashEntry *bounce)
{
    unsigned hash;
    bounce->level = 0;
    bounce->present = 1;
    hash = hash_n(ht, bounce->key, 0);
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
        hash = hash_n(ht, found.key, found.level);
        *bounce = found;

        /* If we detect an infinite loop we bounce back the last pushed out
         * element to the calling function, which will rebuild the hash table.
         * */
    }
    return 1;
}

int hashtable_insert(HashTable *ht, uint64_t key, uint64_t value)
{
    HashEntry bounce;
    bounce.key = key;
    bounce.value = value;
    ++(ht->load);
    if (!ht->bits || insert(ht, &bounce)) {
        if (rebuild(ht, bounce) < 0) {
            return -1;
        }
    }
    return 0;
}


HashEntry *hashtable_find_entry(HashTable *ht, uint64_t key)
{
    int i;
    if (ht->bits) {
        for (i = 0; i < CUCKOO_HASHES; ++i) {
            uint32_t hash = hash_n(ht, key, i);
            HashEntry *found = &ht->table[hash];
            if (found->key == key && found->present) {
                return found;
            }
        }
    }
    return NULL;
}

int hashtable_find(HashTable *ht, uint64_t key, uint64_t *value)
{
    HashEntry *found = hashtable_find_entry(ht, key);
    if (found) {
        *value = found->value;
        return 1;
    } else {
        return 0;
    }
}

void hashtable_delete_entry(HashTable *ht, HashEntry *found)
{
    found->level = 0;
    found->present = 0;
    if (--(ht->load) == 0) {
        hashtable_clear(ht);
    }
}

void hashtable_delete(HashTable *ht, uint64_t key)
{
    HashEntry *found = hashtable_find_entry(ht, key);
    if (found) {
        hashtable_delete_entry(ht, found);
    }
}
