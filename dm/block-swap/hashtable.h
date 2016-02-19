/*
 * Copyright 2012-2016, Bromium, Inc.
 * Author: Jacob Gorm Hansen <jacobgorm@gmail.com>
 * SPDX-License-Identifier: ISC
 */

#ifndef __HASHTABLE_H__
#define __HASHTABLE_H__

#include <stdint.h>
#include <stddef.h>

#define HASHTABLE_START_BITS 2

typedef struct HashEntry {
    /* a hash table entry. The level decides which hash function to use, and is
     * increased modulo 3 every time an element gets kicked to another
     * location. */
    uint8_t present;
    uint8_t level;
    uint64_t key;
    uint64_t value;
} __attribute__((__packed__)) HashEntry;

typedef void *(*HashAllocFn) (void *, size_t, void *);

typedef struct HashTable {
    HashAllocFn alloc;
    void *data;
    HashEntry inline_table[1 << HASHTABLE_START_BITS];
    HashEntry *table; /* pointer to the actual hash table. */
    int bits; /* bit-width of current hash function. */
    uint64_t seed;
    int load;
} HashTable;

int hashtable_init(HashTable *ht, HashAllocFn, void *data);
int hashtable_reinit(HashTable *ht, int bits, HashAllocFn alloc, void *data);
int hashtable_insert(HashTable *ht, uint64_t key, uint64_t value);
HashEntry *hashtable_find_entry(HashTable *ht, uint64_t key);
int hashtable_find(HashTable *ht, uint64_t key, uint64_t *value);
void hashtable_delete_entry(HashTable *ht, HashEntry *found);
void hashtable_delete(HashTable *ht, uint64_t key);
void hashtable_clear(HashTable *ht);

#endif /* __HASHTABLE_H__ */
