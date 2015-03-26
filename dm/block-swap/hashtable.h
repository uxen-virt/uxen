/*
 * Copyright 2012-2015, Bromium, Inc.
 * Author: Jacob Gorm Hansen <jacobgorm@gmail.com>
 * SPDX-License-Identifier: ISC
 */

#ifndef __HASHTABLE_H__
#define __HASHTABLE_H__

#include <stdint.h>
#include <stddef.h>

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
    size_t alloced_size;
    HashEntry *table; /* pointer to the actual hash table. */
    int bits; /* bit-width of current hash function. */
    uint64_t seed;
    int load;
} HashTable;

int hashtableInit(HashTable *ht, HashAllocFn, void *data);
int hashtableReinit(HashTable *ht, int bits, HashAllocFn, void *data);
int hashtableInsert(HashTable *ht, uint64_t key, uint64_t value);
int hashtableFind(HashTable *ht, uint64_t key, uint64_t *value);
void hashtableDelete(HashTable *ht, uint64_t key);
void hashtableClear(HashTable *ht);

#endif /* __HASHTABLE_H__ */
