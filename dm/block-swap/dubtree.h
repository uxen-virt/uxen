/*
 * Copyright 2012-2015, Bromium, Inc.
 * Author: Jacob Gorm Hansen <jacobgorm@gmail.com>
 * SPDX-License-Identifier: ISC
 */

#ifndef __DUBTREE_H__
#define __DUBTREE_H__

#ifndef _WIN32
#include <semaphore.h>
#endif

#include "dubtree_constants.h"
#include "hashtable.h"

#define DUBTREE_MAX_FALLBACKS 8

typedef struct DUBTREEVERSION {
    volatile uint64_t id;
    volatile uint64_t parent;
} DUBTREEVERSION;

/* The per-instance in-memory representation of a dubtree. */

struct COPYBUFFER;
struct HashTable;

typedef struct DUBTREE_HEADER {
    uint32_t magic, version;
    uint32_t dubtree_m;
    uint32_t dubtree_corelimit;
    uint32_t dubtree_max_levels;
    uint32_t dubtree_max_versions;
    uint32_t dubtree_max_treenodes;
    uint32_t dubtree_initialized;
    volatile uint32_t freeListHead;
    volatile uint64_t transaction;
    volatile int refcount;
    volatile uint64_t versions_generation;
} DUBTREE_HEADER;

typedef struct DUBTREE {
    volatile uint32_t *head;
    void *mem;
    DUBTREE_HEADER *header;
    volatile uint32_t *levels;
    volatile uint32_t *freelist;
    /* Handy pre-computed list of level data offsets. */
    uint64_t offsets[DUBTREE_MAX_LEVELS];
    void *versions;

    struct HashTable vht;
    uint64_t vht_generation;
    uint8_t *treeMem;
    uint64_t arraysOffset;
    uint8_t *data;
    struct COPYBUFFER *cb;
    char *fn;
    char *fallbacks[DUBTREE_MAX_FALLBACKS + 1];
    int is_mutable; // false if tree was sealed
#ifdef _WIN32
    HANDLE mutex;
    HANDLE file;
    HANDLE map;
#else
    int lockfile;
    char *mapping_name;
#endif
} DUBTREE;

typedef struct DUBTREECONTEXT {
    struct COPYBUFFER *cb;
    uint64_t path[32];
} DUBTREECONTEXT;

int dubtreeInsert(DUBTREE *t, int n, uint64_t *keys, uint64_t version,
        uint8_t *values, size_t *sizes);

DUBTREECONTEXT *dubtreePrepareFind(DUBTREE *t, uint64_t version);
int dubtreeFind(DUBTREE *t, uint64_t start, uint64_t numKeys,
        uint8_t *out, uint64_t *map, size_t *sizes, DUBTREECONTEXT *cx);
void dubtreeEndFind(DUBTREE *t, DUBTREECONTEXT *cx);

int dubtreeInit(DUBTREE *t, const char *fn, char **fallbacks);
void dubtreeClose(DUBTREE *t);
void dubtreeQuiesce(DUBTREE *t);
void dubtreeQuiesceFind(DUBTREE *t, DUBTREECONTEXT *cx);
int dubtreeSanityCheck(DUBTREE *t);

int dubtreeSeal(DUBTREE *t, int destLevel);

int dubtreeCreateVersion(DUBTREE *t, uint64_t id, uint64_t parent);
int dubtreeDeleteVersion(DUBTREE *t, uint64_t id);

#endif /* __DUBTREE_H__ */
