/*
 * Copyright 2012-2015, Bromium, Inc.
 * Author: Jacob Gorm Hansen <jacobgorm@gmail.com>
 * SPDX-License-Identifier: ISC
 */

#ifndef __SIMPLETREE_H__
#define __SIMPLETREE_H__

#include "dubtree_sys.h"
#include "dubtree_constants.h"

#ifdef _WIN32
//#pragma pack(push, 1)
#endif

typedef uint32_t node_t;

typedef struct SIMPLETREEMETA {
    volatile node_t root;        /* root node offset */
    volatile node_t first;       /* leftmost leaf node offset */
    volatile int maxLevel;       /* Height of tree */
    volatile uint32_t magic;
    volatile uint32_t refCount;
    volatile uint64_t size;        /* How many bytes are addressed by this tree. */
    volatile uint64_t garbage;     /* How much slack space does the tree skip over. */
    volatile uint32_t n_versions;
    volatile uint64_t versions[DUBTREE_MAX_VERSIONS];
} SIMPLETREEMETA;

/* Per-instance tree handle. Most values are only relevant
 * during tree construction. */

typedef struct SIMPLETREE {
    node_t nodes[16];
    node_t prev;
    node_t m;
    uint8_t *mem;
    uint32_t magic;
    uint64_t transaction;
    volatile node_t *head;
    volatile node_t *freelist;

} SIMPLETREE;

typedef struct SIMPLETREEKEY {
    uint64_t key;
    uint64_t version;
} SIMPLETREEKEY;

typedef struct SIMPLETREEINTKEY {
    uint64_t id : 16;
    uint64_t key : 48;
} SIMPLETREEINTKEY;

typedef struct {
    uint64_t a;
    uint64_t b;
} SIMPLETREEVALUE;

typedef struct SIMPLETREERESULT {
    SIMPLETREEKEY key;
    SIMPLETREEVALUE value;
} SIMPLETREERESULT;

typedef struct SIMPLETREEITERATOR {
    size_t index;
    node_t node;
} SIMPLETREEITERATOR;

typedef struct SIMPLETREEINNERNODE {
    int count;
    SIMPLETREEINTKEY keys[SIMPLETREE_INNER_M];
    node_t children[SIMPLETREE_INNER_M + 1];
} SIMPLETREEINNERNODE ;

typedef struct SIMPLETREELEAFNODE {
    int count;
    node_t next;
    SIMPLETREEINTKEY keys[SIMPLETREE_LEAF_M];
    uint64_t values[SIMPLETREE_LEAF_M];
} SIMPLETREELEAFNODE ;

typedef enum {
    SIMPLETREENODE_FREE = 0,
    SIMPLETREENODE_META = 1,
    SIMPLETREENODE_INNER = 2,
    SIMPLETREENODE_LEAF = 3,
} SIMPLETREENODETYPE;

typedef struct SIMPLETREENODE {
    uint32_t type;
    uint64_t transaction;
    union {
        SIMPLETREEMETA mn;
        SIMPLETREELEAFNODE ln;
        SIMPLETREEINNERNODE in;
    } u;
} SIMPLETREENODE;

#ifdef _WIN32
//#pragma pack(pop)
#endif

static inline uint32_t simpletreeTransact(volatile uint64_t *tid)
{
    return ++(*tid);
}

void simpletreeGC(volatile node_t *head,
        volatile node_t *freelist,
        void *mem, volatile uint32_t *levels,
        size_t numLevels, uint64_t transaction, int max);

void simpletreeInit(SIMPLETREE *st, volatile node_t *head,
        volatile node_t *freelist, void *mem,
        uint64_t transaction);

void simpletreeClear(SIMPLETREE *st);
void simpletreeInsert(SIMPLETREE *st, uint64_t key, uint64_t version, 
        SIMPLETREEVALUE value);
SIMPLETREE *simpletreeMerge(SIMPLETREE* a, SIMPLETREE* b, uint64_t transaction);
void simpletreeFinish(SIMPLETREE *st, uint64_t size, uint64_t garbage);
int simpletreeFind(SIMPLETREE *st, uint64_t key, uint64_t version, SIMPLETREEITERATOR *it);

SIMPLETREE* simpletreeOpen(volatile node_t *mn, volatile node_t *head,
        volatile node_t *freelist,
        void *mem);

int simpletreeClose(SIMPLETREE *st, volatile node_t *mn);
void simpletreeReference(volatile node_t *mn, 
        SIMPLETREE *st, volatile node_t *head,
        volatile node_t *freelist, void *mem);

/* Free the per-process in-memory tree representation and
 * NULL the pointer to it to prevent future use. */

static inline void simpletreeRelease(SIMPLETREE** pst)
{
    free(*pst);
    *pst = NULL;
}

static inline size_t simpletreeNodeSize(void)
{
#if 0
    printf("szk %lx\n", sizeof(SIMPLETREEINTKEY));
    printf("szm %lx\n", sizeof(SIMPLETREEMETA));
    printf("szln %lx\n", sizeof(SIMPLETREELEAFNODE));
    printf("szin %lx\n", sizeof(SIMPLETREEINNERNODE));
    printf("sz %lx\n", sizeof(SIMPLETREENODE));
#endif
    assert(sizeof(SIMPLETREENODE) <= SIMPLETREE_NODESIZE);
    return SIMPLETREE_NODESIZE;
}


static inline SIMPLETREENODE* OFF2PTR(void *mem, node_t n)
{
    return (SIMPLETREENODE*) ((uint8_t*)mem + simpletreeNodeSize() * n);
}

static inline uint64_t simpletreeGetSize(const SIMPLETREE *st)
{
    SIMPLETREEMETA *meta = &OFF2PTR(st->mem, st->m)->u.mn;
    return meta->size;
}

static inline uint64_t simpletreeGetGarbage(const SIMPLETREE *st)
{
    SIMPLETREEMETA *meta = &OFF2PTR(st->mem, st->m)->u.mn;
    return meta->garbage;
}

static inline void simpletreeBegin(const SIMPLETREE *st, SIMPLETREEITERATOR *it)
{
    SIMPLETREEMETA *meta = &OFF2PTR(st->mem, st->m)->u.mn;
    it->node = meta->first;
    it->index = 0;
}

static inline void simpletreeNext(const SIMPLETREE *st, SIMPLETREEITERATOR *it)
{
    SIMPLETREELEAFNODE *n = &OFF2PTR(st->mem, it->node)->u.ln;
    if (++(it->index) == n->count) {
        it->node = n->next;
        it->index = 0;
    }
}

static inline int simpletreeAtEnd(const SIMPLETREE *st, SIMPLETREEITERATOR *it)
{
    return (it->node == 0);
}

static inline void simpletreeRead(const SIMPLETREE *st, SIMPLETREERESULT *r,
        SIMPLETREEITERATOR *it)
{
    uint64_t v;
    SIMPLETREEMETA *meta = &OFF2PTR(st->mem, st->m)->u.mn;
    const SIMPLETREELEAFNODE *n = &OFF2PTR(st->mem, it->node)->u.ln;
    const SIMPLETREEINTKEY *k = &n->keys[it->index];

    r->key.key = k->key;
    r->key.version = meta->versions[k->id];
    v = n->values[it->index];
    r->value.a = v >> 16ULL;
    r->value.b = v & 0xffff;
}

#endif /* __SIMPLETREE_H__ */
