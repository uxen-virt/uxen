/*
 * Copyright 2012-2015, Bromium, Inc.
 * Author: Jacob Gorm Hansen <jacobgorm@gmail.com>
 * SPDX-License-Identifier: ISC
 */

#include "dubtree_sys.h"
#include "simpletree.h"

#ifdef _MSC_VER
#include <intrin.h>
#pragma intrinsic (_InterlockedDecrement)
#endif

#include <string.h>

/* B-tree node ids can max be 16 bits. */
#if DUBTREE_TREENODES > (1<<16)
#error "number of tree nodes too large for 16 bits"
#endif

static inline
void simpletreeFreeNode2(volatile node_t *head, volatile node_t *freelist,
        void *mem, node_t n)
{
    SIMPLETREENODE *nn = OFF2PTR(mem, n);
    node_t old_head;
    nn->transaction = 0;
    nn->type = SIMPLETREENODE_FREE; /* 0 */
    do {
        old_head = *head;
        freelist[n] = old_head & 0xffff;
        __sync_synchronize();

    } while (__sync_val_compare_and_swap(head, old_head, (old_head << 16) | n) != old_head);
}

static inline node_t simpletreeAllocNode(
        volatile node_t *head, volatile node_t *freelist,
        int tryhard)
{
    uint32_t h;
    node_t n;
    node_t next;
    int retries = 0;
    do {
retry:
        /* Read current head and mask out the next free node id. */
        h = *head;
        n = h & 0xffff;
        if (!n) {
            /* Out of nodes. This is bad. */
            if (tryhard) {
                /* GC (crash recovery) will temporarily alloc all the free
                 * nodes, but will be quick, so lets wait a little before we
                 * give up. */
                if (retries++ < 10) {
                    printf("swap: retry B-tree node allocation...\n");
#ifdef _WIN32
                    Sleep(1000);
#else
                    sleep(1);
#endif
                    goto retry;
                } else {
                    printf("swap: out of B-tree nodes (fatal)!\n");
                    assert(n);
                }
            } else {
                return 0;
            }
        }
        /* To combat the ABA problem, we combine the next and next->next node
         * numbers into a single 32-bit value. This only leaves space for 64k
         * nodes, unless we use a 64-bit CAS instead of the current 32-bit one.
         */
        next = (freelist[freelist[n]] << 16) | freelist[n];

    } while (!__sync_bool_compare_and_swap(head, h, next));
    return n;
}

static inline
void simpletreeSetNodeInfo(SIMPLETREE *st, node_t n,
        SIMPLETREENODETYPE type)
{
    SIMPLETREENODE *nn = OFF2PTR(st->mem, n);
    assert(nn->type == SIMPLETREENODE_FREE);
    nn->transaction = st->transaction;
    nn->type = type;
    __sync_synchronize();
}

static inline
void simpletreeFreeNode(SIMPLETREE *st, node_t n)
{
    int i;
    SIMPLETREENODE *nn = OFF2PTR(st->mem, n);
    if (nn->type == SIMPLETREENODE_INNER) {
        SIMPLETREEINNERNODE *in = &OFF2PTR(st->mem, n)->u.in;
        for (i = 0; i < in->count + 1; ++i) {
            if (in->children[i]) {
                simpletreeFreeNode(st, in->children[i]);
            }
        }
    }
    simpletreeFreeNode2(st->head, st->freelist, st->mem, n);
}

static inline void mark(void *mem, node_t n, uint8_t *vector)
{
    int i;
    SIMPLETREENODE *nn = OFF2PTR(mem, n);
    if (nn->type == SIMPLETREENODE_INNER) {
        SIMPLETREEINNERNODE *in = &OFF2PTR(mem, n)->u.in;
        for (i = 0; i < in->count + 1; ++i) {
            if (in->children[i]) {
                mark(mem, in->children[i], vector);
            }
        }
    }
    vector[n] = 1;
}

/* Recover nodes allocated by a crashed insert transaction. */
void simpletreeGC(volatile node_t *head, volatile node_t *freelist,
        void *mem, volatile uint32_t *levels,
        size_t numLevels, uint64_t transaction, int max)
{
    node_t n, mn;
    int i;
    uint8_t *marked;
    int num_free = 0;

    /* Better to just assert on mallocs here, to give another process the chance
     * of cleaning up, should we fail to do so. */
    marked = calloc(sizeof(uint8_t), max);
    assert(marked);

    /* If a transaction crashed there may be tree nodes that were allocated for
     * unfinished trees that are not referenced from anywhere. We'll do a
     * simple mark and sweep to find unreferenced nodes, and free the ones from
     * the failed transaction. */

    for (i = 0; i < numLevels; ++i) {
        mn = levels[i] & 0xffffff;
        if (mn) {
            SIMPLETREEMETA *meta = &OFF2PTR(mem, mn)->u.mn;
            marked[mn] = 1;
            assert(meta->magic == 0xfedeabe0);
            if (meta->root) {
                mark(mem, meta->root, marked);
            }
        }
    }

    /* Mark the nodes included in free list, so that we don't double free them.
     * If GC crashes half-way through, we will still get the correct behavior.
     * Stamp these nodes with the crashed transaction id, so that they will get
     * GC'ed even if we should crash before completion. */

    while ((n = simpletreeAllocNode(head, freelist, 0))) {
        OFF2PTR(mem, n)->transaction = transaction;
        ++num_free;
    }
    printf("swap: crash recovery with %d B-tree nodes free.\n", num_free);

    /* Now garbage collect nodes involved in the crashed transaction,
     * including the ones we just allocated. */
    for (n = 0; n < max; ++n) {
        SIMPLETREENODE *node = OFF2PTR((uint8_t*)mem, n);
        if (node->transaction == transaction) {
            if (!marked[n]) {
                simpletreeFreeNode2(head, freelist, mem, n);
            }
        }
    }
    free(marked);
    printf("swap: crash recovery done\n");
}

/* Free nodes in use by a tree. */
void simpletreeClear(SIMPLETREE *st)
{
    SIMPLETREEMETA *meta = &OFF2PTR(st->mem, st->m)->u.mn;
    node_t n = meta->root;

    if (n) simpletreeFreeNode(st, n);
    assert(meta->magic == 0xfedeabe0);
    meta->magic = 0xdeadbeef;
    assert(st->m);
    simpletreeFreeNode2(st->head, st->freelist, st->mem, st->m);
}

/* Create a SIMPLETREE instance and a meta node. May be released and freed via
 * simpletreeRelease(). */

void simpletreeInit(SIMPLETREE *st, volatile node_t *head,
        volatile node_t *freelist,
        void *mem,
        uint64_t transaction)
{
    SIMPLETREEMETA *meta;

    assert(st);
    st->magic = 0xcafebabe;
    st->head = head;
    st->freelist = freelist;
    st->mem = mem;
    st->transaction = transaction;
    st->prev = 0;

    memset(st->nodes, 0, sizeof(st->nodes));

    st->m = simpletreeAllocNode(st->head, st->freelist, 1);
    simpletreeSetNodeInfo(st, st->m, SIMPLETREENODE_META);

    meta = &OFF2PTR(st->mem, st->m)->u.mn;
    meta->maxLevel = 0;
    meta->first = 0;
    meta->magic = 0xfedeabe0;
    meta->refCount = 0;
    meta->size = 0;
    meta->garbage = 0;
    meta->n_versions = 0;
    __sync_synchronize();
}

/* Create a global-scoped reference to the tree's meta node. */
void simpletreeReference(volatile node_t *mn,
        SIMPLETREE *st, volatile node_t *head,
        volatile node_t *freelist,
        void *mem)
{
    SIMPLETREEMETA *meta;
    uint32_t was, is;
    int clear = 0;

    assert(st==NULL || st->m);

    do {
        was = *mn;

        if (was & 0xffffff) {
            /* There was a tree already at this level. */
            if ((was >> 24) > 1) {
                /* The tree that was previously referenced by 'mn' is still
                 * referenced by readers, and so needs to have its refcount
                 * migrated into the meta-data node. Because we are inside the
                 * CAS loop and will detect if 'was' changes under us, it is
                 * safe to update the migrated refcount non-atomically, as long
                 * as we make the update globally visible afterwards. */
                meta = &OFF2PTR(mem, was & 0xffffff)->u.mn;
                meta->refCount = (was >> 24) - 1;
                __sync_synchronize();
                clear = 0;
            } else {
                /* No readers hold references to the old tree, we can go ahead
                 * and free it. */
                clear = 1;
            }
        }

        /* Replace reference with meta-data node of new tree, and refcount of 1,
         * or if there is no new tree, null it. */
        is = st ? (st->m | (1<<24)) : 0;

    } while (__sync_val_compare_and_swap(mn, was, is) != was);
    assert(is & 0xffffff || st==NULL);

    /* content of *mn now points to new tree meta, and new tree
     * meta.replaces points to old meta, if any */

    if (clear) {
        /* We should clear the old tree. Set up a fake tree handle and
         * call simpletreeClear() on it. */
        SIMPLETREE tmp;
        tmp.m = was & 0xffffff;
        tmp.head = head;
        tmp.freelist = freelist;
        tmp.mem = mem;
        simpletreeClear(&tmp);
    }
}

/* Create a new SIMPLETREE instance wrapping the tree with meta node mn, in the
 * node space mem, with freelist starting at head. Assumes that mn already has
 * a non-zero refcount. Returns NULL if no tree at this level. XXX will assert
 * on malloc failure, we should change this to have the caller do the malloc,
 * but this will be wasteful for the common case of having no tree. */
SIMPLETREE* simpletreeOpen(volatile node_t *mn, volatile node_t *head,
        volatile node_t *freelist,
        void *mem)
{
    uint32_t was, is;
    node_t node;
    SIMPLETREE *st;
    SIMPLETREEMETA *meta;

    /* Increment refcount embedded in tree reference. Retry until CAS succeeds. */
    do {
        was = *mn;
        if ((was & 0xffffff) == 0) return NULL;
        is = was + (1<<24);
        assert((is>>24) < 100);
    } while (__sync_val_compare_and_swap(mn, was, is) != was);

    /* The actual node reference is in the lower 24 bits. */
    node = was & 0xffffff;

    st = (SIMPLETREE*) malloc(sizeof(SIMPLETREE));
    assert(st);
    memset(st, 0, sizeof(*st));
    st->magic = 0xcafebabe;

    st->freelist = freelist;
    st->mem = mem;

    meta = &OFF2PTR(st->mem, node)->u.mn;
    assert(meta);

    if (meta->magic!=0xfedeabe0){
        printf("swap: bad magic %x!\n",meta->magic);
    }
    assert(meta->magic == 0xfedeabe0);
    assert(meta->root != node);
    st->m = node;
    st->head = head;
    return st;
}

/* Close a SIMPLETREE handle, decreasing the refcount embedded in the reference
 * pointed to by "mn". Return true if the tree is no longer referenced by the
 * main index, to indicate to the caller that his lookup result may no longer
 * be valid. */
int simpletreeClose(SIMPLETREE *st, volatile node_t *mn)
{
    uint32_t was;
    uint32_t is;
    int invalidated;

    do {
        was = *mn;

        if ((was & 0xffffff) == st->m) {

            /* Tree is still referenced from the global dubtree, with the
             * refcount embedded in the reference.  Decrement this refcount and
             * set it using CAS.  Since being in the global index counts as
             * being referenced, we never have to clear the tree in this case.
             * The simpletreeReference() function will take of that situation
             * when overwriting the reference, if needed. */

            is = was - (1<<24);
            invalidated = 0;

        } else {

            /* Tree is no longer referenced from the global dubtree index, and
             * its refcount has been migrated to within the meta node.
             * Decrement this refcount, and clear the tree if we were the last
             * to use it. Because there is no globally visible reference, we
             * know that the refcount will not suddently increase under us. */

            SIMPLETREEMETA *meta = &OFF2PTR(st->mem, st->m)->u.mn;
            invalidated = 1;

#ifdef __GNUC__
            if (__sync_sub_and_fetch(&meta->refCount, 1) == 0) {
#else
            if (_InterlockedDecrement(&meta->refCount) == 0) {
#endif
                simpletreeClear(st);
            }
            goto out;

        }

    } while (__sync_val_compare_and_swap(mn, was, is) != was);

out:
    free(st);
    return invalidated;
}


/* Factory functions for the inner and leaf node types. */

static inline node_t simpletreeCreateInnerNode(SIMPLETREE *st)
{
    SIMPLETREEINNERNODE *n;
    node_t o = simpletreeAllocNode(st->head, st->freelist, 1);
    simpletreeSetNodeInfo(st, o, SIMPLETREENODE_INNER);
    n = &OFF2PTR(st->mem, o)->u.in;
    memset(n->children, 0, sizeof(n->children));
    n->count = 0;
    return o;
}

static inline node_t simpletreeCreateLeafNode(SIMPLETREE *st)
{
    SIMPLETREELEAFNODE *n;
    node_t o = simpletreeAllocNode(st->head, st->freelist, 1);
    simpletreeSetNodeInfo(st, o, SIMPLETREENODE_LEAF);
    n = &OFF2PTR(st->mem, o)->u.ln;
    n->count = 0;
    n->next = 0;
    return o;
}

/* Internal function to insert a key into an inner node. */

static inline void
simpletreeInsertInner(SIMPLETREE *st, int level, SIMPLETREEINTKEY key)
{
    SIMPLETREEINNERNODE *n;
    SIMPLETREEMETA *meta = &OFF2PTR(st->mem, st->m)->u.mn;

    /* If no node at this level create one. */
    if (st->nodes[level] == 0) {

        st->nodes[level] = simpletreeCreateInnerNode(st);

        /* Did the tree just grow taller? */
        if (level > meta->maxLevel) {
            meta->maxLevel = level;
        }
    }

    n = &OFF2PTR(st->mem, st->nodes[level])->u.in;
    n->keys[n->count] = key;
    n->children[n->count] = st->nodes[level - 1];
    ++(n->count);

    if (n->count == SIMPLETREE_INNER_M) {
        simpletreeInsertInner(st, level + 1, key);
        st->nodes[level] = 0;
    }
}

/* Internal function to insert a key into a leaf node, possibly triggering the
 * recursive creation of one or more inner nodes as well. */

static inline void
simpletreeInsertLeaf(SIMPLETREE *st, SIMPLETREEINTKEY key, uint64_t value)
{
    /* If no node at this level create one. */

    SIMPLETREELEAFNODE *n;

    if (st->nodes[0] == 0) {
        st->nodes[0] = simpletreeCreateLeafNode(st);
        if (st->prev) {
            SIMPLETREELEAFNODE *p = &OFF2PTR(st->mem, st->prev)->u.ln;
            p->next = st->nodes[0];
        } else {
            SIMPLETREEMETA *meta = &OFF2PTR(st->mem, st->m)->u.mn;
            meta->first = st->nodes[0];
        }
    }

    n = &OFF2PTR(st->mem, st->nodes[0])->u.ln;
    assert(n);
    n->keys[n->count] = key;
    n->values[n->count] = value;
    ++(n->count);

    if (n->count == SIMPLETREE_LEAF_M) {
        simpletreeInsertInner(st, 1, key);
        st->prev = st->nodes[0];
        st->nodes[0] = 0;
    }

}

/* Internal version of key insert. */

static inline void simpletreeInsertKey(SIMPLETREE *st, SIMPLETREEINTKEY k, uint64_t v)
{
    simpletreeInsertLeaf(st, k, v);
}

/* Insert key as part of ordered sequence of inserts, into a tree created with
 * simpletreeInit(). Call simpletreeFinish() when done with all inserts. */

void simpletreeInsert(SIMPLETREE *st, uint64_t key, uint64_t version,
        SIMPLETREEVALUE v)
{
    SIMPLETREEINTKEY k;
    SIMPLETREEMETA *meta = &OFF2PTR(st->mem, st->m)->u.mn;
    assert(meta->magic == 0xfedeabe0);

    /* The tree nodes store only 16-bit version ids instead of the full
     * 64-bit ones, to save space. See if this is a new version that needs
     * adding to the versions array in the meta node. Inserts are sorted,
     * so we only have to check against the current tail. */
    if (!meta->n_versions || meta->versions[meta->n_versions - 1] != version) {
        assert(meta->n_versions < DUBTREE_MAX_VERSIONS);
        meta->versions[meta->n_versions++] = version;
    }

    k.key = key;
    k.id = meta->n_versions - 1;
    simpletreeInsertKey(st, k, (v.a << 16ULL) | (v.b & 0xffff));
}

/* Tie up any dangling tree references to finalize batch insertion.  When
 * inserting, we may have been working on e.g. a leaf node, that is is not
 * entirely full. Since we only connect a child with its parent when the child
 * fills up, we sometimes need to do this afterwards. The leaf may not have a
 * direct parent, so we will just connect it with the nearest ancestor.  This
 * means that we sometimes violate the normal B-tree invariant that all leaves
 * are at the bottommost level, which is generally fine given that we don't
 * need to modify the tree after creation. However, it means we cannot infer
 * from the current depth whether a node is a leaf or an inner node, but need
 * to check the node type to avoid embarrassing ourselves during lookups.  */
void simpletreeFinish(SIMPLETREE *st, uint64_t size, uint64_t garbage)
{
    int i;
    SIMPLETREEMETA *meta = &OFF2PTR(st->mem, st->m)->u.mn;

    assert(meta->magic == 0xfedeabe0);

    for (i = 0 ; i < meta->maxLevel; ++i) {

        if (st->nodes[i] != 0) {

            int j;
            for (j = i + 1; j <= meta->maxLevel; ++j) {
                node_t parent = st->nodes[j];
                if (parent != 0) {
                    SIMPLETREEINNERNODE *p = &OFF2PTR(st->mem, parent)->u.in;
                    p->children[p->count] = st->nodes[i];
                    break;
                }
            }
        }
    }
    meta->root = st->nodes[meta->maxLevel];
    meta->size = size;
    meta->garbage = garbage;
}

static inline int simpletreeLessThan(
        SIMPLETREE *st,
        const SIMPLETREEINTKEY *a, const SIMPLETREEINTKEY *b)
{
    if (a->id != b->id) return (a->id < b->id);
    else return (a->key < b->key);
}

static inline int simpletreeLowerBound(SIMPLETREE *st,
        SIMPLETREEINTKEY *first, size_t len, SIMPLETREEINTKEY *key)
{
    int half;
    SIMPLETREEINTKEY *middle;
    SIMPLETREEINTKEY *f = first;
    while (len > 0) {
        half = len >> 1;
        middle = f + half;
        if (simpletreeLessThan(st, middle, key)) {
            f = middle + 1;
            len = len - half - 1;
        } else
            len = half;
    }
    return f - first;
}

/* Find the position of a version id within the sorted list in a
 * tree's meta node using binary search. */
static inline int simpletreeFindVersion(SIMPLETREE *st, uint64_t version)
{
    SIMPLETREEMETA *meta = &OFF2PTR(st->mem, st->m)->u.mn;
    int half;
    volatile uint64_t *middle;
    volatile uint64_t *first = meta->versions;
    int len = meta->n_versions;
    while (len > 0) {
        half = len >> 1;
        middle = first + half;
        if (*middle < version) {
            first = middle + 1;
            len = len - half - 1;
        } else
            len = half;
    }
    return first - meta->versions;
}

/* Recurse through the B-tree looking for a key. As explained in the comment
 * for simpletreeFinish(), the tree is not always entirely well-formed, so we
 * need to check for nil-references, and we need to check the type of a given
 * node to figure out if is an inner node or leaf, instead of just relying on
 * the current depth as would be possible with a well-formed B-tree. */
int simpletreeFind(SIMPLETREE *st, uint64_t key, uint64_t version, SIMPLETREEITERATOR *it)
{
    SIMPLETREEMETA *meta = &OFF2PTR(st->mem, st->m)->u.mn;
    SIMPLETREEINTKEY needle;
    node_t n = meta->root;
    int i;

    /* Do a binary search over the list of versions present in this tree, to
     * quickly eliminate versions not present, and to convert the large 64-bit
     * version id into a 16-bit index used internally to save space in nodes.
     * */
    i = simpletreeFindVersion(st, version);
    if (i == meta->n_versions || meta->versions[i] != version) {
        return 0;
    }

    needle.id = i;
    needle.key = key;

    while (n) {

        int pos;

        if (OFF2PTR(st->mem, n)->type == SIMPLETREENODE_INNER) {

            SIMPLETREEINNERNODE *in = &OFF2PTR(st->mem, n)->u.in;
            pos = simpletreeLowerBound(st, in->keys, in->count, &needle);
            n = in->children[pos];

        } else {

            SIMPLETREELEAFNODE *ln = &OFF2PTR(st->mem, n)->u.ln;
            pos = simpletreeLowerBound(st, ln->keys, ln->count, &needle);
            assert(pos < SIMPLETREE_LEAF_M);

            if (pos < ln->count) {
                it->node = n;
                it->index = pos;
                return 1;
            } else {
                it->node = 0;
                it->index = 0;
                return 0;
            }

        }
    }
    return 0;
}
