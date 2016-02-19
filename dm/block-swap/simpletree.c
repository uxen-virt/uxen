/*
 * Copyright 2012-2016, Bromium, Inc.
 * Author: Jacob Gorm Hansen <jacobgorm@gmail.com>
 * SPDX-License-Identifier: ISC
 */

#include "simpletree.h"

#include <limits.h>
#include <stdlib.h>
#include <string.h>

#include "dubtree_io.h"

/* B-tree node ids can max be 16 bits. */
#if DUBTREE_TREENODES > (1<<16)
#error "number of tree nodes too large for 16 bits"
#endif

static inline node_t alloc_node(SimpleTree *st)
{
    SimpleTreeMetaNode *meta = &off2ptr(st->mem, 0)->u.mn;

    int n = st->mem ? meta->num_nodes : 0;
    if (!((n - 1) & n)) {
        st->mem = realloc(st->mem, simpletree_node_size() * (n ? 2 * n : 1));
        meta = &off2ptr(st->mem, 0)->u.mn;
        meta->num_nodes = n;
    }

    return meta->num_nodes++;
}

static inline
void set_node_info(SimpleTree *st, node_t n,
        SimpleTreeNodeType type)
{
    SimpleTreeNode *nn = off2ptr(st->mem, n);
    nn->type = type;
    /* Zero rest of node after header. XXX revisit later. */
    memset(&nn[1], 0, simpletree_node_size() - sizeof(*nn));
    __sync_synchronize();
}

void simpletree_init(SimpleTree *st)
{
    SimpleTreeMetaNode *meta;

    assert(st);
    st->magic = 0xcafebabe;
    st->mem = NULL;
    st->prev = 0;

    memset(st->nodes, 0, sizeof(st->nodes));

    alloc_node(st);
    set_node_info(st, 0, SimpleTreeNode_Meta);

    meta = &off2ptr(st->mem, 0)->u.mn;
    meta->maxLevel = 0;
    meta->first = 0;
    meta->magic = 0xfedeabe0;
    __sync_synchronize();
}

void simpletree_clear(SimpleTree *st)
{
    free(st->mem);
}

/* Create a new SimpleTree instance wrapping the tree with meta node mn, in the
 * node space mem, with freelist starting at head. Assumes that mn already has
 * a non-zero refcount. Returns NULL if no tree at this level. XXX will assert
 * on malloc failure, we should change this to have the caller do the malloc,
 * but this will be wasteful for the common case of having no tree. */
void simpletree_open(SimpleTree *st, void *mem)
{
    SimpleTreeMetaNode *meta;
    assert(st);
    memset(st, 0, sizeof(*st));
    st->magic = 0xcafebabe;
    st->mem = mem;

    meta = &off2ptr(st->mem, 0)->u.mn;

    if (meta->magic!=0xfedeabe0){
        printf("bad magic %x!\n",meta->magic);
    }
    assert(meta->magic == 0xfedeabe0);
}


/* Factory functions for the inner and leaf node types. */

static inline node_t create_inner_node(SimpleTree *st)
{
    SimpleTreeInnerNode *n;
    node_t o = alloc_node(st);
    set_node_info(st, o, SimpleTreeNode_Inner);
    n = &off2ptr(st->mem, o)->u.in;
    memset(n->children, 0, sizeof(n->children));
    n->count = 0;
    return o;
}

static inline node_t create_leaf_node(SimpleTree *st)
{
    SimpleTreeLeafNode *n;
    node_t o = alloc_node(st);
    set_node_info(st, o, SimpleTreeNode_Leaf);
    n = &off2ptr(st->mem, o)->u.ln;
    n->count = 0;
    n->next = 0;
    return o;
}

/* Internal function to insert a key into an inner node. */

static inline void
simpletree_insert_inner(SimpleTree *st, int level, SimpleTreeInternalKey key)
{
    SimpleTreeInnerNode *n;

    /* If no node at this level create one. */
    if (st->nodes[level] == 0) {

        st->nodes[level] = create_inner_node(st);

        /* Did the tree just grow taller? */
        SimpleTreeMetaNode *meta = &off2ptr(st->mem, 0)->u.mn;
        if (level > meta->maxLevel) {
            meta->maxLevel = level;
        }
    }

    n = &off2ptr(st->mem, st->nodes[level])->u.in;
    n->keys[n->count] = key;
    n->children[n->count] = st->nodes[level - 1];
    ++(n->count);

    if (n->count == SIMPLETREE_INNER_M) {
        simpletree_insert_inner(st, level + 1, key);
        st->nodes[level] = 0;
    }
}

/* Internal function to insert a key into a leaf node, possibly triggering the
 * recursive creation of one or more inner nodes as well. */

static inline void
simpletree_insert_leaf(SimpleTree *st, SimpleTreeInternalKey key, SimpleTreeValue value)
{
    /* If no node at this level create one. */

    SimpleTreeLeafNode *n;

    if (st->nodes[0] == 0) {
        st->nodes[0] = create_leaf_node(st);
        if (st->prev) {
            SimpleTreeLeafNode *p = &off2ptr(st->mem, st->prev)->u.ln;
            p->next = st->nodes[0];
        } else {
            SimpleTreeMetaNode *meta = &off2ptr(st->mem, 0)->u.mn;
            meta->first = st->nodes[0];
        }
    }

    n = &off2ptr(st->mem, st->nodes[0])->u.ln;
    assert(n);
    n->keys[n->count] = key;
    n->values[n->count] = value;
    ++(n->count);

    if (n->count == SIMPLETREE_LEAF_M) {
        simpletree_insert_inner(st, 1, key);
        st->prev = st->nodes[0];
        st->nodes[0] = 0;
    }

}

/* Insert key as part of ordered sequence of inserts, into a tree created with
 * simpletree_init(). Call simpletree_finish() when done with all inserts. */

void simpletree_insert(SimpleTree *st, uint64_t key, SimpleTreeValue v)
{
    SimpleTreeInternalKey k;
    k.key = key;
    simpletree_insert_leaf(st, k, v);
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
void simpletree_finish(SimpleTree *st)
{
    int i;
    SimpleTreeMetaNode *meta = &off2ptr(st->mem, 0)->u.mn;
    assert(meta->magic == 0xfedeabe0);

    for (i = 0 ; i < meta->maxLevel; ++i) {

        if (st->nodes[i] != 0) {

            int j;
            for (j = i + 1; j <= meta->maxLevel; ++j) {
                node_t parent = st->nodes[j];
                if (parent != 0) {
                    SimpleTreeInnerNode *p = &off2ptr(st->mem, parent)->u.in;
                    p->children[p->count] = st->nodes[i];
                    break;
                }
            }
        }
    }
    meta->root = st->nodes[meta->maxLevel];
}

static inline int less_than(
        const SimpleTree *st,
        const SimpleTreeInternalKey *a, const SimpleTreeInternalKey *b)
{
    return (a->key < b->key);
}

static inline int lower_bound(const SimpleTree *st,
        const SimpleTreeInternalKey *first, size_t len, const SimpleTreeInternalKey *key)
{
    int half;
    const SimpleTreeInternalKey *middle;
    const SimpleTreeInternalKey *f = first;
    while (len > 0) {
        half = len >> 1;
        middle = f + half;
        if (less_than(st, middle, key)) {
            f = middle + 1;
            len = len - half - 1;
        } else
            len = half;
    }
    return f - first;
}

/* Recurse through the B-tree looking for a key. As explained in the comment
 * for simpletree_finish(), the tree is not always entirely well-formed, so we
 * need to check for nil-references, and we need to check the type of a given
 * node to figure out if is an inner node or leaf, instead of just relying on
 * the current depth as would be possible with a well-formed B-tree. */
int simpletree_find(SimpleTree *st, uint64_t key, SimpleTreeIterator *it)
{
    SimpleTreeMetaNode *meta = &off2ptr(st->mem, 0)->u.mn;
    const SimpleTreeInternalKey needle = {key};
    node_t n = meta->root;

    while (n) {

        int pos;

        if (off2ptr(st->mem, n)->type == SimpleTreeNode_Inner) {

            SimpleTreeInnerNode *in = &off2ptr(st->mem, n)->u.in;
            pos = lower_bound(st, in->keys, in->count, &needle);
            n = in->children[pos];

        } else {

            SimpleTreeLeafNode *ln = &off2ptr(st->mem, n)->u.ln;
            pos = lower_bound(st, ln->keys, ln->count, &needle);
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

void simpletree_set_user(SimpleTree *st, const void *data, size_t size)
{
    SimpleTreeMetaNode *meta = &off2ptr(st->mem, 0)->u.mn;
    meta->user_size = size;

    if (size <= (SIMPLETREE_NODESIZE - sizeof(*meta))) {
        memcpy((uint8_t *) meta + sizeof(*meta), data, size);
    } else {
        int take;
        int left;
        const uint8_t *in = data;
        uint8_t *out;
        for (left = size; left > 0; in += take, left -= take) {
            take = left < SIMPLETREE_NODESIZE ? left : SIMPLETREE_NODESIZE;
            node_t n = alloc_node(st);
            out = (uint8_t *) off2ptr(st->mem, n);
            memcpy(out, in, take);
            memset(out + take, 0, SIMPLETREE_NODESIZE - take);
        }
        meta = NULL;
    }
}

const void *simpletree_get_user(SimpleTree *st)
{
    SimpleTreeMetaNode *meta = &off2ptr(st->mem, 0)->u.mn;
    if (meta->user_size <= (SIMPLETREE_NODESIZE - sizeof(*meta))) {
        return (void *) (uint8_t *) meta + sizeof(*meta);
    } else {
        node_t n = meta->num_nodes - (meta->user_size + SIMPLETREE_NODESIZE -
                1) / SIMPLETREE_NODESIZE;
        return (void *) off2ptr(st->mem, n);
    }
}
