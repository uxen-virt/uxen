/*
 * Copyright 2012-2015, Bromium, Inc.
 * Author: Christian Limpach <Christian.Limpach@gmail.com>
 * SPDX-License-Identifier: ISC
 */

#include "rbtree.h"

struct rbhist_key {
    uint64_t rhk_key1;
    uint64_t rhk_key2;
};

struct rbhist_node {
    struct rb_node rh_rbnode;
    struct rbhist_key rh_key;
#define rh_key1 rh_key.rhk_key1
#define rh_key2 rh_key.rhk_key2
    int rh_trig;
    struct rbhist_node *rh_next;
    struct rbhist_node **rh_pprev;
};

static inline intptr_t
rbhist_cmp64(uint64_t a, uint64_t b)
{

    if (a > b)
        return 1;
    else if (a < b)
        return -1;
    return 0;
}

RBHIST_STATIC intptr_t
rbhist_compare_key(void *ctx, const void *b, const void *key)
{
    const struct rbhist_node * const pnp = b;
    const struct rbhist_key * const fhp = key;

    if (pnp->rh_key1 != fhp->rhk_key1)
	return pnp->rh_key1 - fhp->rhk_key1;
    return pnp->rh_key2 - fhp->rhk_key2;
}

RBHIST_STATIC intptr_t
rbhist_compare_nodes(void *ctx, const void *parent, const void *node)
{
    const struct rbhist_node * const np = node;

    return rbhist_compare_key(ctx, parent, &np->rh_key);
}

RBHIST_STATIC int rbhist_ready = 0;
RBHIST_STATIC struct rbhist_node *rbhist_list = NULL;
RBHIST_STATIC rb_tree_t rbhist_rbtree;
RBHIST_STATIC rb_tree_ops_t rbhist_rbtree_ops = {
    .rbto_compare_nodes = rbhist_compare_nodes,
    .rbto_compare_key = rbhist_compare_key,
    .rbto_node_offset = offsetof(struct rbhist_node, rh_rbnode),
    .rbto_context = NULL
};

RBHIST_STATIC void
rbhist_dump(void)
{
    struct rbhist_node *rhp;
    int rh_trig_tot = 0;

    if (!rbhist_ready)
	return;

    for (rhp = rbhist_list; rhp; rhp = rhp->rh_next) {
	if (rhp->rh_trig)
	    RBHIST_PRINTF("key1 %8"PRIx64" key2 %4"PRIx64" triggered %8d\n",
			  rhp->rh_key1, rhp->rh_key2, rhp->rh_trig);
	rh_trig_tot += rhp->rh_trig;
    }
    RBHIST_PRINTF("triggered total: %d\n", rh_trig_tot);
}

RBHIST_STATIC void
rbhist_clear(void)
{
    struct rbhist_node *rhp;

    if (!rbhist_ready)
	return;

    for (rhp = rbhist_list; rhp; rhp = rhp->rh_next)
	rhp->rh_trig = 0;
}

RBHIST_STATIC void
rbhist_trigger(uint64_t key1, uint64_t key2)
{
    struct rbhist_key rhkey;
    struct rbhist_node *rhp;

    if (!rbhist_ready)
	return;

    rhkey.rhk_key1 = key1;
    rhkey.rhk_key2 = key2;

    rhp = RB_TREE_(find_node)(&rbhist_rbtree, &rhkey);
    if (rhp == NULL) {
	rhp = RBHIST_MALLOCZ(sizeof(*rhp));
	rhp->rh_key = rhkey;
	RB_TREE_(insert_node)(&rbhist_rbtree, rhp);
	if (rbhist_list) {
	    rbhist_list->rh_pprev = &rhp->rh_next;
	    rhp->rh_next = rbhist_list;
	}
	rhp->rh_pprev = &rbhist_list;
	rbhist_list = rhp;
    }
    rhp->rh_trig++;
    while (rhp->rh_next && rhp->rh_trig > rhp->rh_next->rh_trig) {
	struct rbhist_node *next = rhp->rh_next;
	/* p - a(rhp) - b(next) - n */
	/* nextpointer in p = b */
	*rhp->rh_pprev = next;
	/* backpointer in b = &nextpointer in p */
	next->rh_pprev = rhp->rh_pprev;
	/* backpointer in a = &nextpointer in b */
	rhp->rh_pprev = &next->rh_next;
	/* nextpointer in a = n */
	rhp->rh_next = next->rh_next;
	/* nextpointer in b = a */
	next->rh_next = rhp;
	/* backpointer in n = &nextpointer in a */
	if (rhp->rh_next)
	    rhp->rh_next->rh_pprev = &rhp->rh_next;
    }
}

RBHIST_STATIC void
rbhist_init(void)
{

    if (rbhist_ready)
	return;

    RB_TREE_(init)(&rbhist_rbtree, &rbhist_rbtree_ops);
    rbhist_ready = 1;
}

