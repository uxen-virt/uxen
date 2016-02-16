/*
 * Copyright 2015-2016, Bromium, Inc.
 * SPDX-License-Identifier: ISC
 */

#ifndef __V4V_PRIVATE_H__
#define __V4V_PRIVATE_H__

#include <xen/config.h>
#include <xen/types.h>
#include <xen/spinlock.h>
#include <xen/smp.h>
#include <xen/shared.h>
#include <xen/list.h>
#include <public/v4v.h>

#define V4V_HTABLE_SIZE 32

static inline uint16_t
v4v_hash_fn(struct v4v_ring_id *id)
{
    uint16_t ret;

    ret = (uint16_t)(id->addr.port >> 16);
    ret ^= (uint16_t)id->addr.port;
    ret ^= id->addr.domain;
    ret ^= id->partner;

    ret &= (V4V_HTABLE_SIZE - 1);

    return ret;
}

struct v4v_pending_ent
{
    struct hlist_node node;
    domid_t id;
    uint32_t len;
};

struct v4v_ring_info
{
    struct hlist_node node;     /* next node in the hash, protected by L2 */
    struct v4v_ring_id id;      /* this ring's id, protected by L2 */

    spinlock_t lock;            /* L3 */

    uint32_t len;               /* cached length of the ring (from
                                 * ring->len), protected by L3 */
    uint32_t tx_ptr;            /* cached tx pointer location,
                                 * protected by L3 */
    XEN_GUEST_HANDLE(v4v_ring_t) ring; /* guest ring, protected by L3 */

    uint32_t npage;             /* number of pages in ring */
    uint32_t nmfns;             /* number of pages translated to mfns */
    mfn_t *mfns;                /* list of mfns of guest ring */
    uint8_t **mfn_mapping;      /* mapped ring pages protected by L3*/
    struct hlist_head pending;  /* list of struct v4v_pending_ent for
                                 * this ring, L3 */
};


/* The value of the v4v element in a struct domain is protected by the
 * global lock L1 */
struct v4v_domain
{
    rwlock_t lock;                                /* L2 */
    struct hlist_head ring_hash[V4V_HTABLE_SIZE]; /* protected by L2 */
};

void v4v_destroy(struct domain *d);
int v4v_init(struct domain *d);
void v4v_shutdown(struct domain *d);
void v4v_resume(struct domain *d);
long do_v4v_op(int cmd, XEN_GUEST_HANDLE(void) arg1,
               XEN_GUEST_HANDLE(void) arg2, XEN_GUEST_HANDLE(void) arg3,
               uint32_t arg4, uint32_t arg5);

#endif /* __V4V_PRIVATE_H__ */

/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
