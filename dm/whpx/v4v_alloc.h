/*
 * Copyright 2018, Bromium, Inc.
 * Author: Tomasz Wroblewski <tomasz.wroblewski@gmail.com>
 * SPDX-License-Identifier: ISC
 */

static struct v4v_ring_info *alloc_ring_info(void) {
    return calloc(1, sizeof(struct v4v_ring_info));
}

static void free_ring_info(struct v4v_ring_info *v) {
    free(v);
}

static struct v4v_pending_ent *alloc_pending_ent(void) {
    return calloc(1, sizeof(struct v4v_pending_ent));
}

static void free_pending_ent(struct v4v_pending_ent *v) {
    free(v);
}

static struct v4v_domain *alloc_v4v_domain(void) {
    return calloc(1, sizeof(struct v4v_domain));
}

static void free_v4v_domain(struct v4v_domain *v) {
    free(v);
}

#define v4v_xmalloc_array(type, count) \
    calloc(count, sizeof(type))

#define v4v_xfree(ptr) \
    free(ptr)
