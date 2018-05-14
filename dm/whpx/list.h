/*
 * Copyright 2018, Bromium, Inc.
 * SPDX-License-Identifier: ISC
 */

#ifndef LIST_H
#define LIST_H

struct hlist_head {
  struct hlist_node *head;
};

struct hlist_node {
  struct hlist_node *next;
  struct hlist_node **prev_p;
};

#define HLIST_HEAD_INIT { .head = NULL }
#define HLIST_HEAD(name) struct hlist_head name = {  .head = NULL }
#define INIT_HLIST_HEAD(ptr) ((ptr)->head = NULL)

static inline int
hlist_empty(struct hlist_head *h)
{
  return !h->head;
}

static inline void
hlist_del(struct hlist_node *n)
{
  struct hlist_node *next    = n->next;
  struct hlist_node **prev_p = n->prev_p;

  ASSERT(prev_p);

  *prev_p = next;
  if (next)
    next->prev_p = prev_p;
  n->next   = NULL;
  n->prev_p = NULL;
}

static inline void
hlist_add_head(struct hlist_node *n, struct hlist_head *h)
{
  struct hlist_node *head = h->head;

  n->next = head;
  if (head)
    head->prev_p = &n->next;
  h->head = n;
  n->prev_p = &h->head;
}

#define hlist_for_each_entry_safe(e, pos, n, hd, member)                \
  for (pos = (hd)->head;                                                \
       pos && (n = pos->next, e = container_of(pos, typeof(*e), member)); \
       pos = n)

#endif

