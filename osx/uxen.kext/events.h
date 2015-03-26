/*
 *  events.h
 *  uxen
 *
 * Copyright 2012-2015, Bromium, Inc.
 * Author: Christian Limpach <Christian.Limpach@gmail.com>
 * SPDX-License-Identifier: ISC
 * 
 */

#ifndef _EVENTS_H_
#define _EVENTS_H_

#include <libkern/OSAtomic.h>

#define EVENT_UNINTERRUPTIBLE  0
#define EVENT_INTERRUPTIBLE    1

#define EVENT_NO_TIMEOUT    0

struct event_object {
    semaphore_t sem;
};

#define EVENT_OBJECT_NULL { NULL }

int event_init(struct event_object *ev, uint32_t set);
void event_destroy(struct event_object *ev);
int event_wait(struct event_object *ev, int interruptible,
               uint64_t timeout);
void event_signal(struct event_object *ev);
void event_clear(struct event_object *ev);
int event_state(struct event_object *ev);



struct fast_event_object {
    uint32_t signaled;
    lck_spin_t *lock;
};

#define FAST_EVENT_OBJECT_NULL { 0, NULL }

int fast_event_init(struct fast_event_object *ev, uint32_t set);
void fast_event_destroy(struct fast_event_object *ev);
int fast_event_wait(struct fast_event_object *ev, int interruptible,
                    uint64_t timeout);
void fast_event_signal(struct fast_event_object *ev);
void fast_event_clear(struct fast_event_object *ev);
int fast_event_state(struct fast_event_object *ev);

struct user_notification_event_queue {
    rb_tree_t events_rbtree;
    lck_mtx_t *lck;
};

struct user_notification_event {
    void *notify_address;
    struct fast_event_object fast_ev;
    struct rb_node rbnode;
    struct user_notification_event_queue *user_events;
};

struct notification_event_queue {
    TAILQ_HEAD(, notification_event) queue;
    lck_spin_t *lck;
    unsigned last_id;
    uint32_t signaled;

};

struct notification_event {
    unsigned id;
    struct notification_event_queue *events;
    TAILQ_ENTRY(notification_event) entry;
};

uint32_t poll_notification_event(struct notification_event_queue *events);
void signal_notification_event(struct notification_event *ev);
int create_notification_event(struct notification_event_queue *events,
                              UXEN_EVENT_HANDLE_T handle,
                              struct notification_event *ev);
void destroy_notification_event(struct notification_event_queue *events,
                                struct notification_event *ev);

#endif  /* _EVENTS_H_ */
