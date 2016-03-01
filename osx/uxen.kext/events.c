/*
 *  events.c
 *  uxen
 *
 * Copyright 2012-2016, Bromium, Inc.
 * Author: Christian Limpach <Christian.Limpach@gmail.com>
 * SPDX-License-Identifier: ISC
 * 
 */

#include "uxen.h"
#include "events.h"

#include <kern/sched_prim.h>
#include <kern/task.h>
#include <libkern/libkern.h>
#include <mach/semaphore.h>
#include <mach/task.h>
#include <sys/proc.h>
#include <sys/vm.h>
#include <kern/ipc_mig.h>

int
event_init(struct event_object *ev, uint32_t set)
{
    kern_return_t rc;

#ifdef DEBUG
    if (ev->sem) {
        fail_msg("semaphore already initialized");
        return EEXIST;
    }
#endif

    rc = semaphore_create(kernel_task, &ev->sem, SYNC_POLICY_FIFO, set);
    if (rc != KERN_SUCCESS) {
        fail_msg("semaphore_create failed: %d", rc);
        return ENOMEM;
    }

    return 0;
}

void
event_destroy(struct event_object *ev)
{
    if (ev->sem) {
        semaphore_destroy(kernel_task, ev->sem);
        ev->sem = NULL;
    }
}

int
event_wait(struct event_object *ev, int interruptible,
           uint64_t timeout)
{
    kern_return_t rc;

    if (!interruptible)
        fail_msg("interruptible=0 has no effect");

    rc = semaphore_wait_deadline(ev->sem, timeout);

    switch (rc) {
    case KERN_SUCCESS:
        return 0;
    case KERN_OPERATION_TIMED_OUT:
        return -1;
    case KERN_ABORTED:
        return EINTR;
    default:
        return EINVAL;
    }
}

void
event_signal(struct event_object *ev)
{

    semaphore_signal(ev->sem);
}

void
event_clear(struct event_object *ev)
{

    while (semaphore_wait_noblock(ev->sem) == KERN_SUCCESS)
        /* nothing */ ;
}


int
fast_event_init(struct fast_event_object *ev, uint32_t set)
{

#ifdef DEBUG
    if (ev->lock) {
        fail_msg("lock already initialized");
        return EEXIST;
    }
#endif

    ev->lock = lck_spin_alloc_init(uxen_lck_grp, LCK_ATTR_NULL);
    if (!ev->lock) {
        fail_msg("lck_spin_alloc_init");
        return ENOMEM;
    }

    ev->signaled = set;

    return 0;
}

void
fast_event_destroy(struct fast_event_object *ev)
{

    if (ev->lock) {
        lck_spin_destroy(ev->lock, uxen_lck_grp);
        ev->lock = NULL;
    }
}

int
fast_event_wait(struct fast_event_object *ev, int interruptible,
                uint64_t timeout)
{
    int ret;

    lck_spin_lock(ev->lock);
    MemoryBarrier();
    if (ev->signaled) {
        lck_spin_unlock(ev->lock);
        return 0;
    }
    if (timeout)
        ret = lck_spin_sleep_deadline(ev->lock, LCK_SLEEP_UNLOCK, ev,
                                      interruptible ? THREAD_ABORTSAFE :
                                                      THREAD_UNINT,
                                      timeout);
    else
        ret = lck_spin_sleep(ev->lock, LCK_SLEEP_UNLOCK, ev,
                             interruptible ? THREAD_ABORTSAFE : THREAD_UNINT);
    if (ret != THREAD_AWAKENED && ret != THREAD_TIMED_OUT &&
        ret != THREAD_INTERRUPTED)
        fail_msg("lck_spin_sleep failed: %d", ret);

    switch (ret) {
    case THREAD_AWAKENED:
        return 0;
    case THREAD_TIMED_OUT:
        return timeout ? -1 : EINVAL;
    case THREAD_INTERRUPTED:
        return EINTR;
    default:
        return EINVAL;
    }
}

void
fast_event_signal(struct fast_event_object *ev)
{

    lck_spin_lock(ev->lock);
    ev->signaled = 1;
    thread_wakeup(ev);
    lck_spin_unlock(ev->lock);
}

void
fast_event_clear(struct fast_event_object *ev)
{

    lck_spin_lock(ev->lock);
    ev->signaled = 0;
    lck_spin_unlock(ev->lock);
}

int
fast_event_state(struct fast_event_object *ev)
{

    return ev->signaled;
}


#ifndef container_of
#define container_of(ptr, type, member) ({                      \
        const typeof(((type *) 0)->member) *__mptr = (ptr);     \
        (type *) ((char *) __mptr - offsetof(type, member));})
#endif

uint32_t
poll_notification_event(struct notification_event_queue *events)
{
    uint32_t signaled;

    do {
        signaled = events->signaled;
    } while (!OSCompareAndSwap(signaled, 0, &events->signaled));

    return signaled;
}


void
signal_notification_event(struct notification_event *ev)
{
    mach_msg_header_t hdr;
    struct fd_assoc *fda;

    fda = container_of(ev->events, struct fd_assoc, events);
    if (fda->notification_port == MACH_PORT_NULL)
        return;

    if (OSBitOrAtomic((1 << ev->id), &ev->events->signaled)) {
        /* Do not send a notification message if host still hasn't
         * polled a previous one. */
        return;
    }
    MemoryBarrier();

    hdr.msgh_bits = MACH_MSGH_BITS(MACH_MSG_TYPE_COPY_SEND, 0);
    hdr.msgh_size = sizeof(mach_msg_header_t);
    hdr.msgh_remote_port = fda->notification_port;
    hdr.msgh_local_port = MACH_PORT_NULL;
    hdr.msgh_reserved = 0;
    hdr.msgh_id = 0;

    /* This might fail, but everything is fine anyway. */
    mach_msg_send_from_kernel_proper(&hdr, sizeof(hdr));
}

#define NOTIFICATION_EVENT_MAXID 31

int
create_notification_event(struct notification_event_queue *events,
                          UXEN_EVENT_HANDLE_T handle,
                          struct notification_event *ev)
{
    int ret;
    unsigned id;

    ret = EINVAL;
    if (!handle)
        goto out;

    id = OSIncrementAtomic(&events->last_id);
    if (id > NOTIFICATION_EVENT_MAXID) {
        fail_msg("%s: Too many events.\n", __FUNCTION__);
        events->last_id = NOTIFICATION_EVENT_MAXID;
        ret = ENOMEM;
        goto out;
    }

    ev->id = id;
    ev->events = events;

    ret = copyout(&ev->id, (user_addr_t)(uintptr_t)handle, sizeof(uint32_t));
    if (ret) {
        fail_msg("%s: error notifying user", __FUNCTION__);
        goto out;
    }

    lck_spin_lock(events->lck);
    TAILQ_INSERT_TAIL(&events->queue, ev, entry);
    lck_spin_unlock(events->lck);
    ret = 0;
out:
    if (ret)
        ev->id = -1;
    return ret;
}

void
destroy_notification_event(struct notification_event_queue *events,
                           struct notification_event *ev)
{
    lck_spin_lock(events->lck);
    TAILQ_REMOVE(&events->queue, ev, entry);
    lck_spin_unlock(events->lck);
    ev->id = -1;
}
