/*
 * Copyright 2012-2015, Bromium, Inc.
 * Author: Julian Pidancet <julian@pidancet.net>
 * SPDX-License-Identifier: ISC
 */

#include "config.h"

#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>

#include <sys/select.h>
#include <sys/types.h>
#include <sys/event.h>
#include <sys/time.h>

#include "dm.h"
#include "ioh.h"
#include "timer.h"
#include "queue.h"

#if defined(CONFIG_SLIRP) && !defined(SLIRP_THREADED)
#if defined(__APPLE__)
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#endif

#include <dm/slirp/libslirp.h>
#endif

#ifndef LIBIMG
#include "async-op.h"
#endif

WaitObjects wait_objects;
struct io_handler_queue io_handlers;

#ifdef DEBUG_WAITOBJECTS
int trace_waitobjects = 0;
#define trace_waitobjects_print(fmt, ...) if (trace_waitobjects) dprintf(fmt, ## __VA_ARGS__)
#else
#define trace_waitobjects_print(fmt, ...) do { ; } while(0)
#endif

#if 0
#define delay_log(fmt, ...) do {		\
	debug_printf(fmt, ## __VA_ARGS__);	\
    } while (0)
#else
#define delay_log(fmt, ...) do { ; } while(0)
#endif

void
ioh_waitobjects_grow(WaitObjects *w)
{
    w->max += 8;
    w->events = realloc(w->events, sizeof(ioh_wait_event) * w->max);
    w->desc = realloc(w->desc, sizeof(WaitObjectsDesc) * w->max);
}

static int
ioh_add_wait(int fd, int events, WaitObjects *w)
{

    assert(w != NULL);

    if (w->num == w->max)
        ioh_waitobjects_grow(w);

    assert((unsigned int)fd < FD_SETSIZE);
    w->events[w->num].fd = fd;
    w->events[w->num].events = events;

    w->desc[w->num].del = 0;

#ifdef DEBUG_WAITOBJECTS
    w->desc[w->num].func_name = __FUNCTION__;
    w->desc[w->num].triggered = 0;
#endif

    return w->num++;
}

int
ioh_add_wait_fd(int fd, int events, WaitObjectFunc2 *func2, void *opaque,
                WaitObjects *w)
{
    int num;

    if (w == NULL)
        w = &wait_objects;

    num = ioh_add_wait(fd, events, w);

    w->desc[num].func2 = func2;
    w->desc[num].opaque = opaque;

    return 0;
}

static void
ioh_event_queue_drain(WaitObjects *w, ioh_event_queue *list)
{
    struct kevent kev[64];
    struct timespec timeout = { .tv_sec = 0, .tv_nsec = 0 };
    int num;
    int ev;

    do {
        num = kevent(w->queue_fd, NULL, 0, kev, 64, &timeout);
        if (num == -1) {
            debug_printf("kevent failed\n");
            break;
        }
        for (ev = 0; ev < num; ev++) {
            ioh_event *event = kev[ev].udata;

            if (event->processq)
                TAILQ_REMOVE(event->processq, event, link);
            event->processq = list;
            TAILQ_INSERT_TAIL(list, event, link);
        }
    } while (num == 64);
}

void ioh_init_wait_objects(WaitObjects *w)
{
    w->num = 0;
    w->events = NULL;
    w->desc = NULL;
    w->max = 0;
    w->del_state = WO_OK;
    w->queue_len = 0;
    w->queue_fd = kqueue();

    if (w->queue_fd < 0)
        err(1, "%s: kqueue failed", __FUNCTION__);
}

void ioh_cleanup_wait_objects(WaitObjects *w)
{
    close(w->queue_fd);
}

#ifndef DEBUG_WAITOBJECTS
int ioh_add_wait_object(ioh_event *event, WaitObjectFunc *func, void *opaque,
                        WaitObjects *w)
#else
int _ioh_add_wait_object(ioh_event *event, WaitObjectFunc *func, void *opaque,
                         WaitObjects *w, const char *func_name)
#endif
{
    struct kevent kev;
    int rc;

    if (w == NULL)
	w = &wait_objects;

    event->func = func;
    event->opaque = opaque;
#ifdef DEBUG_WAITOBJECTS
    event->func_name = func_name;
#endif

    critical_section_enter(&event->lock);

    EV_SET(&kev, event->ident, event->filter, EV_ADD | EV_CLEAR, 0, 0, event);
    rc = kevent(w->queue_fd, &kev, 1, NULL, 0, NULL);
    if (rc == -1)
        err(1, "%s: kevent failed", __FUNCTION__);

    if (event->filter == EVFILT_USER && event->signaled) {
        EV_SET(&kev, event->ident, event->filter, EV_ENABLE, NOTE_TRIGGER, 0,
               event);
        rc = kevent(w->queue_fd, &kev, 1, NULL, 0, NULL);
        if (rc == -1)
            err(1, "%s: kevent failed", __FUNCTION__);

    }

    ioh_event_queue_add(event, w->queue_fd);

    critical_section_leave(&event->lock);

    w->queue_len++;

    return 0;
}

static void ioh_gc_del_fds(WaitObjects *w)
{
    int i = -1, j;
    if (!w)
        w = &wait_objects;
    while (++i < w->num) {
        if (!w->desc[i].del)
           continue;
        j = i+1;
        while (j < w->num && w->desc[j].del)
            j++;
        if (j < w->num) {
            memmove(&w->events[i], &w->events[j],
                    (w->num - j) * sizeof(w->events[0]));
            memmove(&w->desc[i], &w->desc[j],
                    (w->num - j) * sizeof(w->desc[0]));
        }
        w->num -= (j-i);
    }
}

void ioh_del_wait_fd(int fd, WaitObjects *w)
{
    int i;

    if (w == NULL)
        w = &wait_objects;

    for (i = 0; i < w->num; i++)
        if (!w->desc[i].del && w->events[i].fd == fd)
            break;

    if (i == w->num) {
        debug_printf("ioh_del_wait_object: fd %d not found in %s\n",
                     fd, w == &wait_objects ? "main" : "block");
        debug_break();
        return;
    }


    if (w->del_state != WO_OK) {
        w->desc[i].del = 1;
        w->del_state = WO_GC;
        return;
    }
    w->num--;
    if (i < w->num) {
	memmove(&w->events[i], &w->events[i + 1],
		(w->num - i) * sizeof(w->events[0]));
	memmove(&w->desc[i], &w->desc[i + 1],
		(w->num - i) * sizeof(w->desc[0]));
    }
}

void ioh_del_wait_object(ioh_event *event, WaitObjects *w)
{
    struct kevent kev;
    int rc;

    if (w == NULL)
	w = &wait_objects;

    critical_section_enter(&event->lock);

    ioh_event_queue_del(event, w->queue_fd);

    EV_SET(&kev, event->ident, event->filter, EV_DELETE, 0, 0, NULL);
    rc = kevent(w->queue_fd, &kev, 1, NULL, 0, NULL);
    if (rc == -1)
        err(1, "%s: kevent failed", __FUNCTION__);

    critical_section_leave(&event->lock);

    w->queue_len--;
}

#if defined(CONFIG_NETEVENT)
static void
ioh_object_signalled(void *context, int events)
{
    int devents;

    IOHandlerRecord *ioh = (IOHandlerRecord *)context;

    if (ioh->deleted)
        return;

#define IOH_READ_EVENTS (POLLIN | POLLERR)
#define IOH_WRITE_EVENTS (POLLOUT | POLLERR)
    if (events) {
        devents = events;
        if (ioh->fd_read)
            if (events & IOH_READ_EVENTS) {
                ioh->fd_read(ioh->opaque);
                devents &= ~IOH_READ_EVENTS;
            }

        if (ioh->fd_write)
            if (ioh->object_events & IOH_WRITE_EVENTS) {
                ioh->fd_write(ioh->opaque);
                devents &= ~IOH_WRITE_EVENTS;
            }
    }
}
#endif  /* CONFIG_NETEVENT */

void ioh_wait_for_objects(struct io_handler_queue *iohq,
                          WaitObjects *w, TimerQueue *active_timers,
                          int *timeout, int *ret_wait)
{
    IOHandlerRecord *ioh, *next;
    int ret, ev;
    int64_t tmp_ts;
#ifdef DEBUG_WAITOBJECTS
    uint64_t t1, t2, t3, t4;
#endif
    ioh_event_queue events = TAILQ_HEAD_INITIALIZER(events);

    if (ret_wait)
        *ret_wait = 0;

    if (iohq) {
        critical_section_enter(&iohq->lock);
        TAILQ_FOREACH_SAFE(ioh, &iohq->queue, queue, next) {
#if defined(CONFIG_NETEVENT)
            int events = 0;

            if (ioh->fd != -1 && !ioh->deleted) {
                if (ioh->fd_read &&
                    (!ioh->fd_read_poll ||
                     ioh->fd_read_poll(ioh->opaque) != 0)) {
                    events |= POLLIN | POLLERR;
                }
                if (ioh->fd_write &&
                    (!ioh->fd_write_poll ||
                     ioh->fd_write_poll(ioh->opaque) != 0)) {
                    events |= POLLOUT | POLLERR;
                }
            }
            if (events) {
                if (!ioh->object_events)
                    ioh_add_wait_fd(ioh->fd, events, ioh_object_signalled,
                                    ioh, w);
            } else {
                if (ioh->object_events)
                    ioh_del_wait_fd(ioh->fd, w);
            }
            ioh->object_events = events;
#endif  /* CONFIG_NETEVENT */
        }
        critical_section_leave(&iohq->lock);
    }

#ifndef LIBIMG
    if (active_timers) {
        timer_deadline(active_timers, rt_clock, timeout);
        timer_deadline(active_timers, vm_clock, timeout);
    }
#endif

#ifdef DEBUG_WAITOBJECTS
    if (trace_waitobjects)
	t1 = os_get_clock();
#endif

#ifdef DEBUG_WAITOBJECTS
    t1 = os_get_clock();
#endif

    do {
        fd_set rfds, wfds, xfds;
        int nfds = -1;
        struct timeval tv;
        int i;

        FD_ZERO(&rfds);
        FD_ZERO(&wfds);
        FD_ZERO(&xfds);

        for (i = 0; i < w->num; i++) {
            if (w->events[i].events & POLLIN)
                FD_SET(w->events[i].fd, &rfds);
            if (w->events[i].events & POLLOUT)
                FD_SET(w->events[i].fd, &wfds);
            if (w->events[i].events & POLLERR)
                FD_SET(w->events[i].fd, &xfds);
            if (w->events[i].events & (POLLIN|POLLOUT|POLLERR) &&
                w->events[i].fd > nfds)
                nfds = w->events[i].fd;
        }
        if (w->queue_fd != -1) {
            FD_SET(w->queue_fd, &rfds);
            if (w->queue_fd > nfds)
                nfds = w->queue_fd;
        }
        tv.tv_sec = *timeout / 1000;
        tv.tv_usec = (*timeout % 1000) * 1000;

        if (ret_wait)
            tmp_ts = os_get_clock_ms();
        ret = select(nfds + 1, &rfds, &wfds, &xfds, &tv);
        if (ret_wait)
            *ret_wait += (int) (os_get_clock_ms() - tmp_ts);
        if (ret <= 0) {
            if (ret == -1)
                ret = -errno;
            break;
        }

        for (i = 0; i < w->num; i++) {
            w->events[i].revents = 0;
            if (FD_ISSET(w->events[i].fd, &rfds))
                w->events[i].revents |= POLLIN;
            if (FD_ISSET(w->events[i].fd, &wfds))
                w->events[i].revents |= POLLOUT;
            if (FD_ISSET(w->events[i].fd, &xfds))
                w->events[i].revents |= POLLERR;
        }
        if (w->queue_fd != -1 && FD_ISSET(w->queue_fd, &rfds))
            ioh_event_queue_drain(w, &events);
    } while(0);

#ifndef LIBIMG
#ifdef DEBUG_WAITOBJECTS
    if (trace_waitobjects) {
        t2 = os_get_clock();
        trace_waitobjects_print("wait for events %d: pcount %"PRIx64
                                "/%x\n", w->num, (t2 - t1) / SCALE_MS,
                                *timeout);
    }
    t2 = os_get_clock();
    if ((t2 - t1) / SCALE_MS > *timeout + 1)
        delay_log("W %05"PRId64" - late %"PRId64" past %"PRId64
                  " tout %d\n", (t2 / SCALE_MS) % 100000,
                  ((t2 - t1) / SCALE_MS) - *timeout,
                  ((t1 / SCALE_MS) + *timeout) % 10000,
                  *timeout);
#endif
    if (active_timers) {
        run_timers(active_timers, vm_clock);
        run_timers(active_timers, rt_clock);
    }
#ifdef DEBUG_WAITOBJECTS
    if (active_timers) {
        t3 = os_get_clock();
        if ((t3 - t2) > 2 * SCALE_MS)
            delay_log("T %05"PRId64" - timers took %"PRId64".%03"PRId64"\n",
                      (t3 / SCALE_MS) % 100000,
                      ((t3 - t2) / SCALE_MS) % 10000,
                      ((t3 - t2) / SCALE_US) % 1000);
    }
#endif
#endif
    if (ret > 0) {
        ioh_event *event, *next;

        w->del_state = WO_PROTECT;
        for (ev = 0; ev < w->num; ev++) {
            if (w->desc[ev].del || !w->events[ev].revents)
                continue;
#ifdef DEBUG_WAITOBJECTS
            trace_waitobjects_print("event fn %p/%s\n", w->desc[ev].func,
                                    w->desc[ev].func_name);
            w->desc[ev].triggered++;
#endif
            if (w->desc[ev].func2)
                w->desc[ev].func2(w->desc[ev].opaque,
                                  w->events[ev].revents);
#ifdef DEBUG_WAITOBJECTS
            t4 = os_get_clock();
            if ((t4 - t3) > SCALE_MS)
                delay_log("F %05"PRId64" - callback %s took %"PRId64
                          ".%03"PRId64"\n",
                          (t4 / SCALE_MS) % 100000, w->desc[ev].func_name,
                          ((t4 - t3) / SCALE_MS) % 10000,
                          ((t4 - t3) / SCALE_US) % 1000);
#endif
        }
        TAILQ_FOREACH_SAFE(event, &events, link, next) {
            TAILQ_REMOVE(&events, event, link);
            event->processq = NULL;
#ifdef DEBUG_WAITOBJECTS
            trace_waitobjects_print("event fn %p/%s\n", event->func,
                                    event->func_name);
#endif
            ioh_event_reset(event);
            if (event->func)
                event->func(event->opaque);
#ifdef DEBUG_WAITOBJECTS
            t4 = os_get_clock();
            if ((t4 - t3) > SCALE_MS)
                delay_log("F %05"PRId64" - callback %s took %"PRId64
                          ".%03"PRId64"\n",
                          (t4 / SCALE_MS) % 100000, event->func_name,
                          ((t4 - t3) / SCALE_MS) % 10000,
                          ((t4 - t3) / SCALE_US) % 1000);
#endif
        }
        if (w->del_state == WO_GC)
            ioh_gc_del_fds(w);
        w->del_state = WO_OK;
    } else if (ret == 0) {
        trace_waitobjects_print("timeout\n");
    } else {
        debug_printf("select error %d\n", ret);
        for (ev = 0; ev < w->num; ev++) {
#ifndef DEBUG_WAITOBJECTS
            debug_printf("object %d: cb %p\n", ev,
                         w->desc[ev].func);
#else
            debug_printf("object %d: cb %p/%s\n", ev,
                         w->desc[ev].func,
                         w->desc[ev].func_name);
#endif
        }
    }

    /* remove deleted IO handlers */
    if (iohq) {
        critical_section_enter(&iohq->lock);
        TAILQ_FOREACH_SAFE(ioh, &iohq->queue, queue, next) {
#if defined(CONFIG_NETEVENT)
            if (ioh->deleted) {
                TAILQ_REMOVE(&iohq->queue, ioh, queue);
                if (ioh->object_events)
                    ioh_del_wait_fd(ioh->fd, w);
                free(ioh);
            }
#endif  /* CONFIG_NETEVENT */
        }
        critical_section_leave(&iohq->lock);
    }

#ifndef LIBIMG
    if (active_timers) {
#ifdef DEBUG_WAITOBJECTS
        t3 = os_get_clock();
#endif
        run_timers(active_timers, vm_clock);
        run_timers(active_timers, rt_clock);
#ifdef DEBUG_WAITOBJECTS
        t4 = os_get_clock();
        if ((t4 - t3) > 2 * SCALE_MS)
            delay_log("T %05"PRId64" - tail timers took %"PRId64
                      ".%03"PRId64"\n",
                      (t4 / SCALE_MS) % 100000, ((t4 - t3) / SCALE_MS) % 10000,
                      ((t4 - t3) / SCALE_US) % 1000);
#endif
    }
#endif
}

void host_main_loop_wait(int *timeout)
{

#if defined(CONFIG_SLIRP) && !defined(SLIRP_THREADED)
    slirp_select_fill(timeout);
#endif

#ifndef LIBIMG
    ioh_wait_for_objects(&io_handlers, &wait_objects, main_active_timers, timeout, NULL);
#else
    ioh_wait_for_objects(&io_handlers, &wait_objects, NULL, timeout, NULL);
#endif

#if defined(CONFIG_SLIRP) && !defined(SLIRP_THREADED)
    slirp_check_timeout();
#endif

#ifndef LIBIMG
    async_op_process(NULL);
#endif
}

#ifdef DEBUG_WAITOBJECTS
void
ic_wo(struct Monitor *mon)
{
    int i;
    WaitObjects *w = &wait_objects;

    for (i = 0; i < w->num; i++) {
        debug_printf("wo %d fn %p %30s triggered %10d\n", i, w->desc[i].func,
                     w->desc[i].func_name, w->desc[i].triggered);
    }
}

static void
clear_wo(void)
{
    int i;
    WaitObjects *w = &wait_objects;

    for (i = 0; i < w->num; i++) {
        w->desc[i].triggered = 0;
    }
}

#ifdef MONITOR
void
mc_clear_stats(Monitor *mon, const dict args)
{
    void ioreqstat_clear(void);

    clear_wo();
    ioreqstat_clear();
}
#endif  /* MONITOR */

#endif	/* DEBUG_WAITOBJECTS */

#if 0                           /* np */
int ioh_set_np_handler2(HANDLE np,
                        IOCanRWHandler *np_read_poll,
                        IOHandler *np_read,
                        IOHandler *np_write,
                        void *opaque,
                        struct io_handlers_tailq *iohq)
{
    IOHandlerRecord *ioh;

    if (!iohq)
        iohq = &io_handlers;

    TAILQ_FOREACH(ioh, iohq, queue)
	if (ioh->np == np)
	    break;

    if (!np_read && !np_write) {
	if (ioh)
	    ioh->deleted = 1;
    } else {
	if (ioh == NULL) {
	    ioh = calloc(1, sizeof(IOHandlerRecord));
	    TAILQ_INSERT_HEAD(iohq, ioh, queue);
	}
        ioh->np = np;
        ioh->np_read_poll = np_read_poll;
        ioh->np_read = np_read;
        ioh->np_write = np_write;
        ioh->opaque = opaque;
        ioh->deleted = 0;
    }

    return 0;
}
#endif  /* np */
