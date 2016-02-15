/*
 * Copyright 2012-2016, Bromium, Inc.
 * Author: Christian Limpach <Christian.Limpach@gmail.com>
 * SPDX-License-Identifier: ISC
 */

#include "config.h"

#include <stdint.h>

#include "dm.h"
#include "ioh.h"
#include "timer.h"
#include "queue.h"

#if defined(CONFIG_NICKEL)
#include "libnickel.h"
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

#ifndef DEBUG_WAITOBJECTS
int ioh_add_wait_object(ioh_event *event, WaitObjectFunc *func, void *opaque,
                        WaitObjects *w)
#else
int _ioh_add_wait_object(ioh_event *event, WaitObjectFunc *func, void *opaque,
                         WaitObjects *w, const char *func_name)
#endif
{

    if (w == NULL)
	w = &wait_objects;

    if (w->num == w->max)
        ioh_waitobjects_grow(w);
    w->events[w->num] = *event;
    w->desc[w->num].func = func;
    w->desc[w->num].opaque = opaque;
#ifdef DEBUG_WAITOBJECTS
    w->desc[w->num].func_name = func_name;
    w->desc[w->num].triggered = 0;
#endif

    w->num++;

    return 0;
}

void ioh_del_wait_object(ioh_event *event, WaitObjects *w)
{
    int i;

    if (w == NULL)
        w = &wait_objects;

    for (i = 0; i < w->num; i++)
        if (w->events[i] == *event)
            break;

    if (i == w->num) {
        debug_printf("ioh_del_wait_object: event %p not found in %s\n",
                     event, w == &wait_objects ? "main" : "block");
        debug_break();
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

#if defined(CONFIG_NETEVENT)
static void
ioh_object_signalled(void * context)
{
    WSANETWORKEVENTS net_events;
    int events;
    int devents;

    IOHandlerRecord *ioh = (IOHandlerRecord *)context;

    if (ioh->deleted)
        return;

    if (WSAEnumNetworkEvents(ioh->fd, NULL, &net_events) == SOCKET_ERROR) {
	Wwarn("WSAEnumNetworkEvents fd %d events 0x%x",
              ioh->fd, ioh->object_events);
	return;
    }

    events = net_events.lNetworkEvents;

#define IOH_READ_EVENTS (FD_READ|FD_ACCEPT|FD_CLOSE)
#define IOH_WRITE_EVENTS (FD_WRITE|FD_CLOSE)
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
#if 0
        if (devents)
            printf("===== unhandled events 0x%x =====\n", devents);
#endif
    }
}
#endif  /* CONFIG_NETEVENT */

static void
np_signalled(void *context)
{
    IOHandlerRecord *ioh = (IOHandlerRecord *)context;

    ioh->np_read(ioh->opaque);
    ioh->np_read_pending = NP_READ_DONE;
}

void ioh_init_wait_objects(WaitObjects *w)
{
    w->num = 0;
    w->events = NULL;
    w->desc = NULL;
    w->max = 0;
    w->del_state = WO_OK;
    w->interrupt = (uintptr_t)CreateEvent(NULL, TRUE, FALSE, NULL);
}

void ioh_wait_interrupt(WaitObjects *w)
{
    SetEvent((HANDLE)w->interrupt);
}

void ioh_cleanup_wait_objects(WaitObjects *w)
{
    CloseHandle((HANDLE)w->interrupt);
}

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
    int first;

    if (ret_wait)
        *ret_wait = 0;

    ret = 0;

    if (iohq) {
        critical_section_enter(&iohq->lock);
        TAILQ_FOREACH_SAFE(ioh, &iohq->queue, queue, next) {
            if (ioh->np) {
                if (ioh->deleted) {
                    if (ioh->np_read_pending == NP_READ_PENDING)
                        ioh_del_wait_object(&ioh->np, w);
                    TAILQ_REMOVE(&iohq->queue, ioh, queue);
                    free(ioh);
                    continue;
                }
                if (ioh->np_read_pending == NP_READ_PENDING)
                    continue;
                if (ioh->np_read_poll && ioh->np_read_poll(ioh->opaque) == 0)
                    continue;
                ioh->np_read_pending = NP_READ_PENDING;
                ioh_add_wait_object(&ioh->np, np_signalled, ioh, w);
#if defined(CONFIG_NETEVENT)
            } else {
                int events = 0;

                if (ioh->fd != -1 && !ioh->deleted) {
                    if (ioh->fd_read &&
                        (!ioh->fd_read_poll ||
                         ioh->fd_read_poll(ioh->opaque) != 0)) {
                        events |= FD_READ | FD_ACCEPT | FD_CLOSE;
                    }
                    if (ioh->fd_write &&
                        (!ioh->fd_write_poll ||
                         ioh->fd_write_poll(ioh->opaque) != 0)) {
                        events |= FD_WRITE | FD_CLOSE;
                    }
                }
                if (events) {
                    if (!ioh->event)
                        ioh->event = WSACreateEvent();
                    WSAEventSelect(ioh->fd, ioh->event, events);
                    if (!ioh->object_events) {
                        ioh_add_wait_object(&ioh->event, ioh_object_signalled,
                                            ioh, w);
                    }
                } else {
                    if (ioh->object_events)
                        ioh_del_wait_object(&ioh->event, w);
                }
                ioh->object_events = events;
#endif  /* CONFIG_NETEVENT */
            }
        }
        assert(!iohq->wait_queue);
        iohq->wait_queue = w;
        critical_section_leave(&iohq->lock);
    }
    ioh_add_wait_object((ioh_event *)&w->interrupt, NULL, NULL, w);

#ifndef LIBIMG
    if (active_timers) {
        timer_deadline(active_timers, rt_clock, timeout);
        timer_deadline(active_timers, vm_clock, timeout);
    }
#endif

    first = 0;

#ifdef DEBUG_WAITOBJECTS
    if (trace_waitobjects)
	t1 = os_get_clock();
#endif

    while (ret == 0 && (w->num - first) > 0) {
        int num;

#ifdef DEBUG_WAITOBJECTS
	t1 = os_get_clock();
	if (0 && !first && *timeout)
	    delay_log("B %05"PRId64" - timeout %d\n",
		      (t1 / SCALE_MS) % 100000, *timeout);
#endif

        num = w->num - first;
        if (num >=  MAXIMUM_WAIT_EVENTS)
            num = MAXIMUM_WAIT_EVENTS;
        if (ret_wait)
            tmp_ts = os_get_clock_ms();
        ret = WaitForMultipleObjectsEx(num, &w->events[first], FALSE,
                                       first ? 0 : *timeout, TRUE);
        if (ret_wait)
            *ret_wait += (int) (os_get_clock_ms() - tmp_ts);

#ifndef LIBIMG
#ifdef DEBUG_WAITOBJECTS
        if (trace_waitobjects) {
            t2 = os_get_clock();
            trace_waitobjects_print("wait for events %d: pcount %"PRIx64
				    "/%x\n", w->num, (t2 - t1) / SCALE_MS,
				    *timeout);
        }
	t2 = os_get_clock();
	if (!first && ((t2 - t1) / SCALE_MS > *timeout + 1))
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
        if (WAIT_OBJECT_0 <= ret && ret < WAIT_OBJECT_0 + num) {
            ev = first + ret - WAIT_OBJECT_0;
            ResetEvent(w->events[ev]);
#ifdef DEBUG_WAITOBJECTS
	    trace_waitobjects_print("event fn %p/%s\n", w->desc[ev].func,
				    w->desc[ev].func_name);
            w->desc[ev].triggered++;
#endif
            if (w->desc[ev].func)
                w->desc[ev].func(w->desc[ev].opaque);
#ifdef DEBUG_WAITOBJECTS
	    t4 = os_get_clock();
	    if ((t4 - t3) > SCALE_MS)
		delay_log("F %05"PRId64" - callback %s took %"PRId64
			  ".%03"PRId64"\n",
			  (t4 / SCALE_MS) % 100000, w->desc[ev].func_name,
			  ((t4 - t3) / SCALE_MS) % 10000,
			  ((t4 - t3) / SCALE_US) % 1000);
#endif
	    first = ev + 1;
            ret = 0;
        } else if (ret == WAIT_TIMEOUT) {
	    trace_waitobjects_print("timeout\n");
            ret = 0;
	    break;
        } else if (ret == WAIT_IO_COMPLETION) {
	    trace_waitobjects_print("io completion\n");
            ret = 0;
	    break;
        } else {
            debug_printf("WaitForMultipleObjects error %d %ld\n", ret,
                         GetLastError());
            for (ev = 0; ev < w->num; ev++) {
#ifndef DEBUG_WAITOBJECTS
                debug_printf("object %d: event %p cb %p\n", ev,
                             w->events[ev], w->desc[ev].func);
#else
                debug_printf("object %d: event %p cb %p/%s\n", ev,
                             w->events[ev], w->desc[ev].func,
                             w->desc[ev].func_name);
#endif
            }
	    break;
        }
    }

    ioh_del_wait_object((ioh_event *)&w->interrupt, w);
    /* remove deleted IO handlers */
    if (iohq) {
        critical_section_enter(&iohq->lock);
        assert(iohq->wait_queue);
        iohq->wait_queue = NULL;
        TAILQ_FOREACH_SAFE(ioh, &iohq->queue, queue, next) {
            if (ioh->np) {
                if (ioh->deleted) {
                    if (ioh->np_read_pending == NP_READ_PENDING)
                        ioh_del_wait_object(&ioh->np, w);
                    TAILQ_REMOVE(&iohq->queue, ioh, queue);
                    free(ioh);
                    continue;
                }
                if (ioh->np_read_pending != NP_READ_DONE)
                    continue;
                if (ioh->np_read_poll && ioh->np_read_poll(ioh->opaque)) {
                    ioh->np_read_pending = NP_READ_PENDING;
                    continue;	    
                }
                ioh_del_wait_object(&ioh->np, w);
                ioh->np_read_pending = NP_READ_POLL;
#if defined(CONFIG_NETEVENT)
            } else {
                if (ioh->deleted) {
                    TAILQ_REMOVE(&iohq->queue, ioh, queue);
                    if (ioh->object_events)
                        ioh_del_wait_object(&ioh->event, w);
                    if (ioh->event)
                        WSACloseEvent(ioh->event);
                    free(ioh);
                }
#endif  /* CONFIG_NETEVENT */
            }
        }
        critical_section_leave(&iohq->lock);
    }
    ResetEvent((HANDLE)w->interrupt);

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

#if defined(CONFIG_NICKEL) && !defined(NICKEL_THREADED)
    ni_prepare(NULL, timeout);
#endif

#ifndef LIBIMG
    ioh_wait_for_objects(&io_handlers, &wait_objects, main_active_timers, timeout, NULL);
#else
    ioh_wait_for_objects(&io_handlers, &wait_objects, NULL, timeout, NULL);
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

int ioh_set_np_handler2(HANDLE np,
                        IOCanRWHandler *np_read_poll,
                        IOHandler *np_read,
                        IOHandler *np_write,
                        void *opaque,
                        struct io_handler_queue *iohq)
{
    IOHandlerRecord *ioh;

    if (!iohq)
        iohq = &io_handlers;

    critical_section_enter(&iohq->lock);
    TAILQ_FOREACH(ioh, &iohq->queue, queue)
	if (ioh->np == np)
	    break;

    if (!np_read && !np_write) {
	if (ioh)
	    ioh->deleted = 1;
    } else {
	if (ioh == NULL) {
	    ioh = calloc(1, sizeof(IOHandlerRecord));
	    TAILQ_INSERT_HEAD(&iohq->queue, ioh, queue);
	}
        ioh->np = np;
        ioh->np_read_poll = np_read_poll;
        ioh->np_read = np_read;
        ioh->np_write = np_write;
        ioh->opaque = opaque;
        ioh->deleted = 0;
    }
    if (iohq->wait_queue) /* asleep in another thread */
        ioh_wait_interrupt(iohq->wait_queue);
    critical_section_leave(&iohq->lock);

    return 0;
}
