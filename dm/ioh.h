/*
 * Copyright 2012-2018, Bromium, Inc.
 * Author: Christian Limpach <Christian.Limpach@gmail.com>
 * SPDX-License-Identifier: ISC
 */

#ifndef _IOH_H_
#define _IOH_H_

#include <stdint.h>

#include "os.h"
#include "queue.h"
#include "typedef.h"

enum {
   WO_OK,
   WO_PROTECT,
   WO_GC
};

typedef void IOReadHandler(void *opaque, const uint8_t *buf, int size);
typedef int IOCanRWHandler(void *opaque);
typedef int IOCanWHandler(void *opaque, uint8_t **pbuf);
typedef void IOHandler(void *opaque);
typedef void IOEventHandler(void *opaque, int event);

struct io_handler_queue;

void ioh_queue_init(struct io_handler_queue *iohq);

int ioh_set_read_handler2(int fd,
                          struct io_handler_queue *iohq,
                          IOCanRWHandler *fd_read_poll,
                          IOHandler *fd_read,
                          void *opaque);
int ioh_set_write_handler2(int fd,
                           struct io_handler_queue *iohq,
                           IOCanRWHandler *fd_write_poll,
                           IOHandler *fd_write,
                           void *opaque);
#define ioh_set_read_handler(fd, iohq, fd_read, opaque) \
    ioh_set_read_handler2(fd, iohq, NULL , fd_read, opaque)
#define ioh_set_write_handler(fd, iohq, fd_write, opaque) \
    ioh_set_write_handler2(fd, iohq, NULL , fd_write, opaque)

void ioh_wait_for_objects(struct io_handler_queue *piohq,
                          WaitObjects *w, TimerQueue *active_timers, int *timeout, int *ret_wait);

void host_main_loop_wait(int *timeout);

#if defined(DEBUG) && !defined(LIBIMG)
#define DEBUG_WAITOBJECTS
#endif

struct WaitObjectsDesc {
    union {
        WaitObjectFunc *func;
        WaitObjectFunc2 *func2;
    };
    void *opaque;
    int del;
#ifdef DEBUG_WAITOBJECTS
    const char *func_name;
    int triggered;
#endif
};

struct WaitObjects {
    int num;
    int del_state;
    ioh_wait_event *events;
    WaitObjectsDesc *desc;
    int max;
#ifdef __APPLE__
    int queue_fd;
    int queue_len;
#endif
    uintptr_t interrupt;
    critical_section lock;
};

typedef struct IOHandlerRecord {
    int fd;
#if defined(_WIN32)
    ioh_handle np;
#endif
    union {
	struct {
	    IOCanRWHandler *fd_read_poll;
	    IOHandler *fd_read;
	    IOCanRWHandler *fd_write_poll;
	    IOHandler *fd_write;
	};
#if defined(_WIN32)
	struct {
	    IOCanRWHandler *np_read_poll;
	    IOHandler *np_read;
	    IOHandler *np_write;
	};
#endif
    };
    int deleted;
    void *read_opaque;
    void *write_opaque;
    TAILQ_ENTRY(IOHandlerRecord) queue;
    union {
#if defined(CONFIG_NETEVENT)
	struct {
	    int object_events;
#if defined(_WIN32)
	    WSAEVENT event;
#endif
	};
#endif  /* CONFIG_NETEVENT */
#if defined(_WIN32)
	struct {
#define NP_READ_POLL 0
#define NP_READ_PENDING 1
#define NP_READ_DONE 2
	    int np_read_pending;
	};
#endif
    };
} IOHandlerRecord;

struct io_handler_queue {
    TAILQ_HEAD(, IOHandlerRecord) queue;
    critical_section lock;
    WaitObjects *wait_queue;
};

extern WaitObjects wait_objects;
extern struct io_handler_queue io_handlers;

void ioh_init(void);
void ioh_init_wait_objects(WaitObjects *w);
void ioh_cleanup_wait_objects(WaitObjects *w);

void ioh_wait_interrupt(WaitObjects *w);

#ifndef DEBUG_WAITOBJECTS
int ioh_add_wait_object(ioh_event *event, WaitObjectFunc *func, void *opaque,
                        WaitObjects *w);
#else
int _ioh_add_wait_object(ioh_event *event, WaitObjectFunc *func, void *opaque,
                         WaitObjects *w, const char *func_name);
#define ioh_add_wait_object(event, func, opaque, w) \
    _ioh_add_wait_object(event, func, opaque, w, #func)
#endif
int ioh_add_wait_fd(int fd, int events, WaitObjectFunc2 *func2, void *opaque,
                    WaitObjects *w);
void ioh_del_wait_object(ioh_event *event, WaitObjects *w);
void ioh_del_wait_fd(int fd, WaitObjects *w);

int ioh_set_np_handler2(ioh_handle np,
                         IOCanRWHandler *np_read_poll,
                         IOHandler *np_read,
                         IOHandler *np_write,
                         void *opaque,
                         struct io_handler_queue *ioh_q);

#endif	/* _IOH_H_ */
