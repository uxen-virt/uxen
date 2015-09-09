/*
 * Copyright 2012-2016, Bromium, Inc.
 * Author: Christian Limpach <Christian.Limpach@gmail.com>
 * SPDX-License-Identifier: ISC
 */

#ifndef _OSX_H_
#define _OSX_H_

#include <inttypes.h>
#include <limits.h>
#include <stdlib.h>
#include <stddef.h>

#define ffs strffs
#define fls strfls
#include <string.h>
#undef ffs
#undef fls
#include <err.h>

#include "queue.h"
#include "typedef.h"

static inline void *
align_alloc(size_t alignment, size_t size)
{
    void *ptr;
    int ret;

    ret = posix_memalign(&ptr, alignment, size);
    if (ret) {
	warn("%s", __FUNCTION__);
	return NULL;
    }

    return ptr;
}

static inline void
align_free(void *ptr)
{

    free(ptr);
}

#define ALIGN_PAGE_ALIGN 0x1000
#define page_align_alloc(size) align_alloc(ALIGN_PAGE_ALIGN, size)

#define closesocket(s) close(s)

#ifndef O_BINARY
#define O_BINARY 0
#endif

#define PRIdSIZE "zd"
#define PRIuSIZE "zu"
#define PRIxSIZE "zx"

#define Werr(eval, fmt, ...) err(eval, fmt, ## __VA_ARGS__)
#define Wwarn(fmt, ...) warn(fmt, ## __VA_ARGS__)

#include <pthread.h>
typedef pthread_mutex_t critical_section;
void critical_section_init(critical_section *cs);
void critical_section_enter(critical_section *cs);
void critical_section_leave(critical_section *cs);
void critical_section_free(critical_section *cs);

#include <poll.h>
typedef int ioh_handle;
struct ioh_event_queue;
typedef struct ioh_event {
    uintptr_t ident;
    int16_t filter;
    unsigned fflags;
    WaitObjectFunc *func;
    void *opaque;
#define IOH_MAX_QUEUES 8
    int queues[IOH_MAX_QUEUES];
    int nqueues;
    critical_section lock;
    int signaled;
    int valid;
    const char *func_name;
    struct ioh_event_queue *processq;
    TAILQ_ENTRY(ioh_event) link;
} ioh_event;

typedef TAILQ_HEAD(ioh_event_queue, ioh_event) ioh_event_queue;

typedef struct pollfd ioh_wait_event;

#include <assert.h>
#define assert_always(cond) assert(cond)

/* Must hold event lock */
static inline void ioh_event_queue_add(ioh_event *ev, int queue)
{
    assert(ev->nqueues < IOH_MAX_QUEUES);
    ev->queues[ev->nqueues++] = queue;
}

/* Must hold event lock */
static inline void ioh_event_queue_del(ioh_event *ev, int queue)
{
    int q;

    for (q = 0; q < ev->nqueues; q++)
        if (ev->queues[q] == queue)
            break;
    assert(q != ev->nqueues);
    for (; q < (ev->nqueues - 1); q++)
        ev->queues[q] = ev->queues[q + 1];
    ev->nqueues--;
}

void ioh_event_init(ioh_event *ev);
void ioh_event_init_with_mach_port(ioh_event *ev, mach_port_t port);
void ioh_event_set(ioh_event *ev);
void ioh_event_reset(ioh_event *ev);
void ioh_event_wait(ioh_event *ev);
void ioh_event_close(ioh_event *ev);

static inline int ioh_event_valid(ioh_event *ev) {
    return (ev->valid != 0);
}
int set_nofides(void);

struct uxen_user_notification_event;
typedef struct uxen_notification_event {
    /* id must be first, kernel writes here */
    uint32_t id;
    STAILQ_ENTRY(uxen_notification_event) entry;
    WaitObjectFunc *func;
    void *opaque;
} *uxen_notification_event;
typedef struct uxen_user_notification_event *uxen_user_notification_event;
void uxen_notification_event_init(uxen_notification_event *ev);
void uxen_user_notification_event_init(uxen_user_notification_event *ev);
void uxen_user_notification_event_set(uxen_user_notification_event *ev);
int uxen_notification_add_wait_object(uxen_notification_event *event,
                                      WaitObjectFunc *func, void *opaque,
                                      WaitObjects *wo);
int file_exists(const char *path);

/* XXX NSWindow? */
typedef void *window_handle;

typedef pthread_t uxen_thread;

#define create_thread(thread, fn, arg) (({                              \
                int ret = pthread_create(thread, NULL, fn, arg);        \
                if (ret)                                                \
                    *(thread) = NULL;                                   \
                ret;                                                    \
            }))
#define setcancel_thread() (({                                          \
            int oldstate;                                               \
            int ret = pthread_setcancelstate(PTHREAD_CANCEL_ENABLE,     \
                                             &oldstate);                \
            if (!ret)                                                   \
                ret = pthread_setcanceltype(PTHREAD_CANCEL_DEFERRED,    \
                                            &oldstate);                 \
            ret;                                                        \
            }))
#define cancel_thread(thread) pthread_cancel(thread)
/* TODO: implement */
#define elevate_thread(thread) do {} while(0)
#define wait_thread(thread) pthread_join(thread, 0)
#define detach_thread(thread) pthread_detach(thread)
#define close_thread_handle(thread) do { } while(0)

int generate_random_bytes(void *buf, size_t len);
void cpu_usage(float *user, float *kernel, uint64_t *user_total_ms,
               uint64_t *kernel_total_ms);

#endif	/* _OSX_H_ */
