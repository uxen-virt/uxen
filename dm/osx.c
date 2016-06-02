/*
 * Copyright 2012-2016, Bromium, Inc.
 * Author: Christian Limpach <Christian.Limpach@gmail.com>
 * SPDX-License-Identifier: ISC
 */

#include "config.h"

#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/resource.h>
#include <sys/types.h>
#include <sys/event.h>
#include <sys/time.h>
#include <string.h>
#include <mach/mach.h>
#include <mach/mach_time.h>
#include <sys/stat.h>

#include "queue.h"

#ifdef QEMU_UXEN
#include <uxenctllib.h>
#endif

#ifdef QEMU_UXEN
extern UXEN_HANDLE_T uxen_handle;
#endif

int initcall_logging = 0;

void
socket_set_block(int fd)
{
    int f;

    f = fcntl(fd, F_GETFL);
    fcntl(fd, F_SETFL, f & ~O_NONBLOCK);
}

void
socket_set_nonblock(int fd)
{
    int f;

    f = fcntl(fd, F_GETFL);
    fcntl(fd, F_SETFL, f | O_NONBLOCK);
}

int
get_timeoffset(void)
{
    struct tm *timeinfo;
    time_t current_time;

    time(&current_time);
    timeinfo = localtime(&current_time);

    return timeinfo->tm_gmtoff;
}

void
critical_section_init(critical_section *cs)
{
    static pthread_mutexattr_t mta_recursive;
    static int initialized = 0;
    int ret;

    if (!initialized) {
        assert(!pthread_mutexattr_init(&mta_recursive));
        assert(!pthread_mutexattr_settype(&mta_recursive,
                                          PTHREAD_MUTEX_RECURSIVE));
    }

    ret = pthread_mutex_init(cs, &mta_recursive);
    if (ret) {
        debug_printf("%s: pthread_mutex_init failed: %s", __FUNCTION__,
                     strerror(ret));
        abort();
    }
}

void
critical_section_free(critical_section *cs)
{
    int ret;

    ret = pthread_mutex_destroy(cs);
    if (ret) {
        debug_printf( "%s: pthread_mutex_destroy failed: %s", __FUNCTION__,
                     strerror(ret));
        abort();
    }
}

void
critical_section_enter(critical_section *cs)
{
    int ret;

    ret = pthread_mutex_lock(cs);
    if (ret) {
        debug_printf( "%s: pthread_mutex_lock failed: %s", __FUNCTION__,
                     strerror(ret));
        abort();
    }
}

void
critical_section_leave(critical_section *cs)
{
    int ret;

    ret = pthread_mutex_unlock(cs);
    if (ret) {
        debug_printf( "%s: pthread_mutex_unlock failed: %s", __FUNCTION__,
                     strerror(ret));
        abort();
    }
}

int file_exists(const char *path)
{
    struct stat st;

    if (stat(path, &st) >= 0)
        return 1;
    else
        return 0;
}

static uintptr_t
alloc_ident(void)
{
    static volatile uintptr_t ident = 0;
    uintptr_t ret;

    asm volatile ("lock; xaddq %%rax, %2"
                  : "=a" (ret)
                  : "a" (1), "m" (ident)
                  : "memory" );

    assert(ident);

    return ret;
}

static inline int xchg(int *ptr, int val)
{
    int ret;

    asm volatile ("lock; xchg %%rax, %2"
                  : "=a" (ret)
                  : "a" (val), "m" (*ptr)
                  : "memory" );

    return ret;
}

void
ioh_event_init(ioh_event *ev)
{
    memset(ev, 0, sizeof (*ev));
    ev->ident = alloc_ident();
    ev->valid = 1;
    ev->nqueues = 0;
    ev->signaled = 0;
    ev->filter = EVFILT_USER;
    ev->fflags = 0;
    critical_section_init(&ev->lock);
}

void ioh_event_init_with_mach_port(ioh_event *ev, mach_port_t port)
{
    kern_return_t kr;
    mach_port_t pset;
    
    ioh_event_init(ev);
    
    kr = mach_port_allocate(
        mach_task_self(),
        MACH_PORT_RIGHT_PORT_SET,
        &pset);
    if (kr != KERN_SUCCESS)
        errx(1, "%s: mach_port_allocate failed (%x)", __FUNCTION__, kr);

    kr = mach_port_insert_member(mach_task_self(),
                                 port, pset);
    if (kr != KERN_SUCCESS)
        errx(1, "%s: mach_port_insert_member failed (%x)", __FUNCTION__, kr);

    
    ev->filter = EVFILT_MACHPORT;
    ev->ident = pset;
    ev->fflags = MACH_RCV_MSG;
}

void
ioh_event_set(ioh_event *ev)
{
    struct kevent kev;
    int rc;
    int q;

    assert(ev->filter == EVFILT_USER);

    critical_section_enter(&ev->lock);

    if (!xchg(&ev->signaled, 1)) {
        for (q = 0; q < ev->nqueues; q++) {
            EV_SET(&kev, ev->ident, ev->filter, EV_ENABLE, NOTE_TRIGGER, 0, ev);
            rc = kevent(ev->queues[q], &kev, 1, NULL, 0, NULL);
            if (rc == -1)
                err(1, "%s: kevent failed", __FUNCTION__);
        }
    }

    critical_section_leave(&ev->lock);
}

void
ioh_event_reset(ioh_event *ev)
{
    struct kevent kev;
    int rc;
    int q;

    if (ev->filter != EVFILT_USER)
        return;

    critical_section_enter(&ev->lock);

    for (q = 0; q < ev->nqueues; q++) {
        EV_SET(&kev, ev->ident, ev->filter, EV_CLEAR | EV_DISABLE, 0, 0, ev);
        rc = kevent(ev->queues[q], &kev, 1, NULL, 0, NULL);
        if (rc == -1)
            err(1, "%s: kevent failed", __FUNCTION__);
    }
    ev->signaled = 0;

    critical_section_leave(&ev->lock);
}

void
ioh_event_wait(ioh_event *ev)
{
    struct kevent kev;
    int rc;
    int queue;

    critical_section_enter(&ev->lock);

    if (ev->signaled)
        goto out;

    queue = kqueue();
    if (queue < 0)
        err(1, "%s: queue failed", __FUNCTION__);

    EV_SET(&kev, ev->ident, ev->filter, EV_ADD | EV_CLEAR, 0, 0, ev);
    rc = kevent(queue, &kev, 1, NULL, 0, NULL);
    if (rc == -1)
        err(1, "%s: kevent failed", __FUNCTION__);

    ioh_event_queue_add(ev, queue);

    critical_section_leave(&ev->lock);

    do {
        rc = kevent(queue, NULL, 0, &kev, 1, NULL);
        if (rc == -1 || (rc == 1 && kev.flags & EV_ERROR))
            err(1, "%s: kevent failed", __FUNCTION__);
    } while (rc != 1);

    critical_section_enter(&ev->lock);

    ioh_event_queue_del(ev, queue);

    close(queue);

out:
    critical_section_leave(&ev->lock);
}

void
ioh_event_close(ioh_event *ev)
{
    if (ev->nqueues)
        warnx("%s: event still in %d queues", __FUNCTION__, ev->nqueues);

    ev->valid = 0;

    if (ev->filter == EVFILT_MACHPORT)
    {
        // on mach port based event setup, we created a port set, which we need to get rid of
        mach_port_destroy(mach_task_self(), ev->ident);
    }
    
    critical_section_free(&ev->lock);
}

#ifdef QEMU_UXEN
struct uxen_user_notification_event {
    uint64_t fill;
};

void
uxen_user_notification_event_init(uxen_user_notification_event *ev)
{
    *ev = calloc(1, sizeof(struct uxen_user_notification_event));
    if (!*ev)
        err(1, "%s: calloc failed", __FUNCTION__);
}

void
uxen_notification_event_init(uxen_notification_event *ev)
{
    *ev = calloc(1, sizeof(struct uxen_notification_event));
    if (!*ev)
        err(1, "%s: calloc failed", __FUNCTION__);
}

static STAILQ_HEAD(, uxen_notification_event) uxen_notification_events =
    STAILQ_HEAD_INITIALIZER(uxen_notification_events);

void
uxen_user_notification_event_set(uxen_user_notification_event *ev)
{
    int ret;

    assert(*ev);
    ret = uxen_signal_event(uxen_handle, ev);
    if (ret)
        warnx("%s: uxen_signal_event failed", __FUNCTION__);
}

static ioh_event ioh_notification_event;

static void uxen_notification_wait_func(void *opaque)
{
    uxen_notification_event event;
    uint32_t signaled_events = 0;
    mach_port_t port = uxen_handle->notify_port;
    kern_return_t kr;
    int ret;
    struct {
        mach_msg_header_t hdr;
        char bytes[1024];
    } buf;

    buf.hdr.msgh_size = sizeof(buf);
    buf.hdr.msgh_remote_port = MACH_PORT_NULL;
    buf.hdr.msgh_local_port = port;

    kr = mach_msg(&buf.hdr, MACH_RCV_MSG | MACH_RCV_TIMEOUT, 0, sizeof(buf),
                  port, 0, MACH_PORT_NULL);
    if (kr != MACH_MSG_SUCCESS) {
        warnx("%s: mach_msg failed (%x)", __FUNCTION__, kr);
        return;
    }

    ret = uxen_poll_event(uxen_handle, &signaled_events);
    if (ret)
        warnx("%s: uxen_poll_event failed", __FUNCTION__);

    STAILQ_FOREACH(event, &uxen_notification_events, entry) {
        if (signaled_events == 0)
            break;
        if (signaled_events & (1 << event->id)) {
            event->func(event->opaque);
            signaled_events &= ~(1 << event->id);
        }
    }
}

int
uxen_notification_add_wait_object(uxen_notification_event *event,
                                  WaitObjectFunc *func, void *opaque,
                                  WaitObjects *wo)
{
    static int once = 0;

    if (!once) {
        mach_port_t port;
        mach_port_t pset;
        kern_return_t kr;

        port = uxen_handle->notify_port;

        kr = mach_port_allocate(mach_task_self(),
                                MACH_PORT_RIGHT_PORT_SET,
                                &pset);
        if (kr != KERN_SUCCESS)
            errx(1, "%s: mach_port_allocate failed (%x)", __FUNCTION__, kr);

        kr = mach_port_insert_member(mach_task_self(),
                                     port, pset);
        if (kr != KERN_SUCCESS)
            errx(1, "%s: mach_port_insert_member failed (%x)", __FUNCTION__, kr);

        ioh_event_init(&ioh_notification_event);
        ioh_notification_event.filter = EVFILT_MACHPORT;
        ioh_notification_event.ident = pset;

        ioh_add_wait_object(&ioh_notification_event,
                            uxen_notification_wait_func, NULL, wo);
        once++;
    }

    (*event)->func = func;
    (*event)->opaque = opaque;
    STAILQ_INSERT_TAIL(&uxen_notification_events, *event, entry);

    return 0;
}
#endif /* QEMU_UXEN */

int set_nofides(void)
{
    struct rlimit limit;

    if (getrlimit(RLIMIT_NOFILE, &limit)) {
        warnx("%s: getrlimit failed with %d", __FUNCTION__, errno);
        return -1;
    }
    if (limit.rlim_cur >= FD_SETSIZE)
        return 0;
    if (limit.rlim_max < FD_SETSIZE) {
        warnx("%s: rimit.rlim_max < FD_SETSIZE", __FUNCTION__);
        return -1;
    }
    limit.rlim_cur = FD_SETSIZE < limit.rlim_max ? FD_SETSIZE : limit.rlim_max;
    if (setrlimit(RLIMIT_NOFILE, &limit)) {
        warn("%s: setrlimit failed", __FUNCTION__);
        return -1;
    }
    debug_printf("setting RLIMIT_NOFILE to %"PRIu64" file descriptors\n",
                 limit.rlim_cur);
    return 0;
}

static int fd_random = -1;
static int fd_urandom = -1;

initcall(os_early_init)
{
    fd_random = open("/dev/random", O_WRONLY);
    if (fd_random < 0) {
        errx(1, "open(/dev/random)");
    }
    fd_urandom = open("/dev/urandom", O_RDONLY);
    if (fd_urandom < 0) {
        errx(1, "open(/dev/urandom)");
    }
}

int
generate_random_bytes(void *buf, size_t len)
{
    int ret;
    size_t l = 0;

    while (l < len) {
        ret = write(fd_random, buf + l, len - l);
        if (ret < 0)
            goto out;
        l += ret;
    }

    l = 0;
    while (l < len) {
        ret = read(fd_urandom, buf + l, len - l);
        if (ret < 0)
            goto out;
        l += ret;
    }

    ret = 0;

out:
    return ret;
}

static uint64_t
diff_mach_abs_time_ms(uint64_t start, uint64_t end)
{
    mach_timebase_info_data_t timebase_info = {0};
    mach_timebase_info(&timebase_info);

    uint64_t diff_ns = (end-start)*(timebase_info.numer/timebase_info.denom);
    return diff_ns / 1000000LU;
}

void
cpu_usage(float *user, float *kernel, uint64_t *user_total_ms,
          uint64_t *kernel_total_ms)
{
    static uint64_t last_kernel_time_ms = 0;
    static uint64_t last_user_time_ms = 0;
    static uint64_t last_time = 0;
    uint64_t current_time;
    uint64_t kernel_time_ms;
    uint64_t user_time_ms;
    uint64_t time_diff_ms;
    struct rusage r_usage = {{0}};
    int err = getrusage(RUSAGE_SELF, &r_usage);
    if (err)
        return;

    user_time_ms = (r_usage.ru_utime.tv_sec * 1000LU) +
                   (r_usage.ru_utime.tv_usec / 1000LU);
    kernel_time_ms = (r_usage.ru_stime.tv_sec * 1000LU) +
                      (r_usage.ru_stime.tv_usec / 1000LU);

    current_time = mach_absolute_time();
    time_diff_ms = diff_mach_abs_time_ms(last_time, current_time);

    if (!last_time || (last_time == current_time)) {
        if (user) *user = .0f;
        if (kernel) *kernel = .0f;
    } else {
        if (user) *user = (float)(user_time_ms - last_user_time_ms) /
                          (float)time_diff_ms;
        if (kernel) *kernel = (float)(kernel_time_ms - last_kernel_time_ms) /
                              (float)time_diff_ms;
    }

    if (user_total_ms) *user_total_ms = user_time_ms;
    if (kernel_total_ms) *kernel_total_ms = kernel_time_ms;

    last_kernel_time_ms = kernel_time_ms;
    last_user_time_ms = user_time_ms;
    last_time = current_time;
}
