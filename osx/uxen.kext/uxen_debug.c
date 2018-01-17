/*
 *  uxen_debug.c
 *  uxen
 *
 * Copyright 2012-2018, Bromium, Inc.
 * Author: Julian Pidancet <julian@pidancet.net>
 * SPDX-License-Identifier: ISC
 * 
 */

#include <libkern/libkern.h>

#include "uxen.h"

#include <kern/clock.h>
#include <kern/locks.h>

/* use alloca built-in for gcc, no kernel header prototype */
#if defined(__GNUC__) && __GNUC__ >= 3
void    *alloca(size_t);
#undef  alloca
#undef  __alloca
#define alloca(size)    __alloca(size)
#define __alloca(size)  __builtin_alloca(size)
#else
#error __GNUC__ >= 3 required
#endif

/* lck_mtx_lock and vprintf aren't safe while preemption is disabled,
 * but system logging is convenient for some types of debugging */
// #define UXEN_UNSAFE_SYNCHRONOUS_SYSTEM_LOGGING

#ifdef UXEN_UNSAFE_SYNCHRONOUS_SYSTEM_LOGGING
#ifdef DEBUG
int kdbgprint = 1;
#else
int kdbgprint = 0;
#endif
int kdbgprintvm = 0;

static lck_mtx_t *print_lock = NULL;
#endif

int
uxen_print_init(void)
{

#ifdef UXEN_UNSAFE_SYNCHRONOUS_SYSTEM_LOGGING
    print_lock = lck_mtx_alloc_init(uxen_lck_grp, LCK_ATTR_NULL);
    if (!print_lock)
        return ENOMEM;
#endif

    return 0;
}

void
uxen_print_exit(void)
{

#ifdef UXEN_UNSAFE_SYNCHRONOUS_SYSTEM_LOGGING
    if (print_lock) {
        lck_mtx_free(print_lock, uxen_lck_grp);
        print_lock = NULL;
    }
#endif
}

int
uxen_vprintk(struct vm_info_shared *vmi, const char *fmt, va_list ap)
{
    int ret;

#ifdef UXEN_UNSAFE_SYNCHRONOUS_SYSTEM_LOGGING
    va_list ap2;

    va_copy(ap2, ap);
#endif

    ret = uxen_op_logging_vprintk(vmi, fmt, ap);

#ifdef UXEN_UNSAFE_SYNCHRONOUS_SYSTEM_LOGGING
    if (!kdbgprint)
	return 0;
    if (!kdbgprintvm && ret)
        return 0;

    if (print_lock)
        lck_mtx_lock(print_lock);
    ret = vprintf(fmt, ap2);
    if (print_lock)
        lck_mtx_unlock(print_lock);
    va_end(ap2);

    return ret;
#else
    return 0;
#endif
}

#ifdef UXEN_DPRINTK
uint64_t
uxen_dprintk(struct vm_info_shared *vmi, const char *fmt, ...)
{
    va_list ap;
    int ret;

    va_start(ap, fmt);
    ret = uxen_vprintk(vmi, fmt, ap);
    va_end(ap);

    return ret;
}
#else
uint64_t
uxen_dprintk(struct vm_info_shared *vmi, const char *fmt, ...)
{
    return 0;
}
#endif

uint64_t
uxen_printk(struct vm_info_shared *vmi, const char *fmt, ...)
{
    va_list ap;
    int ret;

    va_start(ap, fmt);
    ret = uxen_vprintk(vmi, fmt, ap);
    va_end(ap);

    return ret;
}

uint64_t __cdecl
ui_printf(struct vm_info_shared *vmi, const char *fmt, ...)
{
    va_list ap;
    int ret;

    va_start(ap, fmt);
    ret = uxen_vprintk(vmi, fmt, ap);
    va_end(ap);

    return ret;
}

#define TIMESTAMP_FMT "%ld.%06d: %s"
#define TIMESTAMP_size (20 + 1 + 6 + 2 + 1)

uint64_t
uxen_printk_with_timestamp(struct vm_info_shared *vmi, const char *_fmt, ...)
{
    char *fmt = alloca(TIMESTAMP_size + strlen(_fmt) + 1);
    clock_sec_t secs;
    clock_usec_t usecs;
    va_list ap;
    int ret;

    clock_get_calendar_microtime(&secs, &usecs);

    ret = snprintf(fmt, TIMESTAMP_size + strlen(_fmt) + 1, TIMESTAMP_FMT,
                   secs, usecs % 1000000, _fmt);
    if (ret >= TIMESTAMP_size + strlen(_fmt) + 1)
        memcpy(fmt, _fmt, strlen(_fmt) + 1);

    va_start(ap, _fmt);
    ret = uxen_vprintk(vmi, fmt, ap);
    va_end(ap);

    return ret;
}
