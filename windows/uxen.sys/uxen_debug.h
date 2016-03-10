/*
 *  uxen_debug.h
 *  uxen
 *
 * Copyright 2013-2016, Bromium, Inc.
 * Author: Christian Limpach <Christian.Limpach@gmail.com>
 * SPDX-License-Identifier: ISC
 *
 */

#include <xen/types.h>

#ifndef _UXEN_DEBUG_H_
#define _UXEN_DEBUG_H_

#ifdef DBG
#define UXEN_DPRINTK
#endif
// #define UXEN_MM_DPRINTK

#if defined(DBG) && defined(__i386__)
#define DEBUG_PAGE_ALLOC
#endif

// #define DEBUG_STRAY_PAGES

#define PRIuuid \
    "02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x"

#define PRIuuid_arg(uuid)                                       \
    uuid[ 0], uuid[ 1], uuid[ 2], uuid[ 3], uuid[ 4], uuid[ 5], \
    uuid[ 6], uuid[ 7], uuid[ 8], uuid[ 9], uuid[10], uuid[11], \
    uuid[12], uuid[13], uuid[14], uuid[15]

struct vm_info_shared;

int kdbgprint;
int uxen_vprintk(struct vm_info_shared *,
                 const __format_string char *, va_list);

uint64_t __cdecl uxen_dprintk(struct vm_info_shared *,
                              const __format_string char *, ...);
#ifdef UXEN_DPRINTK
#define dprintk(fmt, ...) uxen_dprintk(NULL, fmt, ## __VA_ARGS__)
#else
#define dprintk(fmt, ...) do {} while (0)
#endif
#ifdef UXEN_MM_DPRINTK
#define mm_dprintk(fmt, ...) dprintk(fmt, ## __VA_ARGS__)
#else
#define mm_dprintk(fmt, ...) do {} while (0)
#endif

uint64_t __cdecl uxen_printk(struct vm_info_shared *,
                             const __format_string char *, ...);
#define printk(fmt, ...) uxen_printk(NULL, fmt, ## __VA_ARGS__)
#define fail_msg(fmt, ...) uxen_printk(NULL, "uxen: %s:%d: " fmt "\n",  \
                                       __FUNCTION__, __LINE__, ## __VA_ARGS__)
uint64_t  __cdecl uxen_printk_with_timestamp(struct vm_info_shared *,
                                             const __format_string char *, ...);
#define printk_with_timestamp(fmt, ...)                         \
    uxen_printk_with_timestamp(NULL, fmt, ## __VA_ARGS__)

extern void kdbgreboot(void);
extern void _ud2(void);

#define debug_break() DbgBreakPoint();

#define DASSERT(condition) do {                 \
        static int _ignore = 0;                 \
        if (!_ignore && !(condition))           \
            debug_break();                      \
    } while (0)

#define BUG_ON(condition) do {                                  \
        if (condition)                                          \
            KeBugCheckEx(DRIVER_VIOLATION, 0, 0, 0, __LINE__);  \
    } while (0)

#endif  /* _UXEN_DEBUG_H_ */
