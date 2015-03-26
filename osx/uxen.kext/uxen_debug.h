/*
 *  uxen_debug.h
 *  uxen
 *
 * Copyright 2013-2015, Bromium, Inc.
 * Author: Christian Limpach <Christian.Limpach@gmail.com>
 * SPDX-License-Identifier: ISC
 *
 */

#ifndef _UXEN_DEBUG_H_
#define _UXEN_DEBUG_H_

#ifdef DEBUG
#define UXEN_DPRINTK
#endif
// #define UXEN_MM_DPRINTK

int uxen_print_init(void);
void uxen_print_exit(void);

struct vm_info_shared;

int uxen_vprintk(struct vm_info_shared *, const char *fmt, va_list ap)
    __attribute__((format(printf, 2, 0)));

uint64_t uxen_dprintk(struct vm_info_shared *, const char *fmt, ...)
    __attribute__((format(printf, 2, 3)));
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

uint64_t uxen_printk(struct vm_info_shared *, const char *fmt, ...)
    __attribute__((format(printf, 2, 3)));
#define printk(fmt, ...) uxen_printk(NULL, fmt, ## __VA_ARGS__)
#define fail_msg(fmt, ...) uxen_printk(NULL, "uxen: %s: " fmt "\n",     \
                                       __FUNCTION__, ## __VA_ARGS__)
uint64_t uxen_printk_with_timestamp(struct vm_info_shared *, const char *fmt,
                                    ...) __attribute__((format(printf, 2, 3)));
#define printk_with_timestamp(fmt, ...)                         \
    uxen_printk_with_timestamp(NULL, fmt, ## __VA_ARGS__)

#define debug_break() asm("int $3\n")

#define BUG_ON(condition) assert(!(condition))

#endif  /* _UXEN_DEBUG_H_ */
