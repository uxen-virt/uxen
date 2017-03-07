/*
 * Copyright 2017, Bromium, Inc.
 * Author: Tomasz Wroblewski <tomasz.wroblewski@gmail.com>
 * SPDX-License-Identifier: ISC
 */

#ifndef _COMMON_DEBUG_USER_H_
#define _COMMON_DEBUG_USER_H_

#include <stdarg.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#define UXEN_UD_ERR             (1UL << 0)
#define UXEN_UD_MSG             (1UL << 1)
#define UXEN_UD_DBG             (1UL << 2)

#ifndef DEF_UXEN_UD_MASK
#define DEF_UXEN_UD_MASK        (UXEN_UD_ERR | UXEN_UD_MSG | UXEN_UD_DBG)
#endif

#define UXEN_DEBUG_CPUID_8  0x54545400
#define UXEN_DEBUG_CPUID_32 0x54545404

__declspec(selectany)
unsigned int uxen_ud_mask = DEF_UXEN_UD_MASK;
__declspec(selectany)
char uxen_ud_progname[64] = "null";

static inline void
__user_dbg_out(unsigned int fun, unsigned int val)
{
    int ebx, edx;

    asm volatile ("cpuid": "+a" (fun), "=b" (ebx), "+c" (val), "=d" (edx)::"cc");
}

#define __user_dbg_out_char(x) __user_dbg_out(UXEN_DEBUG_CPUID_8 , x)
#define __user_dbg_out_uint(x) __user_dbg_out(UXEN_DEBUG_CPUID_32, x)

static inline void uxen_ud_set_progname(const char *name)
{
    strncpy(uxen_ud_progname, name, sizeof(uxen_ud_progname));
}

#define UXEN_UD_PROGNAME uxen_ud_progname

static inline void
_printk(const char *fmt, ...)
{
    size_t n;
    char buf[1024], *p;
    va_list args;

    va_start(args, fmt);
    n = vsnprintf(&buf[0], sizeof(buf), fmt, args);
    va_end(args);

    p = buf;
    while (n && ((uintptr_t)p & 3)) {
        __user_dbg_out_char(*p);
        p++;
        n--;
    }
    if (n) {
        while (n > 3) {
            __user_dbg_out_uint(*(unsigned int*)p);
            p += 4;
            n -= 4;
        }
        while (n) {
            __user_dbg_out_char(*p);
            p++;
            n--;
        }
    }
}

void _printk(const char *fmt, ...);

#define printk(fmt, ...)                                                \
    _printk("%s!%s:%d: " fmt "\n",                                      \
        UXEN_UD_PROGNAME, __FUNCTION__, __LINE__, ##__VA_ARGS__)

#define uxen_err(fmt, ...) do {                                         \
        if (!(uxen_ud_mask & UXEN_UD_ERR))                              \
            break;                                                      \
        printk("error: " fmt, ##__VA_ARGS__);                           \
    } while (0)

#define uxen_msg(fmt, ...) do {                                         \
        if (!(uxen_ud_mask & UXEN_UD_MSG))                              \
            break;                                                      \
        printk(fmt, ##__VA_ARGS__);                                     \
    } while (0)

#define uxen_debug(fmt, ...) do {                                       \
        if (!(uxen_ud_mask & UXEN_UD_DBG))                              \
            break;                                                      \
        printk(fmt, ##__VA_ARGS__);                                     \
    } while (0)

#endif
