/*
 * Copyright 2017, Bromium, Inc.
 * SPDX-License-Identifier: ISC
 */

#ifndef _DEBUG_USER_H_
#define _DEBUG_USER_H_

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
#define UXEN_UD_PROGNAME uxen_ud_progname

typedef void(*_printk_type)(const char *fmt, ...);
__declspec(selectany)
_printk_type _printk = NULL;
__declspec(selectany)
unsigned int uxen_ud_mask = DEF_UXEN_UD_MASK;
__declspec(selectany)
char uxen_ud_progname[64] = "null";

static inline void uxen_ud_set_progname(const char *name)
{
    memset(uxen_ud_progname, 0, sizeof(uxen_ud_progname));
    memcpy(uxen_ud_progname, name, strlen(name));
}

static inline void uxen_ud_set_printk(void* pfn)
{
    _printk = (_printk_type)pfn;
}

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
