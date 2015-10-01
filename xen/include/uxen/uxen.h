/*
 *  uxen.h
 *  uxen
 *
 * Copyright 2012-2015, Bromium, Inc.
 * Author: Christian Limpach <Christian.Limpach@gmail.com>
 * SPDX-License-Identifier: ISC
 *
 */

#ifndef __UXEN_H__
#define __UXEN_H__

#include <xen/percpu.h>

#define uxen_info _uxen_info
#include "uxen_info.h"
#undef uxen_info
extern struct _uxen_info _uxen_info;

extern void ui_printf(struct vm_info_shared *vmi, const char *fmt, ...);

#if defined(UXEN_HOST_WINDOWS)
#ifdef __x86_64__
#define UXEN_GS_CPU_OFFSET 0x184
#define UXEN_GS_INFO_OFFSET 0x40
#define UXEN_GS_CURRENT_OFFSET 0x48
#else
#define UXEN_FS_CPU_OFFSET 0x51
/* #define UXEN_FS_INFO_OFFSET XXX */
#define UXEN_FS_CURRENT_OFFSET 0x8
#endif
#elif defined(UXEN_HOST_OSX)
/* uxen_info based.  */
#undef UXEN_GS_CPU_OFFSET
#undef UXEN_GS_INFO_OFFSET
#undef UXEN_GS_CURRENT_OFFSET
#else
#error UXEN_HOST undefined
#endif

#ifdef UXEN_GS_INFO_OFFSET
static inline struct _uxen_info *
get_uxen_info(void)
{
    struct _uxen_info *info;
    __asm__ ("movq %%gs:"STR(UXEN_GS_INFO_OFFSET)", %0"
             : "=r" (info));
    return info;
}
#define uxen_info (get_uxen_info())

static inline void
set_uxen_info(struct _uxen_info *info)
{
    __asm__ ("movq %0, %%gs:"STR(UXEN_GS_INFO_OFFSET)
             : : "r" (info));
}
#else
#define uxen_info (&_uxen_info)
#define set_uxen_info(info) (void)(info)
#endif

struct uxen_init_desc;
void options_parse(const struct uxen_init_desc *, uint64_t);

void do_hvm_cpu_up(void *arg);

DECLARE_PER_CPU(uintptr_t, stack_top);
#ifdef __x86_64__
#define set_stack_top() asm("mov %%rsp, %0" : "=m" this_cpu(stack_top))
#else
#define set_stack_top() asm("mov %%esp, %0" : "=m" this_cpu(stack_top))
#endif
#define save_stack_top(x) do {                  \
        (x) = this_cpu(stack_top);              \
        set_stack_top();                        \
    } while (0)
#define restore_stack_top(x) this_cpu(stack_top) = (x)

DECLARE_PER_CPU(struct uxen_hypercall_desc *, hypercall_args);

#endif
