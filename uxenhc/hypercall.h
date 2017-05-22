/*
 * Copyright 2016-2017, Bromium, Inc.
 * Author: Paulian Marinca <paulian@marinca.net>
 * SPDX-License-Identifier: ISC
 */

/******************************************************************************
 * hypercall.h
 *
 * Linux-specific hypervisor handling.
 *
 * Copyright (c) 2002-2004, K A Fraser
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License version 2
 * as published by the Free Software Foundation; or, when distributed
 * separately from the Linux kernel or incorporated into other
 * software packages, subject to the following license:
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this source file (the "Software"), to deal in the Software without
 * restriction, including without limitation the rights to use, copy, modify,
 * merge, publish, distribute, sublicense, and/or sell copies of the Software,
 * and to permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 */

#ifndef _ASM_X86_XEN_HYPERCALL_H
#define _ASM_X86_XEN_HYPERCALL_H

#include <linux/kernel.h>
#include <linux/spinlock.h>
#include <linux/errno.h>
#include <linux/string.h>
#include <linux/types.h>

#include <asm/page.h>
#include <asm/pgtable.h>

#include <xen/interface/xen.h>

/*
 * The hypercall asms have to meet several constraints:
 * - Work on 32- and 64-bit.
 *    The two architectures put their arguments in different sets of
 *    registers.
 *
 * - Work around asm syntax quirks
 *    It isn't possible to specify one of the rNN registers in a
 *    constraint, so we use explicit register variables to get the
 *    args into the right place.
 *
 * - Mark all registers as potentially clobbered
 *    Even unused parameters can be clobbered by the hypervisor, so we
 *    need to make sure gcc knows it.
 *
 * - Avoid compiler bugs.
 *    This is the tricky part.  Because x86_32 has such a constrained
 *    register set, gcc versions below 4.3 have trouble generating
 *    code when all the arg registers and memory are trashed by the
 *    asm.  There are syntactically simpler ways of achieving the
 *    semantics below, but they cause the compiler to crash.
 *
 *    The only combination I found which works is:
 *     - assign the __argX variables first
 *     - list all actually used parameters as "+r" (__argX)
 *     - clobber the rest
 *
 * The result certainly isn't pretty, and it really shows up cpp's
 * weakness as as macro language.  Sorry.  (But let's just give thanks
 * there aren't more than 5 arguments...)
 */

typedef struct { char _entry[32]; } t_hcpage_entry;
extern int uxen_ax;
extern void *uxen_hcbase;

//#define __HYPERCALL_AX		"cpuid" // not yet !
#define __HYPERCALL_AX		"call *%%rax"

#ifdef CONFIG_X86_32
#define __HYPERCALL		"call *%%eax"
#else
#define __HYPERCALL		"call *%%rax"
#endif
#define __HYPERCALL_ENTRY 	"a" (__hcaddr)

#ifdef CONFIG_X86_32
#define __HYPERCALL_RETREG	"eax"
#define __HYPERCALL_ARG1REG	"ebx"
#define __HYPERCALL_ARG2REG	"ecx"
#define __HYPERCALL_ARG3REG	"edx"
#define __HYPERCALL_ARG4REG	"esi"
#define __HYPERCALL_ARG5REG	"edi"
#define __HYPERCALL_ARG6REG     "ebp"
#else
#define __HYPERCALL_RETREG	"rax"
#define __HYPERCALL_ARG1REG	"rdi"
#define __HYPERCALL_ARG2REG	"rsi"
#define __HYPERCALL_ARG3REG	"rdx"
#define __HYPERCALL_ARG4REG	"r10"
#define __HYPERCALL_ARG5REG	"r8"
#define __HYPERCALL_ARG6REG	"r9"
#endif

#define __HYPERCALL_DECLS(x)					\
	unsigned long __hcaddr = (unsigned long) (uxen_hcbase + (__HYPERVISOR_##x * sizeof(t_hcpage_entry))); \
	register unsigned long __res  asm(__HYPERCALL_RETREG);		\
	register unsigned long __arg1 asm(__HYPERCALL_ARG1REG) = (unsigned long)__arg1; \
	register unsigned long __arg2 asm(__HYPERCALL_ARG2REG) = (unsigned long)__arg2; \
	register unsigned long __arg3 asm(__HYPERCALL_ARG3REG) = (unsigned long)__arg3; \
	register unsigned long __arg4 asm(__HYPERCALL_ARG4REG) = (unsigned long)__arg4; \
	register unsigned long __arg5 asm(__HYPERCALL_ARG5REG) = (unsigned long)__arg5;

#ifdef CONFIG_X86_32
#define __HYPERCALL_DECLS6(x) \
	unsigned long __hcaddr = (unsigned long) (uxen_hcbase + (__HYPERVISOR_##x * sizeof(t_hcpage_entry))); \
	register unsigned long __res;		\
	register unsigned long __arg1 asm(__HYPERCALL_ARG1REG) = (unsigned long)__arg1; \
	register unsigned long __arg2 asm(__HYPERCALL_ARG2REG) = (unsigned long)__arg2; \
	register unsigned long __arg3 asm(__HYPERCALL_ARG3REG) = (unsigned long)__arg3; \
	register unsigned long __arg4 asm(__HYPERCALL_ARG4REG) = (unsigned long)__arg4; \
	register unsigned long __arg5 asm(__HYPERCALL_ARG5REG) = (unsigned long)__arg5; \
	unsigned long __arg6 = (unsigned long)__arg6;
#else
#define __HYPERCALL_DECLS6(x)						\
	__HYPERCALL_DECLS(x)	\
	register unsigned long __arg6 asm(__HYPERCALL_ARG6REG) = (unsigned long)__arg6;
#endif

#define __HYPERCALL_0PARAM	"=a" (__res)
#define __HYPERCALL_1PARAM	__HYPERCALL_0PARAM, "+r" (__arg1)
#define __HYPERCALL_2PARAM	__HYPERCALL_1PARAM, "+r" (__arg2)
#define __HYPERCALL_3PARAM	__HYPERCALL_2PARAM, "+r" (__arg3)
#define __HYPERCALL_4PARAM	__HYPERCALL_3PARAM, "+r" (__arg4)
#define __HYPERCALL_5PARAM	__HYPERCALL_4PARAM, "+r" (__arg5)
#ifdef CONFIG_X86_32
#define __HYPERCALL_6PARAM	__HYPERCALL_5PARAM
#else
#define __HYPERCALL_6PARAM      __HYPERCALL_5PARAM, "+r" (__arg6)
#endif

#define __HYPERCALL_0ARG()
#define __HYPERCALL_1ARG(a1)						\
	__HYPERCALL_0ARG()		__arg1 = (unsigned long)(a1);
#define __HYPERCALL_2ARG(a1,a2)						\
	__HYPERCALL_1ARG(a1)		__arg2 = (unsigned long)(a2);
#define __HYPERCALL_3ARG(a1,a2,a3)					\
	__HYPERCALL_2ARG(a1,a2)		__arg3 = (unsigned long)(a3);
#define __HYPERCALL_4ARG(a1,a2,a3,a4)					\
	__HYPERCALL_3ARG(a1,a2,a3)	__arg4 = (unsigned long)(a4);
#define __HYPERCALL_5ARG(a1,a2,a3,a4,a5)				\
	__HYPERCALL_4ARG(a1,a2,a3,a4)	__arg5 = (unsigned long)(a5);
#define __HYPERCALL_6ARG(a1,a2,a3,a4,a5,a6)				\
	__HYPERCALL_5ARG(a1,a2,a3,a4,a5) __arg6 = (unsigned long) (a6);

#define __HYPERCALL_CLOBBER6	"memory"
#define __HYPERCALL_CLOBBER5	__HYPERCALL_CLOBBER6
#define __HYPERCALL_CLOBBER4	__HYPERCALL_CLOBBER5, __HYPERCALL_ARG5REG
#define __HYPERCALL_CLOBBER3	__HYPERCALL_CLOBBER4, __HYPERCALL_ARG4REG
#define __HYPERCALL_CLOBBER2	__HYPERCALL_CLOBBER3, __HYPERCALL_ARG3REG
#define __HYPERCALL_CLOBBER1	__HYPERCALL_CLOBBER2, __HYPERCALL_ARG2REG
#define __HYPERCALL_CLOBBER0	__HYPERCALL_CLOBBER1, __HYPERCALL_ARG1REG

#define _hypercall0(hc, type, name)				        \
({									\
	__HYPERCALL_DECLS(name);					\
	__HYPERCALL_0ARG();						\
	asm volatile (hc                                                \
		      : __HYPERCALL_0PARAM				\
		      : __HYPERCALL_ENTRY				\
		      : __HYPERCALL_CLOBBER0);				\
	(type)__res;							\
})

#define _hypercall1(hc, type, name, a1)					\
({									\
	__HYPERCALL_DECLS(name);					\
	__HYPERCALL_1ARG(a1);						\
	asm volatile (hc                                                \
		      : __HYPERCALL_1PARAM				\
		      : __HYPERCALL_ENTRY				\
		      : __HYPERCALL_CLOBBER1);				\
	(type)__res;							\
})

#define _hypercall2(hc, type, name, a1, a2)                             \
({									\
	__HYPERCALL_DECLS(name);					\
	__HYPERCALL_2ARG(a1, a2);					\
	asm volatile (hc                                                \
		      : __HYPERCALL_2PARAM				\
		      : __HYPERCALL_ENTRY				\
		      : __HYPERCALL_CLOBBER2);				\
	(type)__res;							\
})

#define _hypercall3(hc, type, name, a1, a2, a3)                         \
({									\
	__HYPERCALL_DECLS(name);					\
	__HYPERCALL_3ARG(a1, a2, a3);					\
	asm volatile (hc                                                \
		      : __HYPERCALL_3PARAM				\
		      : __HYPERCALL_ENTRY				\
		      : __HYPERCALL_CLOBBER3);				\
	(type)__res;							\
})

#define _hypercall4(hc, type, name, a1, a2, a3, a4)                     \
({									\
	__HYPERCALL_DECLS(name);					\
	__HYPERCALL_4ARG(a1, a2, a3, a4);				\
	asm volatile (hc                                                \
		      : __HYPERCALL_4PARAM				\
		      : __HYPERCALL_ENTRY				\
		      : __HYPERCALL_CLOBBER4);				\
	(type)__res;							\
})

#define _hypercall5(hc, type, name, a1, a2, a3, a4, a5)			\
({									\
	__HYPERCALL_DECLS(name);					\
	__HYPERCALL_5ARG(a1, a2, a3, a4, a5);				\
	asm volatile (hc                                                \
		      : __HYPERCALL_5PARAM				\
		      : __HYPERCALL_ENTRY				\
		      : __HYPERCALL_CLOBBER5);				\
	(type)__res;							\
})

#ifdef CONFIG_X86_32
#define _hypercall6(hc, type, name, a1, a2, a3, a4, a5, a6)             \
({									\
	__HYPERCALL_DECLS6(name);                                       \
	__HYPERCALL_6ARG(a1, a2, a3, a4, a5, a6);			\
	asm volatile (                                                  \
			"push %%ebp;" \
			"addl $4, %%esp;" \
			"mov %[sebp], %%ebp;"                 \
			"subl $4, %%esp;" \
			hc ";"                                          \
			"pop %%ebp"                                     \
		      : __HYPERCALL_6PARAM				\
		      : __HYPERCALL_ENTRY, [sebp] "g" ((long) (a6))      \
		      : __HYPERCALL_CLOBBER6);				\
	(type)__res;							\
})
#else
#define _hypercall6(hc, type, name, a1, a2, a3, a4, a5, a6)             \
({									\
	__HYPERCALL_DECLS6(name);						\
	__HYPERCALL_6ARG(a1, a2, a3, a4, a5, a6);			\
	asm volatile (hc ";"                                            \
		      : __HYPERCALL_6PARAM				\
		      : __HYPERCALL_ENTRY                         \
		      : __HYPERCALL_CLOBBER6);				\
	(type)__res;							\
})
#endif

static inline uint64_t
ax_cpuid_call (void *rax, void *a1, void* a2, void* a3, void* a4, void* a5, void* a6)
{
  register void* _rax asm  ("rax") = rax;
  register void* _a1  asm  ("rdi") = a1;
  register void* _a2  asm  ("rsi") = a2;
  register void* _a3  asm  ("rdx") = a3;
  register void* _a4  asm  ("r10") = a4;
  register void* _a5  asm  ("r9") = a5;
  register void* _a6  asm  ("r8") = a6;

  asm volatile (
    "cpuid"
    : "+r" (_rax), "+r" (_a1), "+r" (_a2), "+r" (_a3), "+r" (_a4), "+r" (_a5), "+r" (_a6)
    :
    : "cc"
  );
  return (uint64_t)_rax;
}

static inline int
HYPERVISOR_memory_op(unsigned int cmd, void *arg)
{
    if (uxen_ax)
        return _hypercall2(__HYPERCALL_AX, int, memory_op, cmd, arg);
    else
        return _hypercall2(__HYPERCALL, int, memory_op, cmd, arg);
}

static inline int
HYPERVISOR_xen_version(int cmd, void *arg)
{
    if (uxen_ax)
        return _hypercall2(__HYPERCALL_AX, int, xen_version, cmd, arg);
    else
        return _hypercall2(__HYPERCALL, int, xen_version, cmd, arg);
}

static inline unsigned long __must_check
HYPERVISOR_hvm_op(int op, void *arg)
{
    if (uxen_ax)
        return _hypercall2(__HYPERCALL_AX, unsigned long, hvm_op, op, arg);
    else
        return _hypercall2(__HYPERCALL, unsigned long, hvm_op, op, arg);
}

static inline int
HYPERVISOR_v4v_op(int op, void *arg1, void *arg2, void *arg3, void *arg4, void *arg5)
{
    if (uxen_ax) {
        //FIXME: magic numbers
        uint64_t cpuid = 0x35af3466;
        return (int)ax_cpuid_call((void*)cpuid, (void*)(uintptr_t)op, arg1, arg2, arg3, arg4, arg5);
    } else
        return _hypercall6(__HYPERCALL, int, v4v_op, op, arg1, arg2, arg3, arg4, arg5);
}

#endif /* _ASM_X86_XEN_HYPERCALL_H */
