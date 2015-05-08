/*
 * Copyright 2014-2016, Bromium, Inc.
 * Author: Julian Pidancet <julian@pidancet.net>
 * SPDX-License-Identifier: ISC
 */

#ifndef _HYPERCALL_H_
#define _HYPERCALL_H_

#include <stdint.h>
#include <mach/mach_types.h>

static inline void
cpuid(uint32_t idx,
      uint32_t *eax, uint32_t *ebx, uint32_t *ecx, uint32_t *edx)
{
    asm volatile ("cpuid"
                  : "=a" (*eax),
                    "=b" (*ebx),
                    "=c" (*ecx),
                    "=d" (*edx)
                  : "0" (idx)
                  : "memory");
}

static inline void
wrmsr(uint32_t reg, uint64_t val)
{
    asm volatile ("wrmsr"
                  :
                  : "c" (reg), "a" ((uint32_t)val),
                    "d" ((uint32_t)(val >> 32)));
}

#define hcall(name) \
    (((uintptr_t)(hypercall_desc->getBytesNoCopy())) + (__HYPERVISOR_##name * 32))
#define hcall_arg(x) ((uintptr_t)(x))

extern "C" uintptr_t _hypercall0(uintptr_t addr);
extern "C" uintptr_t _hypercall1(uintptr_t addr, uintptr_t arg1);
extern "C" uintptr_t _hypercall2(uintptr_t addr, uintptr_t arg1, uintptr_t arg2);
extern "C" uintptr_t _hypercall3(uintptr_t addr, uintptr_t arg1, uintptr_t arg2,
                      uintptr_t arg3);
extern "C" uintptr_t _hypercall4(uintptr_t addr, uintptr_t arg1, uintptr_t arg2,
                      uintptr_t arg3, uintptr_t arg4);
extern "C" uintptr_t _hypercall5(uintptr_t addr, uintptr_t arg1, uintptr_t arg2,
                      uintptr_t arg3, uintptr_t arg4, uintptr_t arg5);
extern "C" uintptr_t _hypercall6(
    uintptr_t addr, uintptr_t arg1, uintptr_t arg2, uintptr_t arg3,
    uintptr_t arg4, uintptr_t arg5, uintptr_t arg6);

#endif /* _HYPERCALL_H_ */
