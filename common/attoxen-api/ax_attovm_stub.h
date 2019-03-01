/*
 * Copyright 2019, Bromium, Inc.
 * SPDX-License-Identifier: ISC
 */

#ifndef _AX_ATTOVM_STUB_H_
#define _AX_ATTOVM_STUB_H_

#include "ax_attovm.h"

struct attovm_definition;

static inline uint64_t
attovm_call (uint64_t rax, uint64_t rcx, uint64_t rdx, uint64_t r8, uint64_t r9)
{
#ifdef __x86_64__
  register uint64_t _rax asm ("rax") = rax;
  register uint64_t _rcx asm ("rcx") = rcx;
  register uint64_t _rdx asm ("rdx") = rdx;
  register uint64_t _r8 asm ("r8") = r8;
  register uint64_t _r9 asm ("r9") = r9;

  asm volatile (
    "cpuid"
    : "+r" (_rax), "+r" (_rcx), "+r" (_rdx), "+r" (_r8), "+r" (_r9)
    :
    :"cc", "rbx", "memory"
  );
  return _rax;
#else
  return 0;
#endif
}

static inline uint64_t
attovm_call_create (uint64_t domid)
{
  uint64_t eax = ATTOCALL_VM_CREATE, ecx = domid, edx = 0, r8 = 0, r9 = 0;

  return attovm_call (eax, ecx, edx, r8, r9);
}

static inline uint64_t
attovm_call_destroy (uint64_t domid)
{
  uint64_t eax = ATTOCALL_VM_DESTROY, ecx = domid, edx = 0, r8 = 0, r9 = 0;

  return attovm_call (eax, ecx, edx, r8, r9);
}

static inline uint64_t
attovm_call_seal (uint64_t domid, struct attovm_definition_v1 *d)
{
  uint64_t eax = ATTOCALL_VM_SEAL, ecx = domid,
           edx = (uint64_t) (uintptr_t)d, r8 = 0, r9 = 0;

  return attovm_call (eax, ecx, edx, r8, r9);
}

static inline uint64_t
attovm_call_get_guest_pages (uint64_t domid, uint64_t pfn, uint64_t count, void *buffer)
{
  uint64_t eax = ATTOCALL_VM_DEBUG_GET_GUEST_PAGES, ecx = domid,
           edx = pfn, r8 = count, r9 = (uint64_t) (uintptr_t)buffer;

  return attovm_call (eax, ecx, edx, r8, r9);
}

static inline uint64_t
attovm_call_get_guest_cpu_state (uint64_t domid, uint32_t vcpu_id, void *buffer, uint32_t buffer_size)
{
  uint64_t eax = ATTOCALL_VM_DEBUG_GET_GUEST_CPU_STATE, ecx = domid,
           edx = vcpu_id, r8 = (uint64_t) (uintptr_t)buffer, r9 = buffer_size;

  return attovm_call (eax, ecx, edx, r8, r9);
}

static inline uint64_t
attovm_call_assign_token (uint64_t domid, /*uint128_t*/ void *token)
{
  uint64_t eax = ATTOCALL_VM_ASSIGN_TOKEN, ecx = domid,
           edx = (uint64_t) (uintptr_t)token, r8 = 0, r9 = 0;

  return attovm_call (eax, ecx, edx, r8, r9);
}

static inline uint64_t
attovm_call_vcpu_init (uint64_t domid, uint64_t vcpuid)
{
  uint64_t eax = ATTOCALL_VM_VCPU_INIT, ecx = domid, edx = vcpuid, r8 = 0, r9 = 0;

  return attovm_call (eax, ecx, edx, r8, r9);
}

static inline uint64_t
attovm_call_startup_ipi (uint64_t apicid, uint64_t startaddr, uint64_t stackaddr, uint64_t cpuoff)
{
  uint64_t eax = ATTOCALL_STARTUP_IPI, ecx = apicid, edx = startaddr, r8 = stackaddr,
           r9 = cpuoff;

  return attovm_call (eax, ecx, edx, r8, r9);
}

static inline uint64_t
attovm_call_apicop (uint64_t op, uint64_t addr, uint64_t value)
{
  uint64_t eax = ATTOCALL_APICOP, ecx = op, edx = addr, r8 = value, r9 = 0;

  return attovm_call (eax, ecx, edx, r8, r9);
}

static inline uint64_t
attovm_call_v4vop (void *a1, void *a2, void *a3, void *a4,
                   void *a5, void *a6, uint64_t *domsig)
{
#ifdef __x86_64__
  register void *_rax asm ("rax") = (void *) (uintptr_t)ATTOCALL_V4VOP;
  register void *_a1  asm ("rdi") = a1;
  register void *_a2  asm ("rsi") = a2;
  register void *_a3  asm ("rdx") = a3;
  register void *_a4  asm ("r10") = a4;
  register void *_a5  asm ("r8") = a5;
  register void *_a6  asm ("r9") = a6;

  asm volatile (
    "cpuid"
    : "+r" (_rax), "+r" (_a1), "+r" (_a2), "+r" (_a3), "+r" (_a4), "+r" (_a5), "+r" (_a6)
    :
    : "cc", "rbx", "rcx", "memory"
  );

  if (domsig)
    *domsig = (uint64_t)_a1;

  return (uint64_t)_rax;
#else
  return 0;
#endif
}

static inline uint64_t
attovm_call_suspendop (uint64_t type)
{
  uint64_t eax = ATTOCALL_SUSPENDOP, ecx = type, edx = 0, r8 = 0, r9 = 0;

  return attovm_call (eax, ecx, edx, r8, r9);
}

static inline uint64_t
attovm_call_queryop (uint64_t param, uint64_t a1, uint64_t a2, uint64_t a3)
{
  uint64_t eax = ATTOCALL_QUERYOP, ecx = param, edx = a1, r8 = a2, r9 = a3;

  return attovm_call (eax, ecx, edx, r8, r9);
}

static inline uint64_t
attovm_call_kbd_focus (uint64_t domid, uint32_t offer_focus)
{
  uint64_t eax = ATTOCALL_VM_KBD_FOCUS, ecx = domid,
           edx = offer_focus, r8 = 0, r9 = 0;

  return attovm_call (eax, ecx, edx, r8, r9);
}

#endif
