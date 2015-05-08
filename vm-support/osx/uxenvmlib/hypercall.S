/*
 * Copyright 2014-2016, Bromium, Inc.
 * Author: Julian Pidancet <julian@pidancet.net>
 * SPDX-License-Identifier: ISC
 */

.globl __hypercall0
.globl __hypercall1
.globl __hypercall2
.globl __hypercall3
.globl __hypercall4
.globl __hypercall5
.globl __hypercall6

/*
 *
 * uintptr _hypercallX(uintptr_t addr,
 *                     uintptr_t arg1,
 *                     uintptr_t arg2,
 *                     uintptr_t arg3,
 *                     uintptr_t arg4,
 *                     uintptr_t arg5,
 *                     uintptr_t arg6)
 *
 * SysV x86_64 ABI to Xen x86_64 ABI:
 *   addr : %rdi
 *   arg1 : %rsi -> %rdi
 *   arg2 : %rdx -> %rsi
 *   arg3 : %rcx -> %rdx
 *   arg4 : %r8 -> %r10
 *   arg5 : %r9 -> %r8
 *   arg6 : 8(%rsp) -> %r9
 *
 * Since we're not modifying any callee-saved registers, we don't need to
 * touch the stack, hence we can simply jump on the hypercall table
 * and the ret instruction will just return to the calling function.
 */
__hypercall4:
__hypercall5:
__hypercall6:
    movq    %r8,        %r10
    movq    %r9,        %r8
    movq    8(%rsp),    %r9
__hypercall0:
__hypercall1:
__hypercall2:
__hypercall3:
    movq    %rdi,       %rax
    movq    %rsi,       %rdi
    movq    %rdx,       %rsi
    movq    %rcx,       %rdx
    jmp     *%rax
