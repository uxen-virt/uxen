/*
 *  uxen_sys.S
 *  uxen
 *
 * Copyright 2012-2015, Bromium, Inc.
 * Author: Christian Limpach <Christian.Limpach@gmail.com>
 * SPDX-License-Identifier: ISC
 * 
 */

        /* uintptr_t uxen_mem_tlb_flush_fn(uintptr_t arg) */
        .globl _uxen_mem_tlb_flush_fn
_uxen_mem_tlb_flush_fn:
	mov %cr3, %rax
	mov %rax, %cr3
	xor %rax, %rax
	retq

        /* uintptr_t uxen_mem_tlb_flush_fn_global(uintptr_t arg) */
        .globl _uxen_mem_tlb_flush_fn_global
_uxen_mem_tlb_flush_fn_global:
        mov %cr4, %rax
	mov %rax, %rcx
	andb $0x80, %cl
	test %cl, %cl
	jne _flush_global
	/* non-global flush via cr3 reload */
	mov %cr3, %rax
	mov %rax, %cr3
	jmp _out
_flush_global:	
	mov %rax, %rcx
	andb $0x7f, %cl
	mov %rcx, %cr4
	/* barrier */
	mov %rax, %cr4
_out:	
	xor %rax, %rax
	retq
