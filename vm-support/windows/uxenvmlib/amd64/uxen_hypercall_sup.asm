	;;
	;; uxen_hypercall_sup.asm
	;; uxen
	;;
	;; Copyright 2012-2018, Bromium, Inc.
	;; SPDX-License-Identifier: ISC
	;;

	page	,132
	title	hypercall support routines

	.code

	; These functions call hypercalls with 1-6 arguments
	; and interface the windows ABI to the xen hypercall ABI.
	; 
	; uintptr_t hypercall1(void *fnptr, uintptr_t arg1);
	; uintptr_t hypercall2(void *fnptr, uintptr_t arg1, uintptr_t arg2);
	; etc.
	; 
	; Windows 64 bit ABI
	; First four arguments passed in rcx,rdx,r8,r9 
	; then the stack gets used so hypercall1 thru 3 are identical
	; return value is in rax
	; rax,rcx,rdx,r8,r9,r10,r11 can be clobbered

	; Xen 64bit ABI
	; args in order are placed in rdi, rsi, rdx, r10, r8, r9
	; return in rax

	public _hypercall1
	public _hypercall2
	public _hypercall3
	
_hypercall1:
_hypercall2:
_hypercall3	proc

	push	rdi
	push	rsi
	mov	rax, rcx
	mov	rdi, rdx
	mov	rsi, r8
	mov	rdx, r9
	call	rax
	pop	rsi
	pop	rdi
	ret

_hypercall3	endp



	public _hypercall4
_hypercall4	proc

	push	rdi
	push	rsi
	mov	rax, rcx
	mov	rdi, rdx
	mov	rsi, r8
	mov	rdx, r9
	mov	r10, qword ptr [rsp+38h] 
	call	rax
	pop	rsi
	pop	rdi
	ret

_hypercall4	endp



	public _hypercall5
_hypercall5	proc

	push	rdi
	push	rsi
	mov	rax, rcx
	mov	rdi, rdx
	mov	rsi, r8
	mov	rdx, r9
	mov	r10, qword ptr [rsp+38h] 
	mov	r8, qword ptr [rsp+40h] 
	call	rax
	pop	rsi
	pop	rdi
	ret

_hypercall5	endp


	public _hypercall6

_hypercall6	proc
	push	rdi
	push	rsi
	mov	rax, rcx
	mov	rdi, rdx
	mov	rsi, r8
	mov	rdx, r9
	mov	r10, qword ptr [rsp+38h] 
	mov	r8, qword ptr [rsp+40h] 
	mov	r9, qword ptr [rsp+48h] 
	call	rax
	pop	rsi
	pop	rdi
	ret

_hypercall6	endp

        public _whpx_hypercall6

_whpx_hypercall6 proc
	push	rdi
	push	rsi
	mov	rax, rcx
	mov	rdi, rdx
	mov	rsi, r8
	mov	rdx, r9
	mov	r10, qword ptr [rsp+38h] 
	mov	r8, qword ptr [rsp+40h] 
	mov	r9, qword ptr [rsp+48h]
        cpuid
	pop	rsi
	pop	rdi
	ret

_whpx_hypercall6 endp
	end
