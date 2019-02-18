	;;
	;; Copyright 2019, Bromium, Inc.
	;; SPDX-License-Identifier: ISC
	;;

	page	,132
	title	hypercall support routines

	.code

	public _ax_v4v_hypercall

_ax_v4v_hypercall	proc
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
        mov     rsi, qword ptr [rsp+50h]
        mov     [rsi], rdi
	pop	rsi
	pop	rdi
	ret

_ax_v4v_hypercall	endp

	end
