	;;
	;; uxen_debug_sup.asm
	;; uxen
	;;
	;; Copyright 2011-2015, Bromium, Inc.
	;; SPDX-License-Identifier: ISC
	;;

	page	,132
	title	Debug Support routines

	.code
	
	; void _ud2(void)
	public _ud2

_ud2	proc
	ud2
	ret

_ud2	endp
	
	; void kdbgrebootsup(void)
	public kdbgrebootsup

kdbgrebootsup proc
	vmxoff
	push	0ffffffffh
	push	0ffff0000h
	lidt	fword ptr [esp]
	ud2
	ret

kdbgrebootsup endp

	end
