	;;
	;; Copyright 2015, Bromium, Inc.
	;; SPDX-License-Identifier: ISC
	;;

.686p
.xmm
.model flat, c

.data
.code

xmm_wrapper MACRO func
EXTRN	&func&:NEAR
&func&_wrapper PROC PUBLIC FRAME
	sub	    esp, 60h
	movdqu      xmm0, [esp      ]
	movdqu      xmm1, [esp + 10h]
	movdqu      xmm2, [esp + 20h]
	movdqu      xmm3, [esp + 30h]
	movdqu      xmm4, [esp + 40h]
	movdqu      xmm5, [esp + 50h]

	call &func&

	movdqu      [esp + 50h], xmm5
	movdqu      [esp + 40h], xmm4
	movdqu      [esp + 30h], xmm3
	movdqu      [esp + 20h], xmm2
	movdqu      [esp + 10h], xmm1
	movdqu      [esp      ], xmm0

	add 	    esp, 60h
	ret
&func&_wrapper ENDP
	endm

	INCLUDE uxen_ops_wrappers.inc

END



