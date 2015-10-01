	;;
	;; Copyright 2015, Bromium, Inc.
	;; SPDX-License-Identifier: ISC
	;;

.data
.code

xmm_wrapper MACRO func
EXTRN	&func&:NEAR
&func&_wrapper PROC PUBLIC FRAME
	sub	    rsp, 88h
	.allocstack 88h

	movdqa      [rsp + 20h], xmm0
	.savexmm128 xmm0,        0h
	movdqa      [rsp + 30h], xmm1
	.savexmm128 xmm1,        10h
	movdqa      [rsp + 40h], xmm2
	.savexmm128 xmm2,        20h
	movdqa      [rsp + 50h], xmm3
	.savexmm128 xmm3,        30h
	movdqa      [rsp + 60h], xmm4
	.savexmm128 xmm4,        40h
	movdqa      [rsp + 70h], xmm5
	.savexmm128 xmm5,        50h

	movdqa      [rsp + 18h], r9
	movdqa      [rsp + 18h], r8
	movdqa      [rsp + 18h], rdx
	movdqa      [rsp + 18h], rcx

	.endprolog

	call &func&

	movdqa      xmm0, [rsp      ]
	movdqa      xmm1, [rsp + 10h]
	movdqa      xmm2, [rsp + 20h]
	movdqa      xmm3, [rsp + 30h]
	movdqa      xmm4, [rsp + 40h]
	movdqa      xmm5, [rsp + 50h]

	add 	    rsp, 88h
	ret
&func&_wrapper ENDP
	endm

	INCLUDE uxen_ops_wrappers.inc

END



