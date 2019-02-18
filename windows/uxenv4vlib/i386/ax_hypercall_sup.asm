	;;
	;; Copyright 2019, Bromium, Inc.
	;; SPDX-License-Identifier: ISC
	;;

	page	,132
	title	hypercall support routines

    .686p
    .model flat, stdcall
	.code

	public _ax_v4v_hypercall

        ;; currently unsupported, only returns error
_ax_v4v_hypercall	proc NEAR STDCALL, addr1:DWORD, arg1:DWORD, arg2:DWORD, arg3: DWORD, arg4:DWORD, arg5:DWORD, arg6:DWORD, ret1:DWORD
    push esi
    push edi
    push ebx
    push ebp
    mov eax, addr1
    mov ebx, arg1
    mov ecx, arg2
    mov edx, arg3
    mov esi, arg4
    mov edi, arg5
    mov ebp, arg6
    mov eax, 0FFFFFFFFh
    pop ebp
    pop ebx
    pop edi
    pop esi
    ret 28

_ax_v4v_hypercall	endp


	end
