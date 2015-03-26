	;;
	;; uxen_hypercall_sup.asm
	;; uxen
	;;
	;; Copyright 2012-2015, Bromium, Inc.
	;; SPDX-License-Identifier: ISC
	;;

	page	,132
	title	hypercall support routines

    .686p
    .model flat, stdcall
	.code

	; These functions call hypercalls with 1-6 arguments
	; and interface the windows ABI to the xen hypercall ABI.
	; 
	; uintptr_t hypercall1(void *fnptr, uintptr_t arg1);
	; uintptr_t hypercall2(void *fnptr, uintptr_t arg1, uintptr_t arg2);
	; etc.
	; 
	; Windows 32 bit __stdcall ABI
	; All arguments are pushed onto the stack
	; we must preserve esi,edi,ebx,ebp

	; Xen 32bit ABI
	; args in order are placed in ebx, ecx, edx, esi, edi, ebp
	; return in eax


	public _hypercall1

_hypercall1	proc NEAR STDCALL, addr1:DWORD, arg1:DWORD
    push ebx
    mov eax, addr1
    mov ebx, arg1
    call eax
    pop ebx
    ret 8

_hypercall1	endp


	public _hypercall2

_hypercall2	proc NEAR STDCALL, addr1:DWORD, arg1:DWORD, arg2:DWORD
    push ebx
    mov eax, addr1
    mov ebx, arg1
    mov ecx, arg2
    call eax
    pop ebx
    ret 12

_hypercall2	endp


	public _hypercall3

_hypercall3	proc NEAR STDCALL, addr1:DWORD, arg1:DWORD, arg2:DWORD, arg3: DWORD
    push ebx
    mov eax, addr1
    mov ebx, arg1
    mov ecx, arg2
    mov edx, arg3
    call eax
    pop ebx
    ret 16

_hypercall3	endp

	public _hypercall4

_hypercall4	proc NEAR STDCALL, addr1:DWORD, arg1:DWORD, arg2:DWORD, arg3: DWORD, arg4:DWORD
    push esi
    push ebx
    mov eax, addr1
    mov ebx, arg1
    mov ecx, arg2
    mov edx, arg3
    mov esi, arg4
    call eax
    pop ebx
    pop esi
    ret 20

_hypercall4	endp

	public _hypercall5

_hypercall5	proc NEAR STDCALL, addr1:DWORD, arg1:DWORD, arg2:DWORD, arg3: DWORD, arg4:DWORD, arg5:DWORD
    push esi
    push edi
    push ebx
    mov eax, addr1
    mov ebx, arg1
    mov ecx, arg2
    mov edx, arg3
    mov esi, arg4
    mov edi, arg5
    call eax
    pop ebx
    pop edi
    pop esi
    ret 24

_hypercall5	endp


	public _hypercall6

_hypercall6	proc NEAR STDCALL, addr1:DWORD, arg1:DWORD, arg2:DWORD, arg3: DWORD, arg4:DWORD, arg5:DWORD, arg6:DWORD
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
    call eax
    pop ebp
    pop ebx
    pop edi
    pop esi
    ret 28

_hypercall6	endp


	end
