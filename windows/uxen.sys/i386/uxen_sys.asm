	;;
	;; uxen_sys.asm
	;; uxen
	;;
	;; Copyright 2013-2018, Bromium, Inc.
	;; SPDX-License-Identifier: ISC
	;;

	page	,132
	title	asm routines

        .686p
        .model flat, stdcall

	.code
	
	; ULONG_PTR uxen_mem_tlb_flush_fn(ULONG_PTR arg)
	public uxen_mem_tlb_flush_fn

uxen_mem_tlb_flush_fn	proc uses eax ecx , arg:DWORD
	mov eax, cr3
	mov cr3, eax
	xor eax, eax
	ret 4h

uxen_mem_tlb_flush_fn	endp


	; ULONG_PTR uxen_mem_tlb_flush_fn_global(ULONG_PTR arg)
	public uxen_mem_tlb_flush_fn_global

uxen_mem_tlb_flush_fn_global	proc uses eax ecx , arg:DWORD
	mov eax, cr4
	mov ecx, eax
	and ecx, 80h
	test ecx, ecx
	jne _flush_global
	;; non-global flush via cr3 reload
	mov eax, cr3
	mov cr3, eax
	jmp _out
_flush_global:	
	mov ecx, eax
	and cl, 7fh
	mov cr4, ecx
	;; barrier
	mov cr4, eax
_out:	
	xor eax, eax
	ret 4h

uxen_mem_tlb_flush_fn_global	endp

	; uintptr_t read_paging_base(void)
	public read_paging_base

read_paging_base	proc uses eax
	mov eax, cr3
	ret

read_paging_base	endp

	end
