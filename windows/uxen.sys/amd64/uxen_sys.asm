	;;
	;; uxen_sys.asm
	;; uxen
	;;
	;; Copyright 2012-2018, Bromium, Inc.
	;; SPDX-License-Identifier: ISC
	;;

	page	,132
	title	asm routines

	.code
	
	; ULONG_PTR uxen_mem_tlb_flush_fn(ULONG_PTR arg)
	public uxen_mem_tlb_flush_fn

uxen_mem_tlb_flush_fn	proc
	mov rax, cr3
	mov cr3, rax
	xor rax, rax
	ret

uxen_mem_tlb_flush_fn	endp


	; ULONG_PTR uxen_mem_tlb_flush_fn_global(ULONG_PTR arg)
	public uxen_mem_tlb_flush_fn_global

uxen_mem_tlb_flush_fn_global	proc
	mov rax, cr4
	mov rcx, rax
	and rcx, 80h
	test rcx, rcx
	jne _flush_global
	;; non-global flush via cr3 reload
	mov rax, cr3
	mov cr3, rax
	jmp _out
_flush_global:	
	mov rcx, rax
	and cl, 7fh
	mov cr4, rcx
	;; barrier
	mov cr4, rax
_out:	
	xor rax, rax
	ret

uxen_mem_tlb_flush_fn_global	endp

	; uintptr_t read_paging_base(void)
	public read_paging_base

	; 64bit only no PAE to worry about

read_paging_base	proc
	mov rax, cr3
	and ax, 0f000h
	ret

read_paging_base	endp

	; void ax_vars_cpuid(uint64_t *rax, uint64_t *rbx, uint64_t *rcx, uint64_t *rdx)
ax_vars_cpuid	proc
        push   rbx
        mov    r10, rcx
        mov    r11, rdx

        mov    rax, qword ptr [rcx]
        mov    rbx, qword ptr [rdx]
        mov    rcx, qword ptr [r8]
        mov    rdx, qword ptr [r9]
        cpuid
        mov    qword ptr [r10], rax
        mov    qword ptr [r11], rbx
        mov    qword ptr [r8 ], rcx
        mov    qword ptr [r9 ], rdx

        pop    rbx
        ret
ax_vars_cpuid	endp


	end
