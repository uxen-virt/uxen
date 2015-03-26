/*
 * entry.S: SVM architecture-specific entry/exit handling.
 * Copyright (c) 2005-2007, Advanced Micro Devices, Inc.
 * Copyright (c) 2004, Intel Corporation.
 * Copyright (c) 2008, Citrix Systems, Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 59 Temple
 * Place - Suite 330, Boston, MA 02111-1307 USA.
 */
/*
 * uXen changes:
 *
 * Copyright 2011-2015, Bromium, Inc.
 * Author: Christian Limpach <Christian.Limpach@gmail.com>
 * SPDX-License-Identifier: ISC
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
 * SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION
 * OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
 * CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include <xen/config.h>
#include <xen/errno.h>
#include <xen/softirq.h>
#include <asm/types.h>
#include <asm/asm_defns.h>
#include <asm/apicdef.h>
#include <asm/page.h>
#include <public/xen.h>

#define VMRUN  .byte 0x0F,0x01,0xD8
#define STGI   .byte 0x0F,0x01,0xDC
#define CLGI   .byte 0x0F,0x01,0xDD

#define get_current(reg)                        \
        mov CURRENT_vcpu_stack_offset(r(sp)), reg

#define get_user_regs(cur, reg)                 \
        lea VCPU_user_regs(cur), reg

#ifdef __MS_ABI__
#define r_arg r(cx)
#else
#define r_arg r(di)
#endif
        
#if defined(__x86_64__)
#define r(reg) %r##reg
#define addr_of(lbl) lbl(%rip)
#define UREGS_r(_r) UREGS_r ## _r
#define SIZEOF_REG 8
#if defined(__MS_ABI__)
#define CURRENT_vcpu_stack_offset (0x20)
#define SCRATCH_area_size (0x20)
#else
#define CURRENT_vcpu_stack_offset (0)
#endif /* __MS_ABI__ */
#define call_with_abi(fn)                       \
        call fn
#ifdef GS_info_offset
#define call_via_uxen_info(fn, reg)             \
        mov %gs:GS_info_offset, reg;            \
        call *UI_ ## fn(reg)
#else
#define call_via_uxen_info(fn, reg)             \
        fn
#endif
#elif defined(__i386__)
#define r(reg) %e##reg
#define addr_of(lbl) _ ## lbl
#define UREGS_r(_r) UREGS_e ## _r
#define SIZEOF_REG 4
#define CURRENT_vcpu_stack_offset (0)
#define call_with_abi(fn)                       \
        call LABEL(fn)
#ifdef FS_info_offset
#define call_via_uxen_info(fn, reg)             \
        mov %fs:FS_info_offset, reg;            \
        call *UI_ ## fn(reg)
#else
/* XXX simplified version for cli/sti */
#define call_via_uxen_info(fn, reg)             \
        fn
#endif
#endif
        
#define call_with_regs(cur, fn)                 \
        get_user_regs(cur, r_arg);              \
        call_with_abi(fn)

ENTRY(svm_asm_do_vmentry)
        push r(bp)
#ifdef CONFIG_FRAME_POINTER
        mov  r(sp),r(bp)
#endif
        push r(bx)
#ifdef __MS_ABI__
        push r(si)
        push r(di)
#endif /* __MS_ABI__ */

#if defined(__x86_64__)
        push r(12)
        push r(13)
        push r(14)
        push r(15)
#endif

        push r_arg              /* arg = current */

#if defined(__MS_ABI__) && defined(__x86_64__)
        sub  $SCRATCH_area_size,%rsp
#endif /* __MS_ABI__ */

        call_with_abi(svm_intr_assist)
#ifndef __UXEN_NOT_YET__
        call_with_abi(nsvm_vcpu_switch)
#endif  /* __UXEN_NOT_YET__ */

        get_current(r(bx))
        CLGI                    /* XXX call_via_uxen_info(cli, r_arg) */

        mov  r(bx), r_arg
        call_with_abi(check_work_vcpu)

        /* check_work_vcpu returns with 1 if work was done.
	 * Note: interrupts have been re-enabled in that case. */
        test %eax, %eax
        jne  .Lret_from_svm_asm_do_vmentry

#ifndef __UXEN_NOT_YET__
        testb $0, VCPU_nsvm_hap_enabled(r(bx))
UNLIKELY_START(nz, nsvm_hap)
        mov  VCPU_nhvm_p2m(r(bx)),r(ax)
        test r(ax),r(ax)
        sete %al
        andb VCPU_nhvm_guestmode(r(bx)),%al
        jnz  .Lsvm_nsvm_no_p2m
UNLIKELY_END(nsvm_hap)
#endif  /* __UXEN_NOT_YET__ */

        call_with_abi(svm_asid_handle_vmrun)

        cmpb $0,addr_of(tb_init_done)
UNLIKELY_START(nz, svm_trace)
        call_with_abi(svm_trace_vmentry)
UNLIKELY_END(svm_trace)

#if defined(__x86_64__) && defined(UXEN_HOST_WINDOWS)
        mov  %cr8,r(ax)
        mov  r(ax),CPU_cr8(r(bx))
        mov  $1,r(ax)
        mov  r(ax),%cr8
#endif

        get_user_regs(r(bx), r(di))
        mov  VCPU_svm_vmcb(r(bx)),r(cx)
        mov  UREGS_r(ax)(r(di)),r(ax)
        mov  r(ax),VMCB_rax(r(cx))
        mov  UREGS_r(ip)(r(di)),r(ax)
        mov  r(ax),VMCB_rip(r(cx))
        mov  UREGS_r(sp)(r(di)),r(ax)
        mov  r(ax),VMCB_rsp(r(cx))
        mov  UREGS_eflags(r(di)),r(ax)
        mov  r(ax),VMCB_rflags(r(cx))

        mov  VCPU_svm_vmcb_pa(r(bx)),r(ax)
        VMLOAD

#define restreg(_x)  mov UREGS_r(_x)(r(di)), r(_x)
        get_user_regs(r(bx), r(di))
        /* restreg(ax) restored by vmrun */
        restreg(bp)
        restreg(si)
        restreg(dx)
        restreg(cx)
        restreg(bx)

#if defined(__x86_64__)
        restreg(8)
        restreg(9)
        restreg(10)
        restreg(11)
        restreg(12)
        restreg(13)
        restreg(14)
        restreg(15)
#endif

        restreg(di)
#undef restreg

        VMRUN

#define savereg(_x) mov r(_x), UREGS_r(_x)(r(di))
        push r(di)
        mov  CURRENT_vcpu_stack_offset+SIZEOF_REG(r(sp)), r(di)
        lea  VCPU_user_regs(r(di)),r(di)
        /* savereg(ax) */
        savereg(bp)
        savereg(si)
        savereg(dx)
        savereg(cx)
        savereg(bx)
        pop  UREGS_r(di)(r(di))

#if defined(__x86_64__)
        savereg(8)
        savereg(9)
        savereg(10)
        savereg(11)
        savereg(12)
        savereg(13)
        savereg(14)
        savereg(15)
#endif
#undef savereg

        get_current(r(bx))

        movb $0,VCPU_svm_vmcb_in_sync(r(bx))
        mov  VCPU_svm_vmcb(r(bx)),r(cx)
        mov  VMCB_rax(r(cx)),r(ax)
        mov  r(ax),UREGS_r(ax)(r(di))
        mov  VMCB_rip(r(cx)),r(ax)
        mov  r(ax),UREGS_r(ip)(r(di))
        mov  VMCB_rsp(r(cx)),r(ax)
        mov  r(ax),UREGS_r(sp)(r(di))
        mov  VMCB_rflags(r(cx)),r(ax)
        mov  r(ax),UREGS_eflags(r(di))

#if defined(__x86_64__) && defined(UXEN_HOST_WINDOWS)
        mov  CPU_cr8(r(bx)),r(ax)
        mov  r(ax),%cr8
#endif

#ifndef NDEBUG
        mov  $0xbeef,%ax
        mov  %ax,UREGS_error_code(r(di))
        mov  %ax,UREGS_entry_vector(r(di))
        mov  %ax,UREGS_saved_upcall_mask(r(di))
        mov  %ax,UREGS_cs(r(di))
        mov  %ax,UREGS_ds(r(di))
        mov  %ax,UREGS_es(r(di))
        mov  %ax,UREGS_fs(r(di))
        mov  %ax,UREGS_gs(r(di))
        mov  %ax,UREGS_ss(r(di))
#endif

        mov  VCPU_svm_vmcb_pa(r(bx)),r(ax)
        VMSAVE
        mov  VCPU_svm_root_vmcb_pa(r(bx)),r(ax)
        VMLOAD

        STGI                    /* XXX call_via_uxen_info(sti, r(ax)) */

        xor  r(ax),r(ax)

.Lret_from_svm_asm_do_vmentry:
#if defined(__MS_ABI__) && defined(__x86_64__)
        add  $SCRATCH_area_size,%rsp
#endif /* __MS_ABI__ */

        pop  r_arg              /* svm_vmexit_handler argument == current */

#if defined(__x86_64__)
        pop  r(15)
        pop  r(14)
        pop  r(13)
        pop  r(12)
#endif

#ifdef __MS_ABI__
        pop  r(di)
        pop  r(si)
#endif /* __MS_ABI__ */
        pop  r(bx)
        pop  r(bp)

        ret

#if 0
.globl svm_stgi_label
svm_stgi_label:
        call_with_regs(svm_vmexit_handler)
        jmp  svm_asm_do_resume

.Lsvm_process_softirqs:
        STGI                    /* XXX call_via_uxen_info(sti, r(ax)) */
        call do_softirq
        jmp  svm_asm_do_resume

.Lsvm_nsvm_no_p2m:
        /* Someone shot down our nested p2m table; go round again
         * and nsvm_vcpu_switch() will fix it for us. */
        STGI                    /* XXX call_via_uxen_info(sti, r(ax)) */
        jmp  svm_asm_do_resume
#endif
