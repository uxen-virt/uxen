/*
 * entry.S: VMX architecture-specific entry/exit handling.
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
#define UREGS_r(_r) UREGS_r ## _r
#define ABS(label) label ## (%rip)
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
#define UREGS_r(_r) UREGS_e ## _r
#define ABS(label) _ ## label
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

#ifdef UXEN_HOST_OSX
#define SAVE_MORE_STATE 1
#endif
#ifdef SAVE_MORE_STATE
#define EXTRA_stack_space 48
#endif  /* SAVE_MORE_STATE */

ENTRY(vmx_asm_vmexit_handler)
#define savereg(_x) mov r(_x), UREGS_r(_x)(r(di))
        push r(di)
        mov  CURRENT_vcpu_stack_offset+SIZEOF_REG(r(sp)), r(di)
        lea  VCPU_user_regs(r(di)),r(di)
        savereg(ax)
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

        call_with_abi(vmx_save_regs)

        get_current(r(bx))

        mov  %cr2,r(ax)
        mov  r(ax),VCPU_hvm_guest_cr2(r(bx))

#if defined(__x86_64__) && defined(UXEN_HOST_WINDOWS)
        mov  CPU_cr8(r(bx)),r(ax)
        mov  r(ax),%cr8
#endif

#ifndef NDEBUG
        mov  $0xbeef,%ax
        get_user_regs(r(bx), r(di))
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

#if defined(__MS_ABI__) && defined(__x86_64__)
        add  $SCRATCH_area_size,%rsp
#endif /* __MS_ABI__ */

	pop  r_arg              /* vmx_vmexit_handler argument == current */

#ifdef SAVE_MORE_STATE
        lidt (%rsp)
        lgdt 16(%rsp)
        mov  40(%rsp),%bx      /* tr */
        movzx %bx,%rax
        andb $0xf8,%al          /* descriptor offset */
        add  18(%rsp),%rax      /* add gdt base address */
        andl $~0x200,4(%rax)    /* clear busy flag in tr descriptor */
        ltr  %bx
        mov  32(%rsp),%ax
        lldt %ax
        add  $EXTRA_stack_space,%rsp
#endif  /* SAVE_MORE_STATE */

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

        xor  r(ax),r(ax)
        ret

ENTRY(vmx_asm_do_vmentry)
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

#ifdef SAVE_MORE_STATE
        sub  $EXTRA_stack_space,%rsp
        sldt %ax
        mov  %ax,32(%rsp)
        str  %ax
        mov  %ax,40(%rsp)
        sgdt 16(%rsp)
        sidt (%rsp)
#endif  /* SAVE_MORE_STATE */

	push r_arg		/* arg = current */

#if defined(__MS_ABI__) && defined(__x86_64__)
        sub  $SCRATCH_area_size,%rsp
#endif /* __MS_ABI__ */

        call_with_abi(vmx_intr_assist)
#ifndef __UXEN__
        call_with_abi(nvmx_switch_guest)
#endif  /* __UXEN__ */

        get_current(r(bx))
        call_via_uxen_info(cli, r_arg)

        mov  r(bx), r_arg
        call_with_abi(check_work_vcpu)

        /* check_work_vcpu returns with 1 if work was done.
	 * Note: interrupts have been re-enabled in that case. */
        test %eax, %eax
        jne  .Lret_from_vmx_asm_do_vmentry

        testb $0xff,VCPU_vmx_emulate(r(bx))
        jnz .Lvmx_goto_emulator
        testb $0xff,VCPU_vmx_realmode(r(bx))
UNLIKELY_START(nz, realmode)
        cmpw $0,VCPU_vm86_seg_mask(r(bx))
        jnz .Lvmx_goto_emulator
        call_with_regs(r(bx), vmx_enter_realmode) 
UNLIKELY_END(realmode)

        call_with_abi(vmx_vmenter_helper)
        mov  VCPU_hvm_guest_cr2(r(bx)),r(ax)
        mov  r(ax),%cr2

#if defined(__x86_64__) && defined(UXEN_HOST_WINDOWS)
        mov  $1,r(ax)
        mov  r(ax),%cr8
#endif

        mov  r(sp), r_arg
        call_with_abi(vmx_restore_regs)

#define restreg(_x)  mov UREGS_r(_x)(r(di)), r(_x)
        get_user_regs(r(bx), r(di))
        cmpb $0,VCPU_vmx_launched(r(bx))
        restreg(ax)
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

        je   .Lvmx_launch

/*.Lvmx_resume:*/
        vmresume
#if defined(__x86_64__) && defined(UXEN_HOST_WINDOWS)
        get_current(r(bx))
        mov  CPU_cr8(r(bx)),r(ax)
        mov  r(ax),%cr8
#endif
        call_via_uxen_info(sti, r(ax))
        mov $1, r_arg
        call_with_abi(vm_entry_fail)
        jmp .Lret_from_vmx_asm_do_vmentry

.Lvmx_launch:
        vmlaunch
#if defined(__x86_64__) && defined(UXEN_HOST_WINDOWS)
        get_current(r(bx))
        mov  CPU_cr8(r(bx)),r(ax)
        mov  r(ax),%cr8
#endif
        call_via_uxen_info(sti, r(ax))
        xor r_arg, r_arg
        call_with_abi(vm_entry_fail)
        jmp .Lret_from_vmx_asm_do_vmentry

.Lvmx_goto_emulator:
        call_via_uxen_info(sti, r(ax))
        call_with_regs(r(bx), vmx_realmode)

.Lret_from_vmx_asm_do_vmentry:
#if defined(__MS_ABI__) && defined(__x86_64__)
        add  $SCRATCH_area_size,%rsp
#endif /* __MS_ABI__ */

	pop  r_arg

#ifdef SAVE_MORE_STATE
        add  $EXTRA_stack_space,%rsp
#endif  /* SAVE_MORE_STATE */

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

        mov  $1,r(ax)
        ret
