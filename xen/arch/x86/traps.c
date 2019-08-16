/******************************************************************************
 * arch/x86/traps.c
 * 
 * Modifications to Linux original are copyright (c) 2002-2004, K A Fraser
 * 
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */
/*
 * uXen changes:
 *
 * Copyright 2011-2019, Bromium, Inc.
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

/*
 *  Copyright (C) 1991, 1992  Linus Torvalds
 *
 *  Pentium III FXSR, SSE support
 * Gareth Hughes <gareth@valinux.com>, May 2000
 */

#include <xen/config.h>
#include <xen/init.h>
#include <xen/sched.h>
#include <xen/lib.h>
#include <xen/errno.h>
#include <xen/mm.h>
#include <xen/console.h>
#include <xen/shutdown.h>
#include <xen/guest_access.h>
#include <asm/regs.h>
#include <xen/delay.h>
#include <xen/event.h>
#include <xen/spinlock.h>
#include <xen/irq.h>
#include <xen/perfc.h>
#include <xen/softirq.h>
#include <xen/domain_page.h>
#include <xen/symbols.h>
#include <xen/iocap.h>
#include <xen/nmi.h>
#include <xen/version.h>
#include <xen/kexec.h>
#include <xen/trace.h>
#include <xen/paging.h>
#include <asm/system.h>
#include <asm/io.h>
#include <asm/atomic.h>
#include <asm/bitops.h>
#include <asm/desc.h>
#include <asm/debugreg.h>
#include <asm/smp.h>
#include <asm/flushtlb.h>
#include <asm/uaccess.h>
#include <asm/i387.h>
#include <asm/xstate.h>
#include <asm/debugger.h>
#include <asm/msr.h>
#include <asm/shared.h>
#include <asm/x86_emulate.h>
#include <asm/traps.h>
#include <asm/hvm/vpt.h>
#include <asm/hypercall.h>
#include <asm/mce.h>
#include <asm/apic.h>
#include <asm/mc146818rtc.h>
#include <asm/hpet.h>
#include <public/arch-x86/cpuid.h>

DEFINE_PER_CPU(u64, efer);

DEFINE_PER_CPU_READ_MOSTLY(u32, ler_msr);

/* Pointer to the IDT of every CPU. */
idt_entry_t *idt_tables[NR_CPUS] __read_mostly;

static int debug_stack_lines = 20;
integer_param("debug_stack_lines", debug_stack_lines);

static bool_t __devinitdata opt_ler;
boolean_param("ler", opt_ler);

#ifdef CONFIG_X86_32
#define stack_words_per_line 8
#define ESP_BEFORE_EXCEPTION(regs) ((unsigned long *)&regs->esp)
#else
#define stack_words_per_line 4
#define ESP_BEFORE_EXCEPTION(regs) ((unsigned long *)regs->rsp)
#endif

static void show_guest_stack(struct vcpu *v, struct cpu_user_regs *regs)
{
    int i;
    unsigned long *stack, addr;
    unsigned long mask = STACK_SIZE;
    int hvm = is_hvm_vcpu(v);

    if ( is_pv_32on64_vcpu(v) )
    {
        compat_show_guest_stack(v, regs, debug_stack_lines);
        return;
    }

    if ( vm86_mode(regs) )
    {
        stack = (unsigned long *)((regs->ss << 4) + (regs->esp & 0xffff));
        printk("Guest stack trace from ss:sp = %04x:%04x (VM86)\n  ",
               regs->ss, (uint16_t)(regs->esp & 0xffff));
    }
    else
    {
        stack = (unsigned long *)regs->esp;
        printk("Guest stack trace from "__OP"sp=%p:\n  ", stack);
    }

    if ( !hvm && !access_ok(stack, sizeof(*stack)) )
    {
        printk("Guest-inaccessible memory.\n");
        return;
    }

    if ( v != current )
    {
        struct vcpu *vcpu;

        ASSERT(guest_kernel_mode(v, regs));
#ifndef __x86_64__
        addr = read_cr3();
        for_each_vcpu( v->domain, vcpu )
            if ( vcpu->arch.cr3 == addr )
                break;
#else
        vcpu = maddr_get_owner(read_paging_base()) == v->domain ? v : NULL;
#endif
        if ( !vcpu )
        {
            stack = NULL;
            if ( (unsigned long)stack < PAGE_SIZE )
            {
                printk("Inaccessible guest memory.\n");
                return;
            }
            mask = PAGE_SIZE;
        }
    }

    for ( i = 0; i < (debug_stack_lines*stack_words_per_line); i++ )
    {
        int err;

        if ( (((long)stack - 1) ^ ((long)(stack + 1) - 1)) & mask )
            break;
        err = hvm ? copy_from_user_hvm(&addr, stack, sizeof(addr))
                  : __get_user(addr, stack);
        if ( err )
        {
            if ( i != 0 )
                printk("\n    ");
            printk("Fault while accessing guest memory.");
            i = 1;
            break;
        }
        if ( (i != 0) && ((i % stack_words_per_line) == 0) )
            printk("\n  ");
        printk(" %p", _p(addr));
        stack++;
    }
    if ( i == 0 )
        printk("Stack empty.");
    printk("\n");
}

#if !defined(CONFIG_FRAME_POINTER)

#if !defined(__OBJ_PE__)

static void show_trace(struct cpu_user_regs *regs)
{
    unsigned long *stack = ESP_BEFORE_EXCEPTION(regs), addr;

    printk("Xen call trace:\n   ");

    printk("[<%p>] %S\n", _p(regs->eip), (printk_symbol)regs->eip);

    while ( ((long)stack & (STACK_SIZE-BYTES_PER_LONG)) != 0 )
    {
        addr = *stack++;
        if ( is_kernel_text(addr) || is_kernel_inittext(addr) )
        {
            printk("[<%p>] %S\n", _p(addr), (printk_symbol)addr);
        }
    }

    printk("\n");
}

#else  /* __OBJ_PE__ */

#include <uxen/unwind-pe.h>

static void
show_trace(struct cpu_user_regs *regs)
{
    uintptr_t stack = (uintptr_t)ESP_BEFORE_EXCEPTION(regs), addr;
    struct cpu_user_regs uregs = *regs;
    int initial = 0;

    printk("Xen call trace:\n");

    addr = uregs.eip;
    do {
        printk("   [<%p>] %S\n", _p(addr), (printk_symbol)addr);
        if (stack >= this_cpu(stack_top)) {
            printk("   === top of stack reached\n");
            break;
        }
    } while (!unwind_pe(&addr, &stack, &uregs, initial++ == 0));

    printk("\n");
}

#endif  /* __OBJ_PE__ */

#else  /* CONFIG_FRAME_POINTER */

static void show_trace(struct cpu_user_regs *regs)
{
    unsigned long *frame, next, addr, low, high;

    printk("Xen call trace:\n   ");

    printk("[<%p>] %S\n", _p(regs->eip), (printk_symbol)regs->eip);

    /* Bounds for range of valid frame pointer. */
    low = (unsigned long)(ESP_BEFORE_EXCEPTION(regs) - 2);
    high = this_cpu(stack_top);

    /* The initial frame pointer. */
    next = regs->ebp;

    for ( ; ; )
    {
        /* Valid frame pointer? */
        if ( (next < low) || (next >= high) )
        {
            /*
             * Exception stack frames have a different layout, denoted by an
             * inverted frame pointer.
             */
            next = ~next;
            if ( (next < low) || (next >= high) )
                break;
            frame = (unsigned long *)next;
            next  = frame[0];
            addr  = frame[(offsetof(struct cpu_user_regs, eip) -
                           offsetof(struct cpu_user_regs, ebp))
                         / BYTES_PER_LONG];
        }
        else
        {
            /* Ordinary stack frame. */
            frame = (unsigned long *)next;
            next  = frame[0];
            addr  = frame[1];
        }

        printk("[<%p>] %S\n", _p(addr), (printk_symbol)addr);

        low = (unsigned long)&frame[2];
    }

    printk("\n");
}

#endif  /* CONFIG_FRAME_POINTER */

void show_stack(struct cpu_user_regs *regs)
{
    unsigned long *stack = ESP_BEFORE_EXCEPTION(regs), addr;
    int i;

    if ( guest_mode(regs) )
        return show_guest_stack(current, regs);

    printk("Xen stack trace from "__OP"sp=%p:\n  ", stack);

    for ( i = 0; i < (debug_stack_lines*stack_words_per_line); i++ )
    {
        if ( (uintptr_t)stack >= this_cpu(stack_top) )
            break;
        if ( (i != 0) && ((i % stack_words_per_line) == 0) )
            printk("\n  ");
        addr = *stack++;
        printk(" %p", _p(addr));
    }
    if ( i == 0 )
        printk("Stack empty.");
    printk("\n");

    show_trace(regs);
}

void show_execution_state(struct cpu_user_regs *regs)
{
    show_registers(regs);
    show_stack(regs);
}

void vcpu_show_execution_state(struct vcpu *v)
{
    printk("*** Dumping vm%u.%u state: ***\n",
           v->domain->domain_id, v->vcpu_id);

    if ( v == current )
    {
        show_execution_state(guest_cpu_user_regs());
        return;
    }

    vcpu_pause(v); /* acceptably dangerous */

    if ( guest_kernel_mode(v, &v->arch.user_regs) )
        show_guest_stack(v, &v->arch.user_regs);

    vcpu_unpause(v);
}

unsigned long *get_x86_gpr(struct cpu_user_regs *regs, unsigned int modrm_reg)
{
    void *p;

    switch ( modrm_reg )
    {
    case  0: p = &regs->eax; break;
    case  1: p = &regs->ecx; break;
    case  2: p = &regs->edx; break;
    case  3: p = &regs->ebx; break;
    case  4: p = &regs->esp; break;
    case  5: p = &regs->ebp; break;
    case  6: p = &regs->esi; break;
    case  7: p = &regs->edi; break;
#if defined(__x86_64__)
    case  8: p = &regs->r8;  break;
    case  9: p = &regs->r9;  break;
    case 10: p = &regs->r10; break;
    case 11: p = &regs->r11; break;
    case 12: p = &regs->r12; break;
    case 13: p = &regs->r13; break;
    case 14: p = &regs->r14; break;
    case 15: p = &regs->r15; break;
#endif
    default: p = NULL; break;
    }

    return p;
}

static void do_guest_trap(
    int trapnr, const struct cpu_user_regs *regs, int use_error_code)
{
    debugger_trap_fatal(trapnr, (struct cpu_user_regs *)regs);
    WARN_ONCE();
}

int rdmsr_hypervisor_regs(uint32_t idx, uint64_t *val)
{
    struct domain *d = current->domain;
    /* Optionally shift out of the way of Viridian architectural MSRs. */
    uint32_t base = is_viridian_domain(d) ? 0x40000200 : 0x40000000;

    idx -= base;
    if ( idx > 0 )
        return 0;

    switch ( idx )
    {
    case 0:
    {
        *val = 0;
        break;
    }
    default:
        BUG();
    }

    return 1;
}

int wrmsr_hypervisor_regs(uint32_t idx, uint64_t val)
{
    struct domain *d = current->domain;
    /* Optionally shift out of the way of Viridian architectural MSRs. */
    uint32_t base = is_viridian_domain(d) ? 0x40000200 : 0x40000000;

    idx -= base;
    if ( idx > 0 )
        return 0;

    switch ( idx )
    {
    case 0:
    {
        void *hypercall_page;
        unsigned long mfn;
        unsigned long gmfn = val >> 12;
        unsigned int idx  = val & 0xfff;

        if ( idx > 0 )
        {
            gdprintk(XENLOG_WARNING,
                     "Out of range index %u to MSR %08x\n",
                     idx, 0x40000000);
            return 0;
        }

        mfn = get_gfn_untyped(d, gmfn);

        if ( !mfn_valid(mfn) ||
             !get_page_and_type(mfn_to_page(mfn), d, PGT_writable_page) )
        {
            put_gfn(d, gmfn);
            gdprintk(XENLOG_WARNING,
                     "Bad GMFN %lx (MFN %lx) to MSR %08x\n",
                     gmfn, mfn, base + idx);
            return 0;
        }

        hypercall_page = map_domain_page(mfn);
        hypercall_page_initialise(d, hypercall_page);
        unmap_domain_page(hypercall_page);

        put_page_and_type(mfn_to_page(mfn));
        put_gfn(d, gmfn);
        break;
    }

    default:
        BUG();
    }

    return 1;
}

int cpuid_hypervisor_leaves( uint32_t idx, uint32_t sub_idx,
               uint32_t *eax, uint32_t *ebx, uint32_t *ecx, uint32_t *edx)
{
    struct domain *d = current->domain;
    /* Optionally shift out of the way of Viridian architectural leaves. */
    uint32_t base = is_viridian_domain(d) ? 0x40000100 : 0x40000000;
    uint32_t limit;

    idx -= base;

    switch (idx)
    {
    case 192:
        {
            uint64_t lo = d->arch.hvm_domain.params[HVM_PARAM_RAND_SEED_LO];
            uint64_t hi = d->arch.hvm_domain.params[HVM_PARAM_RAND_SEED_HI];

            *eax = (uint32_t)(lo & 0xffffffff);
            *ebx = (uint32_t)(lo >> 32);
            *ecx = (uint32_t)(hi & 0xffffffff);
            *edx = (uint32_t)(hi >> 32);
        }
        return 1;
    case 193:
        {
            *eax = (uint32_t)d->arch.hvm_domain.params[HVM_PARAM_DM_FEATURES];
        }
        return 1;
    default:
        break;
    }

    /*
     * Some Solaris PV drivers fail if max > base + 2. Help them out by
     * hiding the PVRDTSCP leaf if PVRDTSCP is disabled.
     */
    limit = (d->arch.tsc_mode < TSC_MODE_PVRDTSCP) ? 2 : 3;

    if ( idx > limit ) 
        return 0;

    switch ( idx )
    {
    case 0:
        *eax = base + limit; /* Largest leaf */
        *ebx = XEN_CPUID_SIGNATURE_EBX;
        *ecx = XEN_CPUID_SIGNATURE_ECX;
        *edx = XEN_CPUID_SIGNATURE_EDX;
        break;

    case 1:
        *eax = (xen_major_version() << 16) | xen_minor_version();
        *ebx = 0;          /* Reserved */
        *ecx = 0;          /* Reserved */
        *edx = 0;          /* Reserved */
        break;

    case 2:
        *eax = 1;          /* Number of hypercall-transfer pages */
        *ebx = 0x40000000; /* MSR base address */
        if ( is_viridian_domain(d) )
            *ebx = 0x40000200;
        *ecx = 0;          /* Features 1 */
        *edx = 0;          /* Features 2 */
        if ( !is_hvm_vcpu(current) )
            *ecx |= XEN_CPUID_FEAT1_MMU_PT_UPDATE_PRESERVE_AD;
        break;

    case 3:
        *eax = *ebx = *ecx = *edx = 0;
        cpuid_time_leaf( sub_idx, eax, ebx, ecx, edx );
        break;

    default:
        BUG();
    }

    return 1;
}

asmlinkage_sysv void do_machine_check(struct cpu_user_regs *regs)
{
    BUG();
}

u64 read_efer(void)
{
    return this_cpu(efer);
}

void write_efer(u64 val)
{
    this_cpu(efer) = val;
    wrmsrl(MSR_EFER, val);
}

static void ler_enable(void)
{
    u64 debugctl;
    
    if ( !this_cpu(ler_msr) )
        return;

    rdmsrl(MSR_IA32_DEBUGCTLMSR, debugctl);
    wrmsrl(MSR_IA32_DEBUGCTLMSR, debugctl | 1);
}

asmlinkage_sysv void do_debug(struct cpu_user_regs *regs)
{
    struct vcpu *v = current;

    DEBUGGER_trap_entry(TRAP_debug, regs);

    if ( !guest_mode(regs) )
    {
        if ( regs->eflags & X86_EFLAGS_TF )
        {
            if ( !debugger_trap_fatal(TRAP_debug, regs) )
            {
                WARN_ON(1);
                regs->eflags &= ~X86_EFLAGS_TF;
            }
        }
        else
        {
            /*
             * We ignore watchpoints when they trigger within Xen. This may
             * happen when a buffer is passed to us which previously had a
             * watchpoint set on it. No need to bump EIP; the only faulting
             * trap is an instruction breakpoint, which can't happen to us.
             */
            WARN_ON(!search_exception_table(regs->eip));
        }
        goto out;
    }

    /* Save debug status register where guest OS can peek at it */
    v->arch.debugreg[6] = read_debugreg(6);

    ler_enable();
    do_guest_trap(TRAP_debug, regs, 0);
    return;

 out:
    ler_enable();
    return;
}

void __devinit percpu_traps_init(void)
{

    if ( !opt_ler )
        return;

    switch ( boot_cpu_data.x86_vendor )
    {
    case X86_VENDOR_INTEL:
        switch ( boot_cpu_data.x86 )
        {
        case 6:
            this_cpu(ler_msr) = MSR_IA32_LASTINTFROMIP;
            break;
        case 15:
            this_cpu(ler_msr) = MSR_P4_LER_FROM_LIP;
            break;
        }
        break;
    case X86_VENDOR_AMD:
        switch ( boot_cpu_data.x86 )
        {
        case 6:
        case 0xf ... 0x17:
            this_cpu(ler_msr) = MSR_IA32_LASTINTFROMIP;
            break;
        }
        break;
    }

    ler_enable();
}

/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
