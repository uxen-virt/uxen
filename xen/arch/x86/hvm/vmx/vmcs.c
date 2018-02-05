/*
 * vmcs.c: VMCS management
 * Copyright (c) 2004, Intel Corporation.
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
 * Copyright 2011-2018, Bromium, Inc.
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
#include <xen/init.h>
#include <xen/mm.h>
#include <xen/lib.h>
#include <xen/errno.h>
#include <xen/domain_page.h>
#include <asm/current.h>
#include <asm/cpufeature.h>
#include <asm/processor.h>
#include <asm/msr.h>
#include <asm/xstate.h>
#include <asm/hvm/ax.h>
#include <asm/hvm/hvm.h>
#include <asm/hvm/io.h>
#include <asm/hvm/support.h>
#include <asm/hvm/vmx/vmx.h>
#include <asm/hvm/vmx/vmcs.h>
#include <asm/flushtlb.h>
#include <xen/event.h>
#include <xen/kernel.h>
#include <xen/keyhandler.h>
#include <asm/hvm/xen_pv.h>
#include <asm/shadow.h>
#include <asm/tboot.h>

#ifndef __UXEN_NOT_YET__
static bool_t __read_mostly opt_vpid_enabled = 1;
boolean_param("vpid", opt_vpid_enabled);
#else   /* __UXEN_NOT_YET__ */
#define opt_vpid_enabled 0
#endif  /* __UXEN_NOT_YET__ */

#ifndef __UXEN__
static bool_t __read_mostly opt_unrestricted_guest_enabled = 1;
boolean_param("unrestricted_guest", opt_unrestricted_guest_enabled);
#else  /* __UXEN__ */
#define opt_unrestricted_guest_enabled 1
#endif  /* __UXEN__ */

#define VMCS_ITERATE_NO_XEN_MAPPINGS 1
#define VMCS_FIRST_FIELD_OFFSET 8

/*
 * These two parameters are used to config the controls for Pause-Loop Exiting:
 * ple_gap:    upper bound on the amount of time between two successive
 *             executions of PAUSE in a loop.
 * ple_window: upper bound on the amount of time a guest is allowed to execute
 *             in a PAUSE loop.
 * Time is measured based on a counter that runs at the same rate as the TSC,
 * refer SDM volume 3b section 21.6.13 & 22.1.3.
 */
static unsigned int __read_mostly ple_gap = 128;
integer_param("ple_gap", ple_gap);
static unsigned int __read_mostly ple_window = 4096;
integer_param("ple_window", ple_window);

/* Dynamic (run-time adjusted) execution control flags. */
u32 vmx_pin_based_exec_control __read_mostly;
u32 vmx_cpu_based_exec_control __read_mostly;
u32 vmx_secondary_exec_control __read_mostly;
u32 vmx_vmexit_control __read_mostly;
u32 vmx_vmentry_control __read_mostly;
u64 vmx_ept_vpid_cap __read_mostly;
bool_t cpu_has_vmx_ins_outs_instr_info __read_mostly;

static DEFINE_PER_CPU_READ_MOSTLY(struct vmcs_struct *, vmxon_region);
DEFINE_PER_CPU(struct arch_vmx_struct *, current_vmcs_vmx);
static DEFINE_PER_CPU(struct vmcs_struct *, active_vmcs);
static DEFINE_PER_CPU(struct list_head, active_vmcs_list);
static DEFINE_PER_CPU(unsigned char [10], gdt_save);
static DEFINE_PER_CPU(unsigned char [10], idt_save);

static u32 vmcs_revision_id __read_mostly;

static void __init vmx_display_features(void)
{
    int printed = 0;

    printk("VMX: Supported advanced features:\n");

#define P(p,s) if ( p ) { printk(" - %s\n", s); printed = 1; }
    P(cpu_has_vmx_virtualize_apic_accesses, "APIC MMIO access virtualisation");
    P(cpu_has_vmx_tpr_shadow, "APIC TPR shadow");
    P(cpu_has_vmx_ept, "Extended Page Tables (EPT)");
    P(cpu_has_vmx_vpid, "Virtual-Processor Identifiers (VPID)");
    P(cpu_has_vmx_vnmi, "Virtual NMI");
    P(cpu_has_vmx_msr_bitmap, "MSR direct-access bitmap");
    P(cpu_has_vmx_unrestricted_guest, "Unrestricted Guest");
    P(cpu_has_vmx_invpcid, "Invalidate Process Context ID");
#undef P

    if ( !printed )
        printk(" - none\n");

    if ( cpu_has_vmx_ept_1gb )
        printk("EPT supports 1GB super page.\n");
    if ( cpu_has_vmx_ept_2mb )
        printk("EPT supports 2MB super page.\n");

    printk("Pause-Loop Exiting %sabled.\n",
           (vmx_secondary_exec_control & SECONDARY_EXEC_PAUSE_LOOP_EXITING) ?
           "en" : "dis");
}

static u32 adjust_vmx_controls(
    const char *name, u32 ctl_min, u32 ctl_opt, u32 msr, bool_t *mismatch)
{
    u32 vmx_msr_low, vmx_msr_high, ctl = ctl_min | ctl_opt;

    rdmsr(msr, vmx_msr_low, vmx_msr_high);

    ctl &= vmx_msr_high; /* bit == 0 in high word ==> must be zero */
    ctl |= vmx_msr_low;  /* bit == 1 in low word  ==> must be one  */

    /* Ensure minimum (required) set of control bits are supported. */
    if ( ctl_min & ~ctl )
    {
        *mismatch = 1;
        printk("VMX: CPU%d has insufficent %s (%08x but requires min %08x)\n",
               smp_processor_id(), name, ctl, ctl_min);
    }

    return ctl;
}

static bool_t cap_check(const char *name, u32 expected, u32 saw)
{
    if ( saw != expected )
        printk("VMX %s: saw 0x%08x expected 0x%08x\n", name, saw, expected);
    return saw != expected;
}

static int vmx_init_vmcs_config(void)
{
    u32 vmx_basic_msr_low, vmx_basic_msr_high, min, opt;
    u32 _vmx_pin_based_exec_control;
    u32 _vmx_cpu_based_exec_control;
    u32 _vmx_secondary_exec_control = 0;
    u64 _vmx_ept_vpid_cap = 0;
    u32 _vmx_vmexit_control;
    u32 _vmx_vmentry_control;
    bool_t mismatch = 0;

    rdmsr(MSR_IA32_VMX_BASIC, vmx_basic_msr_low, vmx_basic_msr_high);

    min = (PIN_BASED_EXT_INTR_MASK |
           PIN_BASED_NMI_EXITING);
    opt = PIN_BASED_VIRTUAL_NMIS;
    _vmx_pin_based_exec_control = adjust_vmx_controls(
        "Pin-Based Exec Control", min, opt,
        MSR_IA32_VMX_PINBASED_CTLS, &mismatch);

    min = (CPU_BASED_HLT_EXITING |
           CPU_BASED_VIRTUAL_INTR_PENDING |
#ifdef __x86_64__
           CPU_BASED_CR8_LOAD_EXITING |
           CPU_BASED_CR8_STORE_EXITING |
#endif
           CPU_BASED_INVLPG_EXITING |
           CPU_BASED_CR3_LOAD_EXITING |
           CPU_BASED_CR3_STORE_EXITING |
           CPU_BASED_MONITOR_EXITING |
           CPU_BASED_MWAIT_EXITING |
           CPU_BASED_MOV_DR_EXITING |
           CPU_BASED_ACTIVATE_IO_BITMAP |
           CPU_BASED_USE_TSC_OFFSETING |
           CPU_BASED_RDTSC_EXITING);
    opt = (CPU_BASED_ACTIVATE_MSR_BITMAP |
           CPU_BASED_TPR_SHADOW |
           CPU_BASED_MONITOR_TRAP_FLAG |
           CPU_BASED_ACTIVATE_SECONDARY_CONTROLS);
    _vmx_cpu_based_exec_control = adjust_vmx_controls(
        "CPU-Based Exec Control", min, opt,
        MSR_IA32_VMX_PROCBASED_CTLS, &mismatch);
    _vmx_cpu_based_exec_control &= ~CPU_BASED_RDTSC_EXITING;
#ifdef __x86_64__
    if ( _vmx_cpu_based_exec_control & CPU_BASED_TPR_SHADOW )
        _vmx_cpu_based_exec_control &=
            ~(CPU_BASED_CR8_LOAD_EXITING | CPU_BASED_CR8_STORE_EXITING);
#endif

    if ( _vmx_cpu_based_exec_control & CPU_BASED_ACTIVATE_SECONDARY_CONTROLS )
    {
        min = 0;
        opt = (SECONDARY_EXEC_VIRTUALIZE_APIC_ACCESSES |
               SECONDARY_EXEC_WBINVD_EXITING |
               SECONDARY_EXEC_ENABLE_EPT |
               SECONDARY_EXEC_ENABLE_RDTSCP |
               SECONDARY_EXEC_PAUSE_LOOP_EXITING |
               SECONDARY_EXEC_ENABLE_INVPCID);
        if ( opt_vpid_enabled )
            opt |= SECONDARY_EXEC_ENABLE_VPID;
        if ( opt_unrestricted_guest_enabled )
            opt |= SECONDARY_EXEC_UNRESTRICTED_GUEST;

        _vmx_secondary_exec_control = adjust_vmx_controls(
            "Secondary Exec Control", min, opt,
            MSR_IA32_VMX_PROCBASED_CTLS2, &mismatch);
    }

    /* The IA32_VMX_EPT_VPID_CAP MSR exists only when EPT or VPID available */
    if ( _vmx_secondary_exec_control & (SECONDARY_EXEC_ENABLE_EPT |
                                        SECONDARY_EXEC_ENABLE_VPID) )
    {
        rdmsrl(MSR_IA32_VMX_EPT_VPID_CAP, _vmx_ept_vpid_cap);

        /*
         * Additional sanity checking before using EPT:
         * 1) the CPU we are running on must support EPT WB, as we will set
         *    ept paging structures memory type to WB;
         * 2) the CPU must support the EPT page-walk length of 4 according to
         *    Intel SDM 25.2.2.
         * 3) the CPU must support INVEPT all context invalidation, because we
         *    will use it as final resort if other types are not supported.
         *
         * Or we just don't use EPT.
         */
        if ( !(_vmx_ept_vpid_cap & VMX_EPT_MEMORY_TYPE_WB) ||
             !(_vmx_ept_vpid_cap & VMX_EPT_WALK_LENGTH_4_SUPPORTED) ||
             !(_vmx_ept_vpid_cap & VMX_EPT_INVEPT_ALL_CONTEXT) )
            _vmx_secondary_exec_control &= ~SECONDARY_EXEC_ENABLE_EPT;

        /*
         * the CPU must support INVVPID all context invalidation, because we
         * will use it as final resort if other types are not supported.
         *
         * Or we just don't use VPID.
         */
        if ( !(_vmx_ept_vpid_cap & VMX_VPID_INVVPID_ALL_CONTEXT) )
            _vmx_secondary_exec_control &= ~SECONDARY_EXEC_ENABLE_VPID;
    }

    if ( _vmx_secondary_exec_control & SECONDARY_EXEC_ENABLE_EPT )
    {
        /*
         * To use EPT we expect to be able to clear certain intercepts.
         * We check VMX_BASIC_MSR[55] to correctly handle default1 controls.
         */
        uint32_t must_be_one, must_be_zero, msr = MSR_IA32_VMX_PROCBASED_CTLS;
        if ( vmx_basic_msr_high & (1u << 23) )
            msr = MSR_IA32_VMX_TRUE_PROCBASED_CTLS;
        rdmsr(msr, must_be_one, must_be_zero);
        if ( must_be_one & (CPU_BASED_INVLPG_EXITING |
                            CPU_BASED_CR3_LOAD_EXITING |
                            CPU_BASED_CR3_STORE_EXITING) )
            _vmx_secondary_exec_control &=
                ~(SECONDARY_EXEC_ENABLE_EPT |
                  SECONDARY_EXEC_UNRESTRICTED_GUEST);
    }

    if ( (_vmx_secondary_exec_control & SECONDARY_EXEC_PAUSE_LOOP_EXITING) &&
          ple_gap == 0 )
    {
        printk("Disable Pause-Loop Exiting.\n");
        _vmx_secondary_exec_control &= ~ SECONDARY_EXEC_PAUSE_LOOP_EXITING;
    }

#if defined(__i386__)
    /* If we can't virtualise APIC accesses, the TPR shadow is pointless. */
    if ( !(_vmx_secondary_exec_control &
           SECONDARY_EXEC_VIRTUALIZE_APIC_ACCESSES) )
        _vmx_cpu_based_exec_control &= ~CPU_BASED_TPR_SHADOW;
#endif

#ifndef __UXEN__
    min = VM_EXIT_ACK_INTR_ON_EXIT;
#else   /* __UXEN__ */
    min = 0;
#endif  /* __UXEN__ */
    opt = VM_EXIT_SAVE_GUEST_PAT | VM_EXIT_LOAD_HOST_PAT;
#ifdef __x86_64__
    min |= VM_EXIT_IA32E_MODE;
#endif
    _vmx_vmexit_control = adjust_vmx_controls(
        "VMExit Control", min, opt, MSR_IA32_VMX_EXIT_CTLS, &mismatch);

    min = 0;
    opt = VM_ENTRY_LOAD_GUEST_PAT;
    _vmx_vmentry_control = adjust_vmx_controls(
        "VMEntry Control", min, opt, MSR_IA32_VMX_ENTRY_CTLS, &mismatch);

    if ( mismatch )
        return -EINVAL;

    if ( !vmx_pin_based_exec_control )
    {
        /* First time through. */
        vmcs_revision_id = vmx_basic_msr_low;
        vmx_pin_based_exec_control = _vmx_pin_based_exec_control;
        vmx_cpu_based_exec_control = _vmx_cpu_based_exec_control;
        vmx_secondary_exec_control = _vmx_secondary_exec_control;
        vmx_ept_vpid_cap           = _vmx_ept_vpid_cap;
        vmx_vmexit_control         = _vmx_vmexit_control;
        vmx_vmentry_control        = _vmx_vmentry_control;
        cpu_has_vmx_ins_outs_instr_info = !!(vmx_basic_msr_high & (1U<<22));
        vmx_display_features();
    }
    else
    {
        /* Globals are already initialised: re-check them. */
        mismatch |= cap_check(
            "VMCS revision ID",
            vmcs_revision_id, vmx_basic_msr_low);
        mismatch |= cap_check(
            "Pin-Based Exec Control",
            vmx_pin_based_exec_control, _vmx_pin_based_exec_control);
        mismatch |= cap_check(
            "CPU-Based Exec Control",
            vmx_cpu_based_exec_control, _vmx_cpu_based_exec_control);
        mismatch |= cap_check(
            "Secondary Exec Control",
            vmx_secondary_exec_control, _vmx_secondary_exec_control);
        mismatch |= cap_check(
            "VMExit Control",
            vmx_vmexit_control, _vmx_vmexit_control);
        mismatch |= cap_check(
            "VMEntry Control",
            vmx_vmentry_control, _vmx_vmentry_control);
        mismatch |= cap_check(
            "EPT and VPID Capability",
            vmx_ept_vpid_cap, _vmx_ept_vpid_cap);
        if ( cpu_has_vmx_ins_outs_instr_info !=
             !!(vmx_basic_msr_high & (1U<<22)) )
        {
            printk("VMX INS/OUTS Instruction Info: saw %d expected %d\n",
                   !!(vmx_basic_msr_high & (1U<<22)),
                   cpu_has_vmx_ins_outs_instr_info);
            mismatch = 1;
        }
        if ( mismatch )
        {
            printk("VMX: Capabilities fatally differ between CPU%d and CPU0\n",
                   smp_processor_id());
            return -EINVAL;
        }
    }

    /* IA-32 SDM Vol 3B: VMCS size is never greater than 4kB. */
    if ( (vmx_basic_msr_high & 0x1fff) > PAGE_SIZE )
    {
        printk("VMX: CPU%d VMCS size is too big (%u bytes)\n",
               smp_processor_id(), vmx_basic_msr_high & 0x1fff);
        return -EINVAL;
    }

#ifdef __x86_64__
    /* IA-32 SDM Vol 3B: 64-bit CPUs always have VMX_BASIC_MSR[48]==0. */
    if ( vmx_basic_msr_high & (1u<<16) )
    {
        printk("VMX: CPU%d limits VMX structure pointers to 32 bits\n",
               smp_processor_id());
        return -EINVAL;
    }
#endif

    /* Require Write-Back (WB) memory type for VMCS accesses. */
    if ( ((vmx_basic_msr_high >> 18) & 15) != 6 )
    {
        printk("VMX: CPU%d has unexpected VMCS access type %u\n",
               smp_processor_id(), (vmx_basic_msr_high >> 18) & 15);
        return -EINVAL;
    }

    return 0;
}

static struct vmcs_struct *vmx_alloc_vmcs(void)
{
    struct vmcs_struct *vmcs;

    if ( (vmcs = alloc_xenheap_page()) == NULL )
    {
        gdprintk(XENLOG_WARNING, "Failed to allocate VMCS.\n");
        return NULL;
    }

    clear_page(vmcs);
    vmcs->vmcs_revision_id = vmcs_revision_id;

    return vmcs;
}

static void vmx_free_vmcs(struct vmcs_struct *vmcs)
{
    free_xenheap_page(vmcs);
}

static DEFINE_SPINLOCK(vmx_clear_lock);

static void vmx_clear_active_vmcs_ax(struct vcpu *v)
{
    unsigned long flags, flags2;
    int cpu;
    struct arch_vmx_struct *arch_vmx = &v->arch.hvm_vmx;

    cpu_irq_save(flags);
    while (!spin_trylock_irqsave(&vmx_clear_lock, flags2))
        rep_nop();

    while (ax_remote_vmclear(arch_vmx->vmcs_ma)) {
        /*VMCS in use, ax is working on it */
        spin_unlock_irqrestore(&vmx_clear_lock, flags2);

        rep_nop();

        while (!spin_trylock_irqsave(&vmx_clear_lock, flags2))
            rep_nop();
    }

    cpu=arch_vmx->active_cpu;

    arch_vmx->launched   = 0;
    arch_vmx->active_cpu = -1;

    list_del(&arch_vmx->active_list);

    if (cpu!=-1) {
        if (per_cpu(current_vmcs_vmx,cpu) == arch_vmx)
            per_cpu(current_vmcs_vmx,cpu) = NULL;
        if (per_cpu(active_vmcs,cpu) == arch_vmx->vmcs)
            per_cpu(active_vmcs,cpu) = NULL;
    }

    spin_unlock_irqrestore(&vmx_clear_lock, flags2);
    cpu_irq_restore(flags);
}

static void __vmx_clear_vmcs(void *info)
{
    struct vcpu *v = info;
    struct arch_vmx_struct *arch_vmx = &v->arch.hvm_vmx;

    /* Otherwise we can nest (vmx_cpu_down() vs. vmx_clear_vmcs()). */
    ASSERT(!cpu_irq_is_enabled());
    ASSERT(arch_vmx->active_cpu == smp_processor_id());

    if (!vmx_vmcs_late_load)
        __vmpclear(arch_vmx->vmcs_ma);
    else
        pv_vmcs_flush_dirty(arch_vmx, 1);
    arch_vmx->launched   = 0;

    arch_vmx->active_cpu = -1;
    list_del(&arch_vmx->active_list);

    if (this_cpu(current_vmcs_vmx) == arch_vmx)
        this_cpu(current_vmcs_vmx) = NULL;
    if (this_cpu(active_vmcs) == arch_vmx->vmcs)
        this_cpu(active_vmcs) = NULL;
}

static void __vmx_clear_vmcs_isr(void *info)
{
    unsigned long flags;

    cpu_irq_save(flags);
    __vmx_clear_vmcs(info);
    cpu_irq_restore(flags);
}

static void vmx_clear_vmcs(struct vcpu *v)
{
    int cpu = v->arch.hvm_vmx.active_cpu;

    if (cpu == -1)
        return;

    if (!ax_present)
        on_selected_cpus(cpumask_of(cpu), __vmx_clear_vmcs_isr, v, 1);
    else
        vmx_clear_active_vmcs_ax(v);
}

static void vmx_load_vmcs(struct vcpu *v)
{
    unsigned long flags, flags2 = 0;
    int do_load = !vmx_vmcs_late_load;

    if (ax_present)
        spin_lock_irqsave(&vmx_clear_lock, flags2);
    cpu_irq_save(flags);

    if (vmx_vmcs_late_load && !v->arch.hvm_vmx.vmentry_gen)
        do_load = 1;

    if (v->arch.hvm_vmx.active_cpu != smp_processor_id()) {
        if (ax_present && v->arch.hvm_vmx.active_cpu != -1) {
            spin_unlock_irqrestore(&vmx_clear_lock, flags2);
            BUG();
        }

        ASSERT(v->arch.hvm_vmx.active_cpu == -1);
        list_add(&v->arch.hvm_vmx.active_list, &this_cpu(active_vmcs_list));
        v->arch.hvm_vmx.active_cpu = smp_processor_id();
    }

    if (this_cpu(active_vmcs) != v->arch.hvm_vmx.vmcs) {
        if (do_load) {
            __vmptrld(v->arch.hvm_vmx.vmcs_ma);
            if (vmx_vmcs_late_load)
                v->arch.hvm_vmx.loaded = 1;
        }
        this_cpu(active_vmcs) = v->arch.hvm_vmx.vmcs;
    }
    this_cpu(current_vmcs_vmx) = &v->arch.hvm_vmx;

    cpu_irq_restore(flags);
    if (ax_present)
        spin_unlock_irqrestore(&vmx_clear_lock, flags2);
}

static void __vmx_clear_vmcs(void *info);

void vmx_unload_vmcs(struct vcpu *v)
{
    struct arch_vmx_struct *arch_vmx = &v->arch.hvm_vmx;
    unsigned long flags, flags2 = 0;

    if (ax_present)
        spin_lock_irqsave(&vmx_clear_lock, flags2);
    cpu_irq_save(flags);

    ASSERT(arch_vmx == this_cpu(current_vmcs_vmx));
    ASSERT(arch_vmx->active_cpu == smp_processor_id());

    this_cpu(current_vmcs_vmx) = NULL;

    if (!ax_present) /* maybe or maybenot? need to check perf */
        __vmx_clear_vmcs(v);

    cpu_irq_restore(flags);
    if (ax_present)
        spin_unlock_irqrestore(&vmx_clear_lock, flags2);
}

int
vmx_cpu_up_prepare(unsigned int cpu)
{
    if ( per_cpu(vmxon_region, cpu) != NULL )
        return 0;

    per_cpu(vmxon_region, cpu) = vmx_alloc_vmcs();
    if ( per_cpu(vmxon_region, cpu) != NULL )
        return 0;

    printk("CPU%d: Could not allocate host VMCS\n", cpu);
    return -ENOMEM;
}

void
vmx_cpu_dead(unsigned int cpu)
{
DEBUG();
    vmx_free_vmcs(per_cpu(vmxon_region, cpu));
    per_cpu(vmxon_region, cpu) = NULL;
}

int
vmx_cpu_on(void)
{
    int cpu = smp_processor_id();
    unsigned long flags, flags2 = 0;
    u32 vmx_basic_msr_low, vmx_basic_msr_high;

    if (ax_present)
        spin_lock_irqsave(&vmx_clear_lock, flags2);
    cpu_irq_save(flags);

    if (this_cpu(hvmon)) {
        cpu_irq_restore(flags);
        if (ax_present)
            spin_unlock_irqrestore(&vmx_clear_lock, flags2);
        return 0;
    }

    perfc_incr(hvm_cpu_on);

    if (!(read_cr4() & X86_CR4_VMXE))
        set_in_cr4_cpu(X86_CR4_VMXE);

    switch ( __vmxon(virt_to_maddr(this_cpu(vmxon_region))) )
    {
    case -2: /* #UD or #GP */
        cpu_irq_restore(flags);
        if (ax_present)
            spin_unlock_irqrestore(&vmx_clear_lock, flags2);
        printk("CPU%d: unexpected VMXON failure\n", cpu);
        return -EINVAL;
    case -1: /* CF==1 or ZF==1 */
    case 0: /* success */
        this_cpu(hvmon) = hvmon_on;
        break;
    default:
        spin_unlock_irqrestore(&vmx_clear_lock, flags2);
        BUG();
    }
    cpu_irq_restore(flags);
    if (ax_present)
        spin_unlock_irqrestore(&vmx_clear_lock, flags2);

    hvm_asid_init(cpu_has_vmx_vpid ? (1u << VMCS_VPID_WIDTH) : 0);

    if ( cpu_has_vmx_ept )
        ept_sync_all();

    if ( cpu_has_vmx_vpid )
        vpid_sync_all();

    rdmsr(MSR_IA32_VMX_BASIC, vmx_basic_msr_low, vmx_basic_msr_high);

    return 0;
}

void
vmx_cpu_off(void)
{
    struct list_head *active_vmcs_list = &this_cpu(active_vmcs_list);
    unsigned long flags, flags2 = 0;

    if (ax_present)
        spin_lock_irqsave(&vmx_clear_lock, flags2);
    cpu_irq_save(flags);

    /* only turn off if turned on via vmx_cpu_on */
    if ( this_cpu(hvmon) != hvmon_on ) {
        cpu_irq_restore(flags);
        if (ax_present)
            spin_unlock_irqrestore(&vmx_clear_lock, flags2);
        return;
    }

    while ( !list_empty(active_vmcs_list) )
        __vmx_clear_vmcs(list_entry(active_vmcs_list->next,
                                    struct vcpu, arch.hvm_vmx.active_list));

    BUG_ON(!(read_cr4() & X86_CR4_VMXE));
    this_cpu(hvmon) = hvmon_off;
    __vmxoff();

    clear_in_cr4_cpu(X86_CR4_VMXE);

    cpu_irq_restore(flags);
    if (ax_present)
        spin_unlock_irqrestore(&vmx_clear_lock, flags2);
}

int
vmx_cpu_up(enum hvmon hvmon_mode)
{
    u32 eax, edx;
    int rc, bios_locked, cpu = smp_processor_id();
    u64 cr0, vmx_cr0_fixed0, vmx_cr0_fixed1;

    if (this_cpu(hvmon))
        return 0;

    if (!(read_cr4() & X86_CR4_VMXE))
        set_in_cr4(X86_CR4_VMXE);

    printk("%s: vmxon set on cpu %d\n", __FUNCTION__, cpu);

    /* 
     * Ensure the current processor operating mode meets 
     * the requred CRO fixed bits in VMX operation. 
     */
    cr0 = read_cr0();
    rdmsrl(MSR_IA32_VMX_CR0_FIXED0, vmx_cr0_fixed0);
    rdmsrl(MSR_IA32_VMX_CR0_FIXED1, vmx_cr0_fixed1);
    if ( (~cr0 & vmx_cr0_fixed0) || (cr0 & ~vmx_cr0_fixed1) )
    {
        printk("CPU%d: some settings of host CR0 are " 
               "not allowed in VMX operation.\n", cpu);
        return -EINVAL;
    }

    rdmsr(IA32_FEATURE_CONTROL_MSR, eax, edx);

    bios_locked = !!(eax & IA32_FEATURE_CONTROL_MSR_LOCK);
    if ( bios_locked )
    {
        if ( !(eax & (tboot_in_measured_env()
                      ? IA32_FEATURE_CONTROL_MSR_ENABLE_VMXON_INSIDE_SMX
                      : IA32_FEATURE_CONTROL_MSR_ENABLE_VMXON_OUTSIDE_SMX)) )
        {
            printk("CPU%d: VMX disabled by BIOS.\n", cpu);
            return -EINVAL;
        }
    }
    else
    {
        eax  = IA32_FEATURE_CONTROL_MSR_LOCK;
        eax |= IA32_FEATURE_CONTROL_MSR_ENABLE_VMXON_OUTSIDE_SMX;
        if ( test_bit(X86_FEATURE_SMXE, &boot_cpu_data.x86_capability) )
            eax |= IA32_FEATURE_CONTROL_MSR_ENABLE_VMXON_INSIDE_SMX;
        wrmsr(IA32_FEATURE_CONTROL_MSR, eax, 0);
    }

    if ( (rc = vmx_init_vmcs_config()) != 0 )
        return rc;

    INIT_LIST_HEAD(&this_cpu(active_vmcs_list));

    if ( (rc = vmx_cpu_up_prepare(cpu)) != 0 )
        return rc;

    switch ( __vmxon(virt_to_maddr(this_cpu(vmxon_region))) )
    {
    case -2: /* #UD or #GP */
        if ( bios_locked &&
             test_bit(X86_FEATURE_SMXE, &boot_cpu_data.x86_capability) &&
             (!(eax & IA32_FEATURE_CONTROL_MSR_ENABLE_VMXON_OUTSIDE_SMX) ||
              !(eax & IA32_FEATURE_CONTROL_MSR_ENABLE_VMXON_INSIDE_SMX)) )
        {
            printk("CPU%d: VMXON failed: perhaps because of TXT settings "
                   "in your BIOS configuration?\n", cpu);
            printk(" --> Disable TXT in your BIOS unless using a secure "
                   "bootloader.\n");
            return -EINVAL;
        }
        /* fall through */
#ifndef __UXEN__
    case -1: /* CF==1 or ZF==1 */
#endif  /* __UXEN__ */
        printk("CPU%d: unexpected VMXON failure\n", cpu);
        return -EINVAL;
#ifdef __UXEN__
    case -1: /* CF==1 or ZF==1 */
#endif  /* __UXEN__ */
    case 0: /* success */
        printk("CPU%d: vmxon success\n", cpu);
        this_cpu(hvmon) = hvmon_mode;
        break;
    default:
        BUG();
    }

    hvm_asid_init(cpu_has_vmx_vpid ? (1u << VMCS_VPID_WIDTH) : 0);

    if ( cpu_has_vmx_ept )
        ept_sync_all();

    if ( cpu_has_vmx_vpid )
        vpid_sync_all();

    if (ax_pv_vmcs_enabled)
        ax_pv_vmcs_setup();

    return 0;
}

void
vmx_cpu_down(void)
{
    struct list_head *active_vmcs_list = &this_cpu(active_vmcs_list);
    unsigned long flags, flags2 = 0;

    if ( !this_cpu(hvmon) )
        return;

    if (ax_present)
        spin_lock_irqsave(&vmx_clear_lock, flags2);
    cpu_irq_save(flags);

    while ( !list_empty(active_vmcs_list) )
        __vmx_clear_vmcs(list_entry(active_vmcs_list->next,
                                    struct vcpu, arch.hvm_vmx.active_list));

    BUG_ON(!(read_cr4() & X86_CR4_VMXE));
    this_cpu(hvmon) = hvmon_off;
    __vmxoff();

    clear_in_cr4(X86_CR4_VMXE);

    cpu_irq_restore(flags);
    if (ax_present)
        spin_unlock_irqrestore(&vmx_clear_lock, flags2);
}

struct foreign_vmcs {
    struct vcpu *v;
    unsigned int count;
};
static DEFINE_PER_CPU(struct foreign_vmcs, foreign_vmcs);

void vmx_vmcs_enter(struct vcpu *v)
{
    struct foreign_vmcs *fv;

    /*
     * NB. We must *always* run an HVM VCPU on its own VMCS, except for
     * vmx_vmcs_enter/exit critical regions.
     */
    if ( likely(v == current) )
        return;

    fv = &this_cpu(foreign_vmcs);

    if ( fv->v == v )
    {
        BUG_ON(fv->count == 0);
    }
    else
    {
        BUG_ON(fv->v != NULL);
        BUG_ON(fv->count != 0);

        vcpu_pause(v);
        spin_lock(&v->arch.hvm_vmx.vmcs_lock);

        vmx_clear_vmcs(v);
        vmx_load_vmcs(v);

        fv->v = v;
    }

    fv->count++;
}

void vmx_vmcs_exit(struct vcpu *v)
{
    struct foreign_vmcs *fv;

    if ( likely(v == current) )
        return;

    fv = &this_cpu(foreign_vmcs);
    BUG_ON(fv->v != v);
    BUG_ON(fv->count == 0);

    if ( --fv->count == 0 )
    {
        /* Don't confuse vmx_do_resume (for @v or @current!) */
        vmx_clear_vmcs(v);
        if ( is_hvm_vcpu(current) )
            vmx_load_vmcs(current);

        spin_unlock(&v->arch.hvm_vmx.vmcs_lock);
        vcpu_unpause(v);

        fv->v = NULL;
    }
}

#ifndef __UXEN__
struct xgt_desc {
    unsigned short size;
    unsigned long address __attribute__((packed));
};
#endif  /* __UXEN__ */

void vmx_restore_host_env(void)
{

#ifdef UXEN_HOST_WINDOWS
    /* Host's GDT/IDT limits are not saved in VMCS - restore them manually */
    if (!ax_present) {
        __asm__ __volatile__( "lgdt %0" : "=m" (this_cpu(gdt_save)) );
        __asm__ __volatile__( "lidt %0" : "=m" (this_cpu(idt_save)) );
    }
#endif /* UXEN_HOST_WINDOWS */
}

/* static */ void vmx_set_host_env(struct vcpu *v)
{
#ifndef __UXEN__
    unsigned int cpu = smp_processor_id();
#endif  /* __UXEN__ */
    unsigned long base;

    rdmsrl(MSR_FS_BASE, base);
    __vmwrite(HOST_FS_BASE, base);
    rdmsrl(MSR_GS_BASE, base);
    __vmwrite(HOST_GS_BASE, base);
    /* XXX also maybe sync: ss, ds, es, fs, gs, cr0, cr4, cs, sysenter, pat */

#ifndef __UXEN__
    __vmwrite(HOST_GDTR_BASE,
              (unsigned long)(this_cpu(gdt_table) - FIRST_RESERVED_GDT_ENTRY));
#else   /* __UXEN__ */
    __asm__ __volatile__ ( "sgdt %0" : "=m" (this_cpu(gdt_save)) );
    __vmwrite(HOST_GDTR_BASE, (*(unsigned long  *)(&this_cpu(gdt_save)[2])));
#endif  /* __UXEN__ */
#ifndef __UXEN__
    __vmwrite(HOST_IDTR_BASE, (unsigned long)idt_tables[cpu]);
#else   /* __UXEN__ */
    __asm__ __volatile__ ( "sidt %0" : "=m" (this_cpu(idt_save)) );
    __vmwrite(HOST_IDTR_BASE, (*(unsigned long  *)(&this_cpu(idt_save)[2])));
#endif  /* __UXEN__ */

#ifndef __UXEN__
    __vmwrite(HOST_TR_SELECTOR, TSS_ENTRY << 3);
    __vmwrite(HOST_TR_BASE, (unsigned long)&per_cpu(init_tss, cpu));
#else   /* __UXEN__ */
    {
        uint16_t tr;
        struct desc_struct *table, desc;
        unsigned long base;

        __asm__ __volatile__ ( "str %0" : "=g" (tr) );
        __vmwrite(HOST_TR_SELECTOR, tr);

        table = (struct desc_struct *)
                (*(unsigned long  *)(&this_cpu(gdt_save)[2]));
        desc = table[tr >> 3];
        base = ((desc.a >> 16) + ((desc.b & 0xff) << 16) +
                (desc.b & 0xff000000));
#ifdef __x86_64__
        *(((uint32_t *)&base) + 1) = table[(tr >> 3) + 1].a;
#endif
        __vmwrite(HOST_TR_BASE, base);
    }
#endif  /* __UXEN__ */

#ifndef __UXEN__
    __vmwrite(HOST_SYSENTER_ESP, get_stack_bottom());
#else   /* __UXEN__ */
    {
        unsigned long sysenter_esp;

        rdmsrl(MSR_IA32_SYSENTER_ESP, sysenter_esp);
        __vmwrite(HOST_SYSENTER_ESP, sysenter_esp);
    }
#endif  /* __UXEN__ */

    /*
     * Skip end of cpu_user_regs when entering the hypervisor because the
     * CPU does not save context onto the stack. SS,RSP,CS,RIP,RFLAGS,etc
     * all get saved into the VMCS instead.
     */
#ifndef __UXEN__
    __vmwrite(HOST_RSP,
              (unsigned long)&get_cpu_info()->guest_cpu_user_regs.error_code);
#endif  /* __UXEN__ */
}

void vmx_disable_intercept_for_msr(struct vcpu *v, u32 msr)
{
    unsigned long *msr_bitmap = v->arch.hvm_vmx.msr_bitmap;

    /* VMX MSR bitmap supported? */
    if ( msr_bitmap == NULL )
        return;

    /*
     * See Intel PRM Vol. 3, 20.6.9 (MSR-Bitmap Address). Early manuals
     * have the write-low and read-high bitmap offsets the wrong way round.
     * We can control MSRs 0x00000000-0x00001fff and 0xc0000000-0xc0001fff.
     */
    if ( msr <= 0x1fff )
    {
        __clear_bit(msr, msr_bitmap + 0x000/BYTES_PER_LONG); /* read-low */
        __clear_bit(msr, msr_bitmap + 0x800/BYTES_PER_LONG); /* write-low */
    }
    else if ( (msr >= 0xc0000000) && (msr <= 0xc0001fff) )
    {
        msr &= 0x1fff;
        __clear_bit(msr, msr_bitmap + 0x400/BYTES_PER_LONG); /* read-high */
        __clear_bit(msr, msr_bitmap + 0xc00/BYTES_PER_LONG); /* write-high */
    }
}

/*
 * Switch VMCS between layer 1 & 2 guest
 */
void vmx_vmcs_switch(struct vmcs_struct *from, struct vmcs_struct *to)
{
    struct arch_vmx_struct *vmx = &current->arch.hvm_vmx;
    spin_lock(&vmx->vmcs_lock);

DEBUG();
    __vmpclear(virt_to_maddr(from));
    __vmptrld(virt_to_maddr(to));

    vmx->vmcs = to;
    vmx->launched = 0;
    /* this_cpu(current_vmcs) = to; */
    /* XXX current_vmcs_vmx */

    if ( vmx->hostenv_migrated )
    {
        vmx->hostenv_migrated = 0;
        vmx_set_host_env(current);
    }

    spin_unlock(&vmx->vmcs_lock);
}

static int construct_vmcs(struct vcpu *v)
{
    struct domain *d = v->domain;
    uint16_t sysenter_cs;
    unsigned long sysenter_eip;
    u32 vmexit_ctl = vmx_vmexit_control;
    u32 vmentry_ctl = vmx_vmentry_control;

    vmx_vmcs_enter(v);

    /* VMCS controls. */
    __vmwrite(PIN_BASED_VM_EXEC_CONTROL, vmx_pin_based_exec_control);

    v->arch.hvm_vmx.exec_control = vmx_cpu_based_exec_control;
    if ( d->arch.vtsc )
        v->arch.hvm_vmx.exec_control |= CPU_BASED_RDTSC_EXITING;

    v->arch.hvm_vmx.secondary_exec_control = vmx_secondary_exec_control;

    /* Disable VPID for now: we decide when to enable it on VMENTER. */
    v->arch.hvm_vmx.secondary_exec_control &= ~SECONDARY_EXEC_ENABLE_VPID;

    if (!hvm_has_rdtscp(d) && !hvm_has_pvrdtscp(d))
        v->arch.hvm_vmx.secondary_exec_control &= ~SECONDARY_EXEC_ENABLE_RDTSCP;

    if ( paging_mode_hap(d) )
    {
        v->arch.hvm_vmx.exec_control &= ~(CPU_BASED_INVLPG_EXITING |
                                          CPU_BASED_CR3_LOAD_EXITING |
                                          CPU_BASED_CR3_STORE_EXITING);
        if (v->domain->introspection_features &
            XEN_DOMCTL_INTROSPECTION_FEATURE_HIDDEN_PROCESS)
            v->arch.hvm_vmx.exec_control |= CPU_BASED_CR3_LOAD_EXITING;
    }
    else
    {
        v->arch.hvm_vmx.secondary_exec_control &= 
            ~(SECONDARY_EXEC_ENABLE_EPT | 
              SECONDARY_EXEC_UNRESTRICTED_GUEST |
              SECONDARY_EXEC_ENABLE_INVPCID);
        vmexit_ctl &= ~(VM_EXIT_SAVE_GUEST_PAT |
                        VM_EXIT_LOAD_HOST_PAT);
        vmentry_ctl &= ~VM_ENTRY_LOAD_GUEST_PAT;
    }

#if 0
    /* XXX Ideally we'd check here if the guest cpuid flag for invpcid
       is set, but alas there is no interface for that, since
       the *_cpuid functions use current. */
    if (cpu_has_vmx_invpcid) {
        unsigned int eax, ebx, ecx = 0, edx;
        hvm_cpuid(7, &eax, &ebx, &ecx, &edx);
        if (!(ebx & cpufeat_mask(X86_FEATURE_INVPCID)))
            v->arch.hvm_vmx.secondary_exec_control &=
                ~(SECONDARY_EXEC_ENABLE_INVPCID);
    }
#endif

    /* Do not enable Monitor Trap Flag unless start single step debug */
    v->arch.hvm_vmx.exec_control &= ~CPU_BASED_MONITOR_TRAP_FLAG;

    vmx_update_cpu_exec_control(v);
    __vmwrite(VM_EXIT_CONTROLS, vmexit_ctl);
    __vmwrite(VM_ENTRY_CONTROLS, vmentry_ctl);

    if ( cpu_has_vmx_ple )
    {
        __vmwrite(PLE_GAP, ple_gap);
        __vmwrite(PLE_WINDOW, ple_window);
    }

    if ( cpu_has_vmx_secondary_exec_control )
        __vmwrite(SECONDARY_VM_EXEC_CONTROL,
                  v->arch.hvm_vmx.secondary_exec_control);

    /* MSR access bitmap. */
    if ( cpu_has_vmx_msr_bitmap )
    {
        unsigned long *msr_bitmap = alloc_xenheap_page();

        if ( msr_bitmap == NULL ) {
            vmx_vmcs_exit(v);
            return -ENOMEM;
        }

        memset(msr_bitmap, ~0, PAGE_SIZE);
        v->arch.hvm_vmx.msr_bitmap = msr_bitmap;
        __vmwrite(MSR_BITMAP, virt_to_maddr(msr_bitmap));

        vmx_disable_intercept_for_msr(v, MSR_FS_BASE);
        vmx_disable_intercept_for_msr(v, MSR_GS_BASE);
        vmx_disable_intercept_for_msr(v, MSR_IA32_SYSENTER_CS);
        vmx_disable_intercept_for_msr(v, MSR_IA32_SYSENTER_ESP);
        vmx_disable_intercept_for_msr(v, MSR_IA32_SYSENTER_EIP);
        if ( cpu_has_vmx_pat && paging_mode_hap(d) )
            vmx_disable_intercept_for_msr(v, MSR_IA32_CR_PAT);
        if (cpu_has_spec_ctrl)
            vmx_disable_intercept_for_msr(v, MSR_IA32_PRED_CMD);

        vmx_disable_intercept_for_msr(v, MSR_SHADOW_GS_BASE);
    }

    /* I/O access bitmap. */
    __vmwrite(IO_BITMAP_A, virt_to_maddr((char *)hvm_io_bitmap));
    __vmwrite(IO_BITMAP_B, virt_to_maddr((char *)hvm_io_bitmap + PAGE_SIZE));

    /* Host data selectors. */
#ifndef __UXEN__
    __vmwrite(HOST_SS_SELECTOR, __HYPERVISOR_DS);
    __vmwrite(HOST_DS_SELECTOR, __HYPERVISOR_DS);
    __vmwrite(HOST_ES_SELECTOR, __HYPERVISOR_DS);
    __vmwrite(HOST_FS_SELECTOR, 0);
    __vmwrite(HOST_GS_SELECTOR, 0);
    __vmwrite(HOST_FS_BASE, 0);
    __vmwrite(HOST_GS_BASE, 0);
#else   /* __UXEN__ */
    {
#if !defined(__x86_64__)
        unsigned char gdt_save[10];
        struct desc_struct *table, desc;
#endif  /* __x86_64__ */
        int sel;
        unsigned long base;

#ifndef UXEN_HOST_OSX
/* #if 0 */
        __asm__ __volatile__ ( "mov %%ss, %0" : "=r" (sel) );
        __vmwrite(HOST_SS_SELECTOR, sel);
/* #endif */
        __asm__ __volatile__ ( "mov %%ds, %0" : "=r" (sel) );
        __vmwrite(HOST_DS_SELECTOR, sel & ~7);
        __asm__ __volatile__ ( "mov %%es, %0" : "=r" (sel) );
        __vmwrite(HOST_ES_SELECTOR, sel & ~7);
#else
        /* __vmwrite(HOST_SS_SELECTOR, 0); */
        __vmwrite(HOST_DS_SELECTOR, 0);
        __vmwrite(HOST_ES_SELECTOR, 0);
#endif
        __asm__ __volatile__ ( "mov %%fs, %0" : "=r" (sel) );
        __vmwrite(HOST_FS_SELECTOR, sel & ~7);
        __asm__ __volatile__ ( "mov %%gs, %0" : "=r" (sel) );
        __vmwrite(HOST_GS_SELECTOR, sel & ~7);

#if !defined(__x86_64__)
        /* XXX is this needed? */
        __asm__ __volatile__ ( "sgdt %0" : "=m" (gdt_save) );
        __asm__ __volatile__ ( "mov %%gs, %0" : "=r" (sel) );
        table = (struct desc_struct *)(*(unsigned long  *)(&gdt_save[2]));
        desc = table[sel >> 3];
        base = ((desc.a >> 16) + ((desc.b & 0xff) << 16) +
                (desc.b & 0xff000000));
        __vmwrite(HOST_GS_BASE, base);

        __asm__ __volatile__ ( "mov %%fs, %0" : "=r" (sel) );
        table = (struct desc_struct *)(*(unsigned long  *)(&gdt_save[2]));
        desc = table[sel >> 3];
        base = ((desc.a >> 16) + ((desc.b & 0xff) << 16) +
                (desc.b & 0xff000000));
        __vmwrite(HOST_FS_BASE, base);
#else   /* __x86_64__ */
        rdmsrl(MSR_FS_BASE, base);
        __vmwrite(HOST_FS_BASE, base);
        rdmsrl(MSR_GS_BASE, base);
        __vmwrite(HOST_GS_BASE, base);
#endif  /* __x86_64__ */
    }
#endif  /* __UXEN__ */

    /* Host control registers. */
#if defined(__UXEN__)
    v->arch.hvm_vmx.host_cr0 = read_cr0() & ~X86_CR0_TS;
#else   /* __UXEN__ */
    v->arch.hvm_vmx.host_cr0 = read_cr0() | X86_CR0_TS;
#endif  /* __UXEN__ */
    __vmwrite(HOST_CR0, v->arch.hvm_vmx.host_cr0);
#ifndef __UXEN__
    __vmwrite(HOST_CR4,
              mmu_cr4_features | (xsave_enabled(v) ? X86_CR4_OSXSAVE : 0));
#else   /* __UXEN__ */
    __vmwrite(HOST_CR4, mmu_cr4_features);
#endif  /* __UXEN__ */

    /* Host CS:RIP. */
#ifndef __UXEN__
    __vmwrite(HOST_CS_SELECTOR, __HYPERVISOR_CS);
#else   /* __UXEN__ */
#ifndef UXEN_HOST_OSX
/* #if 0 */
    {
        int sel;
        __asm__ __volatile__ ( "mov %%cs, %0" : "=r" (sel) );
        __vmwrite(HOST_CS_SELECTOR, sel);
    }
/* #endif */
#else
    /* __vmwrite(HOST_CS_SELECTOR, 0); */
#endif
#endif  /* __UXEN__ */
    __vmwrite(HOST_RIP, (unsigned long)vmx_asm_vmexit_handler);

    /* Host SYSENTER CS:RIP. */
    rdmsrl(MSR_IA32_SYSENTER_CS, sysenter_cs);
    __vmwrite(HOST_SYSENTER_CS, sysenter_cs);
    rdmsrl(MSR_IA32_SYSENTER_EIP, sysenter_eip);
    __vmwrite(HOST_SYSENTER_EIP, sysenter_eip);

    /* MSR intercepts. */
    __vmwrite(VM_EXIT_MSR_LOAD_COUNT, 0);
    __vmwrite(VM_EXIT_MSR_STORE_COUNT, 0);
    __vmwrite(VM_ENTRY_MSR_LOAD_COUNT, 0);

    __vmwrite(VM_ENTRY_INTR_INFO, 0);

    __vmwrite(CR0_GUEST_HOST_MASK, ~0UL);
    __vmwrite(CR4_GUEST_HOST_MASK, ~0UL);

    __vmwrite(PAGE_FAULT_ERROR_CODE_MASK, 0);
    __vmwrite(PAGE_FAULT_ERROR_CODE_MATCH, 0);

    __vmwrite(CR3_TARGET_COUNT, 0);

    __vmwrite(GUEST_ACTIVITY_STATE, 0);

    /* Guest segment bases. */
    __vmwrite(GUEST_ES_BASE, 0);
    __vmwrite(GUEST_SS_BASE, 0);
    __vmwrite(GUEST_DS_BASE, 0);
    __vmwrite(GUEST_FS_BASE, 0);
    __vmwrite(GUEST_GS_BASE, 0);
    __vmwrite(GUEST_CS_BASE, 0);

    /* Guest segment limits. */
    __vmwrite(GUEST_ES_LIMIT, ~0u);
    __vmwrite(GUEST_SS_LIMIT, ~0u);
    __vmwrite(GUEST_DS_LIMIT, ~0u);
    __vmwrite(GUEST_FS_LIMIT, ~0u);
    __vmwrite(GUEST_GS_LIMIT, ~0u);
    __vmwrite(GUEST_CS_LIMIT, ~0u);

    /* Guest segment AR bytes. */
    __vmwrite(GUEST_ES_AR_BYTES, 0xc093); /* read/write, accessed */
    __vmwrite(GUEST_SS_AR_BYTES, 0xc093);
    __vmwrite(GUEST_DS_AR_BYTES, 0xc093);
    __vmwrite(GUEST_FS_AR_BYTES, 0xc093);
    __vmwrite(GUEST_GS_AR_BYTES, 0xc093);
    __vmwrite(GUEST_CS_AR_BYTES, 0xc09b); /* exec/read, accessed */

    /* Guest IDT. */
    __vmwrite(GUEST_IDTR_BASE, 0);
    __vmwrite(GUEST_IDTR_LIMIT, 0);

    /* Guest GDT. */
    __vmwrite(GUEST_GDTR_BASE, 0);
    __vmwrite(GUEST_GDTR_LIMIT, 0);

    /* Guest LDT. */
    __vmwrite(GUEST_LDTR_AR_BYTES, 0x0082); /* LDT */
    __vmwrite(GUEST_LDTR_SELECTOR, 0);
    __vmwrite(GUEST_LDTR_BASE, 0);
    __vmwrite(GUEST_LDTR_LIMIT, 0);

    /* Guest TSS. */
    __vmwrite(GUEST_TR_AR_BYTES, 0x008b); /* 32-bit TSS (busy) */
    __vmwrite(GUEST_TR_BASE, 0);
    __vmwrite(GUEST_TR_LIMIT, 0xff);

    __vmwrite(GUEST_INTERRUPTIBILITY_INFO, 0);
    __vmwrite(GUEST_DR7, 0);
    __vmwrite(VMCS_LINK_POINTER, ~0UL);
#if defined(__i386__)
    __vmwrite(VMCS_LINK_POINTER_HIGH, ~0UL);
#endif

    v->arch.hvm_vmx.exception_bitmap = HVM_TRAP_MASK
              | (paging_mode_hap(d) ? 0 : (1U << TRAP_page_fault))
              | (1U << TRAP_no_device);
    vmx_update_exception_bitmap(v);

    v->arch.hvm_vcpu.guest_cr[0] = X86_CR0_PE | X86_CR0_ET;
    hvm_update_guest_cr(v, 0);

    v->arch.hvm_vcpu.guest_cr[4] = 0;
    hvm_update_guest_cr(v, 4);

    if ( cpu_has_vmx_tpr_shadow )
    {
        __vmwrite(VIRTUAL_APIC_PAGE_ADDR,
                  page_to_maddr(vcpu_vlapic(v)->regs_page));
        __vmwrite(TPR_THRESHOLD, 0);
    }

    if ( paging_mode_hap(d) )
    {
        __vmwrite(EPT_POINTER, d->arch.hvm_domain.vmx.ept_control.eptp);
#ifdef __i386__
        __vmwrite(EPT_POINTER_HIGH,
                  d->arch.hvm_domain.vmx.ept_control.eptp >> 32);
#endif
    }

    if ( cpu_has_vmx_pat && paging_mode_hap(d) )
    {
        u64 host_pat, guest_pat;

        rdmsrl(MSR_IA32_CR_PAT, host_pat);
        guest_pat = MSR_IA32_CR_PAT_RESET;

        __vmwrite(HOST_PAT, host_pat);
        __vmwrite(GUEST_PAT, guest_pat);
#ifdef __i386__
        __vmwrite(HOST_PAT_HIGH, host_pat >> 32);
        __vmwrite(GUEST_PAT_HIGH, guest_pat >> 32);
#endif
    }

    vmx_vmcs_exit(v);

    paging_update_paging_modes(v); /* will update HOST & GUEST_CR3 as reqd */

    vmx_vlapic_msr_changed(v);

    return 0;
}

#ifndef __UXEN__
int vmx_read_guest_msr(u32 msr, u64 *val)
{
    struct vcpu *curr = current;
    unsigned int i, msr_count = curr->arch.hvm_vmx.msr_count;
    const struct vmx_msr_entry *msr_area = curr->arch.hvm_vmx.msr_area;

    for ( i = 0; i < msr_count; i++ )
    {
        if ( msr_area[i].index == msr )
        {
            *val = msr_area[i].data;
            return 0;
        }
    }

    return -ESRCH;
}

int vmx_write_guest_msr(u32 msr, u64 val)
{
    struct vcpu *curr = current;
    unsigned int i, msr_count = curr->arch.hvm_vmx.msr_count;
    struct vmx_msr_entry *msr_area = curr->arch.hvm_vmx.msr_area;

    for ( i = 0; i < msr_count; i++ )
    {
        if ( msr_area[i].index == msr )
        {
            msr_area[i].data = val;
            return 0;
        }
    }

    return -ESRCH;
}

int vmx_add_guest_msr(u32 msr)
{
    struct vcpu *curr = current;
    unsigned int i, msr_count = curr->arch.hvm_vmx.msr_count;
    struct vmx_msr_entry *msr_area = curr->arch.hvm_vmx.msr_area;

    if ( msr_area == NULL )
    {
        if ( (msr_area = alloc_xenheap_page()) == NULL )
            return -ENOMEM;
        curr->arch.hvm_vmx.msr_area = msr_area;
        __vmwrite(VM_EXIT_MSR_STORE_ADDR, virt_to_maddr(msr_area));
        __vmwrite(VM_ENTRY_MSR_LOAD_ADDR, virt_to_maddr(msr_area));
    }

    for ( i = 0; i < msr_count; i++ )
        if ( msr_area[i].index == msr )
            return 0;

    if ( msr_count == (PAGE_SIZE / sizeof(struct vmx_msr_entry)) )
        return -ENOSPC;

    msr_area[msr_count].index = msr;
    msr_area[msr_count].mbz   = 0;
    msr_area[msr_count].data  = 0;
    curr->arch.hvm_vmx.msr_count = ++msr_count;
    __vmwrite(VM_EXIT_MSR_STORE_COUNT, msr_count);
    __vmwrite(VM_ENTRY_MSR_LOAD_COUNT, msr_count);

    return 0;
}

int vmx_add_host_load_msr(u32 msr)
{
    struct vcpu *curr = current;
    unsigned int i, msr_count = curr->arch.hvm_vmx.host_msr_count;
    struct vmx_msr_entry *msr_area = curr->arch.hvm_vmx.host_msr_area;

    if ( msr_area == NULL )
    {
        if ( (msr_area = alloc_xenheap_page()) == NULL )
            return -ENOMEM;
        curr->arch.hvm_vmx.host_msr_area = msr_area;
        __vmwrite(VM_EXIT_MSR_LOAD_ADDR, virt_to_maddr(msr_area));
    }

    for ( i = 0; i < msr_count; i++ )
        if ( msr_area[i].index == msr )
            return 0;

    if ( msr_count == (PAGE_SIZE / sizeof(struct vmx_msr_entry)) )
        return -ENOSPC;

    msr_area[msr_count].index = msr;
    msr_area[msr_count].mbz   = 0;
    rdmsrl(msr, msr_area[msr_count].data);
    curr->arch.hvm_vmx.host_msr_count = ++msr_count;
    __vmwrite(VM_EXIT_MSR_LOAD_COUNT, msr_count);

    return 0;
}
#endif  /* __UXEN__ */

int vmx_create_vmcs(struct vcpu *v)
{
    struct arch_vmx_struct *arch_vmx = &v->arch.hvm_vmx;
    int rc;

    if ( (arch_vmx->vmcs = vmx_alloc_vmcs()) == NULL )
        return -ENOMEM;

    /* XXX make alloc conditional on using active vmcs shadow */
    arch_vmx->vmcs_shadow = alloc_xenheap_page();
    if (!arch_vmx->vmcs_shadow) {
        vmx_free_vmcs(arch_vmx->vmcs);
        return -ENOMEM;
    }

    arch_vmx->vmcs_ma = virt_to_maddr(arch_vmx->vmcs);

    INIT_LIST_HEAD(&arch_vmx->active_list);
    __vmpclear(arch_vmx->vmcs_ma);
    arch_vmx->active_cpu = -1;
    arch_vmx->context_cpu = -1;
    arch_vmx->launched   = 0;

    if ( (rc = construct_vmcs(v)) != 0 )
    {
        free_xenheap_page(arch_vmx->vmcs_shadow);
        vmx_free_vmcs(arch_vmx->vmcs);
        return rc;
    }

    return 0;
}

void vmx_destroy_vmcs(struct vcpu *v)
{
    struct arch_vmx_struct *arch_vmx = &v->arch.hvm_vmx;

    vmx_clear_vmcs(v);

    free_xenheap_page(arch_vmx->vmcs_shadow);
    vmx_free_vmcs(arch_vmx->vmcs);

    free_xenheap_page(v->arch.hvm_vmx.host_msr_area);
    free_xenheap_page(v->arch.hvm_vmx.msr_area);
    free_xenheap_page(v->arch.hvm_vmx.msr_bitmap);
}

#ifndef __UXEN__
static void wbinvd_ipi(void *info)
{
DEBUG();
    wbinvd();
}
#endif  /* __UXEN__ */

void vmx_do_resume(struct vcpu *v)
{
    bool_t debug_state;

    if ( v->arch.hvm_vmx.context_cpu == smp_processor_id() )
    {
        if ( &v->arch.hvm_vmx != this_cpu(current_vmcs_vmx) )
            vmx_load_vmcs(v);
    }
    else
    {
#ifndef __UXEN__
        /*
         * For pass-through domain, guest PCI-E device driver may leverage the
         * "Non-Snoop" I/O, and explicitly WBINVD or CLFLUSH to a RAM space.
         * Since migration may occur before WBINVD or CLFLUSH, we need to
         * maintain data consistency either by:
         *  1: flushing cache (wbinvd) when the guest is scheduled out if
         *     there is no wbinvd exit, or
         *  2: execute wbinvd on all dirty pCPUs when guest wbinvd exits.
         * If VT-d engine can force snooping, we don't need to do these.
         */
        if ( has_arch_pdevs(v->domain) && !iommu_snoop
                && !cpu_has_wbinvd_exiting )
        {
            int cpu = v->arch.hvm_vmx.active_cpu;
            if ( cpu != -1 )
                on_selected_cpus(cpumask_of(cpu), wbinvd_ipi, NULL, 1);
        }
#endif  /* __UXEN__ */

        vmx_clear_vmcs(v);
        vmx_load_vmcs(v);
        hvm_migrate_timers(v);
        hvm_migrate_pirqs(v);
        /*
         * Both n1 VMCS and n2 VMCS need to update the host environment after 
         * VCPU migration. The environment of current VMCS is updated in place,
         * but the action of another VMCS is deferred till it is switched in.
         */
        v->arch.hvm_vmx.hostenv_migrated = 1;

        hvm_asid_flush_vcpu(v);

        v->arch.hvm_vmx.context_cpu = smp_processor_id();
    }

    debug_state = v->domain->debugger_attached
                  || v->domain->arch.hvm_domain.params[HVM_PARAM_MEMORY_EVENT_INT3]
                  || v->domain->arch.hvm_domain.params[HVM_PARAM_MEMORY_EVENT_SINGLE_STEP];

    if ( unlikely(v->arch.hvm_vcpu.debug_state_latch != debug_state) )
    {
        v->arch.hvm_vcpu.debug_state_latch = debug_state;
        vmx_update_debug_state(v);
    }

#ifndef __UXEN__
    hvm_do_resume(v);
    reset_stack_and_jump(vmx_asm_do_vmentry);
    BUG();
#endif  /* __UXEN__ */
}

static unsigned long vmr(unsigned long field)
{
    int rc;
    unsigned long val;
    val = __vmread_safe(field, &rc);
    return rc ? 0 : val;
}

static void vmx_dump_sel(char *name, uint32_t selector)
{
    uint32_t sel, attr, limit;
    uint64_t base;
    sel = vmr(selector);
    attr = vmr(selector + (GUEST_ES_AR_BYTES - GUEST_ES_SELECTOR));
    limit = vmr(selector + (GUEST_ES_LIMIT - GUEST_ES_SELECTOR));
    base = vmr(selector + (GUEST_ES_BASE - GUEST_ES_SELECTOR));
    printk("%s: sel=0x%04x, attr=0x%05x, limit=0x%08x, base=0x%016"PRIx64"\n",
           name, sel, attr, limit, base);
}

static void vmx_dump_sel2(char *name, uint32_t lim)
{
    uint32_t limit;
    uint64_t base;
    limit = vmr(lim);
    base = vmr(lim + (GUEST_GDTR_BASE - GUEST_GDTR_LIMIT));
    printk("%s:                           limit=0x%08x, base=0x%016"PRIx64"\n",
           name, limit, base);
}

void vmcs_mini_dump_vcpu(const char *from, struct vcpu *v, int exit_reason)
{
    struct cpu_user_regs *regs = &v->arch.user_regs;
    unsigned long pfn;
    uint32_t pfec;

    if ( v == current )
        regs = guest_cpu_user_regs();

    vmx_vmcs_enter(v);

    printk("Dumping guest's current state at %s...\n", from);

    printk("CR0=%08lx CR4=%08lx CR3=%08lx\n",
           (unsigned long)vmr(GUEST_CR0),
           (unsigned long)vmr(GUEST_CR4),
           (unsigned long)vmr(GUEST_CR3));
    printk("GUEST_LINEAR_ADDRESS=%08lx Exit reason: %02d\n",
           (unsigned long)vmr(GUEST_LINEAR_ADDRESS),
           exit_reason);
#if 0
    printk("RSP=0x%016llx RIP=0x%016llx\n", 
           (unsigned long long)vmr(GUEST_RSP),
           (unsigned long long)vmr(GUEST_RIP));
#endif
#ifndef __x86_64__
    printk("eax=%08x ebx=%08x ecx=%08x "
           "edx=%08x esi=%08x edi=%08x\n",
           regs->eax, regs->ebx, regs->ecx, regs->edx,
           regs->esi, regs->edi);
    printk("eip=%08x esp=%08x ebp=%08x eflags=%05x\n",
           regs->eip, regs->esp, regs->ebp, regs->eflags);
#else
    printk("rip=%16lx rflags=%13lx\n"
           "rsp=%16lx rbp=%16lx\n",
           regs->rip, regs->rflags,
           regs->rsp, regs->rbp);
    printk("rax=%16lx rbx=%16lx\n"
           "rcx=%16lx rdx=%16lx\n"
           "rsi=%16lx rdi=%16lx\n",
           regs->rax, regs->rbx,
           regs->rcx, regs->rdx,
           regs->rsi, regs->rdi);
    printk("r8 =%16lx r9 =%16lx\n"
           "r10=%16lx r11=%16lx\n"
           "r12=%16lx r13=%16lx\n"
           "r14=%16lx r15=%16lx\n",
           regs->r8,  regs->r9,
           regs->r10, regs->r11,
           regs->r12, regs->r13,
           regs->r14, regs->r15);
#endif

    pfn = paging_gva_to_gfn(v, regs->eip, paging_g2g_query, &pfec);
    if (pfn != INVALID_GFN)
        printk("rip gfn %lx\n", pfn);

    vmx_vmcs_exit(v);
}

void vmcs_dump_vcpu(struct vcpu *v)
{
    struct cpu_user_regs *regs = &v->arch.user_regs;
    unsigned long long x;

    if ( v == current )
        regs = guest_cpu_user_regs();

    vmx_vmcs_enter(v);

    printk("*** Guest State ***\n");
    printk("CR0: actual=0x%016llx, shadow=0x%016llx, gh_mask=%016llx\n",
           (unsigned long long)vmr(GUEST_CR0),
           (unsigned long long)vmr(CR0_READ_SHADOW), 
           (unsigned long long)vmr(CR0_GUEST_HOST_MASK));
    printk("CR4: actual=0x%016llx, shadow=0x%016llx, gh_mask=%016llx\n",
           (unsigned long long)vmr(GUEST_CR4),
           (unsigned long long)vmr(CR4_READ_SHADOW), 
           (unsigned long long)vmr(CR4_GUEST_HOST_MASK));
    printk("CR3: actual=0x%016llx, target_count=%d\n",
           (unsigned long long)vmr(GUEST_CR3),
           (int)vmr(CR3_TARGET_COUNT));
    printk("     target0=%016llx, target1=%016llx\n",
           (unsigned long long)vmr(CR3_TARGET_VALUE0),
           (unsigned long long)vmr(CR3_TARGET_VALUE1));
    printk("     target2=%016llx, target3=%016llx\n",
           (unsigned long long)vmr(CR3_TARGET_VALUE2),
           (unsigned long long)vmr(CR3_TARGET_VALUE3));
    printk("RSP = 0x%016llx (0x%016llx)  RIP = 0x%016llx (0x%016llx)\n", 
           (unsigned long long)vmr(GUEST_RSP),
           (unsigned long long)regs->esp,
           (unsigned long long)vmr(GUEST_RIP),
           (unsigned long long)regs->eip);
    printk("RFLAGS=0x%016llx (0x%016llx)  DR7 = 0x%016llx\n", 
           (unsigned long long)vmr(GUEST_RFLAGS),
           (unsigned long long)regs->eflags,
           (unsigned long long)vmr(GUEST_DR7));
    printk("Sysenter RSP=%016llx CS:RIP=%04x:%016llx\n",
           (unsigned long long)vmr(GUEST_SYSENTER_ESP),
           (int)vmr(GUEST_SYSENTER_CS),
           (unsigned long long)vmr(GUEST_SYSENTER_EIP));
    vmx_dump_sel("CS", GUEST_CS_SELECTOR);
    vmx_dump_sel("DS", GUEST_DS_SELECTOR);
    vmx_dump_sel("SS", GUEST_SS_SELECTOR);
    vmx_dump_sel("ES", GUEST_ES_SELECTOR);
    vmx_dump_sel("FS", GUEST_FS_SELECTOR);
    vmx_dump_sel("GS", GUEST_GS_SELECTOR);
    vmx_dump_sel2("GDTR", GUEST_GDTR_LIMIT);
    vmx_dump_sel("LDTR", GUEST_LDTR_SELECTOR);
    vmx_dump_sel2("IDTR", GUEST_IDTR_LIMIT);
    vmx_dump_sel("TR", GUEST_TR_SELECTOR);
    printk("Guest PAT = 0x%08x%08x\n",
           (uint32_t)vmr(GUEST_PAT_HIGH), (uint32_t)vmr(GUEST_PAT));
    x  = (unsigned long long)vmr(TSC_OFFSET_HIGH) << 32;
    x |= (uint32_t)vmr(TSC_OFFSET);
    printk("TSC Offset = %016llx\n", x);
    x  = (unsigned long long)vmr(GUEST_IA32_DEBUGCTL_HIGH) << 32;
    x |= (uint32_t)vmr(GUEST_IA32_DEBUGCTL);
    printk("DebugCtl=%016llx DebugExceptions=%016llx\n", x,
           (unsigned long long)vmr(GUEST_PENDING_DBG_EXCEPTIONS));
    printk("Interruptibility=%04x ActivityState=%04x\n",
           (int)vmr(GUEST_INTERRUPTIBILITY_INFO),
           (int)vmr(GUEST_ACTIVITY_STATE));

    printk("*** Host State ***\n");
    printk("RSP = 0x%016llx  RIP = 0x%016llx\n", 
           (unsigned long long)vmr(HOST_RSP),
           (unsigned long long)vmr(HOST_RIP));
    printk("CS=%04x DS=%04x ES=%04x FS=%04x GS=%04x SS=%04x TR=%04x\n",
           (uint16_t)vmr(HOST_CS_SELECTOR),
           (uint16_t)vmr(HOST_DS_SELECTOR),
           (uint16_t)vmr(HOST_ES_SELECTOR),
           (uint16_t)vmr(HOST_FS_SELECTOR),
           (uint16_t)vmr(HOST_GS_SELECTOR),
           (uint16_t)vmr(HOST_SS_SELECTOR),
           (uint16_t)vmr(HOST_TR_SELECTOR));
    printk("FSBase=%016llx GSBase=%016llx TRBase=%016llx\n",
           (unsigned long long)vmr(HOST_FS_BASE),
           (unsigned long long)vmr(HOST_GS_BASE),
           (unsigned long long)vmr(HOST_TR_BASE));
    printk("GDTBase=%016llx IDTBase=%016llx\n",
           (unsigned long long)vmr(HOST_GDTR_BASE),
           (unsigned long long)vmr(HOST_IDTR_BASE));
    printk("CR0=%016llx CR3=%016llx CR4=%016llx\n",
           (unsigned long long)vmr(HOST_CR0),
           (unsigned long long)vmr(HOST_CR3),
           (unsigned long long)vmr(HOST_CR4));
    printk("Sysenter RSP=%016llx CS:RIP=%04x:%016llx\n",
           (unsigned long long)vmr(HOST_SYSENTER_ESP),
           (int)vmr(HOST_SYSENTER_CS),
           (unsigned long long)vmr(HOST_SYSENTER_EIP));
    printk("Host PAT = 0x%08x%08x\n",
           (uint32_t)vmr(HOST_PAT_HIGH), (uint32_t)vmr(HOST_PAT));

    printk("*** Control State ***\n");
    printk("PinBased=%08x CPUBased=%08x SecondaryExec=%08x\n",
           (uint32_t)vmr(PIN_BASED_VM_EXEC_CONTROL),
           (uint32_t)vmr(CPU_BASED_VM_EXEC_CONTROL),
           (uint32_t)vmr(SECONDARY_VM_EXEC_CONTROL));
    printk("EntryControls=%08x ExitControls=%08x\n",
           (uint32_t)vmr(VM_ENTRY_CONTROLS),
           (uint32_t)vmr(VM_EXIT_CONTROLS));
    printk("ExceptionBitmap=%08x\n",
           (uint32_t)vmr(EXCEPTION_BITMAP));
    printk("VMEntry: intr_info=%08x errcode=%08x ilen=%08x\n",
           (uint32_t)vmr(VM_ENTRY_INTR_INFO),
           (uint32_t)vmr(VM_ENTRY_EXCEPTION_ERROR_CODE),
           (uint32_t)vmr(VM_ENTRY_INSTRUCTION_LEN));
    printk("VMExit: intr_info=%08x errcode=%08x ilen=%08x\n",
           (uint32_t)vmr(VM_EXIT_INTR_INFO),
           (uint32_t)vmr(VM_EXIT_INTR_ERROR_CODE),
           (uint32_t)vmr(VM_ENTRY_INSTRUCTION_LEN));
    printk("        reason=%08x qualification=%08x\n",
           (uint32_t)vmr(VM_EXIT_REASON),
           (uint32_t)vmr(EXIT_QUALIFICATION));
    printk("IDTVectoring: info=%08x errcode=%08x\n",
           (uint32_t)vmr(IDT_VECTORING_INFO),
           (uint32_t)vmr(IDT_VECTORING_ERROR_CODE));
    printk("TPR Threshold = 0x%02x\n",
           (uint32_t)vmr(TPR_THRESHOLD));
    printk("EPT pointer = 0x%08x%08x\n",
           (uint32_t)vmr(EPT_POINTER_HIGH), (uint32_t)vmr(EPT_POINTER));
    printk("Virtual processor ID = 0x%04x\n",
           (uint32_t)vmr(VIRTUAL_PROCESSOR_ID));
    printk("VMEntry generation: %d\n", v->arch.hvm_vmx.vmentry_gen);

    vmx_vmcs_exit(v);
}

static void vmcs_dump(unsigned char ch)
{
    struct domain *d;
    struct vcpu *v;
    
    printk("*********** VMCS Areas **************\n");

    rcu_read_lock(&domlist_read_lock);

    for_each_domain ( d )
    {
        if ( !is_hvm_domain(d) )
            continue;
        printk("\n>>> vm%u <<<\n", d->domain_id);
        for_each_vcpu ( d, v )
        {
            printk("\tvm%u.%u\n", d->domain_id, v->vcpu_id);
            vmcs_dump_vcpu(v);
        }
    }

    rcu_read_unlock(&domlist_read_lock);

    printk("**************************************\n");
}

static struct keyhandler vmcs_dump_keyhandler = {
    .diagnostic = 1,
    .u.fn = vmcs_dump,
    .desc = "dump Intel's VMCS"
};

void setup_vmcs_dump(void)
{
    register_keyhandler('v', &vmcs_dump_keyhandler);
}

static unsigned long
__vmread_direct(unsigned long field)
{
    unsigned long ecx;

    asm volatile ( VMREAD_OPCODE
                   MODRM_EAX_ECX
                   /* CF==1 or ZF==1 --> crash (ud2) */
                   "ja 1f ; ud2 ; 1:\n"
                   : "=c" (ecx)
                   : "a" (field)
                   : "memory");

    return ecx;
}

static void
__vmwrite_direct(unsigned long field, unsigned long value)
{

    asm volatile ( VMWRITE_OPCODE
                   MODRM_EAX_ECX
                   /* CF==1 or ZF==1 --> crash (ud2) */
                   "ja 1f ; ud2 ; 1:\n"
                   :
                   : "a" (field) , "c" (value)
                   : "memory");
}

static unsigned long
__vmread_safe_direct(unsigned long field, int *error)
{
    unsigned long ecx;

    asm volatile ( VMREAD_OPCODE
                   MODRM_EAX_ECX
                   /* CF==1 or ZF==1 --> rc = -1 */
                   "setna %b0 ; neg %0"
                   : "=q" (*error), "=c" (ecx)
                   : "0" (0), "a" (field)
                   : "memory");

    return ecx;
}

static int 
__vmptrld_safe_direct(u64 addr)
{
    int error;

    asm volatile ( VMPTRLD_OPCODE
                   MODRM_EAX_06
                   /* CF==1 or ZF==1 --> rc = -1 */
                   "setna %b0 ; neg %0"
                   : "=q" (error)
                   : "0" (0), "a" (&addr)
                   : "memory");

    return error;
}

unsigned long (*__vmread_fn)(unsigned long field) = __vmread_direct;
void (*__vmwrite_fn)(unsigned long field, unsigned long value) =
    __vmwrite_direct;
unsigned long (*__vmread_safe_fn)(unsigned long field, int *error) =
    __vmread_safe_direct;
uint8_t vmx_vmcs_late_load = 0;

#ifdef PERF_VMRW
static int _pv_vmcs_get_offset_xen(u32 width, u32 type, u32 index);

unsigned long
__vmread(unsigned long field)
{
    union vmcs_encoding enc;
    int offset;

    enc.word = field;
    offset = _pv_vmcs_get_offset_xen(enc.width, enc.type, enc.index);
    perfc_incra(vmreads, offset);

    return __vmread_fn(field);
}

void
__vmwrite(unsigned long field, unsigned long value)
{
    union vmcs_encoding enc;
    int offset;

    enc.word = field;
    offset = _pv_vmcs_get_offset_xen(enc.width, enc.type, enc.index);
    perfc_incra(vmwrites, offset);

    __vmwrite_fn(field, value);
}

unsigned long
__vmread_safe(unsigned long field, int *error)
{
    union vmcs_encoding enc;
    int offset;

    enc.word = field;
    offset = _pv_vmcs_get_offset_xen(enc.width, enc.type, enc.index);
    perfc_incra(vmreads, offset);

    return __vmread_safe_fn(field, error);
}
#endif  /* PERF_VMRW */

/* also used to computer offset in _pv_vmcs_offset_table table */
static int _pv_vmcs_get_offset_xen(u32 width, u32 type, u32 index)
{
    int offset;

    offset = (index & 0x1f) | type << 5 | width << 7;

    if ( offset == 0 )    /* vpid */
        offset = 0x3f;

    return offset;
}

static always_inline unsigned long
_pv_vmcs_read_xen(unsigned long vmcs_encoding, u64 *content)
{
    union vmcs_encoding enc;
    int offset;
    u64 res;

    BUG_ON(!content);

    enc.word = vmcs_encoding;
    offset = _pv_vmcs_get_offset_xen(enc.width, enc.type, enc.index);
    res = content[offset];

    switch ( enc.width ) {
    case VVMCS_WIDTH_16:
        res &= 0xffff;
        break;
    case VVMCS_WIDTH_64:
        if ( enc.access_type )
            res >>= 32;
        break;
    case VVMCS_WIDTH_32:
        res &= 0xffffffff;
        break;
    case VVMCS_WIDTH_NATURAL:
    default:
        break;
    }

    return (unsigned long)res;
}

static unsigned long
pv_vmcs_read_xen(unsigned long vmcs_encoding)
{

    perfc_incr(pv_vmcs_read);

    return _pv_vmcs_read_xen(vmcs_encoding,
                             (u64 *)this_cpu(current_vmcs_vmx)->vmcs);
}

static void
_pv_vmcs_write_xen(unsigned long vmcs_encoding, unsigned long val, u64 *content)
{
    union vmcs_encoding enc;
    int offset;
    u64 res;

    BUG_ON(!content);

    enc.word = vmcs_encoding;
    offset = _pv_vmcs_get_offset_xen(enc.width, enc.type, enc.index);
    res = content[offset];

    switch ( enc.width ) {
    case VVMCS_WIDTH_16:
        res = val & 0xffff;
        break;
    case VVMCS_WIDTH_64:
        if ( enc.access_type )
        {
            res &= 0xffffffff;
            res |= (uint64_t)val << 32;
        }
        else
            res = val;
        break;
    case VVMCS_WIDTH_32:
        res = val & 0xffffffff;
        break;
    case VVMCS_WIDTH_NATURAL:
    default:
        res = val;
        break;
    }

    content[offset] = res;
}

static void
pv_vmcs_write_xen(unsigned long vmcs_encoding, unsigned long val)
{

    perfc_incr(pv_vmcs_write);

    _pv_vmcs_write_xen(vmcs_encoding, val,
                       (u64 *)this_cpu(current_vmcs_vmx)->vmcs);
}

static unsigned long
pv_vmcs_read_safe_xen(unsigned long vmcs_encoding, int *error)
{
    union vmcs_encoding enc;
    u64 *content = (u64 *)this_cpu(current_vmcs_vmx)->vmcs;
    int offset;
    u64 res;

    perfc_incr(pv_vmcs_read_safe);

    if (!content) {
        *error = -1;
        return -1;
    }

    enc.word = vmcs_encoding;
    offset = _pv_vmcs_get_offset_xen(enc.width, enc.type, enc.index);
    res = content[offset];

    switch ( enc.width ) {
    case VVMCS_WIDTH_16:
        res &= 0xffff;
        break;
    case VVMCS_WIDTH_64:
        if ( enc.access_type )
            res >>= 32;
        break;
    case VVMCS_WIDTH_32:
        res &= 0xffffffff;
        break;
    case VVMCS_WIDTH_NATURAL:
    default:
        break;
    }

    *error = 0;
    return (unsigned long)res;
}

#define PV_VMX_XEN_CPUID_LEAF_BASE 0x40000000
#define PV_VMX_XEN_CPUID_LEAF_RANGE 0x10000
#define PV_VMX_XEN_CPUID_LEAD_SKIP 0x100

static const enum vmcs_field all_vmcs_fields[] = {
    VIRTUAL_PROCESSOR_ID,
    GUEST_ES_SELECTOR,
    GUEST_CS_SELECTOR,
    GUEST_SS_SELECTOR,
    GUEST_DS_SELECTOR,
    GUEST_FS_SELECTOR,
    GUEST_GS_SELECTOR,
    GUEST_LDTR_SELECTOR,
    GUEST_TR_SELECTOR,
    HOST_ES_SELECTOR,
    HOST_CS_SELECTOR,
    HOST_SS_SELECTOR,
    HOST_DS_SELECTOR,
    HOST_FS_SELECTOR,
    HOST_GS_SELECTOR,
    HOST_TR_SELECTOR,
    IO_BITMAP_A,
    IO_BITMAP_A_HIGH,
    IO_BITMAP_B,
    IO_BITMAP_B_HIGH,
    MSR_BITMAP,
    MSR_BITMAP_HIGH,
    VM_EXIT_MSR_STORE_ADDR,
    VM_EXIT_MSR_STORE_ADDR_HIGH,
    VM_EXIT_MSR_LOAD_ADDR,
    VM_EXIT_MSR_LOAD_ADDR_HIGH,
    VM_ENTRY_MSR_LOAD_ADDR,
    VM_ENTRY_MSR_LOAD_ADDR_HIGH,
    TSC_OFFSET,
    TSC_OFFSET_HIGH,
    VIRTUAL_APIC_PAGE_ADDR,
    VIRTUAL_APIC_PAGE_ADDR_HIGH,
    APIC_ACCESS_ADDR,
    APIC_ACCESS_ADDR_HIGH,
    EPT_POINTER,
    EPT_POINTER_HIGH,
    GUEST_PHYSICAL_ADDRESS,
    GUEST_PHYSICAL_ADDRESS_HIGH,
    VMCS_LINK_POINTER,
    VMCS_LINK_POINTER_HIGH,
    GUEST_IA32_DEBUGCTL,
    GUEST_IA32_DEBUGCTL_HIGH,
    GUEST_PAT,
    GUEST_PAT_HIGH,
    GUEST_PDPTR0,
    GUEST_PDPTR0_HIGH,
    GUEST_PDPTR1,
    GUEST_PDPTR1_HIGH,
    GUEST_PDPTR2,
    GUEST_PDPTR2_HIGH,
    GUEST_PDPTR3,
    GUEST_PDPTR3_HIGH,
    HOST_PAT,
    HOST_PAT_HIGH,
    PIN_BASED_VM_EXEC_CONTROL,
    CPU_BASED_VM_EXEC_CONTROL,
    EXCEPTION_BITMAP,
    PAGE_FAULT_ERROR_CODE_MASK,
    PAGE_FAULT_ERROR_CODE_MATCH,
    CR3_TARGET_COUNT,
    VM_EXIT_CONTROLS,
    VM_EXIT_MSR_STORE_COUNT,
    VM_EXIT_MSR_LOAD_COUNT,
    VM_ENTRY_CONTROLS,
    VM_ENTRY_MSR_LOAD_COUNT,
    VM_ENTRY_INTR_INFO,
    VM_ENTRY_EXCEPTION_ERROR_CODE,
    VM_ENTRY_INSTRUCTION_LEN,
    TPR_THRESHOLD,
    SECONDARY_VM_EXEC_CONTROL,
    PLE_GAP,
    PLE_WINDOW,
    VM_INSTRUCTION_ERROR,
    VM_EXIT_REASON,
    VM_EXIT_INTR_INFO,
    VM_EXIT_INTR_ERROR_CODE,
    IDT_VECTORING_INFO,
    IDT_VECTORING_ERROR_CODE,
    VM_EXIT_INSTRUCTION_LEN,
    VMX_INSTRUCTION_INFO,
    GUEST_ES_LIMIT,
    GUEST_CS_LIMIT,
    GUEST_SS_LIMIT,
    GUEST_DS_LIMIT,
    GUEST_FS_LIMIT,
    GUEST_GS_LIMIT,
    GUEST_LDTR_LIMIT,
    GUEST_TR_LIMIT,
    GUEST_GDTR_LIMIT,
    GUEST_IDTR_LIMIT,
    GUEST_ES_AR_BYTES,
    GUEST_CS_AR_BYTES,
    GUEST_SS_AR_BYTES,
    GUEST_DS_AR_BYTES,
    GUEST_FS_AR_BYTES,
    GUEST_GS_AR_BYTES,
    GUEST_LDTR_AR_BYTES,
    GUEST_TR_AR_BYTES,
    GUEST_INTERRUPTIBILITY_INFO,
    GUEST_ACTIVITY_STATE,
    GUEST_SYSENTER_CS,
    HOST_SYSENTER_CS,
    CR0_GUEST_HOST_MASK,
    CR4_GUEST_HOST_MASK,
    CR0_READ_SHADOW,
    CR4_READ_SHADOW,
    CR3_TARGET_VALUE0,
    CR3_TARGET_VALUE1,
    CR3_TARGET_VALUE2,
    CR3_TARGET_VALUE3,
    EXIT_QUALIFICATION,
    GUEST_LINEAR_ADDRESS,
    GUEST_CR0,
    GUEST_CR3,
    GUEST_CR4,
    GUEST_ES_BASE,
    GUEST_CS_BASE,
    GUEST_SS_BASE,
    GUEST_DS_BASE,
    GUEST_FS_BASE,
    GUEST_GS_BASE,
    GUEST_LDTR_BASE,
    GUEST_TR_BASE,
    GUEST_GDTR_BASE,
    GUEST_IDTR_BASE,
    GUEST_DR7,
    GUEST_RSP,
    GUEST_RIP,
    GUEST_RFLAGS,
    GUEST_PENDING_DBG_EXCEPTIONS,
    GUEST_SYSENTER_ESP,
    GUEST_SYSENTER_EIP,
    HOST_CR0,
    HOST_CR3,
    HOST_CR4,
    HOST_FS_BASE,
    HOST_GS_BASE,
    HOST_TR_BASE,
    HOST_GDTR_BASE,
    HOST_IDTR_BASE,
    HOST_SYSENTER_ESP,
    HOST_SYSENTER_EIP,
    HOST_RSP,
    HOST_RIP,
    /* A virtual VMCS field used for nestedvmx only */
    /* NVMX_LAUNCH_STATE */
};

/* find offset of a given vmcs field */
static uint64_t
vmcs_scan_for_field(void *vmcs, uint64_t vmcs_ma, enum vmcs_field f,
                    uint16_t shoot_v, uint32_t flags, uint32_t *begin)
{
    int i;
    int error = 0;
    uint64_t off = 0;

#define NEXT_OFF(x) (x+2 < PAGE_SIZE ? x+2 : VMCS_FIRST_FIELD_OFFSET)

    /* Xen throws an exception on vmptrld if it can't map the various bitmaps */
    if (flags & VMCS_ITERATE_NO_XEN_MAPPINGS) {
        if (f == IO_BITMAP_A || f == IO_BITMAP_A_HIGH ||
            f == IO_BITMAP_B || f == IO_BITMAP_B_HIGH ||
            f == MSR_BITMAP  || f == MSR_BITMAP_HIGH)
            /* can't find its offset */
            return 0;
    }

    __vmpclear(vmcs_ma);
    /* zero whole vmcs minus hdr bits */
    memset(vmcs+VMCS_FIRST_FIELD_OFFSET, 0, PAGE_SIZE-VMCS_FIRST_FIELD_OFFSET);
    i = *begin;
    do {
        unsigned long v;

        /* shoot safe value & reload vmcs, assumes little endian */
        __vmpclear(vmcs_ma);
        *((uint16_t*)(vmcs+i)) = shoot_v;
        if (!__vmptrld_safe_direct(vmcs_ma)) {
            /* did we hit bullseye? */
            v = __vmread_safe_direct(f, &error);
            if (!error && v == shoot_v) {
                off = i;
                break;
            } else if (error) {
                printk("HVM/VMX: vmread of vmcs field %x failed!\n", f);
                off = 0;
                break;
            }
        } else {
            printk("HVM/VMX: vmptrld of *((uint16_t*)(vmcs+0x%x)) = 0x%x failed\n",
                   (unsigned)i, (unsigned)shoot_v);
        }
        /* restore 0 */
        *((uint16_t*)(vmcs+i)) = 0;

        i = NEXT_OFF(i);
    } while (i != *begin);

    __vmpclear(vmcs_ma);
    /* clear vmcs */
    memset(vmcs+VMCS_FIRST_FIELD_OFFSET, 0, PAGE_SIZE-VMCS_FIRST_FIELD_OFFSET);
    __vmptrld(vmcs_ma);
    __vmpclear(vmcs_ma);

    /* next time don't start from beginning */
    *begin = off ? NEXT_OFF(off) : VMCS_FIRST_FIELD_OFFSET;
    return off;
}

static int
vmcs_field_accessible(enum vmcs_field f)
{
    if (!cpu_has_vmx_ple &&
        (f == PLE_GAP || f == PLE_WINDOW))
        return 0;

    if (!cpu_has_vmx_pat &&
        (f == GUEST_PAT || f == GUEST_PAT_HIGH ||
         f == HOST_PAT  || f == HOST_PAT_HIGH))
        return 0;

    if (!cpu_has_vmx_virtualize_apic_accesses &&
        (f == APIC_ACCESS_ADDR || f == APIC_ACCESS_ADDR_HIGH))
        return 0;

    if (!cpu_has_vmx_tpr_shadow &&
        (f == TPR_THRESHOLD))
        return 0;

    return 1;
}

static int
vmcs_fields_iterate(int (*fn)(uint64_t, union vmcs_encoding, int), uint32_t flags)
{
    struct vmcs_struct *vmcs;
    uint64_t vmcs_ma;
    int i;
    int ret = 0;
    uint32_t offset_iter;

    vmcs = vmx_alloc_vmcs();
    if (!vmcs) {
        dprintk(XENLOG_ERR, "out of memory\n");
        ret = -ENOMEM;
        goto out;
    }
    vmcs_ma = virt_to_maddr(vmcs);

    /* start scanning vmcs at byte 8 to skip revision id (uint32_t) and
     * vmx abort indicator (uint32_t) */
    offset_iter = VMCS_FIRST_FIELD_OFFSET;
    for (i = 0; i < ARRAY_SIZE(all_vmcs_fields); i++) {
        union vmcs_encoding enc;
        int index;
        uint64_t offset;
        enum vmcs_field f = all_vmcs_fields[i];

        if (!vmcs_field_accessible(f))
            continue;
        offset = vmcs_scan_for_field(vmcs, vmcs_ma, f, 1, flags, &offset_iter);
        enc.word = f;
        index = _pv_vmcs_get_offset_xen(enc.width, enc.type, enc.index);
        ret = fn(offset, enc, index);
        if (ret)
            break;
    }
  out:
    if (vmcs)
        vmx_free_vmcs(vmcs);
    return ret;
}

static int
verify_pv_xen_vmcs_layout_fn(uint64_t v, union vmcs_encoding enc, int index)
{
    int ret = 0;


    /* Xen throws an exception on vmptrld if it can't map the various bitmaps */
    /* so we know these will deffinately be wrong */

    switch(enc.word) {
    case IO_BITMAP_A:
    case IO_BITMAP_A_HIGH:
    case IO_BITMAP_B:
    case IO_BITMAP_B_HIGH:
    case MSR_BITMAP:
    case MSR_BITMAP_HIGH:
        return ret;
    }

    if (index * 8 + enc.access_type * 4 != (v & 0xffff)) {
        dprintk(XENLOG_INFO, "%04x:%03x w:%x at:%x offset:%"PRIx64" mismatch\n",
                enc.word, index, enc.width, enc.access_type, v & 0xffff);
        ret = -EINVAL;
    }

    return ret;
}

static int
verify_pv_xen_vmcs_layout(void)
{
    return vmcs_fields_iterate(verify_pv_xen_vmcs_layout_fn, VMCS_ITERATE_NO_XEN_MAPPINGS);
}

static int
setup_pv_vmcs_access_xen(void)
{
    uint32_t eax, ebx, ecx, edx;
    uint32_t leaf;

    leaf = running_on_xen(&eax);
    if (leaf == (uint32_t)-1)
        return -1;

    cpuid(PV_VMX_XEN_CPUID_LEAF_BASE + leaf + 1, &eax,
          &ebx, &ecx, &edx);
    /* no version check since vmcs layout is verified below */
    /* if (eax != (4 << 16 | 3)) */
    /*     return -1; */

    if (verify_pv_xen_vmcs_layout())
        return -1;

    printk("HVM/VMX: Found Xen %d.%d, enabling nested pv optimisations\n",
           (eax >> 16) & 0xffff, eax & 0xffff);

    __vmread_fn = pv_vmcs_read_xen;
    __vmwrite_fn = pv_vmcs_write_xen;
    __vmread_safe_fn = pv_vmcs_read_safe_xen;

    return 0;
}

static uint16_t *_pv_vmcs_offset_table = NULL;

static int _pv_vmcs_get_offset_table(u32 width, u32 type, u32 index)
{
    int i;

    i = _pv_vmcs_get_offset_xen(width, type, index);
    return _pv_vmcs_offset_table[i];
}

static unsigned long
pv_vmcs_read_table(unsigned long vmcs_encoding)
{
    struct arch_vmx_struct *vmcs_vmx = this_cpu(current_vmcs_vmx);
    union vmcs_encoding enc;
    u8 *content;
    int offset;
    unsigned long res;

    perfc_incr(pv_vmcs_read);

    if (vmcs_vmx->loaded)
        return __vmread_direct(vmcs_encoding);

    content = (u8 *)vmcs_vmx->vmcs;
    BUG_ON(!content);

    if ((vmcs_encoding & ~1) == GUEST_PHYSICAL_ADDRESS) {
        unsigned long flags;
        cpu_irq_save(flags);
        __vmptrld(vmcs_vmx->vmcs_ma);
        vmcs_vmx->loaded = 1;
        res = __vmread_direct(vmcs_encoding);
        __vmpclear(vmcs_vmx->vmcs_ma);
        vmcs_vmx->loaded = 0;
        cpu_irq_restore(flags);
        return res;
    }

    enc.word = vmcs_encoding;
    offset = _pv_vmcs_get_offset_table(enc.width, enc.type, enc.index);
    ASSERT(offset);
    res = *(unsigned long *)(&content[offset]);

    switch ( enc.width ) {
    case VVMCS_WIDTH_16:
        res &= 0xffff;
        break;
    case VVMCS_WIDTH_64:
#ifdef __x86_64__
        if ( enc.access_type )
            res &= 0xffffffff;
#endif
        break;
    case VVMCS_WIDTH_32:
        res &= 0xffffffff;
        break;
    case VVMCS_WIDTH_NATURAL:
    default:
        break;
    }

    switch (vmcs_encoding) {
    case GUEST_RSP:
    /* case GUEST_RIP: */
    case GUEST_RFLAGS:
    case GUEST_CR3:
    case VM_ENTRY_CONTROLS:
        _pv_vmcs_write_xen(vmcs_encoding, res, vmcs_vmx->vmcs_shadow);
        break;
    }

    return res;
}

static void
pv_vmcs_write_table(unsigned long vmcs_encoding, unsigned long val)
{
    struct arch_vmx_struct *vmcs_vmx = this_cpu(current_vmcs_vmx);
    uint64_t *vmcs_shadow = vmcs_vmx->vmcs_shadow;
    union vmcs_encoding enc;
    u8 *content;
    int offset;

    perfc_incr(pv_vmcs_write);

    if (vmcs_vmx->loaded) {
        _pv_vmcs_write_xen(vmcs_encoding, val, vmcs_shadow);
        return __vmwrite_direct(vmcs_encoding, val);
    }

    switch (vmcs_encoding) {
    case VIRTUAL_PROCESSOR_ID:
    /* case GUEST_ES_SELECTOR: */
    /* case GUEST_CS_SELECTOR: */
    /* case GUEST_SS_SELECTOR: */
    /* case GUEST_DS_SELECTOR: */
    /* case GUEST_FS_SELECTOR: */
    /* case GUEST_GS_SELECTOR: */
    /* case GUEST_LDTR_SELECTOR: */
    /* case GUEST_TR_SELECTOR: */
    case HOST_ES_SELECTOR:
    case HOST_CS_SELECTOR:
    case HOST_SS_SELECTOR:
    case HOST_DS_SELECTOR:
    case HOST_FS_SELECTOR:
    case HOST_GS_SELECTOR:
    case HOST_TR_SELECTOR:
    /* case IO_BITMAP_A: */
    /* case IO_BITMAP_A_HIGH: */
    /* case IO_BITMAP_B: */
    /* case IO_BITMAP_B_HIGH: */
    /* case MSR_BITMAP: */
    /* case MSR_BITMAP_HIGH: */
    case VM_EXIT_MSR_STORE_ADDR:
    case VM_EXIT_MSR_STORE_ADDR_HIGH:
    case VM_EXIT_MSR_LOAD_ADDR:
    case VM_EXIT_MSR_LOAD_ADDR_HIGH:
    case VM_ENTRY_MSR_LOAD_ADDR:
    case VM_ENTRY_MSR_LOAD_ADDR_HIGH:
    /* case TSC_OFFSET: */
    /* case TSC_OFFSET_HIGH: */
    /* case VIRTUAL_APIC_PAGE_ADDR: */
    /* case VIRTUAL_APIC_PAGE_ADDR_HIGH: */
    case APIC_ACCESS_ADDR:
    case APIC_ACCESS_ADDR_HIGH:
    /* case EPT_POINTER: */
    /* case EPT_POINTER_HIGH: */
    case GUEST_PHYSICAL_ADDRESS:
    case GUEST_PHYSICAL_ADDRESS_HIGH:
    /* case VMCS_LINK_POINTER: */
    /* case VMCS_LINK_POINTER_HIGH: */
    /* case GUEST_IA32_DEBUGCTL: */
    /* case GUEST_IA32_DEBUGCTL_HIGH: */
    /* case GUEST_PAT: */
    /* case GUEST_PAT_HIGH: */
    /* case GUEST_PDPTR0: */
    /* case GUEST_PDPTR0_HIGH: */
    /* case GUEST_PDPTR1: */
    /* case GUEST_PDPTR1_HIGH: */
    /* case GUEST_PDPTR2: */
    /* case GUEST_PDPTR2_HIGH: */
    /* case GUEST_PDPTR3: */
    /* case GUEST_PDPTR3_HIGH: */
    case HOST_PAT:
    case HOST_PAT_HIGH:
    case PIN_BASED_VM_EXEC_CONTROL:
    case CPU_BASED_VM_EXEC_CONTROL:
    case EXCEPTION_BITMAP:
    /* /\* case PAGE_FAULT_ERROR_CODE_MASK: *\/ */
    /* /\* case PAGE_FAULT_ERROR_CODE_MATCH: *\/ */
    /* /\* case CR3_TARGET_COUNT: *\/ */
    case VM_EXIT_CONTROLS:
    case VM_EXIT_MSR_STORE_COUNT:
    case VM_EXIT_MSR_LOAD_COUNT:
    case VM_ENTRY_CONTROLS:
    case VM_ENTRY_MSR_LOAD_COUNT:
    /* /\* case VM_ENTRY_INTR_INFO: *\/ */
    /* /\* case VM_ENTRY_EXCEPTION_ERROR_CODE: *\/ */
    /* /\* case VM_ENTRY_INSTRUCTION_LEN: *\/ */
    case TPR_THRESHOLD:
    case SECONDARY_VM_EXEC_CONTROL:
    case PLE_GAP:
    case PLE_WINDOW:
    /* case VM_INSTRUCTION_ERROR: */
    /* case VM_EXIT_REASON: */
    /* case VM_EXIT_INTR_INFO: */
    /* case VM_EXIT_INTR_ERROR_CODE: */
    /* case IDT_VECTORING_INFO: */
    /* case IDT_VECTORING_ERROR_CODE: */
    /* case VM_EXIT_INSTRUCTION_LEN: */
    /* case VMX_INSTRUCTION_INFO: */
    /* case GUEST_ES_LIMIT: */
    /* case GUEST_CS_LIMIT: */
    /* case GUEST_SS_LIMIT: */
    /* case GUEST_DS_LIMIT: */
    /* case GUEST_FS_LIMIT: */
    /* case GUEST_GS_LIMIT: */
    /* case GUEST_LDTR_LIMIT: */
    /* case GUEST_TR_LIMIT: */
    /* case GUEST_GDTR_LIMIT: */
    /* case GUEST_IDTR_LIMIT: */
    /* case GUEST_ES_AR_BYTES: */
    /* case GUEST_CS_AR_BYTES: */
    /* case GUEST_SS_AR_BYTES: */
    /* case GUEST_DS_AR_BYTES: */
    /* case GUEST_FS_AR_BYTES: */
    /* case GUEST_GS_AR_BYTES: */
    /* case GUEST_LDTR_AR_BYTES: */
    /* case GUEST_TR_AR_BYTES: */
    /* case GUEST_INTERRUPTIBILITY_INFO: */
    /* case GUEST_ACTIVITY_STATE: */
    /* case GUEST_SYSENTER_CS: */
    case HOST_SYSENTER_CS:
    /* case CR0_GUEST_HOST_MASK: */
    /* case CR4_GUEST_HOST_MASK: */
    case CR0_READ_SHADOW:
    case CR4_READ_SHADOW:
    /* /\* case CR3_TARGET_VALUE0: *\/ */
    /* /\* case CR3_TARGET_VALUE1: *\/ */
    /* /\* case CR3_TARGET_VALUE2: *\/ */
    /* /\* case CR3_TARGET_VALUE3: *\/ */
    /* case EXIT_QUALIFICATION: */
    /* case GUEST_LINEAR_ADDRESS: */
    /* case GUEST_CR0: */
    case GUEST_CR3:
    /* case GUEST_CR4: */
    /* case GUEST_ES_BASE: */
    /* case GUEST_CS_BASE: */
    /* case GUEST_SS_BASE: */
    /* case GUEST_DS_BASE: */
    /* case GUEST_FS_BASE: */
    /* case GUEST_GS_BASE: */
    /* case GUEST_LDTR_BASE: */
    /* case GUEST_TR_BASE: */
    /* case GUEST_GDTR_BASE: */
    /* case GUEST_IDTR_BASE: */
    /* case GUEST_DR7: */
    case GUEST_RSP:
        /* case GUEST_RIP: */ /* XXX changes constantly */
    case GUEST_RFLAGS:
    /* case GUEST_PENDING_DBG_EXCEPTIONS: */
    /* case GUEST_SYSENTER_ESP: */
    /* case GUEST_SYSENTER_EIP: */
    case HOST_CR0:
    case HOST_CR3:
    case HOST_CR4:
    case HOST_FS_BASE:
    case HOST_GS_BASE:
    case HOST_TR_BASE:
    case HOST_GDTR_BASE:
    case HOST_IDTR_BASE:
    case HOST_SYSENTER_ESP:
    case HOST_SYSENTER_EIP:
    case HOST_RSP:
    case HOST_RIP:
        if (val == _pv_vmcs_read_xen(vmcs_encoding, vmcs_shadow)) {
            perfc_incr(pv_vmcs_idem_write);
            return;
        }
        _pv_vmcs_write_xen(vmcs_encoding, val, vmcs_shadow);
        perfc_incr(pv_vmcs_idem_write_miss);
        break;
#define W(f) case f: 
        W(IO_BITMAP_A);
        W(IO_BITMAP_A_HIGH);
        W(IO_BITMAP_B);
        W(IO_BITMAP_B_HIGH);
        W(MSR_BITMAP);
        W(MSR_BITMAP_HIGH);
        W(TSC_OFFSET);
        W(TSC_OFFSET_HIGH);
        W(VIRTUAL_APIC_PAGE_ADDR);
        W(VIRTUAL_APIC_PAGE_ADDR_HIGH);
        W(EPT_POINTER);
        W(EPT_POINTER_HIGH);
        W(VMCS_LINK_POINTER);
        W(VMCS_LINK_POINTER_HIGH);
        W(GUEST_PDPTR0);
        W(GUEST_PDPTR0_HIGH);
        W(GUEST_PDPTR1);
        W(GUEST_PDPTR1_HIGH);
        W(GUEST_PDPTR2);
        W(GUEST_PDPTR2_HIGH);
        W(GUEST_PDPTR3);
        W(GUEST_PDPTR3_HIGH);
#undef W
        _pv_vmcs_write_xen(vmcs_encoding, val, vmcs_shadow);
        break;
    default:
        break;
    }

    switch (vmcs_encoding) {
#define W(f) case f:                                          \
        vmcs_vmx->vmcs_dirty_bits |= VMCS_DIRTY_BIT(f);       \
        return
        W(IO_BITMAP_A);
        W(IO_BITMAP_A_HIGH);
        W(IO_BITMAP_B);
        W(IO_BITMAP_B_HIGH);
        W(MSR_BITMAP);
        W(MSR_BITMAP_HIGH);
        W(TSC_OFFSET);
        W(TSC_OFFSET_HIGH);
        W(VIRTUAL_APIC_PAGE_ADDR);
        W(VIRTUAL_APIC_PAGE_ADDR_HIGH);
        W(EPT_POINTER);
        W(EPT_POINTER_HIGH);
        W(VMCS_LINK_POINTER);
        W(VMCS_LINK_POINTER_HIGH);
        W(GUEST_PDPTR0);
        W(GUEST_PDPTR0_HIGH);
        W(GUEST_PDPTR1);
        W(GUEST_PDPTR1_HIGH);
        W(GUEST_PDPTR2);
        W(GUEST_PDPTR2_HIGH);
        W(GUEST_PDPTR3);
        W(GUEST_PDPTR3_HIGH);
#undef W
    }

    content = (u8 *)this_cpu(current_vmcs_vmx)->vmcs;
    BUG_ON(!content);

    enc.word = vmcs_encoding;
    offset = _pv_vmcs_get_offset_table(enc.width, enc.type, enc.index);
    ASSERT(offset);

    switch ( enc.width ) {
    case VVMCS_WIDTH_16:
        *(uint16_t *)(&content[offset]) = val & 0xffff;
        break;
    case VVMCS_WIDTH_64:
#ifdef __x86_64__
        if ( enc.access_type )
            *(uint32_t *)(&content[offset]) = val & 0xffffffff;
        else
            *(uint64_t *)(&content[offset]) = val;
#else
        *(uint32_t *)(&content[offset]) = val;
#endif
        break;
    case VVMCS_WIDTH_32:
        *(uint32_t *)(&content[offset]) = val;
        break;
    case VVMCS_WIDTH_NATURAL:
    default:
        *(unsigned long *)(&content[offset]) = val;
        break;
    }
}

static unsigned long
pv_vmcs_read_safe_table(unsigned long vmcs_encoding, int *error)
{
    struct arch_vmx_struct *vmcs_vmx = this_cpu(current_vmcs_vmx);
    union vmcs_encoding enc;
    u8 *content;
    int offset;
    unsigned long res;

    perfc_incr(pv_vmcs_read_safe);

    if (vmcs_vmx->loaded)
        return __vmread_safe_direct(vmcs_encoding, error);

    content = (u8 *)vmcs_vmx->vmcs;
    if (!content) {
        *error = -1;
        return -1;
    }

    if ((vmcs_encoding & ~1) == GUEST_PHYSICAL_ADDRESS) {
        unsigned long flags;
        cpu_irq_save(flags);
        __vmptrld(vmcs_vmx->vmcs_ma);
        vmcs_vmx->loaded = 1;
        res = __vmread_safe_direct(vmcs_encoding, error);
        __vmpclear(vmcs_vmx->vmcs_ma);
        vmcs_vmx->loaded = 0;
        cpu_irq_restore(flags);
        return res;
    }

    enc.word = vmcs_encoding;
    offset = _pv_vmcs_get_offset_table(enc.width, enc.type, enc.index);
    ASSERT(offset);
    res = *(unsigned long *)(&content[offset]);

    switch ( enc.width ) {
    case VVMCS_WIDTH_16:
        res &= 0xffff;
        break;
    case VVMCS_WIDTH_64:
#ifdef __x86_64__
        if ( enc.access_type )
            res &= 0xffffffff;
#endif
        break;
    case VVMCS_WIDTH_32:
        res &= 0xffffffff;
        break;
    case VVMCS_WIDTH_NATURAL:
    default:
        break;
    }

    switch (vmcs_encoding) {
    case GUEST_RSP:
    /* case GUEST_RIP: */
    case GUEST_RFLAGS:
    case GUEST_CR3:
    case VM_ENTRY_CONTROLS:
        _pv_vmcs_write_xen(vmcs_encoding, res, vmcs_vmx->vmcs_shadow);
        break;
    }

    *error = 0;
    return res;
}

void
pv_vmcs_flush_dirty(struct arch_vmx_struct *vmcs_vmx, int unload)
{
    uint64_t *vmcs_shadow;

    if (!vmcs_vmx)
        return;

    if (unload && !vmcs_vmx->vmcs_dirty_bits)
        goto out;

    if (!vmcs_vmx->loaded) {
        __vmptrld(vmcs_vmx->vmcs_ma);
        vmcs_vmx->loaded = 1;
    }

    if (!vmcs_vmx->vmcs_dirty_bits)
        goto out;

    vmcs_shadow = vmcs_vmx->vmcs_shadow;

#define CHECK2(db, A, B) do {                                       \
        if (!((db) & (VMCS_DIRTY_BIT(A) | VMCS_DIRTY_BIT(B))))      \
            break;                                                  \
        if ((db) & VMCS_DIRTY_BIT(A))                               \
            __vmwrite_direct(A, _pv_vmcs_read_xen(A, vmcs_shadow)); \
        if ((db) & VMCS_DIRTY_BIT(B))                               \
            __vmwrite_direct(B, _pv_vmcs_read_xen(B, vmcs_shadow)); \
    } while (0)
#define CHECK4(db, A, B, C, D) do {                                 \
        if (!((db) & (VMCS_DIRTY_BIT(A) | VMCS_DIRTY_BIT(B) |       \
                      VMCS_DIRTY_BIT(C) | VMCS_DIRTY_BIT(D))))      \
            break;                                                  \
        if ((db) & VMCS_DIRTY_BIT(A))                               \
            __vmwrite_direct(A, _pv_vmcs_read_xen(A, vmcs_shadow)); \
        if ((db) & VMCS_DIRTY_BIT(B))                               \
            __vmwrite_direct(B, _pv_vmcs_read_xen(B, vmcs_shadow)); \
        if ((db) & VMCS_DIRTY_BIT(C))                               \
            __vmwrite_direct(C, _pv_vmcs_read_xen(C, vmcs_shadow)); \
        if ((db) & VMCS_DIRTY_BIT(D))                               \
            __vmwrite_direct(D, _pv_vmcs_read_xen(D, vmcs_shadow)); \
    } while (0)
    CHECK4(vmcs_vmx->vmcs_dirty_bits,
           IO_BITMAP_A, IO_BITMAP_A_HIGH,
           IO_BITMAP_B, IO_BITMAP_B_HIGH);
    CHECK4(vmcs_vmx->vmcs_dirty_bits,
           MSR_BITMAP, MSR_BITMAP_HIGH,
           TSC_OFFSET, TSC_OFFSET_HIGH);
    CHECK4(vmcs_vmx->vmcs_dirty_bits,
           VIRTUAL_APIC_PAGE_ADDR, VIRTUAL_APIC_PAGE_ADDR_HIGH,
           EPT_POINTER, EPT_POINTER_HIGH);
    CHECK2(vmcs_vmx->vmcs_dirty_bits,
           VMCS_LINK_POINTER, VMCS_LINK_POINTER_HIGH);
    CHECK4(vmcs_vmx->vmcs_dirty_bits,
           GUEST_PDPTR0, GUEST_PDPTR0_HIGH,
           GUEST_PDPTR1, GUEST_PDPTR1_HIGH);
    CHECK4(vmcs_vmx->vmcs_dirty_bits,
           GUEST_PDPTR2, GUEST_PDPTR2_HIGH,
           GUEST_PDPTR3, GUEST_PDPTR3_HIGH);
#undef CHECK2
#undef CHECK4
    vmcs_vmx->vmcs_dirty_bits = 0;

  out:
    if (unload && vmcs_vmx->loaded) {
        __vmpclear(vmcs_vmx->vmcs_ma);
        vmcs_vmx->loaded = 0;
    }
}

static int num_failed_offsets = 0;

static int
fill_vmcs_offsets_table_fn(uint64_t v, union vmcs_encoding enc, int index)
{
    if (v) {
        _pv_vmcs_offset_table[index] = v & 0xffff;
        dprintk(XENLOG_DEBUG, "%04x:%03x w:%x at:%x offset:%"PRIx64"\n",
                enc.word, index, enc.width, enc.access_type, v & 0xffff);
        return 0;
    } else {
        printk("failed to find offset of vmcs field %04x:%03x w:%x at:%x\n",
               enc.word, index, enc.width, enc.access_type);
        num_failed_offsets++;
        return 0;
    }
}

static int
fill_vmcs_offsets_table(void)
{
    int i;
    int ret = 0;
    union vmcs_encoding enc;
    int index, max_index = 0;

    dprintk(XENLOG_INFO, "%s: nr vmcs fields %"PRId64"\n", __FUNCTION__,
            ARRAY_SIZE(all_vmcs_fields));

    for (i = 0; i < ARRAY_SIZE(all_vmcs_fields); i++) {
        enc.word = all_vmcs_fields[i];
        index = _pv_vmcs_get_offset_xen(enc.width, enc.type, enc.index);
        if (index > max_index)
            max_index = index;
    }
    dprintk(XENLOG_INFO, "max table index %x\n", max_index);

    _pv_vmcs_offset_table = xzalloc_array(uint16_t, max_index + 1);
    if (!_pv_vmcs_offset_table) {
        dprintk(XENLOG_ERR, "out of memory\n");
        return -ENOMEM;
    }

    ret = vmcs_fields_iterate(fill_vmcs_offsets_table_fn, 0);

    if (ret && _pv_vmcs_offset_table) {
        xfree(_pv_vmcs_offset_table);
        _pv_vmcs_offset_table = NULL;
    }
    return ret;
}

static int
setup_pv_vmcs_access_vmware(void)
{
    uint32_t eax = 0;
    char signature[13];

    cpuid(0x40000000, &eax,
          (uint32_t *)&signature[0], (uint32_t *)&signature[4],
          (uint32_t *)&signature[8]);
    signature[12] = 0;

    if (strcmp(signature, "VMwareVMware"))
        return -1;

    if (fill_vmcs_offsets_table()) {
        printk("HVM/VMX: Found VMware, but failed scan for vmcs offsets - "
               "not enabling pv nested optimizations\n");
        return -1;
    }

    printk("HVM/VMX: Found VMware, enabling pv nested optimisations\n");

    __vmread_fn = pv_vmcs_read_table;
    __vmwrite_fn = pv_vmcs_write_table;
    __vmread_safe_fn = pv_vmcs_read_safe_table;
    vmx_vmcs_late_load = 1;

    return 0;
}

void
setup_pv_vmcs_access(void)
{
    int ret;

    if (ax_has_pv_vmcs && ax_pv_vmcs_setup()) {
        __vmread_fn = ax_pv_vmcs_read;
        __vmwrite_fn = ax_pv_vmcs_write;
        __vmread_safe_fn = ax_pv_vmcs_read_safe;

        vmx_vmcs_late_load = 0;
	return;
    }

    if (!boot_cpu_has(X86_FEATURE_HYPERVISOR))
        return;

    num_failed_offsets = 0;
    ret = setup_pv_vmcs_access_xen();
    if (ret)
        ret = setup_pv_vmcs_access_vmware();
    if (num_failed_offsets) {
        printk("HVM/VMX: failed to find %d vmcs offsets "
               "(secondary exec ctrl=%08x)\n",
               num_failed_offsets, vmx_secondary_exec_control);
        BUG_ON(1);
    }
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
