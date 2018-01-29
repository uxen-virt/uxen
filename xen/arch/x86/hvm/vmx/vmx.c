/*
 * vmx.c: handling VMX architecture-related VM exits
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
#include <xen/lib.h>
#include <xen/trace.h>
#include <xen/sched.h>
#include <xen/irq.h>
#include <xen/softirq.h>
#include <xen/domain_page.h>
#include <xen/hypercall.h>
#include <xen/perfc.h>
#include <asm/current.h>
#include <asm/io.h>
#include <asm/regs.h>
#include <asm/cpufeature.h>
#include <asm/processor.h>
#include <asm/types.h>
#include <asm/debugreg.h>
#include <asm/msr.h>
#include <asm/spinlock.h>
#include <asm/paging.h>
#include <asm/p2m.h>
#ifndef __UXEN__
#include <asm/mem_sharing.h>
#endif  /* __UXEN__ */
#include <asm/hvm/emulate.h>
#include <asm/hvm/hvm.h>
#include <asm/hvm/support.h>
#include <asm/hvm/vmx/vmx.h>
#include <asm/hvm/vmx/vmcs.h>
#include <asm/hvm/ax.h>
#include <public/sched.h>
#include <public/hvm/ioreq.h>
#include <asm/hvm/vpic.h>
#include <asm/hvm/vlapic.h>
#include <asm/x86_emulate.h>
#include <asm/hvm/vpt.h>
#include <public/hvm/save.h>
#include <asm/hvm/trace.h>
#include <asm/xenoprof.h>
#include <asm/debugger.h>
#include <asm/apic.h>
#ifndef __UXEN_NOT_YET__
#include <asm/hvm/nestedhvm.h>
#endif  /* __UXEN_NOT_YET__ */
#include <asm/xstate.h>
#include <asm/hvm/xen_pv.h>
#include <asm/poke.h>

enum handler_return { HNDL_done, HNDL_unhandled, HNDL_exception_raised };

static DEFINE_PER_CPU(unsigned long, host_msr_tsc_aux);
static unsigned long __read_mostly host_msr_spec_ctrl;
static bool_t __read_mostly update_host_vm_ibrs;
static DEFINE_SPINLOCK(ept_sync_lock);

static void vmx_ctxt_switch_from(struct vcpu *v);
static void vmx_ctxt_switch_to(struct vcpu *v);

static int  vmx_alloc_vlapic_mapping(struct domain *d);
static void vmx_free_vlapic_mapping(struct domain *d);
static void vmx_install_vlapic_mapping(struct vcpu *v);
static int vmx_update_guest_cr(struct vcpu *v, unsigned int cr);
static void vmx_update_guest_efer(struct vcpu *v);
static void vmx_cpuid_intercept(
    unsigned int *eax, unsigned int *ebx,
    unsigned int *ecx, unsigned int *edx);
static void vmx_wbinvd_intercept(void);
static void vmx_fpu_dirty_intercept(void);
static int vmx_msr_read_intercept(unsigned int msr, uint64_t *msr_content);
static int vmx_msr_write_intercept(unsigned int msr, uint64_t msr_content);
static void vmx_invlpg_intercept(unsigned long vaddr);
static inline void ept_maybe_sync_cpu(struct domain *d);

static void setup_pv_vmx(void);

static void vmx_execute(struct vcpu *v);

static void vmx_do_suspend(struct vcpu *v);

static int vmx_domain_initialise(struct domain *d)
{
    int rc;

    /* Set the memory type used when accessing EPT paging structures. */
    d->arch.hvm_domain.vmx.ept_control.ept_mt = EPT_DEFAULT_MT;

    /* set EPT page-walk length, now it's actual walk length - 1, i.e. 3 */
    d->arch.hvm_domain.vmx.ept_control.ept_wl = 3;

    d->arch.hvm_domain.vmx.ept_control.asr  =
        pagetable_get_pfn(p2m_get_pagetable(p2m_get_hostp2m(d)));

    if ( !zalloc_cpumask_var(&d->arch.hvm_domain.vmx.ept_synced) )
        return -ENOMEM;

    if ( !zalloc_cpumask_var(&d->arch.hvm_domain.vmx.ept_in_use) ) {
        free_cpumask_var(d->arch.hvm_domain.vmx.ept_synced);
        return -ENOMEM;
    }

    if ( (rc = vmx_alloc_vlapic_mapping(d)) != 0 )
    {
        free_cpumask_var(d->arch.hvm_domain.vmx.ept_in_use);
        free_cpumask_var(d->arch.hvm_domain.vmx.ept_synced);
        return rc;
    }

    return 0;
}

static void vmx_domain_destroy(struct domain *d)
{
#if 0
    /*
     * This is unnecessary, as no domain can execute, and any new domain
     * reusing the VPID/EPT BASE will flish first
     */
    if ( paging_mode_hap(d) )
        on_each_cpu(__ept_sync_domain, d, 1);
#endif

    free_cpumask_var(d->arch.hvm_domain.vmx.ept_in_use);
    free_cpumask_var(d->arch.hvm_domain.vmx.ept_synced);
    vmx_free_vlapic_mapping(d);
}

static void
vmx_domain_relinquish_memory(struct domain *d)
{

    if (d->arch.hvm_domain.vmx.apic_access_va)
        put_page(virt_to_page(d->arch.hvm_domain.vmx.apic_access_va));
}

static int vmx_vcpu_initialise(struct vcpu *v)
{
    int rc;

    spin_lock_init(&v->arch.hvm_vmx.vmcs_lock);

#ifdef __x86_64__
    /* Always save/restore shadow gs. */
    set_bit(VMX_INDEX_MSR_SHADOW_GS_BASE, &v->arch.hvm_vmx.msr_state.flags);
#endif

    v->arch.schedule_tail    = vmx_do_resume;
    v->arch.ctxt_switch_from = vmx_ctxt_switch_from;
    v->arch.ctxt_switch_to   = vmx_ctxt_switch_to;

    if ( (rc = vmx_create_vmcs(v)) != 0 )
    {
        dprintk(XENLOG_WARNING,
                "Failed to create VMCS for vcpu vm%u.%u: err=%d.\n",
                v->domain->domain_id, v->vcpu_id, rc);
        return rc;
    }

#ifndef __UXEN_NOT_YET__
    vpmu_initialise(v);
#endif  /* __UXEN_NOT_YET__ */

    vmx_install_vlapic_mapping(v);

    /* %eax == 1 signals full real-mode support to the guest loader. */
    if ( v->vcpu_id == 0 )
        v->arch.user_regs.eax = 1;

    return 0;
}

static void vmx_vcpu_destroy(struct vcpu *v)
{
    vmx_destroy_vmcs(v);
#ifndef __UXEN_NOT_YET__
    vpmu_destroy(v);
#endif  /* __UXEN_NOT_YET__ */
#ifndef __UXEN__
    passive_domain_destroy(v);
#endif  /* __UXEN__ */
}

#ifdef __x86_64__

static DEFINE_PER_CPU(struct vmx_msr_state, host_msr_state);

static u32 msr_index[] =
{
    MSR_LSTAR, MSR_STAR, MSR_SYSCALL_MASK, MSR_SHADOW_GS_BASE
};

#ifndef __UXEN__
#define WRITE_MSR(address)                                              \
        guest_msr_state->msrs[VMX_INDEX_MSR_ ## address] = msr_content; \
        set_bit(VMX_INDEX_MSR_ ## address, &guest_msr_state->flags);    \
        wrmsrl(MSR_ ## address, msr_content);                           \
        set_bit(VMX_INDEX_MSR_ ## address, &host_msr_state->flags);     \
        break
#else   /* __UXEN__ */
#define WRITE_MSR(address)                                                  \
        guest_msr_state->msrs[VMX_INDEX_MSR_ ## address] = msr_content;     \
        if (!ax_present) {                                                  \
            if (!test_and_set_bit(VMX_INDEX_MSR_ ## address,                \
                                  &guest_msr_state->flags)) {               \
                ASSERT(!test_bit(VMX_INDEX_MSR_ ## address,                 \
                                 &host_msr_state->flags));                  \
                rdmsrl(MSR_ ## address,                                     \
                       host_msr_state->msrs[VMX_INDEX_MSR_ ## address]);    \
                set_bit(VMX_INDEX_MSR_ ## address, &host_msr_state->flags); \
                if (host_msr_state->msrs[VMX_INDEX_MSR_ ## address] ==      \
                    msr_content)                                            \
                    break;                                                  \
            }                                                               \
        } else                                                              \
            set_bit(VMX_INDEX_MSR_ ## address, &guest_msr_state->flags);    \
        pv_wrmsrl(MSR_ ## address, msr_content, v);                         \
        break
#endif  /* __UXEN__ */

static enum handler_return
long_mode_do_msr_read(unsigned int msr, uint64_t *msr_content)
{
    struct vcpu *v = current;
    struct vmx_msr_state *guest_msr_state = &v->arch.hvm_vmx.msr_state;

    switch ( msr )
    {
    case MSR_FS_BASE:
        *msr_content = __vmread(GUEST_FS_BASE);
        break;

    case MSR_GS_BASE:
        *msr_content = __vmread(GUEST_GS_BASE);
        break;

    case MSR_SHADOW_GS_BASE:
        if (!ax_present)
            rdmsrl(MSR_SHADOW_GS_BASE, *msr_content);
        break;

    case MSR_STAR:
        *msr_content = guest_msr_state->msrs[VMX_INDEX_MSR_STAR];
        break;

    case MSR_LSTAR:
        *msr_content = guest_msr_state->msrs[VMX_INDEX_MSR_LSTAR];
        break;

    case MSR_CSTAR:
        *msr_content = v->arch.hvm_vmx.cstar;
        break;

    case MSR_SYSCALL_MASK:
        *msr_content = guest_msr_state->msrs[VMX_INDEX_MSR_SYSCALL_MASK];
        break;

    case MSR_CORE_THREAD_COUNT:
        rdmsrl(MSR_CORE_THREAD_COUNT, *msr_content);
        /* XXX MSR_CORE_THREAD_COUNT correct for NEHALEM and newer */
        if ((*msr_content >> 16 & 0xffff) > v->domain->max_vcpus) {
            uint16_t threads = v->domain->max_vcpus;
            uint16_t cores = *msr_content & 0xffff;
            if (cores > threads)
                cores = threads;
            *msr_content = (threads << 16) | cores;
        }
        break;

    default:
        return HNDL_unhandled;
    }

    HVM_DBG_LOG(DBG_LEVEL_0, "msr 0x%x content 0x%"PRIx64, msr, *msr_content);

    return HNDL_done;
}

static enum handler_return
long_mode_do_msr_write(unsigned int msr, uint64_t msr_content)
{
    struct vcpu *v = current;
    struct vmx_msr_state *guest_msr_state = &v->arch.hvm_vmx.msr_state;
    struct vmx_msr_state *host_msr_state = &this_cpu(host_msr_state);

    HVM_DBG_LOG(DBG_LEVEL_0, "msr 0x%x content 0x%"PRIx64, msr, msr_content);

    switch ( msr )
    {
    case MSR_FS_BASE:
    case MSR_GS_BASE:
    case MSR_SHADOW_GS_BASE:
        if ( !is_canonical_address(msr_content) )
            goto uncanonical_address;

        if ( msr == MSR_FS_BASE )
            __vmwrite(GUEST_FS_BASE, msr_content);
        else if ( msr == MSR_GS_BASE )
            __vmwrite(GUEST_GS_BASE, msr_content);
        else
            pv_wrmsrl(MSR_SHADOW_GS_BASE, msr_content, v);

        break;

    case MSR_STAR:
        WRITE_MSR(STAR);

    case MSR_LSTAR:
        if ( !is_canonical_address(msr_content) )
            goto uncanonical_address;
        WRITE_MSR(LSTAR);

    case MSR_CSTAR:
        if ( !is_canonical_address(msr_content) )
            goto uncanonical_address;
        v->arch.hvm_vmx.cstar = msr_content;
        break;

    case MSR_SYSCALL_MASK:
        WRITE_MSR(SYSCALL_MASK);

    default:
        return HNDL_unhandled;
    }

    return HNDL_done;

 uncanonical_address:
    HVM_DBG_LOG(DBG_LEVEL_0, "Not cano address of msr write %x", msr);
    vmx_inject_hw_exception(TRAP_gp_fault, 0);
    return HNDL_exception_raised;
}

/*
 * To avoid MSR save/restore at every VM exit/entry time, we restore
 * the x86_64 specific MSRs at domain switch time. Since these MSRs
 * are not modified once set for para domains, we don't save them,
 * but simply reset them to values set in percpu_traps_init().
 */
static void vmx_restore_host_msrs(struct vcpu *v)
{
    struct vmx_msr_state *host_msr_state = &this_cpu(host_msr_state);
    struct vmx_msr_state *guest_msr_state = &v->arch.hvm_vmx.msr_state;
    int i;

    /*
     * We cannot cache SHADOW_GS_BASE while the VCPU runs, as it can
     * be updated at any time via SWAPGS, which we cannot trap.
     */
    pv_rdmsrl(MSR_SHADOW_GS_BASE,
              guest_msr_state->msrs[VMX_INDEX_MSR_SHADOW_GS_BASE],
              v);

    while ( host_msr_state->flags )
    {
        i = find_first_set_bit(host_msr_state->flags);
        if (host_msr_state->msrs[i] != guest_msr_state->msrs[i])
            if (wrmsr_safe(msr_index[i], host_msr_state->msrs[i]))
                wrmsrl(msr_index[i],0);
        clear_bit(i, &host_msr_state->flags);
    }
}

static void vmx_restore_guest_msrs(struct vcpu *v)
{
    struct vmx_msr_state *guest_msr_state, *host_msr_state;
    unsigned long guest_flags;
    int i;

    guest_msr_state = &v->arch.hvm_vmx.msr_state;
    host_msr_state = &this_cpu(host_msr_state);

    guest_flags = guest_msr_state->flags;

    while ( guest_flags )
    {
        i = find_first_set_bit(guest_flags);

        if (!ax_present) {
            rdmsrl(msr_index[i], host_msr_state->msrs[i]);
            set_bit(i, &host_msr_state->flags);
            if (host_msr_state->msrs[i] != guest_msr_state->msrs[i]) {
                HVM_DBG_LOG(DBG_LEVEL_2,
                            "restore guest's index %d msr %x with value %lx",
                            i, msr_index[i], guest_msr_state->msrs[i]);
                if (wrmsr_safe(msr_index[i], guest_msr_state->msrs[i]))
                    wrmsrl(msr_index[i], 0);
            }
        } else
            ax_vmcs_x_wrmsrl(v, msr_index[i], guest_msr_state->msrs[i]);
        clear_bit(i, &guest_flags);
    }

#ifndef __UXEN__
    if ( (v->arch.hvm_vcpu.guest_efer ^ read_efer()) & EFER_SCE )
    {
        HVM_DBG_LOG(DBG_LEVEL_2,
                    "restore guest's EFER with value %lx",
                    v->arch.hvm_vcpu.guest_efer);
        write_efer((read_efer() & ~EFER_SCE) |
                   (v->arch.hvm_vcpu.guest_efer & EFER_SCE));
    }
#endif  /* __UXEN__ */
}

#else  /* __i386__ */

void vmx_save_host_msrs(void) {}
#define vmx_restore_host_msrs(v)    ((void)0)

#define vmx_restore_guest_msrs(v)   ((void)0)

static enum handler_return
long_mode_do_msr_read(unsigned int msr, uint64_t *msr_content)
{
    return HNDL_unhandled;
}

static enum handler_return
long_mode_do_msr_write(unsigned int msr, uint64_t msr_content)
{
    return HNDL_unhandled;
}

#endif /* __i386__ */

void vmx_update_cpu_exec_control(struct vcpu *v)
{
#ifndef __UXEN_NOT_YET__
    if ( nestedhvm_vcpu_in_guestmode(v) )
        nvmx_update_exec_control(v, v->arch.hvm_vmx.exec_control);
    else
#endif  /* __UXEN_NOT_YET__ */
        __vmwrite(CPU_BASED_VM_EXEC_CONTROL, v->arch.hvm_vmx.exec_control);
}

static void vmx_update_secondary_exec_control(struct vcpu *v)
{
#ifndef __UXEN_NOT_YET__
    if ( nestedhvm_vcpu_in_guestmode(v) )
        nvmx_update_secondary_exec_control(v,
            v->arch.hvm_vmx.secondary_exec_control);
    else
#endif  /* __UXEN_NOT_YET__ */
        __vmwrite(SECONDARY_VM_EXEC_CONTROL,
                  v->arch.hvm_vmx.secondary_exec_control);
}

void vmx_update_exception_bitmap(struct vcpu *v)
{
    /* In FEATURE_SMEP case, we have set pfec_mask and pfec_match be
     * be P|ID.  Now, set the PF bit in the bitmap, so that vmexit
     * happens only in the above pfec case, meaning DEP or SMEP
     * violation. */
    uint32_t forced_pf = 0;

    if (v->domain->introspection_features &
        XEN_DOMCTL_INTROSPECTION_FEATURE_SMEP) {
        forced_pf = (1U << TRAP_page_fault);
        __vmwrite(PAGE_FAULT_ERROR_CODE_MASK,
            PFEC_page_present | PFEC_insn_fetch);
        __vmwrite(PAGE_FAULT_ERROR_CODE_MATCH,
            PFEC_page_present | PFEC_insn_fetch);
    }

#ifndef __UXEN_NOT_YET__
    if ( nestedhvm_vcpu_in_guestmode(v) )
        nvmx_update_exception_bitmap(v, v->arch.hvm_vmx.exception_bitmap);
    else
#endif  /* __UXEN_NOT_YET__ */
        __vmwrite(EXCEPTION_BITMAP, v->arch.hvm_vmx.exception_bitmap |
                  forced_pf);
}

static int vmx_guest_x86_mode(struct vcpu *v)
{
    unsigned int cs_ar_bytes;

    if ( unlikely(!(v->arch.hvm_vcpu.guest_cr[0] & X86_CR0_PE)) )
        return 0;
    if ( unlikely(guest_cpu_user_regs()->eflags & X86_EFLAGS_VM) )
        return 1;
    cs_ar_bytes = __vmread(GUEST_CS_AR_BYTES);
    if ( hvm_long_mode_enabled(v) &&
         likely(cs_ar_bytes & X86_SEG_AR_CS_LM_ACTIVE) )
        return 8;
    return (likely(cs_ar_bytes & X86_SEG_AR_DEF_OP_SIZE) ? 4 : 2);
}

#ifndef __UXEN__
static void vmx_save_dr(struct vcpu *v)
{
DEBUG();
    if ( !v->arch.hvm_vcpu.flag_dr_dirty )
        return;

    /* Clear the DR dirty flag and re-enable intercepts for DR accesses. */
    v->arch.hvm_vcpu.flag_dr_dirty = 0;
    v->arch.hvm_vmx.exec_control |= CPU_BASED_MOV_DR_EXITING;
    vmx_update_cpu_exec_control(v);

    v->arch.debugreg[0] = read_debugreg(0);
    v->arch.debugreg[1] = read_debugreg(1);
    v->arch.debugreg[2] = read_debugreg(2);
    v->arch.debugreg[3] = read_debugreg(3);
    v->arch.debugreg[6] = read_debugreg(6);
    /* DR7 must be saved as it is used by vmx_restore_dr(). */
    v->arch.debugreg[7] = __vmread(GUEST_DR7);
}
#endif  /* __UXEN__ */

static void __restore_debug_registers(struct vcpu *v)
{
    if ( v->arch.hvm_vcpu.flag_dr_dirty )
        return;

    v->arch.hvm_vcpu.flag_dr_dirty = 1;

    write_debugreg(0, v->arch.debugreg[0]);
    write_debugreg(1, v->arch.debugreg[1]);
    write_debugreg(2, v->arch.debugreg[2]);
    write_debugreg(3, v->arch.debugreg[3]);
    write_debugreg(6, v->arch.debugreg[6]);
    /* DR7 is loaded from the VMCS. */
}

#ifndef __UXEN__
/*
 * DR7 is saved and restored on every vmexit.  Other debug registers only
 * need to be restored if their value is going to affect execution -- i.e.,
 * if one of the breakpoints is enabled.  So mask out all bits that don't
 * enable some breakpoint functionality.
 */
static void vmx_restore_dr(struct vcpu *v)
{
    /* NB. __vmread() is not usable here, so we cannot read from the VMCS. */
DEBUG();
    if ( unlikely(v->arch.debugreg[7] & DR7_ACTIVE_MASK) )
        __restore_debug_registers(v);
}
#endif  /* __UXEN__ */

static void vmx_vmcs_save(struct vcpu *v, struct hvm_hw_cpu *c)
{
    uint32_t ev;

    vmx_vmcs_enter(v);

    c->cr0 = v->arch.hvm_vcpu.guest_cr[0];
    c->cr2 = v->arch.hvm_vcpu.guest_cr[2];
    c->cr3 = v->arch.hvm_vcpu.guest_cr[3];
    c->cr4 = v->arch.hvm_vcpu.guest_cr[4];

    c->msr_efer = v->arch.hvm_vcpu.guest_efer;

    c->sysenter_cs = __vmread(GUEST_SYSENTER_CS);
    c->sysenter_esp = __vmread(GUEST_SYSENTER_ESP);
    c->sysenter_eip = __vmread(GUEST_SYSENTER_EIP);

    c->pending_event = 0;
    c->error_code = 0;
    if ( ((ev = __vmread(VM_ENTRY_INTR_INFO)) & INTR_INFO_VALID_MASK) &&
         hvm_event_needs_reinjection((ev >> 8) & 7, ev & 0xff) )
    {
        c->pending_event = ev;
        c->error_code = __vmread(VM_ENTRY_EXCEPTION_ERROR_CODE);
    }

    vmx_vmcs_exit(v);
}

static int vmx_restore_cr0_cr3(
    struct vcpu *v, unsigned long cr0, unsigned long cr3)
{
#ifndef __UXEN__
    unsigned long mfn = 0;
    p2m_type_t p2mt;

    if ( paging_mode_shadow(v->domain) )
    {
        if ( cr0 & X86_CR0_PG )
        {
            mfn = mfn_x(get_gfn(v->domain, cr3 >> PAGE_SHIFT, &p2mt));
#error handle get_gfn retry here
            if ( !p2m_is_ram(p2mt) || !get_page(mfn_to_page(mfn), v->domain) )
            {
                put_gfn(v->domain, cr3 >> PAGE_SHIFT);
                gdprintk(XENLOG_ERR, "Invalid CR3 value=0x%lx\n", cr3);
                return -EINVAL;
            }
        }

        if ( hvm_paging_enabled(v) )
            put_page(pagetable_get_page(v->arch.guest_table));

        v->arch.guest_table = pagetable_from_pfn(mfn);
        if ( cr0 & X86_CR0_PG )
            put_gfn(v->domain, cr3 >> PAGE_SHIFT);
    }
#endif  /* __UXEN__ */

    v->arch.hvm_vcpu.guest_cr[0] = cr0 | X86_CR0_ET;
    v->arch.hvm_vcpu.guest_cr[3] = cr3;

    return 0;
}

static int vmx_vmcs_restore(struct vcpu *v, struct hvm_hw_cpu *c)
{
    int rc;

    if ( c->pending_valid &&
         ((c->pending_type == 1) || (c->pending_type > 6) ||
          (c->pending_reserved != 0)) )
    {
        gdprintk(XENLOG_ERR, "Invalid pending event 0x%"PRIx32".\n",
                 c->pending_event);
        return -EINVAL;
    }

    rc = vmx_restore_cr0_cr3(v, c->cr0, c->cr3);
    if ( rc )
        return rc;

    vmx_vmcs_enter(v);

    v->arch.hvm_vcpu.guest_cr[2] = c->cr2;
    v->arch.hvm_vcpu.guest_cr[4] = c->cr4;
    vmx_update_guest_cr(v, 0);
    vmx_update_guest_cr(v, 2);
    vmx_update_guest_cr(v, 4);

    v->arch.hvm_vcpu.guest_efer = c->msr_efer;
    vmx_update_guest_efer(v);

    __vmwrite(GUEST_SYSENTER_CS, c->sysenter_cs);
    __vmwrite(GUEST_SYSENTER_ESP, c->sysenter_esp);
    __vmwrite(GUEST_SYSENTER_EIP, c->sysenter_eip);

    __vmwrite(GUEST_DR7, c->dr7);

    vmx_vmcs_exit(v);

    rc = paging_update_paging_modes(v);
    if (rc)
        return rc;

    if ( c->pending_valid )
    {
        gdprintk(XENLOG_INFO, "Re-injecting 0x%"PRIx32", 0x%"PRIx32"\n",
                 c->pending_event, c->error_code);

        if ( hvm_event_needs_reinjection(c->pending_type, c->pending_vector) )
        {
            vmx_vmcs_enter(v);
            __vmwrite(VM_ENTRY_INTR_INFO, c->pending_event);
            __vmwrite(VM_ENTRY_EXCEPTION_ERROR_CODE, c->error_code);
            vmx_vmcs_exit(v);
        }
    }

    return 0;
}

static void vmx_save_cpu_state(struct vcpu *v, struct hvm_hw_cpu *data)
{
#ifdef __x86_64__
    struct vmx_msr_state *guest_state = &v->arch.hvm_vmx.msr_state;
    unsigned long guest_flags = guest_state->flags;

    data->shadow_gs = guest_state->msrs[VMX_INDEX_MSR_SHADOW_GS_BASE];
    data->msr_cstar = v->arch.hvm_vmx.cstar;

    /* save msrs */
    data->msr_flags        = guest_flags;
    data->msr_lstar        = guest_state->msrs[VMX_INDEX_MSR_LSTAR];
    data->msr_star         = guest_state->msrs[VMX_INDEX_MSR_STAR];
    data->msr_syscall_mask = guest_state->msrs[VMX_INDEX_MSR_SYSCALL_MASK];
#endif

    /* must be done with paused time or tsc desyncs across vcpus */
    WARN_ON(!v->arch.pause_tsc);
    data->tsc = hvm_get_guest_tsc(v);
}

static void vmx_load_cpu_state(struct vcpu *v, struct hvm_hw_cpu *data)
{
#ifdef __x86_64__
    struct vmx_msr_state *guest_state = &v->arch.hvm_vmx.msr_state;

    /* restore msrs */
    guest_state->flags = data->msr_flags & ((1 << VMX_MSR_COUNT) - 1);
    guest_state->msrs[VMX_INDEX_MSR_LSTAR]        = data->msr_lstar;
    guest_state->msrs[VMX_INDEX_MSR_STAR]         = data->msr_star;
    guest_state->msrs[VMX_INDEX_MSR_SYSCALL_MASK] = data->msr_syscall_mask;

    v->arch.hvm_vmx.cstar     = data->msr_cstar;
    guest_state->msrs[VMX_INDEX_MSR_SHADOW_GS_BASE] = data->shadow_gs;
    /* Always save/restore shadow gs. */
    set_bit(VMX_INDEX_MSR_SHADOW_GS_BASE, &guest_state->flags);
#endif

    /* must be done with paused time or tsc desyncs across vcpus */
    WARN_ON(!v->arch.pause_tsc);
    hvm_set_guest_tsc(v, data->tsc);
}


static void vmx_save_vmcs_ctxt(struct vcpu *v, struct hvm_hw_cpu *ctxt)
{
    vmx_save_cpu_state(v, ctxt);
    vmx_vmcs_save(v, ctxt);
}

static int vmx_load_vmcs_ctxt(struct vcpu *v, struct hvm_hw_cpu *ctxt)
{
    int ret;

    vmx_load_cpu_state(v, ctxt);

    ret = vmx_vmcs_restore(v, ctxt);
    if (ret && ret != -ECONTINUATION) {
        gdprintk(XENLOG_ERR, "vmx_vmcs restore failed!\n");
        domain_crash(v->domain);
    }

    return ret;
}

static void vmx_fpu_enter(struct vcpu *v)
{
    v->arch.hvm_vmx.exception_bitmap &= ~(1u << TRAP_no_device);
    vmx_update_exception_bitmap(v);
}

#ifndef __UXEN__
static void vmx_fpu_leave(struct vcpu *v)
{
DEBUG();
    ASSERT(!v->fpu_dirtied);
    ASSERT(read_cr0() & X86_CR0_TS);

    if ( !(v->arch.hvm_vmx.host_cr0 & X86_CR0_TS) )
    {
        v->arch.hvm_vmx.host_cr0 |= X86_CR0_TS;
        __vmwrite(HOST_CR0, v->arch.hvm_vmx.host_cr0);
    }

    /*
     * If the guest does not have TS enabled then we must cause and handle an
     * exception on first use of the FPU. If the guest *does* have TS enabled
     * then this is not necessary: no FPU activity can occur until the guest
     * clears CR0.TS, and we will initialise the FPU when that happens.
     */
    if ( !(v->arch.hvm_vcpu.guest_cr[0] & X86_CR0_TS) )
    {
        v->arch.hvm_vcpu.hw_cr[0] |= X86_CR0_TS;
        __vmwrite(GUEST_CR0, v->arch.hvm_vcpu.hw_cr[0]);
        v->arch.hvm_vmx.exception_bitmap |= (1u << TRAP_no_device);
        vmx_update_exception_bitmap(v);
    }
}
#endif  /* __UXEN__ */

static void vmx_ctxt_switch_from(struct vcpu *v)
{
    if (v->context_loaded == 0)
        return;
    v->context_loaded = 0;
#ifndef __UXEN_NOT_YET__
    vmx_fpu_leave(v);
#endif  /* __UXEN_NOT_YET__ */
    vcpu_save_fpu(v);
    vmx_restore_host_msrs(v);
    vmx_restore_host_env();
#ifndef __UXEN_NOT_YET__
    vmx_save_dr(v);
    vpmu_save(v);
#endif  /* __UXEN_NOT_YET__ */
    cpumask_clear_cpu(v->processor, v->domain->domain_dirty_cpumask);
    cpumask_clear_cpu(v->processor, v->vcpu_dirty_cpumask);
    vmx_unload_vmcs(v);

    if ( cpu_has_rdtscp && hvm_has_rdtscp(v->domain) )
        wrmsrl(MSR_TSC_AUX, this_cpu(host_msr_tsc_aux));

    vcpu_restore_fpu_host(v);
}

static unsigned long vmr(unsigned long field)
{
    int rc;
    unsigned long val;
    val = __vmread_safe(field, &rc);
    return rc ? 0 : val;
}

static void sync_host_vmcs_state(struct vcpu *v)
{
    uint64_t cr, base;
    int sel;

    vmx_set_host_env(v);

    cr = read_cr3();
    if (v->arch.cr3 != cr) {
        make_cr3(v, cr);
        hvm_update_host_cr3(v);
    }

#ifdef UXEN_HOST_WINDOWS
#ifdef __x86_64__
    v->arch.hvm_vcpu.hw_cr8 = read_cr8();
#endif
    return;
#endif  /* UXEN_HOST_OSX */

    vmx_vmcs_enter(v);

    cr = read_cr0() & ~X86_CR0_TS;
    if (v->arch.hvm_vmx.host_cr0 != cr) {
        /* printk("%s:%d: cr0 host %"PRIx64" vcpu %"PRIx64"\n", __FUNCTION__, */
        /*        host_processor_id(), cr, v->arch.hvm_vmx.host_cr0); */
        v->arch.hvm_vmx.host_cr0 = cr;
    }
    if (vmr(HOST_CR0) != v->arch.hvm_vmx.host_cr0) {
        printk("%s:%d: cr0 vcpu %lx vmcs %lx\n", __FUNCTION__,
               host_processor_id(), v->arch.hvm_vmx.host_cr0, vmr(HOST_CR0));
        __vmwrite(HOST_CR0, v->arch.hvm_vmx.host_cr0);
    }

    cr = read_cr4_cpu();
    if (this_cpu(cr4) != cr) {
        printk("%s:%d: cr4 host %"PRIx64" vmcs %lx\n", __FUNCTION__,
               host_processor_id(), cr, this_cpu(cr4));
        this_cpu(cr4) = cr;
        __vmwrite(HOST_CR4, cr);
    }

    __asm__ __volatile__ ( "mov %%cs, %0" : "=r" (sel) );
    if (vmr(HOST_CS_SELECTOR) != sel) {
        printk("%s:%d: cs host %x vmcs %lx\n", __FUNCTION__,
               host_processor_id(), sel, vmr(HOST_CS_SELECTOR));
        __vmwrite(HOST_CS_SELECTOR, sel);
    }

    __asm__ __volatile__ ( "mov %%ss, %0" : "=r" (sel) );
    if (vmr(HOST_SS_SELECTOR) != sel) {
        /* printk("%s:%d: ss host %x vmcs %"PRIx64"\n", __FUNCTION__, */
        /*        host_processor_id(), sel, vmr(HOST_SS_SELECTOR)); */
        __vmwrite(HOST_SS_SELECTOR, sel);
    }

    __asm__ __volatile__ ( "mov %%gs, %0" : "=r" (sel) );
    if (vmr(HOST_GS_SELECTOR) != (sel & ~7)) {
        printk("%s:%d: gs host %x vmcs %lx\n", __FUNCTION__,
               host_processor_id(), sel, vmr(HOST_GS_SELECTOR));
        __vmwrite(HOST_GS_SELECTOR, sel & ~7);
    }

    __asm__ __volatile__ ( "mov %%fs, %0" : "=r" (sel) );
    if (vmr(HOST_FS_SELECTOR) != (sel & ~7)) {
        printk("%s:%d: fs host %x vmcs %lx\n", __FUNCTION__,
               host_processor_id(), sel, vmr(HOST_FS_SELECTOR));
        __vmwrite(HOST_FS_SELECTOR, sel & ~7);
    }

    __asm__ __volatile__ ( "mov %%es, %0" : "=r" (sel) );
    if (vmr(HOST_ES_SELECTOR) != (sel & ~7)) {
        printk("%s:%d: es host %x vmcs %lx\n", __FUNCTION__,
               host_processor_id(), sel, vmr(HOST_ES_SELECTOR));
        __vmwrite(HOST_ES_SELECTOR, sel & ~7);
    }

    __asm__ __volatile__ ( "mov %%ds, %0" : "=r" (sel) );
    if (vmr(HOST_DS_SELECTOR) != (sel & ~7)) {
        printk("%s:%d: ds host %x vmcs %lx\n", __FUNCTION__,
               host_processor_id(), sel, vmr(HOST_DS_SELECTOR));
        __vmwrite(HOST_DS_SELECTOR, sel & ~7);
    }

    {
        unsigned char gdt_save[10];

        __asm__ __volatile__ ( "sgdt %0" : "=m" (gdt_save) );
        if (vmr(HOST_GDTR_BASE) != (*(unsigned long  *)(&gdt_save[2]))) {
            printk("%s:%d: gdtr base host %lx vmcs %lx\n",
                   __FUNCTION__, host_processor_id(),
                   (*(unsigned long  *)(&gdt_save[2])), vmr(HOST_GDTR_BASE));
            __vmwrite(HOST_GDTR_BASE, (*(unsigned long  *)(&gdt_save[2])));
        }
    }

    {
        unsigned char idt_save[10];

        __asm__ __volatile__ ( "sidt %0" : "=m" (idt_save) );
        if (vmr(HOST_IDTR_BASE) != (*(unsigned long  *)(&idt_save[2]))) {
            printk("%s:%d: idtr base host %lx vmcs %lx\n",
                   __FUNCTION__, host_processor_id(),
                   (*(unsigned long  *)(&idt_save[2])), vmr(HOST_IDTR_BASE));
            __vmwrite(HOST_IDTR_BASE, (*(unsigned long  *)(&idt_save[2])));
        }
    }

    {
        unsigned char gdt_save[10];
        uint16_t tr;
        struct desc_struct *table, desc;
        unsigned long base;

        __asm__ __volatile__ ( "str %0" : "=g" (tr) );
        if (vmr(HOST_TR_SELECTOR) != (tr /* & ~7 */)) {
            printk("%s:%d: tr sel host %x vmcs %lx\n", __FUNCTION__,
                   host_processor_id(), sel, vmr(HOST_TR_SELECTOR));
            __vmwrite(HOST_TR_SELECTOR, tr /* & ~7 */);
        }

        __asm__ __volatile__ ( "sgdt %0" : "=m" (gdt_save) );
        table = (struct desc_struct *)(*(unsigned long  *)(&gdt_save[2]));
        desc = table[tr >> 3];
        base = ((desc.a >> 16) + ((desc.b & 0xff) << 16) +
                (desc.b & 0xff000000));
#ifdef __x86_64__
        *(((uint32_t *)&base) + 1) = table[(tr >> 3) + 1].a;
#endif
        if (vmr(HOST_TR_BASE) != base) {
            printk("%s:%d: tr base host %lx vmcs %lx\n",
                   __FUNCTION__, host_processor_id(),
                   base, vmr(HOST_TR_BASE));
            __vmwrite(HOST_TR_BASE, base);
        }
    }

    {
        unsigned long sysenter_esp;

        rdmsrl(MSR_IA32_SYSENTER_ESP, sysenter_esp);
        if (vmr(HOST_SYSENTER_ESP) != sysenter_esp) {
            printk("%s:%d: sysenter esp host %lx vmcs %lx\n",
                   __FUNCTION__, host_processor_id(),
                   sysenter_esp, vmr(HOST_SYSENTER_ESP));
            __vmwrite(HOST_SYSENTER_ESP, sysenter_esp);
        }
    }

    {
        unsigned long sysenter_eip;

        rdmsrl(MSR_IA32_SYSENTER_EIP, sysenter_eip);
        if (vmr(HOST_SYSENTER_EIP) != sysenter_eip) {
            printk("%s:%d: sysenter eip host %lx vmcs %lx\n",
                   __FUNCTION__, host_processor_id(),
                   sysenter_eip, vmr(HOST_SYSENTER_EIP));
            __vmwrite(HOST_SYSENTER_EIP, sysenter_eip);
        }
    }

    {
        unsigned long sysenter_cs;

        rdmsrl(MSR_IA32_SYSENTER_CS, sysenter_cs);
        if (vmr(HOST_SYSENTER_CS) != sysenter_cs) {
            printk("%s:%d: sysenter cs host %lx vmcs %lx\n",
                   __FUNCTION__, host_processor_id(),
                   sysenter_cs, vmr(HOST_SYSENTER_CS));
            __vmwrite(HOST_SYSENTER_CS, sysenter_cs);
        }
    }

    rdmsrl(MSR_FS_BASE, base);
    if (vmr(HOST_FS_BASE) != base) {
        printk("%s:%d: fs base host %"PRIx64" vmcs %lx\n",
               __FUNCTION__, host_processor_id(),
               base, vmr(HOST_FS_BASE));
        __vmwrite(HOST_FS_BASE, base);
    }
    rdmsrl(MSR_GS_BASE, base);
    if (vmr(HOST_GS_BASE) != base) {
        printk("%s:%d: gs base host %"PRIx64" vmcs %lx\n",
               __FUNCTION__, host_processor_id(),
               base, vmr(HOST_GS_BASE));
        __vmwrite(HOST_GS_BASE, base);
    }


    vmx_vmcs_exit(v);
}

static void vmx_ctxt_switch_to(struct vcpu *v)
{
    struct domain *d = v->domain;
#ifndef __UXEN__
    unsigned long old_cr4 = read_cr4(), new_cr4 = mmu_cr4_features;

    /* HOST_CR4 in VMCS is always mmu_cr4_features. Sync CR4 now. */
    if ( old_cr4 != new_cr4 )
        write_cr4(new_cr4);
#endif  /* __UXEN__ */
    unsigned int cpu = smp_processor_id();

#ifdef DEBUG
    ASSERT(!v->context_loaded || v->arch.cr3 == read_cr3());
#endif

    if (v->context_loaded != 0)
        return;

    vcpu_save_fpu_host(v);

    ASSERT(v->is_running);

    vcpu_switch_host_cpu(v);
    vmx_do_resume(v);

    sync_host_vmcs_state(v);

    cpumask_set_cpu(cpu, v->domain->domain_dirty_cpumask);
    cpumask_set_cpu(cpu, v->vcpu_dirty_cpumask);

    ept_maybe_sync_cpu(d);

    vmx_restore_guest_msrs(v);
#ifndef __UXEN_NOT_YET__
    vmx_restore_dr(v);
    vpmu_load(v);
#endif  /* __UXEN_NOT_YET__ */

    if ( cpu_has_rdtscp && hvm_has_rdtscp(v->domain) ) {
        unsigned long tsc_aux = hvm_msr_tsc_aux(v);
        rdmsrl(MSR_TSC_AUX, this_cpu(host_msr_tsc_aux));
        if (this_cpu(host_msr_tsc_aux) != tsc_aux)
            wrmsrl(MSR_TSC_AUX, tsc_aux);
    }

    v->context_loaded = 1;
}


/* SDM volume 3b section 22.3.1.2: we can only enter virtual 8086 mode
 * if all of CS, SS, DS, ES, FS and GS are 16bit ring-3 data segments.
 * The guest thinks it's got ring-0 segments, so we need to fudge
 * things.  We store the ring-3 version in the VMCS to avoid lots of
 * shuffling on vmenter and vmexit, and translate in these accessors. */

#define rm_cs_attr (((union segment_attributes) {                       \
        .fields = { .type = 0xb, .s = 1, .dpl = 0, .p = 1, .avl = 0,    \
                    .l = 0, .db = 0, .g = 0, .pad = 0 } }).bytes)
#define rm_ds_attr (((union segment_attributes) {                       \
        .fields = { .type = 0x3, .s = 1, .dpl = 0, .p = 1, .avl = 0,    \
                    .l = 0, .db = 0, .g = 0, .pad = 0 } }).bytes)
#define vm86_ds_attr (((union segment_attributes) {                     \
        .fields = { .type = 0x3, .s = 1, .dpl = 3, .p = 1, .avl = 0,    \
                    .l = 0, .db = 0, .g = 0, .pad = 0 } }).bytes)
#define vm86_tr_attr (((union segment_attributes) {                     \
        .fields = { .type = 0xb, .s = 0, .dpl = 0, .p = 1, .avl = 0,    \
                    .l = 0, .db = 0, .g = 0, .pad = 0 } }).bytes)

static void vmx_get_segment_register(struct vcpu *v, enum x86_segment seg,
                                     struct segment_register *reg)
{
    uint32_t attr = 0;

    vmx_vmcs_enter(v);

    switch ( seg )
    {
    case x86_seg_cs:
        reg->sel   = __vmread(GUEST_CS_SELECTOR);
        reg->limit = __vmread(GUEST_CS_LIMIT);
        reg->base  = __vmread(GUEST_CS_BASE);
        attr       = __vmread(GUEST_CS_AR_BYTES);
        break;
    case x86_seg_ds:
        reg->sel   = __vmread(GUEST_DS_SELECTOR);
        reg->limit = __vmread(GUEST_DS_LIMIT);
        reg->base  = __vmread(GUEST_DS_BASE);
        attr       = __vmread(GUEST_DS_AR_BYTES);
        break;
    case x86_seg_es:
        reg->sel   = __vmread(GUEST_ES_SELECTOR);
        reg->limit = __vmread(GUEST_ES_LIMIT);
        reg->base  = __vmread(GUEST_ES_BASE);
        attr       = __vmread(GUEST_ES_AR_BYTES);
        break;
    case x86_seg_fs:
        reg->sel   = __vmread(GUEST_FS_SELECTOR);
        reg->limit = __vmread(GUEST_FS_LIMIT);
        reg->base  = __vmread(GUEST_FS_BASE);
        attr       = __vmread(GUEST_FS_AR_BYTES);
        break;
    case x86_seg_gs:
        reg->sel   = __vmread(GUEST_GS_SELECTOR);
        reg->limit = __vmread(GUEST_GS_LIMIT);
        reg->base  = __vmread(GUEST_GS_BASE);
        attr       = __vmread(GUEST_GS_AR_BYTES);
        break;
    case x86_seg_ss:
        reg->sel   = __vmread(GUEST_SS_SELECTOR);
        reg->limit = __vmread(GUEST_SS_LIMIT);
        reg->base  = __vmread(GUEST_SS_BASE);
        attr       = __vmread(GUEST_SS_AR_BYTES);
        break;
    case x86_seg_tr:
        reg->sel   = __vmread(GUEST_TR_SELECTOR);
        reg->limit = __vmread(GUEST_TR_LIMIT);
        reg->base  = __vmread(GUEST_TR_BASE);
        attr       = __vmread(GUEST_TR_AR_BYTES);
        break;
    case x86_seg_gdtr:
        reg->limit = __vmread(GUEST_GDTR_LIMIT);
        reg->base  = __vmread(GUEST_GDTR_BASE);
        break;
    case x86_seg_idtr:
        reg->limit = __vmread(GUEST_IDTR_LIMIT);
        reg->base  = __vmread(GUEST_IDTR_BASE);
        break;
    case x86_seg_ldtr:
        reg->sel   = __vmread(GUEST_LDTR_SELECTOR);
        reg->limit = __vmread(GUEST_LDTR_LIMIT);
        reg->base  = __vmread(GUEST_LDTR_BASE);
        attr       = __vmread(GUEST_LDTR_AR_BYTES);
        break;
    default:
        BUG();
    }

    vmx_vmcs_exit(v);

    reg->attr.bytes = (attr & 0xff) | ((attr >> 4) & 0xf00);
    /* Unusable flag is folded into Present flag. */
    if ( attr & (1u<<16) )
        reg->attr.fields.p = 0;

    /* Adjust for virtual 8086 mode */
    if ( v->arch.hvm_vmx.vmx_realmode && seg <= x86_seg_tr 
         && !(v->arch.hvm_vmx.vm86_segment_mask & (1u << seg)) )
    {
        struct segment_register *sreg = &v->arch.hvm_vmx.vm86_saved_seg[seg];
        if ( seg == x86_seg_tr ) 
            *reg = *sreg;
        else if ( reg->base != sreg->base || seg == x86_seg_ss )
        {
            /* If the guest's reloaded the segment, remember the new version.
             * We can't tell if the guest reloaded the segment with another 
             * one that has the same base.  By default we assume it hasn't,
             * since we don't want to lose big-real-mode segment attributes,
             * but for SS we assume it has: the Ubuntu graphical bootloader
             * does this and gets badly confused if we leave the old SS in 
             * place. */
            reg->attr.bytes = (seg == x86_seg_cs ? rm_cs_attr : rm_ds_attr);
            *sreg = *reg;
        }
        else 
        {
            /* Always give realmode guests a selector that matches the base
             * but keep the attr and limit from before */
            *reg = *sreg;
            reg->sel = reg->base >> 4;
        }
    }
}

static void vmx_set_segment_register(struct vcpu *v, enum x86_segment seg,
                                     struct segment_register *reg)
{
    uint32_t attr, sel, limit;
    uint64_t base;

    sel = reg->sel;
    attr = reg->attr.bytes;
    limit = reg->limit;
    base = reg->base;

    /* Adjust CS/SS/DS/ES/FS/GS/TR for virtual 8086 mode */
    if ( v->arch.hvm_vmx.vmx_realmode && seg <= x86_seg_tr )
    {
        /* Remember the proper contents */
        v->arch.hvm_vmx.vm86_saved_seg[seg] = *reg;
        
        if ( seg == x86_seg_tr ) 
        {
            if ( v->domain->arch.hvm_domain.params[HVM_PARAM_VM86_TSS] )
            {
                sel = 0;
                attr = vm86_tr_attr;
                limit = 0xff;
                base = v->domain->arch.hvm_domain.params[HVM_PARAM_VM86_TSS];
                v->arch.hvm_vmx.vm86_segment_mask &= ~(1u << seg);
            }
            else
                v->arch.hvm_vmx.vm86_segment_mask |= (1u << seg);
        }
        else
        {
            /* Try to fake it out as a 16bit data segment.  This could
             * cause confusion for the guest if it reads the selector,
             * but otherwise we have to emulate if *any* segment hasn't
             * been reloaded. */
            if ( base < 0x100000 && !(base & 0xf) && limit >= 0xffff
                 && reg->attr.fields.p )
            {
                sel = base >> 4;
                attr = vm86_ds_attr;
                limit = 0xffff;
                v->arch.hvm_vmx.vm86_segment_mask &= ~(1u << seg);
            }
            else 
                v->arch.hvm_vmx.vm86_segment_mask |= (1u << seg);
        }
    }

    attr = ((attr & 0xf00) << 4) | (attr & 0xff);

    /* Not-present must mean unusable. */
    if ( !reg->attr.fields.p )
        attr |= (1u << 16);

    /* VMX has strict consistency requirement for flag G. */
    attr |= !!(limit >> 20) << 15;

    vmx_vmcs_enter(v);

    switch ( seg )
    {
    case x86_seg_cs:
        __vmwrite(GUEST_CS_SELECTOR, sel);
        __vmwrite(GUEST_CS_LIMIT, limit);
        __vmwrite(GUEST_CS_BASE, base);
        __vmwrite(GUEST_CS_AR_BYTES, attr);
        break;
    case x86_seg_ds:
        __vmwrite(GUEST_DS_SELECTOR, sel);
        __vmwrite(GUEST_DS_LIMIT, limit);
        __vmwrite(GUEST_DS_BASE, base);
        __vmwrite(GUEST_DS_AR_BYTES, attr);
        break;
    case x86_seg_es:
        __vmwrite(GUEST_ES_SELECTOR, sel);
        __vmwrite(GUEST_ES_LIMIT, limit);
        __vmwrite(GUEST_ES_BASE, base);
        __vmwrite(GUEST_ES_AR_BYTES, attr);
        break;
    case x86_seg_fs:
        __vmwrite(GUEST_FS_SELECTOR, sel);
        __vmwrite(GUEST_FS_LIMIT, limit);
        __vmwrite(GUEST_FS_BASE, base);
        __vmwrite(GUEST_FS_AR_BYTES, attr);
        break;
    case x86_seg_gs:
        __vmwrite(GUEST_GS_SELECTOR, sel);
        __vmwrite(GUEST_GS_LIMIT, limit);
        __vmwrite(GUEST_GS_BASE, base);
        __vmwrite(GUEST_GS_AR_BYTES, attr);
        break;
    case x86_seg_ss:
        __vmwrite(GUEST_SS_SELECTOR, sel);
        __vmwrite(GUEST_SS_LIMIT, limit);
        __vmwrite(GUEST_SS_BASE, base);
        __vmwrite(GUEST_SS_AR_BYTES, attr);
        break;
    case x86_seg_tr:
        __vmwrite(GUEST_TR_SELECTOR, sel);
        __vmwrite(GUEST_TR_LIMIT, limit);
        __vmwrite(GUEST_TR_BASE, base);
        /* VMX checks that the the busy flag (bit 1) is set. */
        __vmwrite(GUEST_TR_AR_BYTES, attr | 2);
        break;
    case x86_seg_gdtr:
        __vmwrite(GUEST_GDTR_LIMIT, limit);
        __vmwrite(GUEST_GDTR_BASE, base);
        break;
    case x86_seg_idtr:
        __vmwrite(GUEST_IDTR_LIMIT, limit);
        __vmwrite(GUEST_IDTR_BASE, base);
        break;
    case x86_seg_ldtr:
        __vmwrite(GUEST_LDTR_SELECTOR, sel);
        __vmwrite(GUEST_LDTR_LIMIT, limit);
        __vmwrite(GUEST_LDTR_BASE, base);
        __vmwrite(GUEST_LDTR_AR_BYTES, attr);
        break;
    default:
        BUG();
    }

    vmx_vmcs_exit(v);
}

static void vmx_set_tsc_offset(struct vcpu *v, u64 offset)
{
    vmx_vmcs_enter(v);

#ifndef __UXEN_NOT_YET__
    if ( nestedhvm_vcpu_in_guestmode(v) )
        offset += nvmx_get_tsc_offset(v);
#endif  /* __UXEN_NOT_YET__ */

    __vmwrite(TSC_OFFSET, offset);
#if defined (__i386__)
    __vmwrite(TSC_OFFSET_HIGH, offset >> 32);
#endif
    vmx_vmcs_exit(v);
}

static void vmx_set_rdtsc_exiting(struct vcpu *v, bool_t enable)
{
    vmx_vmcs_enter(v);
    v->arch.hvm_vmx.exec_control &= ~CPU_BASED_RDTSC_EXITING;
    if ( enable )
        v->arch.hvm_vmx.exec_control |= CPU_BASED_RDTSC_EXITING;
    vmx_update_cpu_exec_control(v);
    v->arch.hvm_vmx.secondary_exec_control |=
        vmx_secondary_exec_control & SECONDARY_EXEC_ENABLE_RDTSCP;
    if (!hvm_has_rdtscp(v->domain) && !hvm_has_pvrdtscp(v->domain))
        v->arch.hvm_vmx.secondary_exec_control &= ~SECONDARY_EXEC_ENABLE_RDTSCP;
    vmx_update_secondary_exec_control(v);
    vmx_vmcs_exit(v);
}

static bool_t vmx_ple_enabled(struct vcpu *v)
{
    return !!(v->arch.hvm_vmx.secondary_exec_control &
              SECONDARY_EXEC_PAUSE_LOOP_EXITING);
}

static void vmx_init_hypercall_page(struct domain *d, void *hypercall_page)
{
    char *p;
    int i;

    for ( i = 0; i < (PAGE_SIZE / 32); i++ )
    {
        p = (char *)(hypercall_page + (i * 32));
        *(u8  *)(p + 0) = 0xb8; /* mov imm32, %eax */
        *(u32 *)(p + 1) = i;
        *(u8  *)(p + 5) = 0x0f; /* vmcall */
        *(u8  *)(p + 6) = 0x01;
        *(u8  *)(p + 7) = 0xc1;
        *(u8  *)(p + 8) = 0xc3; /* ret */
    }

    /* Don't support HYPERVISOR_iret at the moment */
    *(u16 *)(hypercall_page + (__HYPERVISOR_iret * 32)) = 0x0b0f; /* ud2 */
}

static unsigned int vmx_get_interrupt_shadow(struct vcpu *v)
{
    return __vmread(GUEST_INTERRUPTIBILITY_INFO);
}

static void vmx_set_interrupt_shadow(struct vcpu *v, unsigned int intr_shadow)
{
    __vmwrite(GUEST_INTERRUPTIBILITY_INFO, intr_shadow);
}

static int vmx_load_pdptrs(struct vcpu *v)
{
    unsigned long cr3 = v->arch.hvm_vcpu.guest_cr[3], mfn;
    uint64_t *guest_pdptrs;
    p2m_type_t p2mt;
    char *p;
    int ret = 0;

    /* EPT needs to load PDPTRS into VMCS for PAE. */
    if ( !hvm_pae_enabled(v) || (v->arch.hvm_vcpu.guest_efer & EFER_LMA) )
        return 0;

    if ( cr3 & 0x1fUL )
        goto crash;

    mfn = mfn_x(get_gfn(v->domain, cr3 >> PAGE_SHIFT, &p2mt));
    if (__mfn_retry(mfn)) {
        ret = -ECONTINUATION;
        goto out;
    }
    if ( !p2m_is_ram(p2mt) )
    {
        put_gfn(v->domain, cr3 >> PAGE_SHIFT);
        goto crash;
    }

    p = map_domain_page(mfn);

    guest_pdptrs = (uint64_t *)(p + (cr3 & ~PAGE_MASK));

    /*
     * We do not check the PDPTRs for validity. The CPU will do this during
     * vm entry, and we can handle the failure there and crash the guest.
     * The only thing we could do better here is #GP instead.
     */

    vmx_vmcs_enter(v);

    __vmwrite(GUEST_PDPTR0, guest_pdptrs[0]);
    __vmwrite(GUEST_PDPTR1, guest_pdptrs[1]);
    __vmwrite(GUEST_PDPTR2, guest_pdptrs[2]);
    __vmwrite(GUEST_PDPTR3, guest_pdptrs[3]);
#ifdef __i386__
    __vmwrite(GUEST_PDPTR0_HIGH, guest_pdptrs[0] >> 32);
    __vmwrite(GUEST_PDPTR1_HIGH, guest_pdptrs[1] >> 32);
    __vmwrite(GUEST_PDPTR2_HIGH, guest_pdptrs[2] >> 32);
    __vmwrite(GUEST_PDPTR3_HIGH, guest_pdptrs[3] >> 32);
#endif

    vmx_vmcs_exit(v);

    unmap_domain_page(p);
  out:
    put_gfn(v->domain, cr3 >> PAGE_SHIFT);
    return ret;

 crash:
    domain_crash(v->domain);
    return -EINVAL;
}

static void vmx_update_host_cr3(struct vcpu *v)
{
    vmx_vmcs_enter(v);
    __vmwrite(HOST_CR3, v->arch.cr3);
    vmx_vmcs_exit(v);
#ifndef __UXEN__
    WARN();
#endif  /* __UXEN__ */
}

void vmx_update_debug_state(struct vcpu *v)
{
    ASSERT(v == current);

    if ( v->arch.hvm_vcpu.debug_state_latch )
        v->arch.hvm_vmx.exception_bitmap |= 1U << TRAP_int3;
    else
        v->arch.hvm_vmx.exception_bitmap &= ~(1U << TRAP_int3);
    vmx_update_exception_bitmap(v);
}

static int vmx_update_guest_cr(struct vcpu *v, unsigned int cr)
{
    int ret = 0;

    vmx_vmcs_enter(v);

    switch ( cr )
    {
    case 0: {
        int realmode;
        unsigned long hw_cr0_mask = X86_CR0_NE;

        if ( !vmx_unrestricted_guest(v) )
            hw_cr0_mask |= X86_CR0_PG | X86_CR0_PE;

        if ( paging_mode_shadow(v->domain) )
           hw_cr0_mask |= X86_CR0_WP;

        if ( paging_mode_hap(v->domain) )
        {
            /* We manage GUEST_CR3 when guest CR0.PE is zero or when cr3 memevents are on */            
            uint32_t cr3_ctls = (CPU_BASED_CR3_LOAD_EXITING |
                                 CPU_BASED_CR3_STORE_EXITING);
            v->arch.hvm_vmx.exec_control &= ~cr3_ctls;
            if ( !hvm_paging_enabled(v) )
                v->arch.hvm_vmx.exec_control |= cr3_ctls;

            if ( v->domain->arch.hvm_domain.params[HVM_PARAM_MEMORY_EVENT_CR3] )
                v->arch.hvm_vmx.exec_control |= CPU_BASED_CR3_LOAD_EXITING;

            if (v->domain->introspection_features &
                XEN_DOMCTL_INTROSPECTION_FEATURE_HIDDEN_PROCESS)
                v->arch.hvm_vmx.exec_control |= CPU_BASED_CR3_LOAD_EXITING;

            vmx_update_cpu_exec_control(v);

            /* Changing CR0.PE can change some bits in real CR4. */
            vmx_update_guest_cr(v, 4);
        }

        if ( !(v->arch.hvm_vcpu.guest_cr[0] & X86_CR0_TS) )
        {
            if ( v != current )
                hw_cr0_mask |= X86_CR0_TS;
            else if ( v->arch.hvm_vcpu.hw_cr[0] & X86_CR0_TS )
                vmx_fpu_enter(v);
        }

        realmode = !(v->arch.hvm_vcpu.guest_cr[0] & X86_CR0_PE); 

        if ( (!vmx_unrestricted_guest(v)) &&
             (realmode != v->arch.hvm_vmx.vmx_realmode) )
        {
            enum x86_segment s; 
            struct segment_register reg[x86_seg_tr + 1];

            /* Entering or leaving real mode: adjust the segment registers.
             * Need to read them all either way, as realmode reads can update
             * the saved values we'll use when returning to prot mode. */
            for ( s = x86_seg_cs ; s <= x86_seg_tr ; s++ )
                vmx_get_segment_register(v, s, &reg[s]);
            v->arch.hvm_vmx.vmx_realmode = realmode;
            
            if ( realmode )
            {
                for ( s = x86_seg_cs ; s <= x86_seg_tr ; s++ )
                    vmx_set_segment_register(v, s, &reg[s]);
                v->arch.hvm_vcpu.hw_cr[4] |= X86_CR4_VME;
                __vmwrite(GUEST_CR4, v->arch.hvm_vcpu.hw_cr[4]);
                v->arch.hvm_vmx.exception_bitmap = 0xffffffff;
                vmx_update_exception_bitmap(v);
            }
            else 
            {
                for ( s = x86_seg_cs ; s <= x86_seg_tr ; s++ ) 
                    if ( !(v->arch.hvm_vmx.vm86_segment_mask & (1<<s)) )
                        vmx_set_segment_register(
                            v, s, &v->arch.hvm_vmx.vm86_saved_seg[s]);
                v->arch.hvm_vcpu.hw_cr[4] =
                    ((v->arch.hvm_vcpu.hw_cr[4] & ~X86_CR4_VME)
                     |(v->arch.hvm_vcpu.guest_cr[4] & X86_CR4_VME));
                __vmwrite(GUEST_CR4, v->arch.hvm_vcpu.hw_cr[4]);
                v->arch.hvm_vmx.exception_bitmap = HVM_TRAP_MASK
                          | (paging_mode_hap(v->domain) ?
                             0 : (1U << TRAP_page_fault))
                          | (1U << TRAP_no_device);
                vmx_update_exception_bitmap(v);
                vmx_update_debug_state(v);
            }
        }

        v->arch.hvm_vcpu.hw_cr[0] =
            v->arch.hvm_vcpu.guest_cr[0] | hw_cr0_mask;
        __vmwrite(GUEST_CR0, v->arch.hvm_vcpu.hw_cr[0]);
        __vmwrite(CR0_READ_SHADOW, v->arch.hvm_vcpu.guest_cr[0]);
        break;
    }
    case 2:
        /* CR2 is updated in exit stub. */
        break;
    case 3:
        if ( paging_mode_hap(v->domain) )
        {
            if ( !hvm_paging_enabled(v) )
                v->arch.hvm_vcpu.hw_cr[3] =
                    v->domain->arch.hvm_domain.params[HVM_PARAM_IDENT_PT];
            ret = vmx_load_pdptrs(v);
        }
 
        __vmwrite(GUEST_CR3, v->arch.hvm_vcpu.hw_cr[3]);
        hvm_asid_flush_vcpu(v);
        break;
    case 4:
        v->arch.hvm_vcpu.hw_cr[4] = HVM_CR4_HOST_MASK;
        if ( paging_mode_hap(v->domain) )
            v->arch.hvm_vcpu.hw_cr[4] &= ~X86_CR4_PAE;
        v->arch.hvm_vcpu.hw_cr[4] |= v->arch.hvm_vcpu.guest_cr[4];
        if ( v->arch.hvm_vmx.vmx_realmode ) 
            v->arch.hvm_vcpu.hw_cr[4] |= X86_CR4_VME;
        if ( paging_mode_hap(v->domain) && !hvm_paging_enabled(v) )
        {
            v->arch.hvm_vcpu.hw_cr[4] |= X86_CR4_PSE;
            v->arch.hvm_vcpu.hw_cr[4] &= ~X86_CR4_PAE;
        }

        if (v->domain->introspection_features &
            XEN_DOMCTL_INTROSPECTION_FEATURE_SMEP_OFF) {
            __vmwrite(GUEST_CR4, v->arch.hvm_vcpu.hw_cr[4]&~X86_CR4_SMEP);
            __vmwrite(CR4_READ_SHADOW,
                      v->arch.hvm_vcpu.guest_cr[4] & ~X86_CR4_SMEP);
        } else if (v->domain->introspection_features &
                   XEN_DOMCTL_INTROSPECTION_FEATURE_SMEP) {
            __vmwrite(GUEST_CR4, v->arch.hvm_vcpu.hw_cr[4] | X86_CR4_SMEP);
            __vmwrite(CR4_READ_SHADOW,
                      v->arch.hvm_vcpu.guest_cr[4] | X86_CR4_SMEP);
        }
        else {
            __vmwrite(GUEST_CR4, v->arch.hvm_vcpu.hw_cr[4]);
            __vmwrite(CR4_READ_SHADOW, v->arch.hvm_vcpu.guest_cr[4]);
        }
        break;
    default:
        BUG();
    }

    vmx_vmcs_exit(v);

    return ret;
}

static void vmx_update_guest_efer(struct vcpu *v)
{
#ifdef __x86_64__
    unsigned long vm_entry_value;

    vmx_vmcs_enter(v);

    vm_entry_value = __vmread(VM_ENTRY_CONTROLS);
    if ( v->arch.hvm_vcpu.guest_efer & EFER_LMA )
        vm_entry_value |= VM_ENTRY_IA32E_MODE;
    else
        vm_entry_value &= ~VM_ENTRY_IA32E_MODE;
    __vmwrite(VM_ENTRY_CONTROLS, vm_entry_value);

    vmx_vmcs_exit(v);
#endif

#ifndef __UXEN__
    if ( v == current )
        write_efer((read_efer() & ~EFER_SCE) |
                   (v->arch.hvm_vcpu.guest_efer & EFER_SCE));
#endif  /* __UXEN__ */
}

/* Caller must hold ept_sync_lock */
static void
ept_maybe_sync_cpu_no_lock(struct domain *d, unsigned int cpu)
{
    if (!cpumask_test_cpu(cpu, d->arch.hvm_domain.vmx.ept_synced)) {
        struct p2m_domain *p2m = p2m_get_hostp2m(d);

        cpumask_set_cpu(cpu, d->arch.hvm_domain.vmx.ept_synced);

        __invept(INVEPT_SINGLE_CONTEXT, ept_get_eptp(d), 0);
        p2m->virgin = 1;
    }
}

static inline void
ept_maybe_sync_cpu(struct domain *d)
{
    unsigned long flags, flags2;

    if (!paging_mode_hap(d))
        return;

    cpu_irq_save(flags); 
    spin_lock_irqsave(&ept_sync_lock, flags2);

    ept_maybe_sync_cpu_no_lock(d, smp_processor_id());

    spin_unlock_irqrestore(&ept_sync_lock, flags2);
    cpu_irq_restore(flags); 
}

static void
ept_maybe_sync_cpu_enter(struct domain *d)
{
    unsigned int cpu = smp_processor_id();
    struct p2m_domain *p2m = p2m_get_hostp2m(d);
    unsigned long flags, flags2;

    if (!paging_mode_hap(d))
        return;

    /* We're about to do a vmenter, which should clear this */

    cpu_irq_save(flags); 
    spin_lock_irqsave(&ept_sync_lock, flags2);

    cpumask_set_cpu(cpu, d->arch.hvm_domain.vmx.ept_in_use);

    ept_maybe_sync_cpu_no_lock(d, cpu);

    p2m->virgin = 0;
    spin_unlock_irqrestore(&ept_sync_lock, flags2);
    cpu_irq_restore(flags); 
}

static void
ept_maybe_sync_cpu_leave(struct domain *d)
{
    unsigned int cpu = smp_processor_id();
    unsigned long flags, flags2;

    if (!paging_mode_hap(d))
        return;

    cpu_irq_save(flags);
    spin_lock_irqsave(&ept_sync_lock, flags2);

    ept_maybe_sync_cpu_no_lock(d, cpu);

    cpumask_clear_cpu(cpu, d->arch.hvm_domain.vmx.ept_in_use);

    spin_unlock_irqrestore(&ept_sync_lock, flags2);
    cpu_irq_restore(flags);
}

static void
ept_sync_domain(struct domain *d)
{
    int misery = 0;
    unsigned long flags, flags2;

    /* Only if using EPT and this domain has some VCPUs to dirty. */
    if ( !paging_mode_hap(d) || !d->vcpu || !d->vcpu[0] )
        return;

    ASSERT(local_irq_is_enabled());

    if (ax_present)
        ax_invept_all_cpus();
    else {
        cpumask_var_t ept_dirty;

        /* Misery: only the test_and_set_bit operations are properly atomic */

        cpu_irq_save(flags); 
        spin_lock_irqsave(&ept_sync_lock, flags2);

        cpumask_clear(d->arch.hvm_domain.vmx.ept_synced);

        ept_maybe_sync_cpu_no_lock(d, smp_processor_id());

        cpumask_andnot(ept_dirty,
                       d->arch.hvm_domain.vmx.ept_in_use,
                       d->arch.hvm_domain.vmx.ept_synced);

        while (!cpumask_empty(ept_dirty)) {
            unsigned int cpu;

            spin_unlock_irqrestore(&ept_sync_lock, flags2);
            cpu_irq_restore(flags); 

            for_each_cpu(cpu, ept_dirty) {
                ASSERT(cpu != smp_processor_id());
                if (!cpumask_test_cpu(cpu, d->arch.hvm_domain.vmx.ept_synced))
                    poke_cpu(cpu);
            }

            rep_nop();
            rep_nop();
            rep_nop();
            rep_nop();
            rep_nop();
            rep_nop();

            cpu_irq_save(flags); 
            spin_lock_irqsave(&ept_sync_lock, flags2);

            if ((misery++) > 1000000) {
                WARNISH();
                break;
            }

            ept_maybe_sync_cpu_no_lock(d, smp_processor_id());

            cpumask_andnot(ept_dirty,
                           d->arch.hvm_domain.vmx.ept_in_use,
                           d->arch.hvm_domain.vmx.ept_synced);
        }

        spin_unlock_irqrestore(&ept_sync_lock, flags2);
        cpu_irq_restore(flags); 
    }
}

#ifndef __UXEN_NOT_YET__
void nvmx_enqueue_n2_exceptions(struct vcpu *v, 
            unsigned long intr_fields, int error_code)
{
    struct nestedvmx *nvmx = &vcpu_2_nvmx(v);

DEBUG();
    if ( !(nvmx->intr.intr_info & INTR_INFO_VALID_MASK) ) {
        /* enqueue the exception till the VMCS switch back to L1 */
        nvmx->intr.intr_info = intr_fields;
        nvmx->intr.error_code = error_code;
        vcpu_nestedhvm(v).nv_vmexit_pending = 1;
        return;
    }
    else
        gdprintk(XENLOG_ERR, "Double Fault on Nested Guest: exception %lx %x"
                 "on %lx %x\n", intr_fields, error_code,
                 nvmx->intr.intr_info, nvmx->intr.error_code);
}

static int nvmx_vmexit_exceptions(struct vcpu *v, unsigned int trapnr,
                      int errcode, unsigned long cr2)
{
DEBUG();
    nvmx_enqueue_n2_exceptions(v, trapnr, errcode);
    return NESTEDHVM_VMEXIT_DONE;
}
#endif  /* __UXEN_NOT_YET__ */

static void __vmx_inject_exception(int trap, int type, int error_code)
{
    unsigned long intr_fields;
    struct vcpu *curr = current;

    /*
     * NB. Callers do not need to worry about clearing STI/MOV-SS blocking:
     *  "If the VM entry is injecting, there is no blocking by STI or by
     *   MOV SS following the VM entry, regardless of the contents of the
     *   interruptibility-state field [in the guest-state area before the
     *   VM entry]", PRM Vol. 3, 22.6.1 (Interruptibility State).
     */

    intr_fields = (INTR_INFO_VALID_MASK | (type<<8) | trap);
    if ( error_code != HVM_DELIVER_NO_ERROR_CODE ) {
        __vmwrite(VM_ENTRY_EXCEPTION_ERROR_CODE, error_code);
        intr_fields |= INTR_INFO_DELIVER_CODE_MASK;
    }

    __vmwrite(VM_ENTRY_INTR_INFO, intr_fields);

    /* Can't inject exceptions in virtual 8086 mode because they would 
     * use the protected-mode IDT.  Emulate at the next vmenter instead. */
    if ( curr->arch.hvm_vmx.vmx_realmode ) 
        curr->arch.hvm_vmx.vmx_emulate = 1;
}

void vmx_inject_hw_exception(int trap, int error_code)
{
    unsigned long intr_info;
    struct vcpu *curr = current;

    int type = X86_EVENTTYPE_HW_EXCEPTION;

#ifndef __UXEN_NOT_YET__
    if ( nestedhvm_vcpu_in_guestmode(curr) )
        intr_info = vcpu_2_nvmx(curr).intr.intr_info;
    else
#endif  /* __UXEN_NOT_YET__ */
        intr_info = __vmread(VM_ENTRY_INTR_INFO);

    switch ( trap )
    {
    case TRAP_debug:
        if ( guest_cpu_user_regs()->eflags & X86_EFLAGS_TF )
        {
            __restore_debug_registers(curr);
            write_debugreg(6, read_debugreg(6) | 0x4000);
        }
        if ( cpu_has_monitor_trap_flag || !curr->domain->debugger_attached )
            break;
    case TRAP_int3:
        if ( curr->domain->debugger_attached )
        {
            /* Debug/Int3: Trap to debugger. */
            domain_pause_for_debugger();
            return;
        }

        type = X86_EVENTTYPE_SW_EXCEPTION;
        __vmwrite(VM_ENTRY_INSTRUCTION_LEN, 1); /* int3 */
    }

    if ( unlikely(intr_info & INTR_INFO_VALID_MASK) &&
         (((intr_info >> 8) & 7) == X86_EVENTTYPE_HW_EXCEPTION) )
    {
        trap = hvm_combine_hw_exceptions((uint8_t)intr_info, trap);
        if ( trap == TRAP_double_fault )
            error_code = 0;
    }

#ifndef __UXEN_NOT_YET__
    if ( nestedhvm_vcpu_in_guestmode(curr) &&
         nvmx_intercepts_exception(curr, trap, error_code) )
    {
        nvmx_enqueue_n2_exceptions (curr, 
            INTR_INFO_VALID_MASK | (type<<8) | trap,
            error_code); 
        return;
    }
    else
#endif  /* __UXEN_NOT_YET__ */
        __vmx_inject_exception(trap, type, error_code);

    if ( trap == TRAP_page_fault )
        HVMTRACE_LONG_2D(PF_INJECT, error_code,
                         TRC_PAR_LONG(current->arch.hvm_vcpu.guest_cr[2]));
    else
        HVMTRACE_2D(INJ_EXC, trap, error_code);
}

void vmx_inject_extint(int trap)
{
#ifndef __UXEN_NOT_YET__
    struct vcpu *v = current;
    u32    pin_based_cntrl;
#endif  /* __UXEN_NOT_YET__ */

#ifndef __UXEN_NOT_YET__
    if ( nestedhvm_vcpu_in_guestmode(v) ) {
        pin_based_cntrl = __get_vvmcs(vcpu_nestedhvm(v).nv_vvmcx, 
                                     PIN_BASED_VM_EXEC_CONTROL);
        if ( pin_based_cntrl && PIN_BASED_EXT_INTR_MASK ) {
            nvmx_enqueue_n2_exceptions (v, 
               INTR_INFO_VALID_MASK | (X86_EVENTTYPE_EXT_INTR<<8) | trap,
               HVM_DELIVER_NO_ERROR_CODE);
            return;
        }
    }
#endif  /* __UXEN_NOT_YET__ */
    __vmx_inject_exception(trap, X86_EVENTTYPE_EXT_INTR,
                           HVM_DELIVER_NO_ERROR_CODE);
}

void vmx_inject_nmi(void)
{
#ifndef __UXEN_NOT_YET__
    struct vcpu *v = current;
    u32    pin_based_cntrl;
#endif  /* __UXEN_NOT_YET__ */

#ifndef __UXEN_NOT_YET__
    if ( nestedhvm_vcpu_in_guestmode(v) ) {
        pin_based_cntrl = __get_vvmcs(vcpu_nestedhvm(v).nv_vvmcx, 
                                     PIN_BASED_VM_EXEC_CONTROL);
        if ( pin_based_cntrl && PIN_BASED_NMI_EXITING ) {
            nvmx_enqueue_n2_exceptions (v, 
               INTR_INFO_VALID_MASK | (X86_EVENTTYPE_NMI<<8) | TRAP_nmi,
               HVM_DELIVER_NO_ERROR_CODE);
            return;
        }
    }
#endif  /* __UXEN_NOT_YET__ */
    __vmx_inject_exception(2, X86_EVENTTYPE_NMI,
                           HVM_DELIVER_NO_ERROR_CODE);
}

static void vmx_inject_exception(
    unsigned int trapnr, int errcode, unsigned long cr2)
{
    if ( trapnr == TRAP_page_fault )
        current->arch.hvm_vcpu.guest_cr[2] = cr2;

    vmx_inject_hw_exception(trapnr, errcode);
}

static int vmx_event_pending(struct vcpu *v)
{
    ASSERT(v == current);
    return (__vmread(VM_ENTRY_INTR_INFO) & INTR_INFO_VALID_MASK);
}

static int vmx_do_pmu_interrupt(struct cpu_user_regs *regs)
{

#ifndef __UXEN__
    return vpmu_do_interrupt(regs);
#else  /* __UXEN_NOT_YET__ */
    return 0;
#endif  /* __UXEN_NOT_YET__ */
}

static void vmx_set_uc_mode(struct vcpu *v)
{
DEBUG();
    if ( paging_mode_hap(v->domain) )
        ept_change_entry_emt_with_range(
            v->domain, 0, p2m_get_hostp2m(v->domain)->max_mapped_pfn);
    hvm_asid_flush_vcpu(v);
}

static void vmx_set_info_guest(struct vcpu *v)
{
    unsigned long intr_shadow;

    vmx_vmcs_enter(v);

    __vmwrite(GUEST_DR7, v->arch.debugreg[7]);

    /* 
     * If the interruptibility-state field indicates blocking by STI,
     * setting the TF flag in the EFLAGS may cause VM entry to fail
     * and crash the guest. See SDM 3B 22.3.1.5.
     * Resetting the VMX_INTR_SHADOW_STI flag looks hackish but
     * to set the GUEST_PENDING_DBG_EXCEPTIONS.BS here incurs
     * immediately vmexit and hence make no progress.
     */
    intr_shadow = __vmread(GUEST_INTERRUPTIBILITY_INFO);
    if ( v->domain->debugger_attached &&
         (v->arch.user_regs.eflags & X86_EFLAGS_TF) &&
         (intr_shadow & VMX_INTR_SHADOW_STI) )
    {
        intr_shadow &= ~VMX_INTR_SHADOW_STI;
        __vmwrite(GUEST_INTERRUPTIBILITY_INFO, intr_shadow);
    }

    vmx_vmcs_exit(v);
}

static void
vmx_dump_vcpu(struct vcpu *v, const char *from)
{
    vmcs_mini_dump_vcpu(from, v, -1);
}

#ifdef __x86_64__
#define GUEST_OS_PER_CPU_SEGMENT_BASE GUEST_GS_BASE
#else
#define GUEST_OS_PER_CPU_SEGMENT_BASE GUEST_FS_BASE
#endif

static uintptr_t
vmx_exit_info(struct vcpu *v, unsigned int field)
{
    uintptr_t ret = 0;
    int err;

    switch (field) {
    case EXIT_INFO_guest_linear_address:
        vmx_vmcs_enter(v);
        ret = __vmread_safe(GUEST_LINEAR_ADDRESS, &err);
        if (err)
            ret = ~0ul;
        vmx_vmcs_exit(v);
        break;
    case EXIT_INFO_per_cpu_segment_base:
        vmx_vmcs_enter(v);
        ret = __vmread_safe(GUEST_OS_PER_CPU_SEGMENT_BASE, &err);
        if (err)
            ret = 0;
        vmx_vmcs_exit(v);
        break;
    }

    return ret;
}

static struct hvm_function_table __read_mostly vmx_function_table = {
    .name                 = "VMX",
    .cpu_up_prepare       = vmx_cpu_up_prepare,
    .cpu_dead             = vmx_cpu_dead,
    .domain_initialise    = vmx_domain_initialise,
    .domain_destroy       = vmx_domain_destroy,
    .domain_relinquish_memory = vmx_domain_relinquish_memory,
    .vcpu_initialise      = vmx_vcpu_initialise,
    .vcpu_destroy         = vmx_vcpu_destroy,
    .save_cpu_ctxt        = vmx_save_vmcs_ctxt,
    .load_cpu_ctxt        = vmx_load_vmcs_ctxt,
    .get_interrupt_shadow = vmx_get_interrupt_shadow,
    .set_interrupt_shadow = vmx_set_interrupt_shadow,
    .guest_x86_mode       = vmx_guest_x86_mode,
    .get_segment_register = vmx_get_segment_register,
    .set_segment_register = vmx_set_segment_register,
    .update_host_cr3      = vmx_update_host_cr3,
    .update_guest_cr      = vmx_update_guest_cr,
    .update_guest_efer    = vmx_update_guest_efer,
    .set_tsc_offset       = vmx_set_tsc_offset,
    .inject_exception     = vmx_inject_exception,
    .init_hypercall_page  = vmx_init_hypercall_page,
    .event_pending        = vmx_event_pending,
    .do_pmu_interrupt     = vmx_do_pmu_interrupt,
    .do_execute           = vmx_execute,
    .do_suspend           = vmx_do_suspend,
    .pt_sync_domain       = ept_sync_domain,
    .cpu_on               = vmx_cpu_on,
    .cpu_off              = vmx_cpu_off,
    .cpu_up               = vmx_cpu_up,
    .cpu_down             = vmx_cpu_down,
    .dump_vcpu            = vmx_dump_vcpu,
    .exit_info            = vmx_exit_info,
    .cpuid_intercept      = vmx_cpuid_intercept,
    .wbinvd_intercept     = vmx_wbinvd_intercept,
    .fpu_dirty_intercept  = vmx_fpu_dirty_intercept,
    .msr_read_intercept   = vmx_msr_read_intercept,
    .msr_write_intercept  = vmx_msr_write_intercept,
    .invlpg_intercept     = vmx_invlpg_intercept,
    .set_uc_mode          = vmx_set_uc_mode,
    .set_info_guest       = vmx_set_info_guest,
    .set_rdtsc_exiting    = vmx_set_rdtsc_exiting,
    .ple_enabled          = vmx_ple_enabled,
#ifndef __UXEN_NOT_YET__
    .nhvm_vcpu_initialise = nvmx_vcpu_initialise,
    .nhvm_vcpu_destroy    = nvmx_vcpu_destroy,
    .nhvm_vcpu_reset      = nvmx_vcpu_reset,
    .nhvm_vcpu_guestcr3   = nvmx_vcpu_guestcr3,
    .nhvm_vcpu_hostcr3    = nvmx_vcpu_hostcr3,
    .nhvm_vcpu_asid       = nvmx_vcpu_asid,
    .nhvm_vmcx_guest_intercepts_trap = nvmx_intercepts_exception,
    .nhvm_vcpu_vmexit_trap = nvmx_vmexit_exceptions,
    .nhvm_intr_blocked    = nvmx_intr_blocked
#endif  /* __UXEN_NOT_YET__ */
};

struct hvm_function_table * __init start_vmx(void)
{
    if ( !test_bit(X86_FEATURE_VMXE, &boot_cpu_data.x86_capability) )
        return NULL;

    if (ax_setup())
        return NULL;

    if ( vmx_cpu_up(hvmon_default) )
    {
        printk("VMX: failed to initialise.\n");
        return NULL;
    }

    if ( cpu_has_vmx_ept )
    {
        vmx_function_table.hap_supported = 1;

        vmx_function_table.hap_capabilities = 0;

        if ( cpu_has_vmx_ept_2mb )
            vmx_function_table.hap_capabilities |= HVM_HAP_SUPERPAGE_2MB;
#ifndef __UXEN_NOT_YET__
        if ( cpu_has_vmx_ept_1gb )
            vmx_function_table.hap_capabilities |= HVM_HAP_SUPERPAGE_1GB;
#endif  /* __UXEN_NOT_YET__ */

        setup_ept_dump();
    }

    setup_vmcs_dump();

    setup_pv_vmx();

    if (cpu_has_spec_ctrl) {
        rdmsrl(MSR_IA32_SPEC_CTRL, host_msr_spec_ctrl);
        printk(XENLOG_INFO "SPEC CTRL: host (%lx) IBRS %sabled\n",
               host_msr_spec_ctrl,
               (host_msr_spec_ctrl & SPEC_CTRL_FEATURE_IBRS_mask) ?
               "en" : "dis");
        update_host_vm_ibrs = !ax_present;
    }

    return &vmx_function_table;
}

/*
 * Not all cases receive valid value in the VM-exit instruction length field.
 * Callers must know what they're doing!
 */
static int get_instruction_length(void)
{
    int len;
    len = __vmread(VM_EXIT_INSTRUCTION_LEN); /* Safe: callers audited */
    BUG_ON((len < 1) || (len > 15));
    return len;
}

static void update_guest_eip(void)
{
    struct cpu_user_regs *regs = guest_cpu_user_regs();
    unsigned long x;

    regs->eip += get_instruction_length(); /* Safe: callers audited */
    regs->eflags &= ~X86_EFLAGS_RF;

    x = __vmread(GUEST_INTERRUPTIBILITY_INFO);
    if ( x & (VMX_INTR_SHADOW_STI | VMX_INTR_SHADOW_MOV_SS) )
    {
        x &= ~(VMX_INTR_SHADOW_STI | VMX_INTR_SHADOW_MOV_SS);
        __vmwrite(GUEST_INTERRUPTIBILITY_INFO, x);
    }

    if ( regs->eflags & X86_EFLAGS_TF )
        vmx_inject_hw_exception(TRAP_debug, HVM_DELIVER_NO_ERROR_CODE);
}

static void vmx_fpu_dirty_intercept(void)
{
    struct vcpu *curr = current;

    vmx_fpu_enter(curr);

    /* Disable TS in guest CR0 unless the guest wants the exception too. */
    if ( !(curr->arch.hvm_vcpu.guest_cr[0] & X86_CR0_TS) )
    {
        curr->arch.hvm_vcpu.hw_cr[0] &= ~X86_CR0_TS;
        __vmwrite(GUEST_CR0, curr->arch.hvm_vcpu.hw_cr[0]);
    }
}

static void vmx_cpuid_intercept(
    unsigned int *eax, unsigned int *ebx,
    unsigned int *ecx, unsigned int *edx)
{
    unsigned int input = *eax;
    struct segment_register cs;
    struct vcpu *v = current;

    hvm_cpuid(input, eax, ebx, ecx, edx);

    switch ( input )
    {
        case 0x80000001:
            /* SYSCALL is visible iff running in long mode. */
            hvm_get_segment_register(v, x86_seg_cs, &cs);
            if ( cs.attr.fields.l )
                *edx |= cpufeat_mask(X86_FEATURE_SYSCALL);
            else
                *edx &= ~(cpufeat_mask(X86_FEATURE_SYSCALL));

            break;
    }

    HVMTRACE_5D (CPUID, input, *eax, *ebx, *ecx, *edx);
}

static void vmx_do_cpuid(struct cpu_user_regs *regs)
{
    unsigned int eax, ebx, ecx, edx;

    eax = regs->eax;
    ebx = regs->ebx;
    ecx = regs->ecx;
    edx = regs->edx;

    vmx_cpuid_intercept(&eax, &ebx, &ecx, &edx);

    regs->eax = eax;
    regs->ebx = ebx;
    regs->ecx = ecx;
    regs->edx = edx;
}

#define VMX_DEBUG_REG_ACCESS_NUM(eq)     ((eq) & 0x7)
#define VMX_DEBUG_REG_ACCESS_IS_READ(eq) ((eq) & (1<<4))
#define VMX_DEBUG_REG_ACCESS_GPR(eq)     (((eq) >> 8) & 0xf)
#ifdef __x86_64__
#define MAX_WIN7_USERMODE_ADDR (8ULL*1024ULL*1024ULL*1024ULL*1024ULL) //8TB
#else
#define MAX_WIN7_USERMODE_ADDR 0x80000000
#endif

static void vmx_dr_emul_write(int dr, unsigned long val)
{
    if (dr <= 3 && val > MAX_WIN7_USERMODE_ADDR)
        /* guest rootkit sets breakpoint on kernel address */
        send_introspection_ioreq(XEN_DOMCTL_INTROSPECTION_FEATURE_DR_BACKDOOR);

    switch (dr) {
        case 0:
            write_debugreg(0, val);
            break;
        case 1:
            write_debugreg(1, val);
            break;
        case 2:
            write_debugreg(2, val);
            break;
        case 3:
            write_debugreg(3, val);
            break;
        /* we sanitize dr6 writes, and dr7 just in case, to have top 32bits
           zeroed. Intel SDM does not hint about any other conditions when
           writing to DRx may cause an exception; VirtualBox relevant code
           does not do any checks, either. */
        case 6:
            write_debugreg(6, val&0xffffffff);
            break;
        case 7:
            __vmwrite(GUEST_DR7, val&0xffffffff);
            break;
        default:
            gdprintk(XENLOG_ERR, "invalid dr: %u ?\n", dr);
            domain_crash(current->domain);
    }
}

static void vmx_dr_emul_read(int dr, unsigned long *reg)
{
    switch (dr) {
        case 0:
            *reg = read_debugreg(0);
            break;
        case 1:
            *reg = read_debugreg(1);
            break;
        case 2:
            *reg = read_debugreg(2);
            break;
        case 3:
            *reg = read_debugreg(3);
            break;
        case 6:
            *reg = read_debugreg(6);
            break;
        case 7:
            *reg = __vmread(GUEST_DR7);
            break;
        default:
            gdprintk(XENLOG_ERR, "invalid dr: %u ?\n", dr);
            domain_crash(current->domain);
    }
}

static void vmx_dr_emul(unsigned long exit_qualification)
{
    int dr, gpr;
    /* get_x86_gpr is declared to work with long type */
    unsigned long *reg;

    dr = VMX_DEBUG_REG_ACCESS_NUM(exit_qualification);
    gpr = VMX_DEBUG_REG_ACCESS_GPR(exit_qualification);

    reg = get_x86_gpr(guest_cpu_user_regs(), gpr);
    if (!reg) {
        gdprintk(XENLOG_ERR, "invalid gpr: %u\n", gpr);
        domain_crash(current->domain);
        return;
    }

    if (VMX_DEBUG_REG_ACCESS_IS_READ(exit_qualification))
        vmx_dr_emul_read(dr, reg);
    else
        vmx_dr_emul_write(dr, *reg);

    update_guest_eip();
}

static void vmx_dr_access(unsigned long exit_qualification,
                          struct cpu_user_regs *regs)
{
    struct vcpu *v = current;

    HVMTRACE_0D(DR_WRITE);

    if ( !v->arch.hvm_vcpu.flag_dr_dirty )
        __restore_debug_registers(v);

    if (v->domain->introspection_features &
            XEN_DOMCTL_INTROSPECTION_FEATURE_DR_BACKDOOR)
        vmx_dr_emul(exit_qualification);
    else {
        /* If no need to monitor dr access for introspection, then
           Allow guest direct access to DR registers */
        v->arch.hvm_vmx.exec_control &= ~CPU_BASED_MOV_DR_EXITING;
        vmx_update_cpu_exec_control(v);
    }
}

static void vmx_invlpg_intercept(unsigned long vaddr)
{
    struct vcpu *curr = current;
DEBUG();
    HVMTRACE_LONG_2D(INVLPG, /*invlpga=*/ 0, TRC_PAR_LONG(vaddr));
    if ( paging_invlpg(curr, vaddr) && cpu_has_vmx_vpid )
        vpid_sync_vcpu_gva(curr, vaddr);
}

static int vmx_cr_access(unsigned long exit_qualification)
{
    struct vcpu *curr = current;

    switch ( VMX_CONTROL_REG_ACCESS_TYPE(exit_qualification) )
    {
    case VMX_CONTROL_REG_ACCESS_TYPE_MOV_TO_CR: {
        unsigned long gp = VMX_CONTROL_REG_ACCESS_GPR(exit_qualification);
        unsigned long cr = VMX_CONTROL_REG_ACCESS_NUM(exit_qualification);
        return hvm_mov_to_cr(cr, gp);
    }
    case VMX_CONTROL_REG_ACCESS_TYPE_MOV_FROM_CR: {
        unsigned long gp = VMX_CONTROL_REG_ACCESS_GPR(exit_qualification);
        unsigned long cr = VMX_CONTROL_REG_ACCESS_NUM(exit_qualification);
        return hvm_mov_from_cr(cr, gp);
    }
    case VMX_CONTROL_REG_ACCESS_TYPE_CLTS: {
#ifndef __UXEN__
        unsigned long old = curr->arch.hvm_vcpu.guest_cr[0];
#endif  /* __UXEN__ */
        curr->arch.hvm_vcpu.guest_cr[0] &= ~X86_CR0_TS;
        vmx_update_guest_cr(curr, 0);
#ifndef __UXEN__
        hvm_memory_event_cr0(curr->arch.hvm_vcpu.guest_cr[0], old);
#endif  /* __UXEN__ */
        HVMTRACE_0D(CLTS);
        break;
    }
    case VMX_CONTROL_REG_ACCESS_TYPE_LMSW: {
        unsigned long value = curr->arch.hvm_vcpu.guest_cr[0];
        /* LMSW can: (1) set bits 0-3; (2) clear bits 1-3. */
        value = (value & ~0xe) | ((exit_qualification >> 16) & 0xf);
        HVMTRACE_LONG_1D(LMSW, value);
        return hvm_set_cr0(value);
    }
    default:
        BUG();
    }

    return X86EMUL_OKAY;
}

static const struct lbr_info {
    u32 base, count;
} p4_lbr[] = {
    { MSR_P4_LER_FROM_LIP,          1 },
    { MSR_P4_LER_TO_LIP,            1 },
    { MSR_P4_LASTBRANCH_TOS,        1 },
    { MSR_P4_LASTBRANCH_0_FROM_LIP, NUM_MSR_P4_LASTBRANCH_FROM_TO },
    { MSR_P4_LASTBRANCH_0_TO_LIP,   NUM_MSR_P4_LASTBRANCH_FROM_TO },
    { 0, 0 }
}, c2_lbr[] = {
    { MSR_IA32_LASTINTFROMIP,       1 },
    { MSR_IA32_LASTINTTOIP,         1 },
    { MSR_C2_LASTBRANCH_TOS,        1 },
    { MSR_C2_LASTBRANCH_0_FROM_IP,  NUM_MSR_C2_LASTBRANCH_FROM_TO },
    { MSR_C2_LASTBRANCH_0_TO_IP,    NUM_MSR_C2_LASTBRANCH_FROM_TO },
    { 0, 0 }
}, nh_lbr[] = {
    { MSR_IA32_LASTINTFROMIP,       1 },
    { MSR_IA32_LASTINTTOIP,         1 },
    { MSR_C2_LASTBRANCH_TOS,        1 },
    { MSR_P4_LASTBRANCH_0_FROM_LIP, NUM_MSR_P4_LASTBRANCH_FROM_TO },
    { MSR_P4_LASTBRANCH_0_TO_LIP,   NUM_MSR_P4_LASTBRANCH_FROM_TO },
    { 0, 0 }
}, at_lbr[] = {
    { MSR_IA32_LASTINTFROMIP,       1 },
    { MSR_IA32_LASTINTTOIP,         1 },
    { MSR_C2_LASTBRANCH_TOS,        1 },
    { MSR_C2_LASTBRANCH_0_FROM_IP,  NUM_MSR_ATOM_LASTBRANCH_FROM_TO },
    { MSR_C2_LASTBRANCH_0_TO_IP,    NUM_MSR_ATOM_LASTBRANCH_FROM_TO },
    { 0, 0 }
#ifdef __i386__
}, pm_lbr[] = {
    { MSR_IA32_LASTINTFROMIP,       1 },
    { MSR_IA32_LASTINTTOIP,         1 },
    { MSR_PM_LASTBRANCH_TOS,        1 },
    { MSR_PM_LASTBRANCH_0,          NUM_MSR_PM_LASTBRANCH },
    { 0, 0 }
#endif
};

static const struct lbr_info *last_branch_msr_get(void)
{
    switch ( boot_cpu_data.x86 )
    {
    case 6:
        switch ( boot_cpu_data.x86_model )
        {
#ifdef __i386__
        /* PentiumM */
        case 9: case 13:
        /* Core Solo/Duo */
        case 14:
            return pm_lbr;
            break;
#endif
        /* Core2 Duo */
        case 15:
        /* Enhanced Core */
        case 23:
            return c2_lbr;
            break;
        /* Nehalem */
        case 26: case 30: case 31: case 46:
        /* Westmere */
        case 37: case 44: case 47:
        /* Sandy Bridge */
        case 42: case 45:
            return nh_lbr;
            break;
        /* Atom */
        case 28:
            return at_lbr;
            break;
        }
        break;

    case 15:
        switch ( boot_cpu_data.x86_model )
        {
        /* Pentium4/Xeon with em64t */
        case 3: case 4: case 6:
            return p4_lbr;
            break;
        }
        break;
    }

    return NULL;
}

static int is_last_branch_msr(u32 ecx)
{
    const struct lbr_info *lbr = last_branch_msr_get();

    if ( lbr == NULL )
        return 0;

    for ( ; lbr->count; lbr++ )
        if ( (ecx >= lbr->base) && (ecx < (lbr->base + lbr->count)) )
            return 1;

    return 0;
}

static int vmx_msr_read_intercept(unsigned int msr, uint64_t *msr_content)
{
    HVM_DBG_LOG(DBG_LEVEL_1, "ecx=%x", msr);

    switch ( msr )
    {
    case MSR_IA32_SYSENTER_CS:
        *msr_content = (u32)__vmread(GUEST_SYSENTER_CS);
        break;
    case MSR_IA32_SYSENTER_ESP:
        *msr_content = __vmread(GUEST_SYSENTER_ESP);
        break;
    case MSR_IA32_SYSENTER_EIP:
        *msr_content = __vmread(GUEST_SYSENTER_EIP);
        break;
    case MSR_IA32_DEBUGCTLMSR:
        *msr_content = __vmread(GUEST_IA32_DEBUGCTL);
#ifdef __i386__
        *msr_content |= (u64)__vmread(GUEST_IA32_DEBUGCTL_HIGH) << 32;
#endif
        break;
    case IA32_FEATURE_CONTROL_MSR:
    case MSR_IA32_VMX_BASIC...MSR_IA32_VMX_TRUE_ENTRY_CTLS:
#ifndef __UXEN_NOT_YET__
        if ( !nvmx_msr_read_intercept(msr, msr_content) )
#endif  /* __UXEN_NOT_YET__ */
            goto gp_fault;
        break;
    case MSR_IA32_MISC_ENABLE:
        rdmsrl(MSR_IA32_MISC_ENABLE, *msr_content);
        /* Debug Trace Store is not supported. */
        *msr_content |= MSR_IA32_MISC_ENABLE_BTS_UNAVAIL |
                       MSR_IA32_MISC_ENABLE_PEBS_UNAVAIL;
        /* XXX this should FALLTHROUGH with vPMU support */
        break;
    case MSR_P6_PERFCTR(0)...MSR_P6_PERFCTR(7):
    case MSR_P6_EVNTSEL(0)...MSR_P6_EVNTSEL(3):
    case MSR_CORE_PERF_FIXED_CTR0...MSR_CORE_PERF_FIXED_CTR2:
    case MSR_CORE_PERF_FIXED_CTR_CTRL...MSR_CORE_PERF_GLOBAL_OVF_CTRL:
    case MSR_IA32_PEBS_ENABLE:
    case MSR_IA32_DS_AREA:
        *msr_content = 0;       /* no vPMU */
        break;
    case MSR_IA32_SPEC_CTRL:
        *msr_content = current->arch.hvm_vcpu.msr_spec_ctrl;
        if (cpu_has_spec_ctrl && !current->arch.hvm_vcpu.use_spec_ctrl) {
            current->arch.hvm_vcpu.use_spec_ctrl = 1;
            vmx_disable_intercept_for_msr(current, MSR_IA32_SPEC_CTRL);
        } else
            goto gp_fault;
        break;
    default:
#ifndef __UXEN_NOT_YET__
        if ( vpmu_do_rdmsr(msr, msr_content) )
            break;
#endif  /* __UXEN_NOT_YET__ */
#ifndef __UXEN__
        if ( passive_domain_do_rdmsr(msr, msr_content) )
            goto done;
#endif  /* __UXEN__ */
        switch ( long_mode_do_msr_read(msr, msr_content) )
        {
            case HNDL_unhandled:
                break;
            case HNDL_exception_raised:
                return X86EMUL_EXCEPTION;
            case HNDL_done:
                goto done;
        }

#ifndef __UXEN__
        if ( vmx_read_guest_msr(msr, msr_content) == 0 )
            break;
#endif  /* __UXEN__ */

        if ( is_last_branch_msr(msr) )
        {
            *msr_content = 0;
            break;
        }

        if ( rdmsr_viridian_regs(msr, msr_content) ||
             rdmsr_hypervisor_regs(msr, msr_content) )
            break;

        if ( ax_present && msr != MSR_INTEL_PLATFORM_INFO &&
             msr != MSR_INTEL_TEMPERATURE_TARGET &&
             msr != MSR_INTEL_TURBO_RATIO_LIMIT )
        {
            printk("GP fault for rdmsr(%x)\n", msr);
            goto gp_fault;
        }

        if ( rdmsr_safe(msr, *msr_content) == 0 )
            break;

        goto gp_fault;
    }

done:
    HVM_DBG_LOG(DBG_LEVEL_1, "returns: ecx=%x, msr_value=0x%"PRIx64,
                msr, *msr_content);
    return X86EMUL_OKAY;

gp_fault:
    vmx_inject_hw_exception(TRAP_gp_fault, 0);
    return X86EMUL_EXCEPTION;
}

static int vmx_alloc_vlapic_mapping(struct domain *d)
{
    void *apic_va;

    if ( !cpu_has_vmx_virtualize_apic_accesses )
        return 0;

    apic_va = alloc_xenheap_page();
    if ( apic_va == NULL )
        return -ENOMEM;
    share_xen_page_with_guest(virt_to_page(apic_va), d, XENSHARE_writable);
    set_mmio_p2m_entry(d, paddr_to_pfn(APIC_DEFAULT_PHYS_BASE),
        _mfn(virt_to_mfn(apic_va)));
    d->arch.hvm_domain.vmx.apic_access_va = apic_va;

    return 0;
}

static void vmx_free_vlapic_mapping(struct domain *d)
{
    void *va = d->arch.hvm_domain.vmx.apic_access_va;
    if (va)
        free_xenheap_page(va);
}

static void vmx_install_vlapic_mapping(struct vcpu *v)
{
    paddr_t virt_page_ma, apic_page_ma;

    if ( !cpu_has_vmx_virtualize_apic_accesses )
        return;

    virt_page_ma = page_to_maddr(vcpu_vlapic(v)->regs_page);
    apic_page_ma = virt_to_mfn(v->domain->arch.hvm_domain.vmx.apic_access_va);
    apic_page_ma <<= PAGE_SHIFT;

    vmx_vmcs_enter(v);
    __vmwrite(VIRTUAL_APIC_PAGE_ADDR, virt_page_ma);
    __vmwrite(APIC_ACCESS_ADDR, apic_page_ma);
    vmx_vmcs_exit(v);
}

void vmx_vlapic_msr_changed(struct vcpu *v)
{
    struct vlapic *vlapic = vcpu_vlapic(v);

    if ( !cpu_has_vmx_virtualize_apic_accesses )
        return;

    vmx_vmcs_enter(v);
    v->arch.hvm_vmx.secondary_exec_control &=
        ~SECONDARY_EXEC_VIRTUALIZE_APIC_ACCESSES;
    if ( !vlapic_hw_disabled(vlapic) &&
         (vlapic_base_address(vlapic) == APIC_DEFAULT_PHYS_BASE) )
        v->arch.hvm_vmx.secondary_exec_control |=
            SECONDARY_EXEC_VIRTUALIZE_APIC_ACCESSES;
    vmx_update_secondary_exec_control(v);
    vmx_vmcs_exit(v);
}

static int vmx_msr_write_intercept(unsigned int msr, uint64_t msr_content)
{
#ifndef __UXEN__
    struct vcpu *v = current;
#endif  /* __UXEN__ */
    int r;

    HVM_DBG_LOG(DBG_LEVEL_1, "ecx=%x, msr_value=0x%"PRIx64,
                msr, msr_content);

    switch ( msr )
    {
    case MSR_IA32_SYSENTER_CS:
        __vmwrite(GUEST_SYSENTER_CS, msr_content);
        break;
    case MSR_IA32_SYSENTER_ESP:
        __vmwrite(GUEST_SYSENTER_ESP, msr_content);
        break;
    case MSR_IA32_SYSENTER_EIP:
        __vmwrite(GUEST_SYSENTER_EIP, msr_content);
        break;
    case MSR_IA32_DEBUGCTLMSR: {
#ifndef __UXEN__
        int i, rc = 0;

        if ( !msr_content || (msr_content & ~3) )
            break;

        if ( msr_content & 1 )
        {
            const struct lbr_info *lbr = last_branch_msr_get();
            if ( lbr == NULL )
                break;

            for ( ; (rc == 0) && lbr->count; lbr++ )
                for ( i = 0; (rc == 0) && (i < lbr->count); i++ )
                    if ( (rc = vmx_add_guest_msr(lbr->base + i)) == 0 )
                        vmx_disable_intercept_for_msr(v, lbr->base + i);
        }

        if ( (rc < 0) ||
             (vmx_add_host_load_msr(msr) < 0) )
            vmx_inject_hw_exception(TRAP_machine_check, 0);
        else
        {
            __vmwrite(GUEST_IA32_DEBUGCTL, msr_content);
#ifdef __i386__
            __vmwrite(GUEST_IA32_DEBUGCTL_HIGH, msr_content >> 32);
#endif
        }
#endif  /* __UXEN__ */

        break;
    }
    case IA32_FEATURE_CONTROL_MSR:
    case MSR_IA32_VMX_BASIC...MSR_IA32_VMX_TRUE_ENTRY_CTLS:
#ifndef __UXEN_NOT_YET__
        if ( !nvmx_msr_write_intercept(msr, msr_content) )
#endif  /* __UXEN_NOT_YET__ */
            goto gp_fault;
        break;
     case MSR_P6_PERFCTR(0)...MSR_P6_PERFCTR(7):
     case MSR_P6_EVNTSEL(0)...MSR_P6_EVNTSEL(7):
     case MSR_CORE_PERF_FIXED_CTR0...MSR_CORE_PERF_FIXED_CTR2:
     case MSR_CORE_PERF_FIXED_CTR_CTRL...MSR_CORE_PERF_GLOBAL_OVF_CTRL:
     case MSR_IA32_PEBS_ENABLE:
     case MSR_IA32_DS_AREA:
         /* no vPMU */
         break;
    case MSR_IA32_SPEC_CTRL:
        current->arch.hvm_vcpu.msr_spec_ctrl = msr_content;
        if (cpu_has_spec_ctrl && !current->arch.hvm_vcpu.use_spec_ctrl) {
            current->arch.hvm_vcpu.use_spec_ctrl = 1;
            vmx_disable_intercept_for_msr(current, MSR_IA32_SPEC_CTRL);
        } else
            goto gp_fault;
        break;
    default:
#ifndef __UXEN_NOT_YET__
        if ( vpmu_do_wrmsr(msr, msr_content) )
            return X86EMUL_OKAY;
#endif  /* __UXEN_NOT_YET__ */
#ifndef __UXEN__
        if ( passive_domain_do_wrmsr(msr, msr_content) )
            return X86EMUL_OKAY;
#endif  /* __UXEN__ */

        r = wrmsr_viridian_regs(msr, msr_content);
        if (r == -1)
            return X86EMUL_RETRY;
        if (r)
            break;

        switch ( long_mode_do_msr_write(msr, msr_content) )
        {
            case HNDL_unhandled:
                if (
#ifndef __UXEN__
                     (vmx_write_guest_msr(msr, msr_content) != 0) &&
#endif  /* __UXEN__ */
                     !is_last_branch_msr(msr) ) {
                    if (wrmsr_hypervisor_regs(msr, msr_content) == -1)
                        return X86EMUL_RETRY;
                }
                break;
            case HNDL_exception_raised:
                return X86EMUL_EXCEPTION;
            case HNDL_done:
                break;
        }
        break;
    }

    return X86EMUL_OKAY;

gp_fault:
    vmx_inject_hw_exception(TRAP_gp_fault, 0);
    return X86EMUL_EXCEPTION;
}

static void vmx_do_extint(struct cpu_user_regs *regs)
{
#ifndef __UXEN__
    unsigned int vector;

    vector = __vmread(VM_EXIT_INTR_INFO);
    BUG_ON(!(vector & INTR_INFO_VALID_MASK));

    vector &= INTR_INFO_VECTOR_MASK;
    HVMTRACE_1D(INTR, vector);

    switch ( vector )
    {
    case IRQ_MOVE_CLEANUP_VECTOR:
        smp_irq_move_cleanup_interrupt(regs);
        break;
    case LOCAL_TIMER_VECTOR:
        smp_apic_timer_interrupt(regs);
        break;
    case EVENT_CHECK_VECTOR:
        smp_event_check_interrupt(regs);
        break;
    case INVALIDATE_TLB_VECTOR:
        smp_invalidate_interrupt();
        break;
    case CALL_FUNCTION_VECTOR:
        smp_call_function_interrupt(regs);
        break;
    case SPURIOUS_APIC_VECTOR:
        smp_spurious_interrupt(regs);
        break;
    case ERROR_APIC_VECTOR:
        smp_error_interrupt(regs);
        break;
    case CMCI_APIC_VECTOR:
        smp_cmci_interrupt(regs);
        break;
    case PMU_APIC_VECTOR:
        smp_pmu_apic_interrupt(regs);
        break;
#ifdef CONFIG_X86_MCE_THERMAL
    case THERMAL_APIC_VECTOR:
        smp_thermal_interrupt(regs);
        break;
#endif
    default:
        regs->entry_vector = vector;
        do_IRQ(regs);
        break;
    }
#else   /* __UXEN__ */
    perfc_incr(external_int_exit);
#endif  /* __UXEN__ */
}

#ifndef __UXEN__
static void wbinvd_ipi(void *info)
{
DEBUG();
    wbinvd();
}
#endif  /* __UXEN__ */

static void vmx_wbinvd_intercept(void)
{
#ifndef __UXEN__
    if ( !has_arch_mmios(current->domain) )
        return;

#ifndef __UXEN__
    if ( iommu_snoop )
        return;
#endif  /* __UXEN__ */

    if ( cpu_has_wbinvd_exiting )
        on_each_cpu(wbinvd_ipi, NULL, 1);
    else
        wbinvd();
#else  /* __UXEN__ */
    return;
#endif  /* __UXEN__ */
}

static void
ept_handle_violation(unsigned long qualification, paddr_t gpa)
{
    unsigned long gla, gfn = gpa >> PAGE_SHIFT;
    mfn_t mfn;
    p2m_type_t p2mt;
    struct domain *d = current->domain;

    if ( tb_init_done )
    {
        struct {
            uint64_t gpa;
            uint64_t mfn;
            u32 qualification;
            u32 p2mt;
        } _d;

        _d.gpa = gpa;
        _d.qualification = qualification;
        _d.mfn = mfn_x(get_gfn_query_unlocked(d, gfn, &_d.p2mt));
        
        __trace_var(TRC_HVM_NPF, 0, sizeof(_d), &_d);
    }

    if ( hvm_hap_nested_page_fault(gpa,
                                   qualification & EPT_GLA_VALID       ? 1 : 0,
                                   qualification & EPT_GLA_VALID
                                     ? __vmread(GUEST_LINEAR_ADDRESS) : ~0ull,
                                   qualification & EPT_READ_VIOLATION  ? 1 : 0,
                                   qualification & EPT_WRITE_VIOLATION ? 1 : 0,
                                   qualification & EPT_EXEC_VIOLATION  ? 1 : 0) )
        return;

    /* Everything else is an error. */
    mfn = get_gfn_guest_unlocked(d, gfn, &p2mt);
    gdprintk(XENLOG_ERR, "EPT violation %#lx (%c%c%c/%c%c%c), "
             "gpa %#"PRIpaddr", mfn %#lx, type %i.\n", 
             qualification, 
             (qualification & EPT_READ_VIOLATION) ? 'r' : '-',
             (qualification & EPT_WRITE_VIOLATION) ? 'w' : '-',
             (qualification & EPT_EXEC_VIOLATION) ? 'x' : '-',
             (qualification & EPT_EFFECTIVE_READ) ? 'r' : '-',
             (qualification & EPT_EFFECTIVE_WRITE) ? 'w' : '-',
             (qualification & EPT_EFFECTIVE_EXEC) ? 'x' : '-',
             gpa, mfn_x(mfn), p2mt);

    ept_walk_table(d, gfn);

    if ( qualification & EPT_GLA_VALID )
    {
        gla = __vmread(GUEST_LINEAR_ADDRESS);
        gdprintk(XENLOG_ERR, " --- GLA %#lx\n", gla);
    }

    if (ax_present)
        return;

    domain_crash(d);
}

static void vmx_failed_vmentry(unsigned int exit_reason,
                               struct cpu_user_regs *regs)
{
    unsigned int failed_vmentry_reason = (uint16_t)exit_reason;
    unsigned long exit_qualification = __vmread(EXIT_QUALIFICATION);
    struct vcpu *curr = current;

    printk("Failed vm entry (exit reason 0x%x) ", exit_reason);
    switch ( failed_vmentry_reason )
    {
    case EXIT_REASON_INVALID_GUEST_STATE:
        printk("caused by invalid guest state (%ld).\n", exit_qualification);
        break;
    case EXIT_REASON_MSR_LOADING:
        printk("caused by MSR entry %ld loading.\n", exit_qualification);
        break;
    case EXIT_REASON_MCE_DURING_VMENTRY:
        printk("caused by machine check.\n");
        HVMTRACE_0D(MCE);
        /* Already handled. */
        break;
    default:
        printk("reason not known yet!");
        break;
    }

    printk("************* VMCS Area **************\n");
    vmcs_dump_vcpu(curr);
    printk("**************************************\n");

    domain_crash(curr->domain);
}

asmlinkage_abi void vmx_enter_realmode(struct cpu_user_regs *regs)
{
    struct vcpu *v = current;

    /* Adjust RFLAGS to enter virtual 8086 mode with IOPL == 3.  Since
     * we have CR4.VME == 1 and our own TSS with an empty interrupt
     * redirection bitmap, all software INTs will be handled by vm86 */
    v->arch.hvm_vmx.vm86_saved_eflags = regs->eflags;
    regs->eflags |= (X86_EFLAGS_VM | X86_EFLAGS_IOPL);
}

static void vmx_vmexit_ud_intercept(struct cpu_user_regs *regs)
{
    struct hvm_emulate_ctxt ctxt;
    int rc;

    hvm_emulate_prepare(&ctxt, regs);

    rc = hvm_emulate_one(&ctxt);

    switch ( rc )
    {
    case X86EMUL_UNHANDLEABLE:
        vmx_inject_hw_exception(TRAP_invalid_op, HVM_DELIVER_NO_ERROR_CODE);
        break;
    case X86EMUL_EXCEPTION:
        if ( ctxt.exn_pending )
            hvm_inject_exception(ctxt.exn_vector, ctxt.exn_error_code, 0);
        /* fall through */
    default:
        hvm_emulate_writeback(&ctxt);
        break;
    }
}

static int vmx_handle_eoi_write(void)
{
    unsigned long exit_qualification = __vmread(EXIT_QUALIFICATION);

    /*
     * 1. Must be a linear access data write.
     * 2. Data write must be to the EOI register.
     */
    if ( (((exit_qualification >> 12) & 0xf) == 1) &&
         ((exit_qualification & 0xfff) == APIC_EOI) )
    {
        update_guest_eip(); /* Safe: APIC data write */
        vlapic_EOI_set(vcpu_vlapic(current));
        return 1;
    }

    return 0;
}

static void vmx_idtv_reinject(unsigned long idtv_info)
{

    /* Event delivery caused this intercept? Queue for redelivery. */
    if ( unlikely(idtv_info & INTR_INFO_VALID_MASK) )
    {
        if ( hvm_event_needs_reinjection((idtv_info>>8)&7, idtv_info&0xff) )
        {
            /* See SDM 3B 25.7.1.1 and .2 for info about masking resvd bits. */
            __vmwrite(VM_ENTRY_INTR_INFO,
                      idtv_info & ~INTR_INFO_RESVD_BITS_MASK);
            if ( idtv_info & INTR_INFO_DELIVER_CODE_MASK )
                __vmwrite(VM_ENTRY_EXCEPTION_ERROR_CODE,
                          __vmread(IDT_VECTORING_ERROR_CODE));
        }

        /*
         * Clear NMI-blocking interruptibility info if an NMI delivery faulted.
         * Re-delivery will re-set it (see SDM 3B 25.7.1.2).
         */
        if ( (idtv_info & INTR_INFO_INTR_TYPE_MASK) == (X86_EVENTTYPE_NMI<<8) )
            __vmwrite(GUEST_INTERRUPTIBILITY_INFO,
                      __vmread(GUEST_INTERRUPTIBILITY_INFO) &
                      ~VMX_INTR_SHADOW_NMI);
    }
}

static int introspection_page_fault(struct vcpu *v,
                                    unsigned long exit_qualification,
                                    struct cpu_user_regs *regs)
{

    gdprintk(XENLOG_ERR, "page_fault, rip 0x%lx"
             ", introspection_features=0x%"PRIx64"\n",
             (unsigned long)regs->eip, v->domain->introspection_features);

    if (v->domain->introspection_features &
        XEN_DOMCTL_INTROSPECTION_FEATURE_SMEP_OFF) {
        v->arch.hvm_vcpu.guest_cr[2] = exit_qualification;
        vmx_inject_hw_exception(TRAP_page_fault, regs->error_code);
        return 1; /* handled */
    }

    if (v->domain->introspection_features &
        XEN_DOMCTL_INTROSPECTION_FEATURE_SMEP) {
        unsigned int guest_cs = __vmread(GUEST_CS_SELECTOR);

        gdprintk(XENLOG_ERR, "page_fault, smep on, cs=0x%x\n", guest_cs);

        /* We are mostly interested in kernel mode PF with usermode RIP. */
        if (
#ifdef __x86_64__
            (regs->rip>>48) != 0xffff
#else
            (regs->eip) < 0xc0000000
#endif
            && (guest_cs&3) == 0) {
            /* SMEP violation */
            /* We turn off SMEP permanently, to let the instruction reexecute;
             * and to not flood with alerts.
             * Unfortunately, it seems it is not possible to change PFEC_MASK
             * and PFEC_MATCH on live vmcs - so we still will have to handle
             * DEP faults. */
            v->domain->introspection_features |=
                XEN_DOMCTL_INTROSPECTION_FEATURE_SMEP_OFF;
            hvm_update_guest_cr(v, 4); /* this switches off SMEP bit */
            send_introspection_ioreq(XEN_DOMCTL_INTROSPECTION_FEATURE_SMEP);
        } else {
            /* Usermode DEP violation - forward to the guest */
            v->arch.hvm_vcpu.guest_cr[2] = exit_qualification;
            vmx_inject_hw_exception(TRAP_page_fault, regs->error_code);
        }
        return 1; /* handled */
    }
    return 0; /* not handled, do the usual #PF processing */
}

int uxen_dump_vmcs = 0;

static void
vmx_execute(struct vcpu *v)
{
    unsigned int exit_reason, idtv_info, intr_info = 0, vector = 0;
    unsigned long exit_qualification, inst_len = 0;
#ifdef __UXEN__
    struct cpu_user_regs *regs = guest_cpu_user_regs();
#endif  /* __UXEN__ */

    ASSERT(v);

    if ( paging_mode_hap(v->domain) ) {
        struct p2m_domain *p2m = p2m_get_hostp2m(v->domain);
        p2m->virgin = 0;
    }

    if (vmx_asm_do_vmentry(v))
        return;

    if ( paging_mode_hap(v->domain) && hvm_paging_enabled(v) )
        v->arch.hvm_vcpu.guest_cr[3] = v->arch.hvm_vcpu.hw_cr[3] =
            __vmread(GUEST_CR3);

    exit_reason = !vmx_vmcs_late_load ? __vmread(VM_EXIT_REASON) :
        v->arch.hvm_vmx.exit_reason;

    if ( hvm_long_mode_enabled(v) )
        HVMTRACE_ND(VMEXIT64, 0, 1/*cycles*/, 3, exit_reason,
                    (uint32_t)regs->eip, (uint32_t)((uint64_t)regs->eip >> 32),
                    0, 0, 0);
    else
        HVMTRACE_ND(VMEXIT, 0, 1/*cycles*/, 2, exit_reason,
                    (uint32_t)regs->eip, 
                    0, 0, 0, 0);

    perfc_incra(vmexits, exit_reason);

    /* Handle the interrupt we missed before allowing any more in. */
    switch ( (uint16_t)exit_reason )
    {
    case EXIT_REASON_EXTERNAL_INTERRUPT:
        vmx_do_extint(regs);
        v->force_preempt = 1;
        break;
    case EXIT_REASON_EXCEPTION_NMI:
        intr_info = __vmread(VM_EXIT_INTR_INFO);
        BUG_ON(!(intr_info & INTR_INFO_VALID_MASK));
        vector = intr_info & INTR_INFO_VECTOR_MASK;
        if ( vector == TRAP_machine_check )
            do_machine_check(regs);
        else if ( vector == TRAP_nmi &&
                  (intr_info & INTR_INFO_INTR_TYPE_MASK) ==
                  (X86_EVENTTYPE_NMI << 8) ) {
            /* self-inject NMI early, to allow logging via windbg --
             * DO NOT do any logging between return from
             * vmx_asm_do_vmentry and here! */
            if (!ax_present) {
                HVMTRACE_0D(NMI);
                self_nmi(); /* Real NMI, vector 2: normal processing. */
            } else
                v->force_preempt = 1;
        }
        break;
    case EXIT_REASON_MCE_DURING_VMENTRY:
        do_machine_check(regs);
        break;
    }

    /* Now enable interrupts so it's safe to take locks. */
    cpu_irq_enable();
    BUG_ON(!local_irq_is_enabled());

    if (exit_reason < ARRAY_SIZE(v->vmexit_reason_count)) {
        v->vmexit_reason_count[(uint16_t)exit_reason]++;
        if ((v->vmexit_reason_count[(uint16_t)exit_reason] % 500000) == 0) {
            extern bool_t verbose_exit_reason;

            printk("vm%u.%u: 500k reason %d\n", v->domain->domain_id,
                   v->vcpu_id, (uint16_t)exit_reason);
            if (verbose_exit_reason)
                show_execution_state(regs);
        }
    }

#if defined(__UXEN__)
    if (uxen_dump_vmcs && (exit_reason != EXIT_REASON_IO_INSTRUCTION ||
                           (regs->edx != 0xe9 && regs->edx != 0x3f8 &&
                            regs->edx != 0x3fd))) {
        vmcs_mini_dump_vcpu("debug", v, exit_reason);
        uxen_dump_vmcs--;
    }
#endif  /* __UXEN__ */
    /* XXX: This looks ugly, but we need a mechanism to ensure
     * any pending vmresume has really happened
     */
#ifndef __UXEN_NOT_YET__
    vcpu_nestedhvm(v).nv_vmswitch_in_progress = 0;
    if ( nestedhvm_vcpu_in_guestmode(v) )
    {
        if ( nvmx_n2_vmexit_handler(regs, exit_reason) )
            goto out;
    }
#endif  /* __UXEN_NOT_YET__ */

    if ( unlikely(exit_reason & VMX_EXIT_REASONS_FAILED_VMENTRY) )
        return vmx_failed_vmentry(exit_reason, regs);

    if ( v->arch.hvm_vmx.vmx_realmode )
    {
        /* Put RFLAGS back the way the guest wants it */
        regs->eflags &= ~(X86_EFLAGS_VM | X86_EFLAGS_IOPL);
        regs->eflags |= (v->arch.hvm_vmx.vm86_saved_eflags & X86_EFLAGS_IOPL);

        /* Unless this exit was for an interrupt, we've hit something
         * vm86 can't handle.  Try again, using the emulator. */
        switch ( exit_reason )
        {
        case EXIT_REASON_EXCEPTION_NMI:
            if ( vector != TRAP_page_fault
                 && vector != TRAP_nmi 
                 && vector != TRAP_machine_check ) 
            {
                perfc_incr(realmode_exits);
                v->arch.hvm_vmx.vmx_emulate = 1;
                return;
            }
        case EXIT_REASON_EXTERNAL_INTERRUPT:
        case EXIT_REASON_INIT:
        case EXIT_REASON_SIPI:
        case EXIT_REASON_PENDING_VIRT_INTR:
        case EXIT_REASON_PENDING_VIRT_NMI:
        case EXIT_REASON_MCE_DURING_VMENTRY:
        case EXIT_REASON_GETSEC:
        case EXIT_REASON_ACCESS_GDTR_OR_IDTR:
        case EXIT_REASON_ACCESS_LDTR_OR_TR:
        case EXIT_REASON_VMX_PREEMPTION_TIMER_EXPIRED:
        case EXIT_REASON_INVEPT:
        case EXIT_REASON_INVVPID:
            break;

        default:
            v->arch.hvm_vmx.vmx_emulate = 1;
            perfc_incr(realmode_exits);
            return;
        }
    }

#ifndef __UXEN__
    hvm_maybe_deassert_evtchn_irq();
#endif  /* __UXEN__ */

    idtv_info = __vmread(IDT_VECTORING_INFO);
    if (
#ifndef __UXEN_NOT_YET__
         !nestedhvm_vcpu_in_guestmode(v) && 
#endif  /* __UXEN_NOT_YET__ */
         exit_reason != EXIT_REASON_TASK_SWITCH )
        vmx_idtv_reinject(idtv_info);

    switch ( exit_reason )
    {
    case EXIT_REASON_EXCEPTION_NMI:
    {
        /*
         * We don't set the software-interrupt exiting (INT n).
         * (1) We can get an exception (e.g. #PG) in the guest, or
         * (2) NMI
         */

        /*
         * Re-set the NMI shadow if vmexit caused by a guest IRET fault (see 3B
         * 25.7.1.2, "Resuming Guest Software after Handling an Exception").
         * (NB. If we emulate this IRET for any reason, we should re-clear!)
         */
        if ( unlikely(intr_info & INTR_INFO_NMI_UNBLOCKED_BY_IRET) &&
             !(idtv_info & INTR_INFO_VALID_MASK) &&
             (vector != TRAP_double_fault) )
            __vmwrite(GUEST_INTERRUPTIBILITY_INFO,
                      __vmread(GUEST_INTERRUPTIBILITY_INFO)
                      | VMX_INTR_SHADOW_NMI);

        perfc_incra(cause_vector, vector);

        switch ( vector )
        {
        case TRAP_debug:
            /*
             * Updates DR6 where debugger can peek (See 3B 23.2.1,
             * Table 23-1, "Exit Qualification for Debug Exceptions").
             */
            exit_qualification = __vmread(EXIT_QUALIFICATION);
            write_debugreg(6, exit_qualification | 0xffff0ff0);
            if ( !v->domain->debugger_attached )
                hvm_inject_exception(vector, HVM_DELIVER_NO_ERROR_CODE, 0);
            else
                domain_pause_for_debugger();
            break;
        case TRAP_int3: 
        {
            if ( v->domain->debugger_attached )
            {
                update_guest_eip(); /* Safe: INT3 */            
                current->arch.gdbsx_vcpu_event = TRAP_int3;
                domain_pause_for_debugger();
                break;
            }
            else {
#ifndef __UXEN__
                int handled = hvm_memory_event_int3(regs->eip);
                
                if ( handled < 0 ) 
                {
                    vmx_inject_exception(TRAP_int3, HVM_DELIVER_NO_ERROR_CODE, 0);
                    break;
                }
                else if ( handled )
                    break;
#else   /* __UXEN__ */
                vmx_inject_exception(TRAP_int3, HVM_DELIVER_NO_ERROR_CODE, 0);
                break;
#endif  /* __UXEN__ */
            }

            goto exit_and_crash;
        }
        case TRAP_no_device:
            vmx_fpu_dirty_intercept();
            break;
        case TRAP_page_fault:
            exit_qualification = __vmread(EXIT_QUALIFICATION);
            regs->error_code = __vmread(VM_EXIT_INTR_ERROR_CODE);

            if (introspection_page_fault(v, exit_qualification, regs))
                break;
            HVM_DBG_LOG(DBG_LEVEL_VMMU,
                        "eax=%lx, ebx=%lx, ecx=%lx, edx=%lx, esi=%lx, edi=%lx",
                        (unsigned long)regs->eax, (unsigned long)regs->ebx,
                        (unsigned long)regs->ecx, (unsigned long)regs->edx,
                        (unsigned long)regs->esi, (unsigned long)regs->edi);

            if ( paging_fault(exit_qualification, regs) )
            {
                if ( trace_will_trace_event(TRC_SHADOW) )
                    break;
                if ( hvm_long_mode_enabled(v) )
                    HVMTRACE_LONG_2D(PF_XEN, regs->error_code,
                                     TRC_PAR_LONG(exit_qualification) );
                else
                    HVMTRACE_2D(PF_XEN,
                                regs->error_code, exit_qualification );
                break;
            }

            v->arch.hvm_vcpu.guest_cr[2] = exit_qualification;
            vmx_inject_hw_exception(TRAP_page_fault, regs->error_code);
            break;
        case TRAP_alignment_check:
            hvm_inject_exception(vector, __vmread(VM_EXIT_INTR_ERROR_CODE), 0);
            break;
        case TRAP_nmi:
            if ( (intr_info & INTR_INFO_INTR_TYPE_MASK) !=
                 (X86_EVENTTYPE_NMI << 8) )
                goto exit_and_crash;
            /* NMI inject already done above */
            break;
        case TRAP_machine_check:
            HVMTRACE_0D(MCE);
            /* Already handled above. */
            break;
        case TRAP_invalid_op:
            vmx_vmexit_ud_intercept(regs);
            break;
        default:
            goto exit_and_crash;
        }
        break;
    }
    case EXIT_REASON_EXTERNAL_INTERRUPT:
        /* Already handled above. */
        break;
    case EXIT_REASON_TRIPLE_FAULT:
#ifdef __UXEN__
        vmcs_mini_dump_vcpu("triple fault", v, exit_reason);
#endif  /* __UXEN__ */
        hvm_triple_fault();
        break;
    case EXIT_REASON_PENDING_VIRT_INTR:
        /* Disable the interrupt window. */
        v->arch.hvm_vmx.exec_control &= ~CPU_BASED_VIRTUAL_INTR_PENDING;
        vmx_update_cpu_exec_control(v);
        break;
    case EXIT_REASON_PENDING_VIRT_NMI:
        /* Disable the NMI window. */
        v->arch.hvm_vmx.exec_control &= ~CPU_BASED_VIRTUAL_NMI_PENDING;
        vmx_update_cpu_exec_control(v);
        break;
    case EXIT_REASON_TASK_SWITCH: {
        const enum hvm_task_switch_reason reasons[] = {
            TSW_call_or_int, TSW_iret, TSW_jmp, TSW_call_or_int };
        int32_t ecode = -1, source;
        exit_qualification = __vmread(EXIT_QUALIFICATION);
        source = (exit_qualification >> 30) & 3;
        /* Vectored event should fill in interrupt information. */
        WARN_ON((source == 3) && !(idtv_info & INTR_INFO_VALID_MASK));
        /*
         * In the following cases there is an instruction to skip over:
         *  - TSW is due to a CALL, IRET or JMP instruction.
         *  - TSW is a vectored event due to a SW exception or SW interrupt.
         */
        inst_len = ((source != 3) ||        /* CALL, IRET, or JMP? */
                    (idtv_info & (1u<<10))) /* IntrType > 3? */
            ? get_instruction_length() /* Safe: SDM 3B 23.2.4 */ : 0;
        if ( (source == 3) && (idtv_info & INTR_INFO_DELIVER_CODE_MASK) )
            ecode = __vmread(IDT_VECTORING_ERROR_CODE);
        regs->eip += inst_len;
        hvm_task_switch((uint16_t)exit_qualification, reasons[source], ecode);
        break;
    }
    case EXIT_REASON_CPUID:
        update_guest_eip(); /* Safe: CPUID */
        vmx_do_cpuid(regs);
        break;
    case EXIT_REASON_HLT:
        update_guest_eip(); /* Safe: HLT */
        hvm_hlt(regs->eflags);
        break;
    case EXIT_REASON_INVLPG:
        update_guest_eip(); /* Safe: INVLPG */
        exit_qualification = __vmread(EXIT_QUALIFICATION);
        vmx_invlpg_intercept(exit_qualification);
        break;
    case EXIT_REASON_RDTSCP:
        regs->ecx = hvm_msr_tsc_aux(v);
        /* fall through */
    case EXIT_REASON_RDTSC:
        update_guest_eip(); /* Safe: RDTSC, RDTSCP */
        hvm_rdtsc_intercept(regs);
        break;
    case EXIT_REASON_VMCALL:
    {
        int rc;
        HVMTRACE_1D(VMMCALL, regs->eax);
        rc = hvm_do_hypercall(regs);
        if ( rc != HVM_HCALL_preempted )
        {
            update_guest_eip(); /* Safe: VMCALL */
#ifndef __UXEN__
            if ( rc == HVM_HCALL_invalidate )
                send_invalidate_req();
#endif  /* __UXEN__ */
        }
        break;
    }
    case EXIT_REASON_CR_ACCESS:
    {
        exit_qualification = __vmread(EXIT_QUALIFICATION);
        if ( vmx_cr_access(exit_qualification) == X86EMUL_OKAY )
            update_guest_eip(); /* Safe: MOV Cn, LMSW, CLTS */
        break;
    }
    case EXIT_REASON_DR_ACCESS:
        exit_qualification = __vmread(EXIT_QUALIFICATION);
        vmx_dr_access(exit_qualification, regs);
        break;
    case EXIT_REASON_MSR_READ:
    {
        uint64_t msr_content;
        if ( hvm_msr_read_intercept(regs->ecx, &msr_content) == X86EMUL_OKAY )
        {
            regs->eax = (uint32_t)msr_content;
            regs->edx = (uint32_t)(msr_content >> 32);
            update_guest_eip(); /* Safe: RDMSR */
        }
        break;
    }
    case EXIT_REASON_MSR_WRITE:
    {
        uint64_t msr_content;
        msr_content = ((uint64_t)regs->edx << 32) | (uint32_t)regs->eax;
        if ( hvm_msr_write_intercept(regs->ecx, msr_content) == X86EMUL_OKAY )
            update_guest_eip(); /* Safe: WRMSR */
        break;
    }

    case EXIT_REASON_VMXOFF:
#ifndef __UXEN_NOT_YET__
        if ( nvmx_handle_vmxoff(regs) == X86EMUL_OKAY )
            update_guest_eip();
#endif  /* __UXEN_NOT_YET__ */
        break;

    case EXIT_REASON_VMXON:
#ifndef __UXEN_NOT_YET__
        if ( nvmx_handle_vmxon(regs) == X86EMUL_OKAY )
            update_guest_eip();
#endif  /* __UXEN_NOT_YET__ */
        break;

    case EXIT_REASON_VMCLEAR:
#ifndef __UXEN_NOT_YET__
        if ( nvmx_handle_vmclear(regs) == X86EMUL_OKAY )
            update_guest_eip();
#endif  /* __UXEN_NOT_YET__ */
        break;
 
    case EXIT_REASON_VMPTRLD:
#ifndef __UXEN_NOT_YET__
        if ( nvmx_handle_vmptrld(regs) == X86EMUL_OKAY )
            update_guest_eip();
#endif  /* __UXEN_NOT_YET__ */
        break;

    case EXIT_REASON_VMPTRST:
#ifndef __UXEN_NOT_YET__
        if ( nvmx_handle_vmptrst(regs) == X86EMUL_OKAY )
            update_guest_eip();
#endif  /* __UXEN_NOT_YET__ */
        break;

    case EXIT_REASON_VMREAD:
#ifndef __UXEN_NOT_YET__
        if ( nvmx_handle_vmread(regs) == X86EMUL_OKAY )
            update_guest_eip();
#endif  /* __UXEN_NOT_YET__ */
        break;
 
    case EXIT_REASON_VMWRITE:
#ifndef __UXEN_NOT_YET__
        if ( nvmx_handle_vmwrite(regs) == X86EMUL_OKAY )
            update_guest_eip();
#endif  /* __UXEN_NOT_YET__ */
        break;

    case EXIT_REASON_VMLAUNCH:
#ifndef __UXEN_NOT_YET__
        if ( nvmx_handle_vmlaunch(regs) == X86EMUL_OKAY )
            update_guest_eip();
#endif  /* __UXEN_NOT_YET__ */
        break;

    case EXIT_REASON_VMRESUME:
#ifndef __UXEN_NOT_YET__
        if ( nvmx_handle_vmresume(regs) == X86EMUL_OKAY )
            update_guest_eip();
#endif  /* __UXEN_NOT_YET__ */
        break;

    case EXIT_REASON_MWAIT_INSTRUCTION:
    case EXIT_REASON_MONITOR_INSTRUCTION:
    case EXIT_REASON_GETSEC:
    case EXIT_REASON_INVEPT:
    case EXIT_REASON_INVVPID:
        /*
         * We should never exit on GETSEC because CR4.SMXE is always 0 when
         * running in guest context, and the CPU checks that before getting
         * as far as vmexit.
         */
        WARN_ON(exit_reason == EXIT_REASON_GETSEC);
        vmx_inject_hw_exception(TRAP_invalid_op, HVM_DELIVER_NO_ERROR_CODE);
        break;

    case EXIT_REASON_TPR_BELOW_THRESHOLD:
        break;

    case EXIT_REASON_APIC_ACCESS:
        if ( !vmx_handle_eoi_write() && !handle_mmio() )
            vmx_inject_hw_exception(TRAP_gp_fault, 0);
        break;

    case EXIT_REASON_IO_INSTRUCTION:
        exit_qualification = __vmread(EXIT_QUALIFICATION);
        if ( exit_qualification & 0x10 )
        {
            /* INS, OUTS */
            if ( !handle_mmio() )
                vmx_inject_hw_exception(TRAP_gp_fault, 0);
        }
        else
        {
            /* IN, OUT */
            uint16_t port = (exit_qualification >> 16) & 0xFFFF;
            int bytes = (exit_qualification & 0x07) + 1;
            int dir = (exit_qualification & 0x08) ? IOREQ_READ : IOREQ_WRITE;
            if ( handle_pio(port, bytes, dir) )
                update_guest_eip(); /* Safe: IN, OUT */
        }
        break;

    case EXIT_REASON_INVD:
    case EXIT_REASON_WBINVD:
    {
        update_guest_eip(); /* Safe: INVD, WBINVD */
        vmx_wbinvd_intercept();
        break;
    }

    case EXIT_REASON_EPT_VIOLATION:
    {
        paddr_t gpa;

        if (!vmx_vmcs_late_load) {
            gpa = __vmread(GUEST_PHYSICAL_ADDRESS);
#ifdef __i386__
            gpa |= (paddr_t)__vmread(GUEST_PHYSICAL_ADDRESS_HIGH) << 32;
#endif
        } else
            gpa = v->arch.hvm_vmx.gpa;
        exit_qualification = __vmread(EXIT_QUALIFICATION);

        if ((EXIT_REASON_EPT_VIOLATION < ARRAY_SIZE(v->vmexit_reason_count)) &&
            ((v->vmexit_reason_count[EXIT_REASON_EPT_VIOLATION] % 500000) == 0))
            printk("vm%u.%u: 500k EPT violation: gpa %#"PRIpaddr
                   ", RIP: %08lx, exit qualification: %lx\n",
                   v->domain->domain_id, v->vcpu_id,
                   gpa, (unsigned long)regs->eip, exit_qualification);

        ept_handle_violation(exit_qualification, gpa);
        break;
    }

    case EXIT_REASON_MONITOR_TRAP_FLAG:
        v->arch.hvm_vmx.exec_control &= ~CPU_BASED_MONITOR_TRAP_FLAG;
        vmx_update_cpu_exec_control(v);
        if ( v->arch.hvm_vcpu.single_step ) {
#ifndef __UXEN__
          hvm_memory_event_single_step(regs->eip);
#endif  /* __UXEN__ */
          if ( v->domain->debugger_attached )
              domain_pause_for_debugger();
        }

        break;

    case EXIT_REASON_PAUSE_INSTRUCTION:
        perfc_incr(pauseloop_exits);
        do_sched_op(SCHEDOP_yield, XEN_GUEST_HANDLE_NULL(void));
        break;

    case EXIT_REASON_XSETBV:
    {
        u64 new_bv = (((u64)regs->edx) << 32) | regs->eax;
        if ( hvm_handle_xsetbv(new_bv) == 0 )
            update_guest_eip(); /* Safe: XSETBV */
        break;
    }

    case EXIT_REASON_VMX_PREEMPTION_TIMER_EXPIRED:
        v->force_preempt = 1;
        break;

    case EXIT_REASON_ACCESS_GDTR_OR_IDTR:
    case EXIT_REASON_ACCESS_LDTR_OR_TR:
    /* fall through */
    default:
    exit_and_crash:
        gdprintk(XENLOG_ERR, "Bad vmexit (reason %x)\n", exit_reason);
        domain_crash(v->domain);
        break;
    }

#ifndef __UXEN_NOT_YET__
out:
    if ( nestedhvm_vcpu_in_guestmode(v) )
        nvmx_idtv_handling();
#endif  /* __UXEN_NOT_YET__ */
}

asmlinkage_abi void vmx_vmenter_helper(void)
{
    struct vcpu *curr = current;
    u32 new_asid, old_asid;
    struct hvm_vcpu_asid *p_asid;
    bool_t need_flush;

    if ( !cpu_has_vmx_vpid )
        goto out;

    p_asid = &curr->arch.hvm_vcpu.n1asid;
    old_asid = p_asid->asid;
    need_flush = hvm_asid_handle_vmenter(p_asid);
    new_asid = p_asid->asid;

    if ( unlikely(new_asid != old_asid) )
    {
        __vmwrite(VIRTUAL_PROCESSOR_ID, new_asid);
        if ( !old_asid && new_asid )
        {
            /* VPID was disabled: now enabled. */
            curr->arch.hvm_vmx.secondary_exec_control |=
                SECONDARY_EXEC_ENABLE_VPID;
            vmx_update_secondary_exec_control(curr);
        }
        else if ( old_asid && !new_asid )
        {
            /* VPID was enabled: now disabled. */
            curr->arch.hvm_vmx.secondary_exec_control &=
                ~SECONDARY_EXEC_ENABLE_VPID;
            vmx_update_secondary_exec_control(curr);
        }
    }

    if ( unlikely(need_flush) )
        vpid_sync_all();

 out:
    HVMTRACE_ND(VMENTRY, 0, 1/*cycles*/, 0, 0, 0, 0, 0, 0, 0);
}

asmlinkage_abi void vmx_restore_regs(uintptr_t host_rsp)
{
    struct cpu_user_regs *regs = &current->arch.user_regs;

    __vmwrite(HOST_RSP, host_rsp);
    __vmwrite(GUEST_RIP, regs->eip);
    __vmwrite(GUEST_RSP, regs->esp);
    __vmwrite(GUEST_RFLAGS, regs->eflags);

    vcpu_restore_fpu_lazy(current);
    assert_xcr0_state(XCR0_STATE_VM);

    if (vmx_vmcs_late_load)
        pv_vmcs_flush_dirty(this_cpu(current_vmcs_vmx), 0);

    if (update_host_vm_ibrs &&
        current->arch.hvm_vcpu.msr_spec_ctrl != host_msr_spec_ctrl)
        wrmsrl(MSR_IA32_SPEC_CTRL, current->arch.hvm_vcpu.msr_spec_ctrl);

    ept_maybe_sync_cpu_enter(current->domain);
}

asmlinkage_abi void vmx_save_regs(void)
{
    struct cpu_user_regs *regs = &current->arch.user_regs;

    if (update_host_vm_ibrs) {
        if (current->arch.hvm_vcpu.use_spec_ctrl)
            rdmsrl(MSR_IA32_SPEC_CTRL, current->arch.hvm_vcpu.msr_spec_ctrl);
        if (host_msr_spec_ctrl)
            wrmsrl(MSR_IA32_SPEC_CTRL, host_msr_spec_ctrl);
        else {
            lfence();
            if (current->arch.hvm_vcpu.msr_spec_ctrl)
                wrmsrl(MSR_IA32_SPEC_CTRL, SPEC_CTRL_FEATURE_DISABLE_IBRS);
            wrmsrl(MSR_IA32_PRED_CMD, PRED_CMD_IBPB);
        }
    } else
        lfence();

    ept_maybe_sync_cpu_leave(current->domain);

    if (!vmx_vmcs_late_load)
        current->arch.hvm_vmx.launched = 1;
    else {
        struct arch_vmx_struct *vmcs_vmx = this_cpu(current_vmcs_vmx);
        unsigned int exit_reason;
        exit_reason = vmcs_vmx->exit_reason = __vmread(VM_EXIT_REASON);
        if (exit_reason == EXIT_REASON_EPT_VIOLATION) {
            paddr_t gpa;
            gpa = __vmread(GUEST_PHYSICAL_ADDRESS);
#ifdef __i386__
            gpa |= (paddr_t)__vmread(GUEST_PHYSICAL_ADDRESS_HIGH) << 32;
#endif
            vmcs_vmx->gpa = gpa;
        }
        __vmpclear(vmcs_vmx->vmcs_ma);
        vmcs_vmx->loaded = 0;
    }

    current->arch.hvm_vmx.vmentry_gen++;

    regs->eip = __vmread(GUEST_RIP);
    regs->esp = __vmread(GUEST_RSP);
    regs->eflags = __vmread(GUEST_RFLAGS);
}

asmlinkage_abi void vm_entry_fail(uintptr_t resume)
{
    unsigned long error = __vmread(VM_INSTRUCTION_ERROR);

    if (update_host_vm_ibrs) {
        if (current->arch.hvm_vcpu.use_spec_ctrl)
            rdmsrl(MSR_IA32_SPEC_CTRL, current->arch.hvm_vcpu.msr_spec_ctrl);
        if (host_msr_spec_ctrl)
            wrmsrl(MSR_IA32_SPEC_CTRL, host_msr_spec_ctrl);
        else {
            lfence();
            if (current->arch.hvm_vcpu.msr_spec_ctrl)
                wrmsrl(MSR_IA32_SPEC_CTRL, SPEC_CTRL_FEATURE_DISABLE_IBRS);
            wrmsrl(MSR_IA32_PRED_CMD, PRED_CMD_IBPB);
        }
    } else
        lfence();

    ept_maybe_sync_cpu_leave(current->domain);

    cpu_irq_enable();

    printk("<vm_%s_fail> error code %lx\n",
           resume ? "resume" : "launch", error);
    vmcs_dump_vcpu(current);
    __domain_crash(current->domain);
}

void
vmx_do_suspend(struct vcpu *v)
{

    if (/* cpu_has_spec_ctrl && */ host_msr_spec_ctrl)
        wrmsrl(MSR_IA32_PRED_CMD, PRED_CMD_IBPB);
}

static bool_t __initdata disable_pv_vmx;
invbool_param("pv_vmx", disable_pv_vmx);

static void
setup_pv_vmx(void)
{

    if (disable_pv_vmx)
        return;

    setup_pv_vmcs_access();

    xen_pv_ept_probe();
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
