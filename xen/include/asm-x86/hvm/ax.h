/*
 * Copyright 2017-2019, Bromium, Inc.
 * SPDX-License-Identifier: ISC
 */

#ifndef __ASM_X86_HVM_AX_H__
#define __ASM_X86_HVM_AX_H__

#include <asm/msr-index.h>
#include <asm/p2m.h>
#include <asm/hvm/hvm.h>
#include <asm/hvm/support.h>
#include <asm/hvm/vmx/vmx.h>
#include <asm/hvm/vmx/vmcs.h>

#include <attoxen-api/ax_constants.h>
#include <attoxen-api/ax_structures.h>

DECLARE_PER_CPU(void *, ax_pv_vmcs_ctx);

#define AX_VMCS_EXTENSIONS_V1(v) \
    ((ax_vmcs_extensions_v1_t *)(((uint8_t *)v) + 0x1000 - \
                                 sizeof(ax_vmcs_extensions_v1_t)))

extern int ax_present;
extern int ax_present_intel;
extern int ax_present_amd;
extern int ax_pv_ept;
extern int ax_has_pv_vmcs;
extern uint64_t ax_cpuid_pv_vmaccess;
extern int ax_has_attovm;
extern int ax_pv_vmcs_enabled;
extern int ax_l1_invlpg_intercept;
extern void ax_mark_ept_dirty(struct domain *d);
extern void ax_pv_ept_flush(struct p2m_domain *p2m);
extern int ax_setup(void);
extern int ax_svm_vmrun(struct vcpu *v, struct vmcb_struct *vmcb,
                        struct cpu_user_regs *regs);
extern void ax_svm_vmsave_root(struct vcpu *v);
extern unsigned long ax_pv_vmcs_read(unsigned long field);
extern unsigned long ax_pv_vmcs_read_safe(unsigned long field, int *error);
extern void ax_pv_vmcs_write(unsigned long field, unsigned long value);
extern int ax_pv_vmcs_setup(void);

static inline
void ax_vmcs_x_flags_set(struct vcpu *v, uint64_t val)
{
    ax_vmcs_extensions_v1_t *x = AX_VMCS_EXTENSIONS_V1(v->arch.hvm_vmx.vmcs);

    x->flags = val;
}

static inline
void ax_vmcs_x_wrmsrl(struct vcpu *v, uint32_t msr, uint64_t value)
{
    ax_vmcs_extensions_v1_t *x =
        v ? AX_VMCS_EXTENSIONS_V1(v->arch.hvm_vmx.vmcs) : NULL;

    switch (msr) {
    case MSR_SHADOW_GS_BASE:
        x->msr_gs_shadow = value;
        return;

    case MSR_STAR:
        x->msr_star = value;
        return;

    case MSR_CSTAR:
        x->msr_cstar = value;
        return;

    case MSR_LSTAR:
        x->msr_lstar = value;
        return;

    case MSR_SYSCALL_MASK:
        x->msr_syscall_mask = value;
        return;

    case MSR_IA32_SPEC_CTRL:
        x->msr_spec_ctrl = value;
        return;

    case IA32_FEATURE_CONTROL_MSR:
        wrmsrl(msr, value);
        break;
    }
}

static inline
void ax_vmcs_x_rdmsrl(struct vcpu *v, uint32_t msr, uint64_t *value)
{
    ax_vmcs_extensions_v1_t *x =
        v ? AX_VMCS_EXTENSIONS_V1(v->arch.hvm_vmx.vmcs) : NULL;

    switch (msr) {
    case MSR_SHADOW_GS_BASE:
        *value = x->msr_gs_shadow;
        return;

    case MSR_STAR:
        *value = x->msr_star;
        return;

    case MSR_CSTAR:
        *value = x->msr_cstar;
        return;

    case MSR_LSTAR:
        *value = x->msr_lstar;
        return;

    case MSR_SYSCALL_MASK:
        *value = x->msr_syscall_mask;
        return;

    case MSR_IA32_SPEC_CTRL:
        *value = x->msr_spec_ctrl;
        return;

    case MSR_IA32_VMX_CR0_FIXED0:
    case MSR_IA32_VMX_CR0_FIXED1:
    case IA32_FEATURE_CONTROL_MSR:
    case MSR_IA32_VMX_BASIC:
    case MSR_IA32_VMX_EPT_VPID_CAP:
    case MSR_IA32_VMX_PINBASED_CTLS:
    case MSR_IA32_VMX_PROCBASED_CTLS:
    case MSR_IA32_VMX_PROCBASED_CTLS2:
    case MSR_IA32_VMX_TRUE_PROCBASED_CTLS:
    case MSR_IA32_VMX_EXIT_CTLS:
    case MSR_IA32_VMX_ENTRY_CTLS:
        rdmsrl(msr, *value);
        return;
    }
}

static inline void ax_invept_all_cpus(void)
{
#ifdef __x86_64__
    uint64_t rax, rbx, rcx, rdx;

    rax = AX_CPUID_INVEPT_ALL;
    rbx = 0;
    rcx = 0;
    rdx = 0;

    asm volatile ("cpuid":"+a" (rax), "+b" (rbx), "+c" (rcx), "+d" (rdx)::"cc");
#endif
}


extern int ax_remote_vmclear(uint64_t pa);
extern void ax_remote_tblflush(void);
extern void ax_pv_ept_write(struct p2m_domain *p2m, int level, uint64_t gfn,
                     uint64_t new_entry, int invept);

#endif /* __ASM_X86_HVM_AX_H__ */
