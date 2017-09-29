/*
 * Copyright 2017, Bromium, Inc.
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


#define AX_VMCS_EXTENSIONS_V1(v) \
    ((ax_vmcs_extensions_v1_t *)(((uint8_t *)v) + 0x1000 - \
                                 sizeof(ax_vmcs_extensions_v1_t)))

#define AX_ON_AMD_PRESENT()   (ax_present && (boot_cpu_data.x86_vendor == X86_VENDOR_AMD))
extern int ax_present;
extern int ax_pv_ept;
extern int ax_l1_invlpg_intercept;
extern void ax_mark_ept_dirty(struct domain *d);
extern void ax_pv_ept_flush(struct p2m_domain *p2m);
extern int ax_setup(void);
extern int ax_svm_vmrun(struct vcpu *v, struct vmcb_struct *vmcb,
                        struct cpu_user_regs *regs);
extern void ax_svm_vmsave_root(struct vcpu *v);

static inline
void ax_vmcs_x_flags_set(struct vcpu *v, uint64_t val)
{
    ax_vmcs_extensions_v1_t *x = AX_VMCS_EXTENSIONS_V1(v->arch.hvm_vmx.vmcs);

    x->flags = val;
}

static inline
void ax_vmcs_x_wrmsrl(struct vcpu *v, uint32_t msr, uint64_t value)
{
    ax_vmcs_extensions_v1_t *x = AX_VMCS_EXTENSIONS_V1(v->arch.hvm_vmx.vmcs);

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
    }
}

static inline
void ax_vmcs_x_rdmsrl(struct vcpu *v, uint32_t msr, uint64_t *value)
{
    ax_vmcs_extensions_v1_t *x = AX_VMCS_EXTENSIONS_V1(v->arch.hvm_vmx.vmcs);

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

int ax_remote_vmclear(uint64_t pa);
void ax_remote_tblflush(void);
void ax_pv_ept_write(struct p2m_domain *p2m, int level, uint64_t gfn,
                     uint64_t new_entry, int invept);

#endif /* __ASM_X86_HVM_AX_H__ */
