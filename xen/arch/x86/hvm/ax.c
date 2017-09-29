/*
 * Copyright 2017-2018, Bromium, Inc.
 * SPDX-License-Identifier: ISC
 */

#include <xen/lib.h>
#include <asm/hvm/ax.h>
#include <asm/hvm/vmx/vmx.h>
#include <asm/hvm/svm/svm.h>
#include <asm/i387.h>
#include <asm/xstate.h>
#include <attoxen-api/hv_tests.h>

int ax_present = 0;
int ax_pv_ept = 0;
int ax_l1_invlpg_intercept = 0;

void ax_pv_ept_flush(struct p2m_domain *p2m)
{
#ifdef __x86_64__
    uint64_t ept_base;
    int cpu_is_intel = (boot_cpu_data.x86_vendor == X86_VENDOR_INTEL);

    ept_base = (size_t)pagetable_get_pfn(p2m_get_pagetable(p2m)) << PAGE_SHIFT;

    if (cpu_is_intel) {
        __invept(INVEPT_SINGLE_CONTEXT, ept_base, 0);
    } else {
        uint64_t rax, rbx, rcx = 0, rdx = 0;

        rax = AX_CPUID_INVEPT_BASE;
        rbx = ept_base;

        asm volatile ("cpuid":"+a" (rax), "+b" (rbx), "+c" (rcx),
                    "+d" (rdx)::"cc");
    }

    p2m->virgin = 1;
#endif
}

static inline void ax_pv_ept_write_attocall(struct p2m_domain *p2m, int level, uint64_t gfn, uint64_t new_entry, int invept)
{
#ifdef __x86_64__
    uint64_t rax, rbx, rcx, rdx;

    rax = AX_CPUID_PV_EPT_WRITE;
    rbx = (size_t)pagetable_get_pfn(p2m_get_pagetable(p2m)) << PAGE_SHIFT;

    rcx = gfn << PAGE_SHIFT;

    rcx |= level;
    rcx |= AX_CPUID_PV_EPT_WRITE_VALID;

    if (invept)
        rcx |= AX_CPUID_PV_EPT_WRITE_INVEPT_ALL;

    rdx = new_entry;

    if (!rbx)
        BUG();

    asm volatile ("cpuid":"+a" (rax), "+b" (rbx), "+c" (rcx), "+d" (rdx)::"cc");
#endif
}

int ax_remote_vmclear(uint64_t pa)
{
#ifdef __x86_64__
    uint64_t rax, rbx, rcx, rdx;

    rax = AX_CPUID_VMCLEAR;
    rcx = pa;
    rbx = rdx = 0;

    asm volatile ("cpuid":"+a" (rax), "+b" (rbx), "+c" (rcx), "+d" (rdx)::"cc");

    return rax;
#else
    return 0;
#endif
}

void ax_remote_tblflush(void)
{
#ifdef __x86_64__
    uint64_t rax, rbx, rcx, rdx;

    rax = AX_CPUID_FLUSHTLB;
    rbx = rcx = rdx = 0;

    asm volatile ("cpuid":"+a" (rax), "+b" (rbx), "+c" (rcx), "+d" (rdx)::"cc");
#endif
}

void ax_pv_ept_write(struct p2m_domain *p2m, int level, uint64_t gfn,
                     uint64_t new_entry, int invept)
{
#ifdef __x86_64__
    if (p2m->virgin)
        return;

    if (!invept)
        return;

    ax_pv_ept_write_attocall(p2m, level, gfn, new_entry, invept);
#endif
}

void ax_svm_vmsave_root(struct vcpu *v)
{
    struct vmcb_struct *vmcb = v->arch.hvm_svm.vmcb;
    struct ax_vmcb_extra *ax =
            (struct ax_vmcb_extra *) (((uint8_t *) vmcb) + AX_VMCB_OFFSET);

    ax->flags |= AX_SVM_FLAGS_VMSAVE_ROOT;
}

int ax_svm_vmrun(struct vcpu *v, struct vmcb_struct *vmcb, struct cpu_user_regs *regs)
{
    volatile struct ax_vmcb_extra *ax =
            (struct ax_vmcb_extra *) (((uint8_t *) vmcb) + AX_VMCB_OFFSET);

    if (!v->fpu_initialised) {
        clts();
        fpu_init();
        xrstor(v, 0);           /* init xsave area for xsaveopt */
        xsave(v, XSTATE_LAZY);
        v->fpu_initialised = 1;
    }

    ax->g_cr8 = 0x1;
    ax->vmsave_pa = v->arch.hvm_svm.vmcb_pa;
    ax->vmsave_root_pa = v->arch.hvm_svm.root_vmcb_pa;
    ax->xsave_pa = (uint64_t) __pa(v->arch.xsave_area);
    ax->uregs_pa = (uint64_t) __pa(regs);

    if (svm_asm_ax_vmentry(v))
        return -1;

    ax->flags &= ~AX_SVM_FLAGS_VMSAVE_ROOT;
    return 0;
}

int ax_setup(void)
{
#ifndef __i386__
    uint64_t rax, rbx, rcx, rdx;
    int cpu_is_intel = (boot_cpu_data.x86_vendor == X86_VENDOR_INTEL);

    if (hv_tests_hyperv_running() && hv_tests_ax_running()) {
        printk("Hv and AX detected\n");
        ax_present = 1;

        if (hvmon_default == hvmon_on) {
            printk("AX present, but hvmonoff=1, disabling hvmonoff\n");
            hvmon_default = hvmon_always;
        }

        rax = AX_CPUID_AX_FEATURES;
        rbx = 0;
        rcx = 0;
        rdx = 0;

        hv_tests_cpuid(&rax, &rbx, &rcx, &rdx);

        ax_pv_ept = !!(AX_FEATURES_AX_SHADOW_EPT & rdx);
        printk ("Using PV-%s %d\n", cpu_is_intel ? "EPT" : "NPT (async active, smart invept)", ax_pv_ept);
        if (!cpu_is_intel) {
            rax = AX_CPUID_SVM_L1_CHECK_INVLPG_INTERCEPT;
            rbx = 0;
            rcx = 0;
            rdx = 0;
            hv_tests_cpuid(&rax, &rbx, &rcx, &rdx);
            ax_l1_invlpg_intercept = !!rdx;
            printk("L1 intercepts INVLPG: %s\n", ax_l1_invlpg_intercept ? "YES" : "NO");
        }
    }
#endif
    return 0;
}
