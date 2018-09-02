/*
 * Copyright 2017-2019, Bromium, Inc.
 * SPDX-License-Identifier: ISC
 */

#include <xen/lib.h>
#include <asm/hvm/ax.h>
#include <asm/hvm/vmx/vmx.h>
#include <asm/hvm/svm/svm.h>
#include <asm/i387.h>
#include <asm/xstate.h>
#include <attoxen-api/hv_tests.h>

#include "ax_private.h"

int ax_present = 0;
int ax_present_intel = 0;
int ax_present_amd = 0;
int ax_pv_ept = 0;
int ax_l1_invlpg_intercept = 0;
int ax_has_pv_vmcs = 0;
int ax_has_attovm = 0;
int ax_pv_vmcs_enabled = 0;

extern int ax_pv_vmread(void *, uint64_t field, uint64_t *value);
extern int ax_pv_vmwrite(void *, uint64_t field, uint64_t value);

typedef int (*pvi_vmread_pfn)(void *, uint64_t field, uint64_t *value);
typedef int (*pvi_vmwrite_pfn)(void *, uint64_t field, uint64_t value);

static DEFINE_PER_CPU_READ_MOSTLY (void *, ax_pv_vmcs_ctx);

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
    struct ax_vmcb_extra_v1 *ax =
            (struct ax_vmcb_extra_v1 *) (((uint8_t *) vmcb) + AX_VMCB_OFFSET_V1);

    ax->flags |= AX_SVM_FLAGS_VMSAVE_ROOT;
}

int ax_svm_vmrun(struct vcpu *v, struct vmcb_struct *vmcb, struct cpu_user_regs *regs)
{
    volatile struct ax_vmcb_extra_v1 *ax =
            (struct ax_vmcb_extra_v1 *) (((uint8_t *) vmcb) + AX_VMCB_OFFSET_V1);

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

    /*This is ok because there is compile time code to check these structures are compatible */
    ax->uregs_pa = (uint64_t) __pa(regs);

    if (svm_asm_ax_vmentry(v))
        return -1;

    ax->flags &= ~AX_SVM_FLAGS_VMSAVE_ROOT;
    return 0;
}

unsigned long ax_pv_vmcs_read(unsigned long field)
{
    uint64_t value;

    if (ax_pv_vmcs_enabled) {
#ifdef __x86_64__
        if (_uxen_info.ui_pvi_vmread)
            ((pvi_vmread_pfn)((intptr_t)_uxen_info.ui_pvi_vmread))
             (this_cpu(ax_pv_vmcs_ctx), field, &value);
        else
#endif  /* __x86_64__ */
            ax_pv_vmread(this_cpu(ax_pv_vmcs_ctx), field, &value);
    } else {
        vmread(field, &value);
    }

    return value;
}


unsigned long ax_pv_vmcs_read_safe(unsigned long field, int *error)
{
    uint64_t value;

    if (ax_pv_vmcs_enabled) {
#ifdef __x86_64__
        if (_uxen_info.ui_pvi_vmread)
            *error = ((pvi_vmread_pfn)((intptr_t)_uxen_info.ui_pvi_vmread))
                (this_cpu(ax_pv_vmcs_ctx), field, &value);
        else
#endif  /* __x86_64__ */
            *error = ax_pv_vmread(this_cpu(ax_pv_vmcs_ctx), field, &value);
    } else {
        *error = vmread(field, &value);
    }

    return value;
}

void ax_pv_vmcs_write(unsigned long field, unsigned long value)
{
    if (ax_pv_vmcs_enabled) {
#ifdef __x86_64__
        if (_uxen_info.ui_pvi_vmwrite)
            ((pvi_vmwrite_pfn)((intptr_t)_uxen_info.ui_pvi_vmwrite))
                (this_cpu(ax_pv_vmcs_ctx), field, value);
        else
#endif  /* __x86_64__ */
            ax_pv_vmwrite(this_cpu(ax_pv_vmcs_ctx), field, value);
    } else {
        vmwrite(field, value);
    }
}

int ax_setup(void)
{
#ifdef __x86_64__
    uint64_t rax, rbx, rcx, rdx;
    int cpu_is_intel = (boot_cpu_data.x86_vendor == X86_VENDOR_INTEL);

    if (!hv_tests_hyperv_running())
        return 0;

    if (!hv_tests_ax_running())
        return 0;


    printk("Hv and AX detected\n");
    ax_present = 1;

    pv_msr = 1;

    if (hvmon_default == hvmon_on) {
        printk("AX present, but hvmonoff=1, disabling hvmonoff\n");
        hvmon_default = hvmon_always;
    }

    rax = AX_CPUID_AX_FEATURES;
    rbx = 0;
    rcx = 0;
    rdx = 0;

    hv_tests_cpuid(&rax, &rbx, &rcx, &rdx);

    ax_pv_ept = !! (AX_FEATURES_AX_SHADOW_EPT & rdx);
    printk("Using PV-HAP %d\n", ax_pv_ept);

    ax_has_attovm = !! (AX_FEATURES_AX_L2_ATTOVM & rdx);
    printk("AX supports attovm %d\n", ax_has_attovm);

    if (cpu_is_intel) {
        ax_present_intel = 1;
        ax_has_pv_vmcs = !! (AX_FEATURES_AX_PV_VMCS);
        printk("AX has PV VMCS %d\n", ax_has_pv_vmcs);
    } else {
        ax_present_amd = 1;
        rax = AX_CPUID_VMCB_CHECK_MY;
        rbx = 0;
        rcx = 0;
        rdx = 0;
        hv_tests_cpuid(&rax, &rbx, &rcx, &rdx);
        ax_l1_invlpg_intercept = !!(rdx & AX_CPUID_VMCB_CHECK_INTERCEPT_INVLPG);
        printk("L1 intercepts INVLPG: %s\n", ax_l1_invlpg_intercept ? "YES" : "NO");
        vmexec_fpu_ctxt_switch = 1;
        uxen_info->host_os_is_xmm_clean = 1;
    }
#endif

    return 0;
}

int ax_pv_vmcs_setup(void)
{
    uint64_t rax, rbx, rcx, rdx;
    static int patched = 0;

    if (!ax_has_pv_vmcs) return 0;

    rax = AX_CPUID_PV_VMACCESS;
    rbx = 1;

    if (!patched
#ifdef __x86_64__
        && !(_uxen_info.ui_pvi_vmread && _uxen_info.ui_pvi_vmwrite)
#endif  /* __x86_64__ */
        ) {
        rcx = (size_t) ax_pv_vmread;
        rdx = (size_t) ax_pv_vmwrite;
    } else {
        rcx = 0;
        rdx = 0;
    }


#ifdef __x86_64__
    asm volatile("cpuid":"+a" (rax), "+b" (rbx), "+c" (rcx), "+d" (rdx)::"cc");
#endif

    printk("AX PV Call returns %d %lx %lx %lx %lx\n", (int) smp_processor_id(), 
		(unsigned long) rax, (unsigned long) rbx, 
		(unsigned long) rcx, (unsigned long) rdx);

    if (rax != 1)  {
        ax_pv_vmcs_enabled = 0;
        return 0;
    }

    patched = 1;

    this_cpu(ax_pv_vmcs_ctx) = (void *) (size_t) rbx;

    ax_pv_vmcs_enabled = 1;

    return 1;
}


