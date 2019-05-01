/*
 * Copyright 2018-2019, Bromium, Inc.
 * Author: Christian Limpach <Christian.Limpach@gmail.com>
 * SPDX-License-Identifier: ISC
 */

#include <xen/config.h>
#include <xen/types.h>
#include <xen/lib.h>
#include <xen/sched.h>
#include <asm/processor.h>
#include <asm/hvm/pvnested.h>
#include <asm/hvm/ax.h>

bool_t __read_mostly pvnested = 0;

#define _FCC(a, b, c, d)                                                \
    (((uint8_t)d) << 24 | ((uint8_t)c) << 16 | ((uint8_t)b) << 8 | ((uint8_t)a))

void __init
pvnested_setup(void)
{
    u32 eax, sig1, sig2, sig3;

    cpuid(0x40000000, &eax, &sig1, &sig2, &sig3);

    if (sig1 != _FCC('V', 'B', 'o', 'x') ||
        sig2 != _FCC('V', 'B', 'o', 'x') ||
        sig3 != _FCC('V', 'B', 'o', 'x'))
        return;

    if (pvnested_vmx_info.pvi_sig != PVNESTED_VMX_INFO_SIG_FILLED) {
        uint64_t rax, rbx, rcx = 0, rdx = 0;

        ASSERT(pvnested_vmx_info.pvi_sig == PVNESTED_VMX_INFO_SIG_1);

        rax = PVNESTED_CPUID_VMX_INFO;
        rbx = (uintptr_t)&pvnested_vmx_info;
        cpuid64(rax, rbx, rcx, rdx);

        if (rax != 1) {
            printk(XENLOG_ERR "%s: PVNESTED_CPUID_VMX_INFO failed: %"PRIx64"\n",
                   __FUNCTION__, rax);
            return;
        }

        if (pvnested_vmx_info.pvi_sig != PVNESTED_VMX_INFO_SIG_FILLED) {
            printk(XENLOG_ERR
                   "%s: PVNESTED_CPUID_VMX_INFO mismatch sig: %x\n",
                   __FUNCTION__, pvnested_vmx_info.pvi_sig);
            return;
        }

        printk(XENLOG_INFO "%s: PVNESTED_CPUID_VMX_INFO api version: %x\n",
               __FUNCTION__, pvnested_vmx_info.pvi_version);

        pv_msr = 1;
    }

    BUILD_BUG_ON(PVNESTED_PV_VMACCESS_SIG_1 != AX_PV_VMACCESS_SIG_1);
    BUILD_BUG_ON(PVNESTED_PV_VMACCESS_SIG_2 != AX_PV_VMACCESS_SIG_2);
    ax_cpuid_pv_vmaccess = PVNESTED_CPUID_PV_VMACCESS;
    ax_has_pv_vmcs = 1;

    ax_cpuid_pv_ept_write = PVNESTED_CPUID_EPT_WRITE;
    ax_cpuid_pv_ept_write_valid = PVNESTED_CPUID_EPT_WRITE_VALID;
    ax_cpuid_pv_ept_write_invept_all = PVNESTED_CPUID_EPT_WRITE_INVEPT_ALL;
    ax_pv_ept = 1;

    pv_ept_write_hint_gfn = PVNESTED_VMCS_FIELD_EPT_WRITE_HINT_GFN;
    pv_ept_write_hint_entry = PVNESTED_VMCS_FIELD_EPT_WRITE_HINT_ENTRY;

    pvnested = 1;
}

void __init
pvnested_cpu_fixup(struct cpuinfo_x86 *c)
{

    if (pvnested)
        set_bit(X86_FEATURE_VMXE, &c->x86_capability);
}

void
pvnested_rdmsrl(uint32_t msr, uint64_t *value)
{

    switch (msr) {
    case MSR_IA32_VMX_CR0_FIXED0:
        *value = pvnested_vmx_info.pvi_vmx_cr0_fixed0;
        break;
    case MSR_IA32_VMX_CR0_FIXED1:
        *value = pvnested_vmx_info.pvi_vmx_cr0_fixed1;
        break;
    case IA32_FEATURE_CONTROL_MSR:
        *value = pvnested_vmx_info.pvi_feature_control;
        break;
    case MSR_IA32_VMX_BASIC:
        *value = pvnested_vmx_info.pvi_vmx_basic;
        break;
    case MSR_IA32_VMX_EPT_VPID_CAP:
        *value = pvnested_vmx_info.pvi_vmx_ept_vpid_cap;
        break;
    case MSR_IA32_VMX_PINBASED_CTLS:
        *value = pvnested_vmx_info.pvi_vmx_pinbased_ctls;
        break;
    case MSR_IA32_VMX_PROCBASED_CTLS:
        *value = pvnested_vmx_info.pvi_vmx_procbased_ctls;
        break;
    case MSR_IA32_VMX_PROCBASED_CTLS2:
        *value = pvnested_vmx_info.pvi_vmx_procbased_ctls2;
        break;
    case MSR_IA32_VMX_TRUE_PROCBASED_CTLS:
        *value = pvnested_vmx_info.pvi_vmx_true_procbased_ctls;
        break;
    case MSR_IA32_VMX_EXIT_CTLS:
        *value = pvnested_vmx_info.pvi_vmx_exit_ctls;
        break;
    case MSR_IA32_VMX_ENTRY_CTLS:
        *value = pvnested_vmx_info.pvi_vmx_entry_ctls;
        break;
    default:
        rdmsrl(msr, *value);
        break;
    }
}

void
pvnested_wrmsrl(uint32_t msr, uint64_t value)
{

    switch (msr) {
    case IA32_FEATURE_CONTROL_MSR:
        /* noop */
        break;
    default:
        wrmsrl(msr, value);
        break;
    }
}

int
pvnested_vmxon(u64 addr)
{
    uint64_t rax, rbx, rcx = 0, rdx = 0;

    rax = PVNESTED_CPUID_VMXON;
    rbx = addr;
    cpuid64(rax, rbx, rcx, rdx);

    if (rax != 1) {
        printk(XENLOG_ERR "%s: PVNESTED_CPUID_VMXON failed: %"PRIx64"\n",
               __FUNCTION__, rax);
        return -2;              /* #UD or #GP */
    }

    ASSERT(addr == virt_to_maddr(this_cpu(vmxon_region)));
    this_cpu(ax_pv_vmcs_ctx) = this_cpu(vmxon_region);

    return 0;
}

void
pvnested_vmxoff(void)
{
    uint64_t rax, rbx = 0, rcx = 0, rdx = 0;

    rax = PVNESTED_CPUID_VMXOFF;
    cpuid64(rax, rbx, rcx, rdx);
}

void
pvnested_vmptrld(uint64_t addr)
{
    uint64_t rax, rbx, rcx, rdx;

    rax = PVNESTED_CPUID_VMPTRLD;
    rbx = addr;
    rcx = 0;
    rdx = 0;
    cpuid64(rax, rbx, rcx, rdx);
}

void
pvnested_vmpclear(uint64_t addr)
{
    uint64_t rax, rbx, rcx, rdx;

    rax = PVNESTED_CPUID_VMPCLEAR;
    rbx = addr;
    rcx = 0;
    rdx = 0;
    cpuid64(rax, rbx, rcx, rdx);
}

void
pvnested_invept(int type, u64 eptp, u64 gpa)
{
    uint64_t rax, rbx, rcx, rdx;

    rax = PVNESTED_CPUID_INVEPT;
    rbx = type;
    rcx = eptp;
    rdx = gpa;
    cpuid64(rax, rbx, rcx, rdx);
}
