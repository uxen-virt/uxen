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
    }

    pvnested = 1;
}

void __init
pvnested_cpu_fixup(struct cpuinfo_x86 *c)
{

    if (pvnested)
        set_bit(X86_FEATURE_VMXE, &c->x86_capability);
}
