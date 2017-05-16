/*
 * Copyright 2017, Bromium, Inc.
 * SPDX-License-Identifier: ISC
 */

#include <xen/lib.h>
#include <asm/hvm/ax.h>
#include <asm/hvm/vmx/vmx.h>
#include <attoxen-api/hv_tests.h>

int ax_present = 0;
int ax_pv_ept = 0;

void ax_pv_ept_flush(struct p2m_domain *p2m)
{
#ifdef __x86_64__
    uint64_t ept_base;

    ept_base = (size_t)pagetable_get_pfn(p2m_get_pagetable(p2m)) << PAGE_SHIFT;

    __invept(INVEPT_SINGLE_CONTEXT, ept_base, 0);

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

int ax_setup(void)
{
#ifndef __i386__
    uint64_t rax, rbx, rcx, rdx;

    if (hv_tests_hyperv_running() && hv_tests_ax_running()) {
        printk("Hv and AX detected\n");
        ax_present = 1;

        rax = AX_CPUID_AX_FEATURES;
        rbx = 0;
        rcx = 0;
        rdx = 0;

        hv_tests_cpuid(&rax, &rbx, &rcx, &rdx);

        ax_pv_ept = !!(AX_FEATURES_AX_SHADOW_EPT & rdx);
        printk("Using PV-EPT %d\n", ax_pv_ept);
    }
#endif
    return 0;
}
