/*
 * Copyright 2016-2017, Bromium, Inc.
 * Author: Paulian Marinca <paulian@marinca.net>
 * SPDX-License-Identifier: ISC
 */

#include <linux/types.h>
#include <linux/init.h>
#include <linux/module.h>

#include <asm/page.h>
#include <asm/cacheflush.h>
#include <asm/processor.h>
#include <asm/msr-index.h>
#include <linux/vmalloc.h>
#include <linux/mm.h>
#include <linux/spinlock.h>
#include <linux/compiler.h>

#include <xen/xen.h>
#include <xen/version.h>

#include "hypercall.h"
#include <uxen-hypercall.h>
#include <uxen-util.h>

#define AX_CPUID_LEAF_BASE 0x50000000
#define HV_CPUID_LEAF_BASE 0x40000000
#define HV_CPUID_LEAF_RANGE 0x10000
#define HV_CPUID_LEAD_SKIP 0x100

int uxen_ax;
void *uxen_hcbase;
EXPORT_SYMBOL_GPL(uxen_hcbase);

int uxen_ax_hypervisor(void)
{
    return !!uxen_ax;
}
EXPORT_SYMBOL_GPL(uxen_ax_hypervisor);

int
uxen_hypercall_version(int cmd, void *arg)
{
    if (!uxen_hcbase)
	return -ENOENT;
    return HYPERVISOR_xen_version(cmd, arg);
}
EXPORT_SYMBOL_GPL(uxen_hypercall_version);

int
uxen_hypercall_memory_op(int cmd, void *arg)
{
    if (!uxen_hcbase)
	return -ENOENT;
    return HYPERVISOR_memory_op(cmd, arg);
}
EXPORT_SYMBOL_GPL(uxen_hypercall_memory_op);

int
uxen_hypercall_hvm_op(int cmd, void *arg)
{
    if (!uxen_hcbase)
	return -ENOENT;
    return (int) HYPERVISOR_hvm_op(cmd, arg);
}
EXPORT_SYMBOL_GPL(uxen_hypercall_hvm_op);

int
uxen_hypercall_v4v_op(int cmd, void *arg1, void *arg2, void *arg3, void *arg4, void *arg5)
{
    if (!uxen_hcbase)
	return -ENOENT;
    return HYPERVISOR_v4v_op(cmd, arg1, arg2, arg3, arg4, arg5);
}
EXPORT_SYMBOL_GPL(uxen_hypercall_v4v_op);

static int __init uxen_hypercall_init(void)
{
    int ret = -1;
    u32 eax, ebx, ecx, edx;
    char signature[13];
    u32 leaf;
    u64 addr;
    xen_extraversion_t extraversion;

    uxen_ax = 0;
#ifdef LX_TARGET_AX
    uxen_ax = 1;
#endif

    if (uxen_ax) {
        uxen_hcbase = (void *) (unsigned long) (AX_CPUID_LEAF_BASE + 0x10);
        printk(KERN_INFO "using ax hypervisor");
#if 0 // NOT YET
        ret = 0;
        goto out;
#else
        uxen_hcbase = NULL;
#endif
    }

    for (leaf = 0; leaf < HV_CPUID_LEAF_RANGE; leaf += HV_CPUID_LEAD_SKIP) {
        cpuid(HV_CPUID_LEAF_BASE + leaf, &eax, &ebx, &ecx, &edx);
        *(u32 *)(signature + 0) = ebx;
        *(u32 *)(signature + 4) = ecx;
        *(u32 *)(signature + 8) = edx;
        signature[12] = 0;

        if (!strcmp("uXenisnotXen", signature))
            break;
    }

    if (leaf >= HV_CPUID_LEAF_RANGE || (eax - (HV_CPUID_LEAF_BASE + leaf)) < 2) {
        printk(KERN_INFO "uxenhc: hypervisor not found: leaf %x eax %x", leaf, eax);
        ret = -ENODEV;
        goto out;
    }

    printk(KERN_INFO "uxenplatform: hypervisor found at %x eax %x", HV_CPUID_LEAF_BASE + leaf, eax);

    if (!uxen_hcbase) {
        uxen_hcbase =  __vmalloc(PAGE_SIZE, GFP_KERNEL, PAGE_KERNEL_EXEC);
        if (!uxen_hcbase) {
            ret = -ENOMEM;
            goto out;
        }
    }
    memset(uxen_hcbase, 0xc3 /* ret */, PAGE_SIZE);
    addr = ((u64) virtual_to_pfn(uxen_hcbase)) << PAGE_SHIFT;
    cpuid(HV_CPUID_LEAF_BASE + leaf + 2, &eax, &ebx, &ecx, &edx);
    wrmsr_safe(ebx, (u32)addr, (u32)(addr >> 32));
    wbinvd();

    cpuid(HV_CPUID_LEAF_BASE + leaf + 1, &eax, &ebx, &ecx, &edx);
    ret = uxen_hypercall_version(XENVER_extraversion, extraversion);
    if (!ret)
        printk(KERN_INFO "uxenplatform: hypervisor version uXen v%u.%u%s\n", eax >> 16, eax & 0xffff,
               extraversion);
out:
    return ret;
}

static void __exit uxen_hypercall_exit(void)
{
}

module_init(uxen_hypercall_init);
module_exit(uxen_hypercall_exit);
MODULE_AUTHOR("paulian.marinca@bromium.com");
MODULE_DESCRIPTION("uXen hypercall support");
MODULE_LICENSE("GPL");
