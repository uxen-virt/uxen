/*
 * Copyright 2015-2016, Bromium, Inc.
 * Author: Phil Dennis-Jordan <phil@philjordan.eu>
 * SPDX-License-Identifier: ISC
 */

#include "uxen_hypercall.h"
#include "hypercall.h"
#include <mach/mach_types.h>
#include <sys/errno.h>
#include <IOKit/IOBufferMemoryDescriptor.h>
#include <IOKit/IOLib.h>

// vm_kern.h KERNEL_PRIVATE
extern vm_map_t	kernel_map;

#if DEBUG
#define dprintk(fmt, ...) IOLog("uxenhypercall: " fmt, ## __VA_ARGS__)
#else
#define dprintk(fmt, ...) do {} while (0)
#endif

static IOBufferMemoryDescriptor *hypercall_desc;
static uint32_t hypercall_msr;

uint16_t uxen_version_major, uxen_version_minor;
xen_extraversion_t uxen_extraversion;

extern "C" kern_return_t uxenvmlib_start(kmod_info_t *ki, void *d);
extern "C" kern_return_t uxenvmlib_stop(kmod_info_t *ki, void *d);

static bool
hypercall_init();
static void
hypercall_cleanup();

kern_return_t
uxenvmlib_start(kmod_info_t *ki, void *d)
{

    if (!hypercall_init())
        return KERN_FAILURE;
    return KERN_SUCCESS;
}

kern_return_t
uxenvmlib_stop(kmod_info_t *ki, void *d)
{

    hypercall_cleanup();
    return KERN_SUCCESS;
}

int
uxen_hypercall_version(int cmd, void *arg)
{

    if (!hypercall_desc)
        return -ENOENT;
    return (int)_hypercall2(hcall(xen_version), hcall_arg(cmd), hcall_arg(arg));
}

int
uxen_hypercall_memory_op(int cmd, void *arg)
{

    if (!hypercall_desc)
        return -ENOENT;
    return (int)_hypercall2(hcall(memory_op), hcall_arg(cmd), hcall_arg(arg));
}

int
uxen_hypercall_hvm_op(int cmd, void *arg)
{

    if (!hypercall_desc)
        return -ENOENT;
    return (int)_hypercall2(hcall(hvm_op), hcall_arg(cmd), hcall_arg(arg));
}

static bool
hypercall_init(void)
{
    uint32_t eax = 0, ebx, ecx, edx, i;
    uint32_t leaf;
    char signature[13];
    void *page;
    int ret;

    for (leaf = 0x40000000; leaf < 0x40010000; leaf += 0x100) {
        cpuid(leaf, &eax, (unsigned int *)&signature[0],
                          (unsigned int *)&signature[4],
                          (unsigned int *)&signature[8]);
        signature[12] = 0;

        if (!strcmp(signature, "uXenisnotXen"))
            break;
    }

    if (leaf >= 0x40010000 || (eax - leaf) < 2) {
        dprintk("%s: Cannot find hypervisor CPUID leafs\n", __func__);
        return false;
    }

    cpuid(leaf + 2, &eax, &ebx, &ecx, &edx);

    hypercall_desc = IOBufferMemoryDescriptor::inTaskWithPhysicalMask(
        kernel_task,
        kIODirectionIn | kIOMemoryMapperNone,
        eax << PAGE_SHIFT,
        0x00000FFFFFFFF000UL);
    if (!hypercall_desc) {
        dprintk("%s: Failed to allocate IOBufferMemoryDescriptor\n", __func__);
        return false;
    }
    hypercall_desc->prepare();

    page = hypercall_desc->getBytesNoCopy();
    if (!page) {
        dprintk("%s: Failed to get MemoryDescriptor pointer\n", __func__);
        hypercall_desc->complete();
        hypercall_desc->release();
        hypercall_desc = NULL;
        return false;
    }
    memset(page, 0xc3 /* ret */, PAGE_SIZE);

    hypercall_msr = ebx;
    for (i = 0; i < eax; i++) {
        uint64_t addr = (uint64_t)hypercall_desc->getPhysicalSegment(
                i << PAGE_SHIFT,
                NULL);

        wrmsr(ebx, addr + i);
    }

    vm_protect(kernel_map, (uintptr_t)page, eax << PAGE_SHIFT,
               1, VM_PROT_READ | VM_PROT_EXECUTE);
    vm_protect(kernel_map, (uintptr_t)page, eax << PAGE_SHIFT,
               0, VM_PROT_READ | VM_PROT_EXECUTE);

    cpuid(leaf + 1, &eax, &ebx, &ecx, &edx);
    uxen_version_major = eax >> 16;
    uxen_version_minor = eax & 0xFFFF;

    ret = uxen_hypercall_version(XENVER_extraversion, uxen_extraversion);
    if (ret) {
        dprintk("%s: hypercall_version failed: %d\n", __func__, ret);
        hypercall_desc->complete();
        hypercall_desc->release();
        hypercall_desc = NULL;
        return false;
    }

    return true;
}

static void
hypercall_cleanup()
{

    if (hypercall_desc != NULL) {
        /* Revert the memory protection changes and free the memory. Currently
         * no need to "deregister" the hypercall pages. */
        void *hc_pages = hypercall_desc->getBytesNoCopy();
        IOByteCount hc_pages_len = hypercall_desc->getLength();
        vm_protect(kernel_map, (uintptr_t)hc_pages, hc_pages_len,
                   1, VM_PROT_READ | VM_PROT_WRITE);
        vm_protect(kernel_map, (uintptr_t)hc_pages, hc_pages_len,
                   0, VM_PROT_READ | VM_PROT_WRITE);

        hypercall_desc->complete();
        hypercall_desc->release();
        hypercall_desc = NULL;
    }
}

static uintptr_t
hypercall_addr(unsigned hypercall_index)
{

    return ((uintptr_t)hypercall_desc->getBytesNoCopy()) + hypercall_index * 32;
}

uintptr_t
uxen_hypercall0(unsigned hypercall_index)
{

    return _hypercall0(hypercall_addr(hypercall_index));
}
uintptr_t
uxen_hypercall1(unsigned hypercall_index, uintptr_t arg1)
{

    return _hypercall1(hypercall_addr(hypercall_index), arg1);
}
uintptr_t
uxen_hypercall2(
    unsigned hypercall_index, uintptr_t arg1, uintptr_t arg2)
{

    return _hypercall2(hypercall_addr(hypercall_index), arg1, arg2);
}
uintptr_t
uxen_hypercall3(
    unsigned hypercall_index, uintptr_t arg1, uintptr_t arg2, uintptr_t arg3)
{

    return _hypercall3(hypercall_addr(hypercall_index), arg1, arg2, arg3);
}
uintptr_t
uxen_hypercall4(
    unsigned hypercall_index,
    uintptr_t arg1, uintptr_t arg2, uintptr_t arg3, uintptr_t arg4)
{

    return _hypercall4(hypercall_addr(hypercall_index), arg1, arg2, arg3, arg4);
}
uintptr_t
uxen_hypercall5(
    unsigned hypercall_index,
    uintptr_t arg1, uintptr_t arg2, uintptr_t arg3, uintptr_t arg4,
    uintptr_t arg5)
{

    return _hypercall5(
        hypercall_addr(hypercall_index), arg1, arg2, arg3, arg4, arg5);
}
uintptr_t
uxen_hypercall6(
    unsigned hypercall_index,
    uintptr_t arg1, uintptr_t arg2, uintptr_t arg3, uintptr_t arg4,
    uintptr_t arg5, uintptr_t arg6)
{

    return _hypercall6(
        hypercall_addr(hypercall_index), arg1, arg2, arg3, arg4, arg5, arg6);
}

