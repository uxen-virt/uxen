/*
 * Copyright 2014-2016, Bromium, Inc.
 * Author: Julian Pidancet <julian@pidancet.net>
 * SPDX-License-Identifier: ISC
 */

#include <IOKit/IOLib.h>
#include <IOKit/pci/IOPCIDevice.h>

#include "uXenPlatform.h"
#include "uXenPlatformDevice.h"

#include "hypercall.h"

#define super IOService

OSDefineMetaClassAndStructors(uXenPlatform, IOService);

int
uXenPlatform::hypercall_version(int cmd, void *arg)
{
    if (!hypercall_desc)
	return -ENOENT;
    return (int)_hypercall2(hcall(xen_version), hcall_arg(cmd), hcall_arg(arg));
}

int
uXenPlatform::hypercall_memory_op(int cmd, void *arg)
{
    if (!hypercall_desc)
	return -ENOENT;
    return (int)_hypercall2(hcall(memory_op), hcall_arg(cmd), hcall_arg(arg));
}

int
uXenPlatform::hypercall_hvm_op(int cmd, void *arg)
{
    if (!hypercall_desc)
	return -ENOENT;
    return (int)_hypercall2(hcall(hvm_op), hcall_arg(cmd), hcall_arg(arg));
}

bool
uXenPlatform::hypercall_init(void)
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
            kIODirectionIn,
            eax << PAGE_SHIFT,
            0x00000FFFFFFFF000UL);
    if (!hypercall_desc) {
        dprintk("%s: Failed to allocate IOBufferMemoryDescriptor\n", __func__);
        return false;
    }
    hypercall_desc->prepare();

    page = (void *)hypercall_desc->getBytesNoCopy();
    if (!page) {
        dprintk("%s: Failed to get MemoryDescriptor pointer\n", __func__);
        hypercall_desc->complete();
        hypercall_desc->release();
        hypercall_desc = NULL;
        return false;
    }
    memset(page, 0xc3 /* ret */, PAGE_SIZE);

    for (i = 0; i < eax; i++) {
        uint64_t addr = (uint64_t)hypercall_desc->getPhysicalSegment(
                i << PAGE_SHIFT,
                NULL);

        wrmsr(ebx, addr + i);
    }

    vm_protect(get_task_map(kernel_task), (uintptr_t)page, eax << PAGE_SHIFT,
               1, VM_PROT_READ | VM_PROT_EXECUTE);
    vm_protect(get_task_map(kernel_task), (uintptr_t)page, eax << PAGE_SHIFT,
               0, VM_PROT_READ | VM_PROT_EXECUTE);

    cpuid(leaf + 1, &eax, &ebx, &ecx, &edx);
    uxen_version_major = eax >> 16;
    uxen_version_minor = eax & 0xFFFF;

    ret = hypercall_version(XENVER_extraversion, extraversion);
    if (ret) {
        dprintk("%s: hypercall_version failed: %d\n", __func__, ret);
        hypercall_desc->complete();
        hypercall_desc->release();
        hypercall_desc = NULL;
        return false;
    }

    return true;
}

void
uXenPlatform::hypercall_cleanup(void)
{
    hypercall_desc->complete();
    hypercall_desc->release();
    hypercall_desc = NULL;
}

/* Client methods */

IOReturn
uXenPlatform::get_info(struct uXenPlatformInfo *arg)
{
    arg->uxen_version_major = uxen_version_major;
    arg->uxen_version_minor = uxen_version_minor;
    memcpy(arg->uxen_version_extra, extraversion, 16);

    return kIOReturnSuccess;
}

IOReturn
uXenPlatform::get_balloon_stats(struct uXenPlatformBalloonStats *arg)
{
    arg->balloon_mb = balloon.get_size();

    return kIOReturnSuccess;;
}

IOReturn
uXenPlatform::set_balloon_target(struct uXenPlatformBalloonTarget *arg)
{
    IOReturn ret;

    arg->balloon_old_size_mb = balloon.get_size();
    ret = balloon.set_size(arg->target_mb);
    arg->balloon_new_size_mb = balloon.get_size();

    return ret;
}

/* IOService */

bool
uXenPlatform::init(OSDictionary *dict)
{
    bool rc = super::init(dict);

    return rc;
}

void
uXenPlatform::free(void)
{
    super::free();
}

IOService *
uXenPlatform::probe(IOService *provider, SInt32 *score)
{
    IOService *ret;

    ret = super::probe(provider, score);

    return ret;
}

void
uXenPlatform::stop_devices(void)
{
    int i;

    for (i = 0; i < UXENBUS_DEVICE_COUNT; i++) {
        uXenPlatformDevice *nub = (uXenPlatformDevice *)nubs->getObject(i);
        if (nub) {
            nub->terminate();
            nub->release();
            nubs->removeObject(i);
        }
    }
}

void
uXenPlatform::enumerate_devices(void)
{
    int i;

    for (i = 0; i < UXENBUS_DEVICE_COUNT; i++) {
        IODeviceMemory *config;
        uXenPlatformDevice *nub;
        struct uxp_bus_device desc;

        config = IODeviceMemory::withSubRange(bar2, i * UXENBUS_DEVICE_CONFIG_LENGTH,
                                              UXENBUS_DEVICE_CONFIG_LENGTH);
        if (!config)
            continue;

        if (config->readBytes(0, &desc, sizeof(desc)) != sizeof(desc))
            goto next;

        nub = (uXenPlatformDevice *)nubs->getObject(i);

        if (nub && (nub->getDeviceType() != desc.device_type ||
                    nub->getInstanceId() != desc.instance_id)) {
            nub->terminate();
            nub->release();
            nubs->removeObject(i);
        }

        if (desc.device_type != UXENBUS_DEVICE_NOT_PRESENT) {

            nub = uXenPlatformDevice::withConfig(config);
            if (!nub)
                goto next;

            nub->attach(this);
            nub->registerService();
            nubs->setObject(i, nub);
        }

next:
        config->release();
    }
}

#ifndef offsetof
#define offsetof(st, m) ((IOByteCount)(&((st *)0)->m))
#endif

void
uXenPlatform::enable_interrupt(int events)
{
    uint32_t ev = events;

    bar0->writeBytes(offsetof(struct ctl_mmio, cm_events_enabled), &ev, sizeof(ev));
}

bool
uXenPlatform::start(IOService *provider)
{
    bool rc;

    rc = super::start(provider);
    if (!rc)
        return false;

    pcidev = OSDynamicCast(IOPCIDevice, provider);
    if (!pcidev)
        return false;

    pcidev->setMemoryEnable(true);
    bar0 = pcidev->getDeviceMemoryWithRegister(kIOPCIConfigBaseAddress0);
    if (!bar0)
        return false;
    bar2 = pcidev->getDeviceMemoryWithRegister(kIOPCIConfigBaseAddress2);
    if (!bar2)
        return false;
    nubs = OSArray::withCapacity(UXENBUS_DEVICE_COUNT);
    if (!nubs)
        return false;

    evtsrc = IOFilterInterruptEventSource::filterInterruptEventSource(
            this,
            uXenPlatform::handle_interrupt,
            uXenPlatform::filter_interrupt,
            provider,
            0);
    if (!evtsrc)
        return false;
    if (getWorkLoop()->addEventSource(evtsrc) != kIOReturnSuccess)
        return false;
    enable_interrupt(CTL_MMIO_EVENT_HOTPLUG);

    if (!hypercall_init()) {
        getWorkLoop()->removeEventSource(evtsrc);
        return false;
    }

    if (!balloon.init(this)) {
        hypercall_cleanup();
        getWorkLoop()->removeEventSource(evtsrc);
        return false;
    }

    enumerate_devices();

    setProperty("IOUserClientClass", "uXenPlatformClient");
    registerService();

    return true;
}

void
uXenPlatform::stop(IOService *provider)
{
    stop_devices();
    nubs->release();
    nubs = NULL;
    balloon.free();
    hypercall_cleanup();
    getWorkLoop()->removeEventSource(evtsrc);
    super::stop(provider);
}

bool
uXenPlatform::filterInterrupt(IOFilterInterruptEventSource *src)
{
    /*
     * Primary Interrupt handler, called in HW IRQ context.
     *
     * Read interrupt register and return true to schedule secondary
     * interrupt.
     */
    uint32_t ev = 0;

    bar0->readBytes(offsetof(struct ctl_mmio, cm_events), &ev, sizeof(ev));
    pending_events |= ev;

    return true;
}

void
uXenPlatform::handleInterrupt(IOInterruptEventSource *src, int count)
{
    /*
     * Secondary Interrupt handler, called in workloop context.
     */
    if (pending_events & CTL_MMIO_EVENT_HOTPLUG) {
        pending_events &= ~CTL_MMIO_EVENT_HOTPLUG;

        enumerate_devices();
    }
}

