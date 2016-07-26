/*
 * Copyright 2015-2016, Bromium, Inc.
 * Author: Phil Dennis-Jordan <phil@philjordan.eu>
 * SPDX-License-Identifier: ISC
 */

#include "guest_v4v_device.h"
#include <v4v_service.h>
#include <uxenvmlib/uxen_hypercall.h>
#include <uxenplatform/uXenPlatform.h>
#include <uxen/platform_interface.h>
#include <sys/errno.h>
#include <IOKit/IOLib.h>
#include <IOKit/IOBufferMemoryDescriptor.h>

OSDefineMetaClassAndStructors(uxen_guest_v4v_device, uxen_v4v_device);


bool
uxen_guest_v4v_device::start(IOService *provider)
{
    OSDictionary *matching_dict;
    IOService *matching_service;
    uXenPlatform *platform;
    IODeviceMemory *bar;
    
    if (!this->IOService::start(provider))
        return false;
    matching_dict = this->serviceMatching(kUxenPlatformClassName);
    matching_service =
        this->waitForMatchingService(matching_dict, NSEC_PER_SEC * 10);
    platform = OSDynamicCast(uXenPlatform, matching_service);
    if(platform == nullptr) {
        OSSafeReleaseNULL(matching_service);
        kprintf(
            "UxenGuestV4VDevice::start: failed to match the platform device\n");
        return false;
    }
    
    this->platform_device = platform;
    bar = platform->getPlatformStateBAR();
    if(bar == nullptr) {
        OSSafeReleaseNULL(this->platform_device);
        return false;
    }
    this->platform_state_bar_map = bar->createMappingInTask(
        kernel_task, 0, kIOMapAnywhere);
    if(this->platform_state_bar_map == NULL) {
        OSSafeReleaseNULL(this->platform_device);
        return false;
    }
    this->platform_state =
        reinterpret_cast<uxp_state_bar*>(
            this->platform_state_bar_map->getAddress());
    if(this->platform_state->magic != UXEN_STATE_BAR_MAGIC) {
        kprintf(
            "State bar magic does not equal UXEN_STATE_BAR_MAGIC: %08x\n",
            this->platform_state->magic);
        OSSafeReleaseNULL(this->platform_state_bar_map);
        OSSafeReleaseNULL(this->platform_device);
        return false;
    }

    this->intr_event_source = IOInterruptEventSource::interruptEventSource(
        this, &interruptAction, provider, 0);
    if(this->intr_event_source == nullptr) {
        kprintf(
            "UxenGuestV4VDevice::start: "
            "creating interrupt event source failed\n");
        return false;
    }

    this->work_loop = getWorkLoop();
    if (!this->work_loop) {
        OSSafeReleaseNULL(this->platform_device);
        return false;
    }
    if (kIOReturnSuccess != this->work_loop->addEventSource(intr_event_source)){
        kprintf(
            "UxenGuestV4VDevice::start "
            "Error! Adding interrupt event source to work loop failed.\n");
        OSSafeReleaseNULL(intr_event_source);
        OSSafeReleaseNULL(this->platform_device);
        return false;
    }
    
    intr_event_source->enable();
    
    this->registerService();
        
    return true;
}

void
uxen_guest_v4v_device::closeV4VDevice()
{

    if(this->intr_event_source) {
        this->intr_event_source->disable();
        this->work_loop->removeEventSource(this->intr_event_source);
        OSSafeReleaseNULL(this->intr_event_source);
    }
}

void
uxen_guest_v4v_device::stop(IOService *provider)
{

    this->closeV4VDevice();
    OSSafeReleaseNULL(this->platform_device);
    OSSafeReleaseNULL(this->platform_state_bar_map);
    IOService::stop(provider);
}


void
uxen_guest_v4v_device::interruptAction(
    OSObject *me, IOInterruptEventSource *source, int count)
{
    uxen_guest_v4v_device *v4v;
    
    v4v = OSDynamicCast(uxen_guest_v4v_device, me);
    if (!v4v || source != v4v->intr_event_source)
        return;
    
    v4v->interruptAction(source, count);
}

void
uxen_guest_v4v_device::interruptAction(
    IOInterruptEventSource *source, int count)
{
    uxen_v4v_service *v4v_service;
    
    v4v_service = OSDynamicCast(uxen_v4v_service, this->getClient());
    if (v4v_service != nullptr) {
        while(this->platform_state->v4v_running == 0) {
            this->platform_state->v4v_running++;
            v4v_service->notifyV4VRingResetEvent();
        }
        v4v_service->notifyV4VEvent();
    }
}

intptr_t
uxen_guest_v4v_device::v4vOpHypercall_with_priv(
    int privileged, int cmd, void *arg1, void *arg2,
    void *arg3, void *arg4, void *arg5)
{

    return (intptr_t)uxen_hypercall6(
        __HYPERVISOR_v4v_op, cmd,
        (uintptr_t)arg1, (uintptr_t)arg2, (uintptr_t)arg3,
        (uintptr_t)arg4, (uintptr_t)arg5);
}

int
uxen_guest_v4v_device::authorize_action(int action, bool *admin_access)
{

    switch (action) {
    case UXEN_AUTH_OPEN:
        *admin_access = true;
        return 0;
    default:
        *admin_access = false;
        return EINVAL;
    }
}
