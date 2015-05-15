/*
 * Copyright 2015-2016, Bromium, Inc.
 * Author: Phil Dennis-Jordan <phil@philjordan.eu>
 * SPDX-License-Identifier: ISC
 */

#include "guest_v4v_device.h"
#include <v4v_service.h>
#include <uxenvmlib/uxen_hypercall.h>
#include <IOKit/IOLib.h>
#include <IOKit/IOBufferMemoryDescriptor.h>

OSDefineMetaClassAndStructors(uxen_guest_v4v_device, uxen_v4v_device);


bool
uxen_guest_v4v_device::start(IOService *provider)
{
    if (!this->IOService::start(provider))
        return false;
    this->intr_event_source = IOInterruptEventSource::interruptEventSource(this, &interruptAction, provider, 0);
    if(this->intr_event_source == nullptr) {
        kprintf(
            "UxenGuestV4VDevice::start: "
            "creating interrupt event source failed\n");
        return false;
    }

    this->work_loop = getWorkLoop();
    if (!work_loop)
        return false;
    
    if (kIOReturnSuccess != this->work_loop->addEventSource(intr_event_source)) {
        IOLog("UxenGuestV4VDevice::start Error! Adding interrupt event source to work loop failed.\n");
        OSSafeReleaseNULL(intr_event_source);
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
    closeV4VDevice();
    
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
        v4v_service->notifyV4VEvent();
    }
}

intptr_t
uxen_guest_v4v_device::v4vOpHypercall(
    int cmd, void *arg1, void *arg2, void *arg3, void *arg4, void *arg5)
{

    return (intptr_t)uxen_hypercall6(
        __HYPERVISOR_v4v_op, cmd,
        (uintptr_t)arg1, (uintptr_t)arg2, (uintptr_t)arg3,
        (uintptr_t)arg4, (uintptr_t)arg5);
}

