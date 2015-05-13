/*
 * Copyright 2015-2016, Bromium, Inc.
 * Author: Phil Dennis-Jordan <phil@philjordan.eu>
 * SPDX-License-Identifier: ISC
 */

#define UXEN_DEFINE_SYMBOLS_PROTO
#include "uxen.h"
#include <v4v.h>
#include "dom0_v4v_device.h"
#include "../uxenv4vservice/v4v_service.h"
extern "C" {
#include <uxen/uxen_info.h>
#include <uxen/uxen_link.h>
}
#include <IOKit/IOLib.h>

OSDefineMetaClassAndStructors(uxen_dom0_v4v_device, uxen_v4v_device);

static uxen_dom0_v4v_device* v4v_device;

class uxen_dom0_v4v_event_source : public IOEventSource
{
    OSDeclareDefaultStructors(uxen_dom0_v4v_event_source);
    volatile UInt8 v4v_event_pending;
public:
    using IOEventSource::init;
    virtual bool checkForWork() override;
    void signalV4VEvent();
};

OSDefineMetaClassAndStructors(uxen_dom0_v4v_event_source, IOEventSource);

bool
uxen_dom0_v4v_event_source::checkForWork()
{
    bool event;

    // bit 7 is the low bit, apparently
    event = !OSTestAndClear(7, &this->v4v_event_pending);
    if (event)
        this->action(this->owner);
    return (this->v4v_event_pending & 0x1) != 0;
}

void
uxen_dom0_v4v_event_source::signalV4VEvent()
{

    OSBitOrAtomic8(0x1, &this->v4v_event_pending);
    this->signalWorkAvailable();
}

static void
uxen_dom0_v4v_device_NotifyV4VServiceAction(OSObject *target, ...)
{
    uxen_dom0_v4v_device *v4v_dev;
    uxen_v4v_service *v4v_service;
    
    v4v_dev = OSDynamicCast(uxen_dom0_v4v_device, target);
    v4v_service = OSDynamicCast(uxen_v4v_service, v4v_dev->getClient());
    if (v4v_service != nullptr)
        v4v_service->notifyV4VEvent();
}

bool
uxen_dom0_v4v_device::init(OSDictionary* dictionary)
{

    if (!uxen_v4v_device::init(dictionary))
        return false;

    this->work_loop = IOWorkLoop::workLoop();
    this->event_source = new uxen_dom0_v4v_event_source();
    this->event_source->init(this, uxen_dom0_v4v_device_NotifyV4VServiceAction);
    this->work_loop->addEventSource(this->event_source);
    this->event_source->enable();

    this->setName("uxen_dom0_v4v_device");
    return true;
}



static void
uxen_dom0_v4v_device_notify(void)
{

    if (v4v_device != nullptr)
        v4v_device->event_source->signalV4VEvent();
}

bool
uxen_dom0_v4v_device::start(IOService *provider)
{

    if (!uxen_v4v_device::start(provider))
        return false;
    if (uxen_info == nullptr) {
        IOLog("uxen_dom0_v4v_device::start: uxen_info is NULL, aborting.\n");
        return false;
    }

    if (uxen_info->ui_signal_v4v != nullptr) {
        IOLog(
            "uxen_dom0_v4v_device::start: "
            "v4v upcall already registered, aborting.\n");
        return false;
    }

    v4v_device = this;

    uxen_info->ui_signal_v4v = uxen_dom0_v4v_device_notify;
    this->uxen_info_init = true;

    this->registerService();

    return true;
}

void
uxen_dom0_v4v_device::stop(IOService* provider)
{

    if (this->uxen_info_init && uxen_info != nullptr) {
        uxen_info->ui_signal_v4v = nullptr;
        if (this == v4v_device)
            v4v_device = nullptr;
    }
    uxen_v4v_device::stop(provider);
}

intptr_t
uxen_dom0_v4v_device::v4vOpHypercall(
    int cmd, void* arg1, void* arg2, void* arg3, void* arg4, void* arg5)
{
    return uxen_dom0_hypercall(
        NULL, NULL, UXEN_UNRESTRICTED_ACCESS_HYPERCALL, __HYPERVISOR_v4v_op,
        (uintptr_t)cmd, (uintptr_t)arg1, (uintptr_t)arg2,
        (uintptr_t)arg3, (uintptr_t)arg4, (uintptr_t)arg5);
}

IOWorkLoop*
uxen_dom0_v4v_device::getWorkLoop() const
{

    return this->work_loop;
}

void
uxen_dom0_v4v_device::free()
{

    if (this->event_source != nullptr) {
        this->event_source->disable();
        if (this->work_loop != nullptr)
            this->work_loop->removeEventSource(this->event_source);
    }
    OSSafeReleaseNULL(this->event_source);
    OSSafeReleaseNULL(this->work_loop);
    uxen_v4v_device::free();
}
