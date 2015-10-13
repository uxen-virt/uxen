/*
 * Copyright 2015-2016, Bromium, Inc.
 * Author: Phil Dennis-Jordan <phil@philjordan.eu>
 * SPDX-License-Identifier: ISC
 */

#ifndef UxenV4VDevice_UxenGuestV4VDevice_h
#define UxenV4VDevice_UxenGuestV4VDevice_h

#include <v4v_device.h>

#define uxen_guest_v4v_device org_uxen_driver_guest_v4v_device
class uXenPlatform;
/** Uxen v4v mechanism provider for guest domains, based on dedicated interrupt
 * and uxen hypercalls. Interrupts are discovered via the corresponding ACPI
 * entry; provider for this service is the IOACPIPlatformDevice.
 */
class uxen_guest_v4v_device : public uxen_v4v_device
{
    OSDeclareDefaultStructors(uxen_guest_v4v_device);
    
protected:
    IOInterruptEventSource *intr_event_source;
    IOWorkLoop *work_loop;
    uXenPlatform* platform_device;
    IOMemoryMap* platform_state_bar_map;
    struct uxp_state_bar* platform_state;
public:
    virtual bool start(IOService *provider) override;
    static void interruptAction(
        OSObject *me, IOInterruptEventSource *source, int count);
    virtual void interruptAction(IOInterruptEventSource *source, int count);
    
    virtual void closeV4VDevice();
    virtual void stop(IOService *provider) override;

    virtual intptr_t v4vOpHypercall(
        int cmd, void *arg1, void *arg2,
        void *arg3, void *arg4, void *arg5) override;
};

#endif
