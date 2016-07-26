/*
 * Copyright 2015-2016, Bromium, Inc.
 * Author: Phil Dennis-Jordan <phil@philjordan.eu>
 * SPDX-License-Identifier: ISC
 */

#ifndef _DOM0_V4V_DEVICE_H_
#define _DOM0_V4V_DEVICE_H_

#define uxen_dom0_v4v_device org_uxen_driver_dom0_v4v_device
#define uxen_dom0_v4v_event_source org_uxen_driver_dom0_v4v_event_source

#if __cplusplus < 201103L
#define override
#define nullptr NULL
#endif

#include <IOKit/IOService.h>
#include "../uxenv4vservice/v4v_device.h"

class uxen_dom0_v4v_event_source;

class uxen_dom0_v4v_device : public uxen_v4v_device
{
    OSDeclareDefaultStructors(uxen_dom0_v4v_device);
    bool uxen_info_init;
    IOWorkLoop* work_loop;
public:
    uxen_dom0_v4v_event_source* event_source;
    virtual bool init(OSDictionary* dictionary) override;
    virtual void free() override;
    virtual bool start(IOService* provider) override;
    virtual void stop(IOService* provider) override;
    virtual intptr_t v4vOpHypercall_with_priv(
        int privileged, int cmd, void* arg1, void* arg2,
        void* arg3, void* arg4, void* arg5) override;
    virtual int authorize_action(int action, bool *admin_access) override;
    virtual IOWorkLoop* getWorkLoop() const override;
};

#endif
