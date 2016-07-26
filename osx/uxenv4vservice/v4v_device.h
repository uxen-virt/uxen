/*
 * Copyright 2015-2016, Bromium, Inc.
 * Author: Phil Dennis-Jordan <phil@philjordan.eu>
 * SPDX-License-Identifier: ISC
 */

#ifndef _V4V_DEVICE_H_
#define _V4V_DEVICE_H_

#ifdef __cplusplus

#include <IOKit/IOService.h>
#include <IOKit/IOFilterInterruptEventSource.h>

#define uxen_v4v_device org_uxen_driver_v4v_device

/** Abstract base class for underlying V4V hypercall and notification
 * implementations.
 * Concrete subclasses must implement the v4vOpHypercall() method for making
 * a 6-argument V4V_op hypercall. This will be different for guests vs Dom0.
 * uxen_v4v_service will be matched as a client to any registered uxen_v4v_device
 * instance, and implementations must call such a client's notifyV4VEvent()
 * method on the workloop upon receiving an interrupt or upcall.
 */
class uxen_v4v_device : public IOService
{
    OSDeclareAbstractStructors(uxen_v4v_device);
public:
    virtual intptr_t v4vOpHypercall_with_priv(
        int privileged, int cmd, void *arg1, void *arg2,
        void *arg3, void *arg4, void *arg5) = 0;
    virtual intptr_t v4vOpHypercall(
        int cmd, void *arg1, void *arg2,
        void *arg3, void *arg4, void *arg5);
    virtual int authorize_action(int action, bool *admin_access) = 0;

    OSMetaClassDeclareReservedUnused(uxen_v4v_device, 2);
    OSMetaClassDeclareReservedUnused(uxen_v4v_device, 3);
    OSMetaClassDeclareReservedUnused(uxen_v4v_device, 4);
    OSMetaClassDeclareReservedUnused(uxen_v4v_device, 5);
    OSMetaClassDeclareReservedUnused(uxen_v4v_device, 6);
    OSMetaClassDeclareReservedUnused(uxen_v4v_device, 7);
};

#endif  /* __cplusplus */

#define UXEN_AUTH_OPEN 0

#endif // _uxen_v4v_device_H_
