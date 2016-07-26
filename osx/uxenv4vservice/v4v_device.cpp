/*
 * Copyright 2015-2016, Bromium, Inc.
 * Author: Phil Dennis-Jordan <phil@philjordan.eu>
 * SPDX-License-Identifier: ISC
 */

#include "v4v_device.h"

OSDefineMetaClassAndAbstractStructors(uxen_v4v_device, IOService);

intptr_t
uxen_v4v_device::v4vOpHypercall(int cmd, void *arg1, void *arg2,
                                void *arg3, void *arg4, void *arg5)
{

    return this->v4vOpHypercall_with_priv(0, cmd, arg1, arg2, arg3, arg4, arg5);
}

OSMetaClassDefineReservedUnused(uxen_v4v_device, 2)
OSMetaClassDefineReservedUnused(uxen_v4v_device, 3)
OSMetaClassDefineReservedUnused(uxen_v4v_device, 4)
OSMetaClassDefineReservedUnused(uxen_v4v_device, 5)
OSMetaClassDefineReservedUnused(uxen_v4v_device, 6)
OSMetaClassDefineReservedUnused(uxen_v4v_device, 7)
