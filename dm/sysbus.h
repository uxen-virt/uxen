/*
 * Copyright 2012-2015, Bromium, Inc.
 * Author: Christian Limpach <Christian.Limpach@gmail.com>
 * SPDX-License-Identifier: ISC
 */

#ifndef _SYSBUS_H_
#define _SYSBUS_H_

#include "dev.h"
#include "mr.h"

typedef struct SysBusDevice {
    DeviceState qdev;
} SysBusDevice;

typedef int (*sysbus_initfn)(SysBusDevice *dev);

typedef struct SysBusDeviceInfo {
    DeviceInfo qdev;
    sysbus_initfn init;
} SysBusDeviceInfo;

struct BusInfo system_bus_info;

/* Macros to compensate for lack of type inheritance in C.  */
#define sysbus_from_qdev(dev) ((SysBusDevice *)(dev))
#define FROM_SYSBUS(type, dev) DO_UPCAST(type, busdev, dev)

void sysbus_register_withprop(SysBusDeviceInfo *info);

void sysbus_add_io(SysBusDevice *dev, uint64_t addr,
                   MemoryRegion *mem);
void sysbus_init_ioports(SysBusDevice *dev, uint32_t ioport, uint32_t size);

#endif	/* _SYSBUS_H_ */
