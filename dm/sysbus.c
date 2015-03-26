/*
 * Copyright 2012-2015, Bromium, Inc.
 * Author: Christian Limpach <Christian.Limpach@gmail.com>
 * SPDX-License-Identifier: ISC
 */

#include "config.h"

#include <err.h>
#include <stdbool.h>
#include <stdint.h>

#include "mr.h"
#include "sysbus.h"

struct BusInfo system_bus_info = {
    .name       = "System",
    .size       = sizeof(BusState),
    // .print_dev  = sysbus_dev_print,
    // .get_fw_dev_path = sysbus_get_fw_dev_path,
};

static int sysbus_device_init(DeviceState *dev, DeviceInfo *base)
{
    SysBusDeviceInfo *info = container_of(base, SysBusDeviceInfo, qdev);

    return info->init(sysbus_from_qdev(dev));
}

void
sysbus_register_withprop(SysBusDeviceInfo *info)
{
    info->qdev.init = sysbus_device_init;
    info->qdev.bus_info = &system_bus_info;

    assert(info->qdev.size >= sizeof(SysBusDevice));
    dev_register(&info->qdev);
}

void
sysbus_add_io(SysBusDevice *dev, uint64_t addr,
	      MemoryRegion *mem)
{
    memory_region_add_subregion(system_ioport, addr, mem);
}

void
sysbus_init_ioports(SysBusDevice *dev, uint32_t ioport, uint32_t size)
{
}
