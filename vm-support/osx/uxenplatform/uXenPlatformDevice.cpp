/*
 * Copyright 2015-2016, Bromium, Inc.
 * Author: Julian Pidancet <julian@pidancet.net>
 * SPDX-License-Identifier: ISC
 */

#include <IOKit/IOLib.h>

#include "uXenPlatform.h"
#include "uXenPlatformDevice.h"

#define super IOService

OSDefineMetaClassAndStructors(uXenPlatformDevice, IOService);

bool
uXenPlatformDevice::init(IODeviceMemory *config)
{
    if (super::init())
        return false;

    config->retain();
    _config = config;

    if (config->readBytes(0, &_desc, sizeof(_desc)) != sizeof(_desc))
        return false;

    dprintk("%s: dev=%p t=%d id=%d\n", __func__, this,
            _desc.device_type, _desc.instance_id);

    return true;
}

uXenPlatformDevice *
uXenPlatformDevice::withConfig(IODeviceMemory *config)
{
    uXenPlatformDevice *device = new uXenPlatformDevice;

    if (!device)
        return NULL;

    if (!device->init(config)) {
        device->release();
        return NULL;
    }

    return device;
}

void
uXenPlatformDevice::free(void)
{
    _config->release();
    _config = NULL;

    dprintk("%s: dev=%p\n", __func__, this);

    super::free();
}

bool
uXenPlatformDevice::attach(IOService *provider)
{
    if (!super::attach(provider))
        return false;

    _platform = (uXenPlatform *)provider;
    _platform->retain();

    dprintk("%s: dev=%p provider=%p\n", __func__, this, provider);

    return true;
}

void
uXenPlatformDevice::detach(IOService *provider)
{
    _platform->release();
    _platform = NULL;

    dprintk("%s: dev=%p provider=%p\n", __func__, this, provider);

    super::detach(provider);
}

uint8_t
uXenPlatformDevice::getDeviceType(void)
{
    return _desc.device_type;
}

uint8_t
uXenPlatformDevice::getInstanceId(void)
{
    return _desc.instance_id;
}
