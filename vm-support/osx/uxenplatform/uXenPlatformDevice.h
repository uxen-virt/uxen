/*
 * Copyright 2015-2016, Bromium, Inc.
 * Author: Julian Pidancet <julian@pidancet.net>
 * SPDX-License-Identifier: ISC
 */

#ifndef _UXENPLATFORM_DEVICE_H_
#define _UXENPLATFORM_DEVICE_H_

#include <IOKit/IOService.h>

class uXenPlatform;

class uXenPlatformDevice : public IOService
{
    OSDeclareDefaultStructors(uXenPlatformDevice);

public:
    static uXenPlatformDevice *withConfig(IODeviceMemory *);

    /* IOService */
    virtual bool init(IODeviceMemory *);
    virtual void free(void);
    virtual bool attach(IOService *provider);
    virtual void detach(IOService *provider);

    uint8_t getDeviceType(void);
    uint8_t getInstanceId(void);

private:
    struct uxp_bus_device _desc;
    uXenPlatform *_platform;
    IODeviceMemory *_config;
};

#endif /* _UXENPLATFORM_DEVICE_H_ */
