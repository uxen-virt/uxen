/*
 * Copyright 2015-2016, Bromium, Inc.
 * Author: Julian Pidancet <julian@pidancet.net>
 * SPDX-License-Identifier: ISC
 */

#ifndef _UXENPLATFORM_DEVICE_H_
#define _UXENPLATFORM_DEVICE_H_

#include <IOKit/IOService.h>

#define kUXenPlatformXenBusPropertyDeviceTypeKey "XenBusDeviceType"
#define kUXenPlatformXenBusPropertyMTUKey        "XenBusMTU"
#define kUXenPlatformXenBusPropertyMACAddrKey    "XenBusMACAddr"
#define kUXenPlatformXenBusPropertiesKey         "XenBusProperties"

class uXenPlatform;
union uxp_bus_device_config_block;

class uXenPlatformDevice : public IOService
{
    OSDeclareDefaultStructors(uXenPlatformDevice);

public:
    static uXenPlatformDevice *withConfig(const union uxp_bus_device_config_block* config);

    /* IOService */
    virtual bool init(const union uxp_bus_device_config_block* config);
    virtual void free(void);
    virtual bool attach(IOService *provider);
    virtual void detach(IOService *provider);

    virtual bool matchPropertyTable(OSDictionary *table) override;

    uint8_t getDeviceType(void);
    uint8_t getInstanceId(void);

private:
    uint8_t _device_type;
    uint8_t _instance_id;

    uXenPlatform *_platform;
};

#endif /* _UXENPLATFORM_DEVICE_H_ */
