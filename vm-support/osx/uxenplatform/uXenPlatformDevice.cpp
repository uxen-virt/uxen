/*
 * Copyright 2015-2016, Bromium, Inc.
 * Author: Julian Pidancet <julian@pidancet.net>
 * SPDX-License-Identifier: ISC
 */

#include <IOKit/IOLib.h>

#include "uXenPlatform.h"
#include "uXenPlatformDevice.h"

#include <uxen/platform_interface.h>
#include "uxenplatform_local.h"

#define super IOService

OSDefineMetaClassAndStructors(uXenPlatformDevice, IOService);

bool
uXenPlatformDevice::init(const union uxp_bus_device_config_block* config)
{
    if (!super::init())
        return false;

    _device_type = config->device.device_type;
    _instance_id = config->device.instance_id;
    
    setProperty(kUXenPlatformXenBusPropertyDeviceTypeKey, config->device.device_type, 8);
    
    OSArray* prop_array = OSArray::withCapacity(8);
    
    const uint8_t* desc_bytes = config->bytes;
    unsigned offset = offsetof(uxp_bus_device, prop_list);
    while (offset <= UXENBUS_DEVICE_CONFIG_LENGTH - sizeof(uxp_bus_device_property)) {
        const uxp_bus_device_property* prop = reinterpret_cast<const uxp_bus_device_property*>(
            desc_bytes + offset); //aliasing OK as struct is all uint8_ts
        if (prop->property_type == UXENBUS_PROPERTY_TYPE_LIST_END)
            break;
        unsigned end_offset = offset + sizeof(*prop) + prop->length;
        if (end_offset > UXENBUS_DEVICE_CONFIG_LENGTH) {
            IOLog("uXenPlatformDevice::init device %u (type %02x) Warning: property at %u overruns config area\n",
                _instance_id, _device_type, offset);
            break;
        }
        
        unsigned data_offset = offset + sizeof(*prop);
        switch (prop->property_type) {
        case UXENBUS_PROPERTY_TYPE_MTU:
            if (prop->length != 2) {
                IOLog("uXenPlatformDevice::init device %u (type %02x) Warning: MTU (%02x) property at %u has length %u, expected 2\n",
                _instance_id, _device_type, prop->property_type, offset, prop->length);
            }

            if (prop->length >= 2) {
                uint16_t mtu = OSReadBigInt16(desc_bytes, data_offset);
                this->setProperty(kUXenPlatformXenBusPropertyMTUKey, mtu, 16);
            }
            break;

        case UXENBUS_PROPERTY_TYPE_MACADDR:
            if (prop->length != 6) {
                IOLog("uXenPlatformDevice::init device %u (type %02x) Warning: MAC Address (%02x) property at %u has length %u, expected 6\n",
                _instance_id, _device_type, prop->property_type, offset, prop->length);
            }

            if (prop->length >= 6) {
                OSData* mac_data = OSData::withBytes(desc_bytes + data_offset, 6);
                this->setProperty(kUXenPlatformXenBusPropertyMACAddrKey, mac_data);
                OSSafeReleaseNULL(mac_data);
            }
            break;
            
        default:
            break;
        }
        
        OSDictionary* prop_dict = OSDictionary::withCapacity(2);
        OSNumber* type_num = OSNumber::withNumber(prop->property_type, 8);
        OSData* prop_data = OSData::withBytes(desc_bytes + data_offset, prop->length);
        if (prop_dict && type_num && prop_data) {
            prop_dict->setObject("type", type_num);
            prop_dict->setObject("data", prop_data);
            prop_array->setObject(prop_dict);
        }
        OSSafeReleaseNULL(type_num);
        OSSafeReleaseNULL(prop_data);
        OSSafeReleaseNULL(prop_dict);
        
        offset = data_offset + prop->length;
    }
    setProperty(kUXenPlatformXenBusPropertiesKey, prop_array);
    OSSafeReleaseNULL(prop_array);
    
    dprintk("%s: dev=%p t=%d id=%d\n", __func__, this,
            _device_type, _instance_id);
    
    char location_str[11] = "";
    snprintf(location_str, sizeof(location_str), "%u", _instance_id);
    setLocation(location_str);

    return true;
}

bool uXenPlatformDevice::matchPropertyTable(OSDictionary *table)
{
    OSObject* device_type = table->getObject(kUXenPlatformXenBusPropertyDeviceTypeKey);
    if (device_type != nullptr) {
        OSNumber* type_num = OSDynamicCast(OSNumber, device_type);
        if (type_num == nullptr)
            return false;
        
        if (_device_type != type_num->unsigned8BitValue())
            return false;
    }
    return super::matchPropertyTable(table);
}


uXenPlatformDevice *
uXenPlatformDevice::withConfig(const union uxp_bus_device_config_block* config)
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
    return _device_type;
}

uint8_t
uXenPlatformDevice::getInstanceId(void)
{
    return _instance_id;
}
