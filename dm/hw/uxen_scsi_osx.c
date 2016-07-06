/*
 * Copyright 2016, Bromium, Inc.
 * Author: Phil Dennis-Jordan <phil@philjordan.eu>
 * SPDX-License-Identifier: ISC
 */

#include <dm/config.h>
#include "uxen_scsi_osx.h"
#include <DiskArbitration/DADisk.h>
#include <IOKit/storage/IOStorageDeviceCharacteristics.h>

typedef struct v4v_scsi_inquiry_response {
    uint8_t peripheral;
    uint8_t reserved;
    uint8_t version;
    uint8_t response_data;
    uint8_t additional_length;
    uint8_t flag_bits[3];
    uint8_t vendor_id[8];
    uint8_t product_id[16];
    uint8_t product_rev_level[4];
    uint8_t serial_num[8];
} v4v_scsi_inquiry_response_t;

static void
extract_drive_characteristics_string(
    CFDictionaryRef dictionary, CFStringRef property,
    uint8_t* response_field, unsigned response_field_size)
{
    CFTypeRef property_value = NULL;
    bool found_property;
	
    found_property = CFDictionaryGetValueIfPresent(
        dictionary, property, &property_value);
    if(found_property && CFGetTypeID(property_value) == CFStringGetTypeID())
    {
        CFRange range = CFRangeMake(0, CFStringGetLength(property_value));
        CFStringGetBytes(
            property_value, range, kCFStringEncodingASCII, 0, false,
            response_field, response_field_size, NULL);
    }
}

size_t
uxscsi_inquiry(void* dest, size_t max_len)
{
    DASessionRef session;
    v4v_scsi_inquiry_response_t scsi_response = {
        .peripheral = 0x00,
        .reserved = 0x00,
        .version = 0x05, // complies with standard
        .response_data = 0x02, // standard response data format
        .additional_length = sizeof(scsi_response) - 5,
        .flag_bits = {0x00, 0x00, 0x10}
    };
    uint8_t mount_point[] = "/";
    CFURLRef url;
    DADiskRef disk;
    io_service_t service;
    CFTypeRef prop_value;
    CFDictionaryRef dictionary;

    session = DASessionCreate(NULL);
    if (session != NULL) {
        url = CFURLCreateFromFileSystemRepresentation(
            NULL, mount_point, strlen((const char*)mount_point), TRUE);
        disk = DADiskCreateFromVolumePath(NULL, session, url);
        CFRelease(url);
        if (disk) {
            service = DADiskCopyIOMedia(disk);
            if (service != IO_OBJECT_NULL) {
                prop_value = IORegistryEntrySearchCFProperty(
                    service, kIOServicePlane,
                    CFSTR(kIOPropertyDeviceCharacteristicsKey),
                    kCFAllocatorDefault,
                    kIORegistryIterateRecursively | kIORegistryIterateParents);
                if (prop_value != NULL
                    && CFGetTypeID(prop_value) == CFDictionaryGetTypeID()) {
                    dictionary = prop_value;
                    extract_drive_characteristics_string(
                        dictionary, CFSTR(kIOPropertyVendorNameKey),
                        scsi_response.vendor_id,
                        sizeof(scsi_response.vendor_id));
                    extract_drive_characteristics_string(
                        dictionary, CFSTR(kIOPropertyProductNameKey),
                        scsi_response.product_id,
                        sizeof(scsi_response.product_id));
                    extract_drive_characteristics_string(
                        dictionary, CFSTR(kIOPropertyProductRevisionLevelKey),
                        scsi_response.product_rev_level,
                        sizeof(scsi_response.product_rev_level));
                    extract_drive_characteristics_string(
                        dictionary, CFSTR(kIOPropertyProductSerialNumberKey),
                        scsi_response.serial_num,
                        sizeof(scsi_response.serial_num));
                } else {
                    debug_printf(
                        "Error getting root drive device characteristics "
                        "property\n");
                }
                if (prop_value != NULL)
                    CFRelease(prop_value);
                IOObjectRelease(service);
            }
            CFRelease(disk);
        }
        CFRelease(session);
    }
    if (max_len > sizeof(scsi_response)) {
        max_len = sizeof(scsi_response);
    }
    memcpy(dest, &scsi_response, max_len);
    return max_len;
}


