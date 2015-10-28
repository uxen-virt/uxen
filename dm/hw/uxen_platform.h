/*
 * Copyright 2012-2016, Bromium, Inc.
 * Author: Christian Limpach <Christian.Limpach@gmail.com>
 * SPDX-License-Identifier: ISC
 */

#ifndef _UXEN_PLATFORM_H_
#define _UXEN_PLATFORM_H_

#include <dm/dev.h>

void uxen_platform_time_update(void);
int uxen_platform_set_balloon_size(int min_mb, int max_mb);
int uxen_platform_get_balloon_size(int *current, int *min, int *max);

typedef struct UXenPlatformDevice {
    DeviceState qdev;
    uint8_t *config;
} UXenPlatformDevice;

UXenPlatformDevice *uxenplatform_device_create(const char *name);
UXenPlatformDevice *uxenplatform_create_simple(const char *model);
UXenPlatformDevice *uxenplatform_nic_init(NICInfo *nd, const char *model);

typedef struct UXenPlatformDeviceInfo {
    DeviceInfo qdev;
    int (*init)(UXenPlatformDevice *dev);
    int (*exit)(UXenPlatformDevice *dev);
    int (*unplug)(UXenPlatformDevice *dev);
    uint8_t devtype;
} UXenPlatformDeviceInfo;

void uxenplatform_qdev_register(UXenPlatformDeviceInfo *info);

int uxenplatform_device_add_property(UXenPlatformDevice *dev,
                                     uint8_t property_type,
                                     void *property, size_t property_len);

int uxenplatform_device_get_instance_id(UXenPlatformDevice *dev);

#endif  /* _UXEN_PLATFORM_H_ */
