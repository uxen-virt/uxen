/*
 * Copyright 2013-2016, Bromium, Inc.
 * Author: Christian Limpach <Christian.Limpach@gmail.com>
 * SPDX-License-Identifier: ISC
 */

#ifndef _PLATFORM_INTERFACE_H_
#define _PLATFORM_INTERFACE_H_

#define CTL_MMIO_EVENT_SYNC_TIME 0x1
#define CTL_MMIO_EVENT_SET_BALLOON 0x2
#define CTL_MMIO_EVENT_HOTPLUG 0x4

struct ctl_mmio {
    uint32_t cm_events_enabled;
    uint32_t cm_events;
    uint32_t cm_balloon_min;
    uint32_t cm_balloon_max;
    uint32_t cm_balloon_current;
    uint32_t cm_filetime_low;
    uint32_t cm_filetime_high;
};

#define UXEN_STATE_BAR_MAGIC	0x47531628

struct uxp_state_bar {
    uint32_t magic;
    uint32_t v4v_running;
};

#define UXENBUS_DEVICE_CONFIG_LENGTH    256
#define UXENBUS_DEVICE_COUNT            64

#define UXENBUS_DEVICE_TYPE_NET         0x0
#define UXENBUS_DEVICE_TYPE_HID         0x1
#define UXENBUS_DEVICE_TYPE_NULL_NET    0x2
#define UXENBUS_DEVICE_NOT_PRESENT      0xff

#define UXENBUS_PROPERTY_TYPE_MACADDR   0x0
#define UXENBUS_PROPERTY_TYPE_MTU       0x1
#define UXENBUS_PROPERTY_TYPE_HIDTYPE   0x2
#define UXENBUS_PROPERTY_TYPE_LIST_END  0xff

struct uxp_bus_device_property {
    uint8_t property_type;
    uint8_t length;
};

#define UXENBUS_PROP_NEXT_L(p,l) (struct uxp_bus_device_property *)((uint8_t *)((p) + 1) + (l))
#define UXENBUS_PROP_NEXT(p) UXENBUS_PROP_NEXT_L(p, (p)->length)

struct uxp_bus_device {
    uint8_t device_type;
    uint8_t instance_id;
    struct uxp_bus_device_property prop_list;
};

static const wchar_t * const uxenbus_device_names[] = {
    L"uxennet",
    L"uxenhid",
    L"uxennullnet",
};

#endif  /* _PLATFORM_INTERFACE_H_ */
