/*
 * Copyright 2015-2016, Bromium, Inc.
 * SPDX-License-Identifier: ISC
 */

#ifndef _HID_INTERFACE_H_
#define _HID_INTERFACE_H_

#include <initguid.h>

DEFINE_GUID(UXENHID_IFACE_GUID, 0x9FA909FD, 0x9E55, 0x4FDA,
        0x87, 0x6F, 0xAD, 0x2C, 0x77, 0x85, 0x66, 0xD1);

#define FILE_DEVICE_UXENHID 32768

#define IOCTL_UXENHID_SET_VIRTUAL_MODE \
    CTL_CODE(FILE_DEVICE_UXENHID, 0x802, METHOD_BUFFERED, FILE_ANY_ACCESS)

struct virt_mode {
    LONG virt_w;
    LONG virt_h;
    LONG curr_w;
    LONG curr_h;
};


#endif /* _HID_INTERFACE_H_ */
