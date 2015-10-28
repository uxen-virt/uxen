/*
 * Copyright 2015-2016, Bromium, Inc.
 * Author: Julian Pidancet <julian@pidancet.net>
 * SPDX-License-Identifier: ISC
 */

#ifndef __BUS_H
#define __BUS_H

#define UXENBUS_TAG         'ubXu'

// {A5ED3899-3E47-4522-A842-C262B4E059CC}
DEFINE_GUID(GUID_DEVCLASS_UXENBUS,
            0xa5ed3899, 0x3e47, 0x4522, 0xa8, 0x42, 0xc2, 0x62, 0xb4, 0xe0, 0x59, 0xcc);

typedef struct _PDO_IDENTIFICATION_DESCRIPTION
{
    WDF_CHILD_IDENTIFICATION_DESCRIPTION_HEADER header; // should contain this header

    ULONG slot;
    UCHAR deviceType;
    UCHAR deviceId;
} PDO_IDENTIFICATION_DESCRIPTION, *PPDO_IDENTIFICATION_DESCRIPTION;

typedef struct _PDO_DEVICE_DATA
{
    WDFDEVICE parent;
    ULONG slot;

    UCHAR deviceType;
    UCHAR deviceId;
} PDO_DEVICE_DATA, *PPDO_DEVICE_DATA;

WDF_DECLARE_CONTEXT_TYPE_WITH_NAME(PDO_DEVICE_DATA, PdoGetData)

// {763D752C-0CA8-4008-8628-A786586F47E1}
DEFINE_GUID(GUID_UXENBUS_INTERFACE_STANDARD,
            0x763d752c, 0xca8, 0x4008, 0x86, 0x28, 0xa7, 0x86, 0x58, 0x6f, 0x47, 0xe1);

typedef struct _UXENBUS_INTERFACE_STANDARD {
    INTERFACE                        interfaceHeader;
} UXENBUS_INTERFACE_STANDARD, *PUXENBUS_INTERFACE_STANDARD;

NTSTATUS bus_init(PWDFDEVICE_INIT device_init);
NTSTATUS bus_set_info(WDFDEVICE device);
NTSTATUS create_pdo(WDFCHILDLIST device_list,
                    PWDF_CHILD_IDENTIFICATION_DESCRIPTION_HEADER desc,
                    PWDFDEVICE_INIT child_init);
NTSTATUS bus_enumerate(WDFDEVICE device);

#endif /* __BUS_H */
