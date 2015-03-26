/*
 * Copyright 2012-2015, Bromium, Inc.
 * Author: Christian Limpach <Christian.Limpach@gmail.com>
 * SPDX-License-Identifier: ISC
 */

#ifndef _UXENMOUSE_H_
#define _UXENMOUSE_H_

#include <ntddk.h>
#include <kbdmou.h>
#include <ntddmou.h>
#include <wdf.h>

typedef struct _DEVICE_EXTENSION {
    CONNECT_DATA upper_connect_data;
    struct mouse_shared_page {
	volatile unsigned int x;
	volatile unsigned int y;
    } *mouse_shared_page;
    unsigned int mouse_shared_mfn[1];
} DEVICE_EXTENSION, *PDEVICE_EXTENSION;

WDF_DECLARE_CONTEXT_TYPE_WITH_NAME(DEVICE_EXTENSION, FilterGetData)

DRIVER_INITIALIZE DriverEntry;
EVT_WDF_DRIVER_DEVICE_ADD uxenmouse_add;
EVT_WDF_IO_QUEUE_IO_INTERNAL_DEVICE_CONTROL uxenmouse_ioctl;

#endif	/* _UXENMOUSE_H_ */
