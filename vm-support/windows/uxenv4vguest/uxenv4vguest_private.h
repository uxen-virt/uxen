/*
 * Copyright 2015, Bromium, Inc.
 * SPDX-License-Identifier: ISC
 */

#include <initguid.h>
#include <ntddk.h>
#include <wdf.h>

#include "uxenvmlib.h"
#include "uxenv4vlib.h"



typedef struct _DEVICE_EXTENSION {
    WDFDEVICE Device;
    WDFINTERRUPT            Interrupt;
}  DEVICE_EXTENSION, *PDEVICE_EXTENSION;


WDF_DECLARE_CONTEXT_TYPE_WITH_NAME(DEVICE_EXTENSION, UxvgGetDeviceContext)

#include "prototypes.h"
