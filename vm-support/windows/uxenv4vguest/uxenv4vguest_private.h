/*
 * Copyright 2015-2019, Bromium, Inc.
 * SPDX-License-Identifier: ISC
 */

#include <initguid.h>
#include <ntddk.h>
#include <wdf.h>

#include "uxenvmlib.h"
#include "uxenv4vlib.h"



typedef struct _DEVICE_EXTENSION {
    WDFDEVICE Device;
    WDFINTERRUPT Interrupt;
    uxen_v4v_ring_handle_t *EchoRing;
}  DEVICE_EXTENSION, *PDEVICE_EXTENSION;


WDF_DECLARE_CONTEXT_TYPE_WITH_NAME(DEVICE_EXTENSION, UxvgGetDeviceContext)

#include "prototypes.h"
