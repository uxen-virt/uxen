/*
 * Copyright 2015, Bromium, Inc.
 * SPDX-License-Identifier: ISC
 */

#ifndef _UXENNULLNET_H
#define _UXENNULLNET_H

#include <ntddk.h>
#include <ndis.h>

#include "hardware.h"
#include "miniport.h"
#include "vmq.h"
#include "qos1.h"
#include "adapter.h"
#include "mphal.h"
#include "tcbrcb.h"
#include "datapath.h"
#include "ctrlpath.h"


#define DEBUGP(x,...)
#define MP_TRACE
#define MP_ERROR
#define MP_LOUD
#pragma warning(disable:4127)
#pragma warning(disable:4189)
#pragma warning(disable:4100)

NTSTATUS
acpi_get_mac_address(IN PDEVICE_OBJECT pdo, UCHAR *mac_address);

#endif // _UXENNULLNET_H

