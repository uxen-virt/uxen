/*
 * Copyright 2013-2015, Bromium, Inc.
 * Author: Kris Uchronski <kuchronski@gmail.com>
 * SPDX-License-Identifier: ISC
 */

#ifndef _STORFLT_H_
#define _STORFLT_H_


#include <ntddk.h>
#include <ntdddisk.h>
#include <initguid.h>
#include <ntddstor.h>
#include <wmistr.h>
#include <stdio.h>
#include <dontuse.h>

#include "uxenvmlib.h"

#define MEMTAG_STOR_DESC    (ULONG)'0fsu'
#define MEMTAG_REMOVE_LOCK  (ULONG)'1fsu'


typedef struct _DEVICE_EXTENSION {
    PDEVICE_OBJECT pNextLowerDriver;
    IO_REMOVE_LOCK removeLock;
} DEVICE_EXTENSION, *PDEVICE_EXTENSION;


//#define SMART_RCV_MONITORING_ENABLED
//#define LOGGING_ENABLED

#ifdef LOGGING_ENABLED
VOID StorfltLogHex(__in PVOID pData, __in const ULONG cbDataSize);
#else /* LOGGING_ENABLED */
#define StorfltLogHex
#endif /* LOGGING_ENABLED */


#endif /* _STORFLT_H_ */
