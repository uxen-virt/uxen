/*
 * Copyright 2014-2016, Bromium, Inc.
 * Author: Julian Pidancet <julian@pidancet.net>
 * SPDX-License-Identifier: ISC
 */

#ifndef _UXENHID_H_
#define _UXENHID_H_

#include <uxenvmlib.h>
#include <uxenv4vlib.h>
#include "../common/debug.h"
#include "hid_interface.h"

#define UXENHID_DEVICE_STARTED    0x00000001
#define UXENHID_INTERFACE_ENABLED 0x00000002

#define UXENHID_POOL_TAG 'dihu'

typedef struct _DEVICE_EXTENSION
{
    DEVICE_OBJECT *devobj;
    DEVICE_OBJECT *pdo;
    DEVICE_OBJECT *nextdevobj;
    IO_REMOVE_LOCK remove_lock;
    DEVICE_POWER_STATE power_state;
    UINT32 flags;

    v4v_addr_t peer;
    uxen_v4v_ring_handle_t *ring;
    KSPIN_LOCK v4v_lock;

    LIST_ENTRY pending_request_list;
    KSPIN_LOCK pending_request_lock;
    IO_CSQ pending_request_csq;

    LIST_ENTRY pending_report_list;
    KSPIN_LOCK pending_report_lock;
    IO_CSQ pending_report_csq;

    LIST_ENTRY pending_feature_query_list;
    KSPIN_LOCK pending_feature_query_lock;
    IO_CSQ pending_feature_query_csq;

    UCHAR *rpt_desc;
    USHORT rpt_desc_len;

    KDPC resume_dpc;

    UNICODE_STRING symlink_name;
    uint16_t virt_w;
    uint16_t virt_h;
    uint16_t curr_w;
    uint16_t curr_h;
} DEVICE_EXTENSION, *PDEVICE_EXTENSION;

#define DEVEXT(DO) \
    (PDEVICE_EXTENSION)(((PHID_DEVICE_EXTENSION)(DO)->DeviceExtension)->MiniDeviceExtension)
#define NEXT_DEVOBJ(DO) \
    (((PHID_DEVICE_EXTENSION)(DO)->DeviceExtension)->NextDeviceObject)
#define PDO(DO) \
    (((PHID_DEVICE_EXTENSION)(DO)->DeviceExtension)->PhysicalDeviceObject)

#define EAGAIN          11      /* Try again */
#define ECONNREFUSED	111	/* Endpoint not connected */

NTSTATUS hid_init(DEVICE_EXTENSION *devext);
void hid_cleanup(DEVICE_EXTENSION *devext);

NTSTATUS hid_device_descriptor(DEVICE_EXTENSION *devext, IRP *irp,
                               BOOLEAN *pending);
NTSTATUS hid_report_descriptor(DEVICE_EXTENSION *devext, IRP *irp,
                               BOOLEAN *pending);
NTSTATUS hid_read_report(DEVICE_EXTENSION *devext, IRP *irp,
                         BOOLEAN *pending);
NTSTATUS hid_write_report(DEVICE_EXTENSION *devext, IRP *irp,
                          BOOLEAN *pending);
NTSTATUS hid_device_string(DEVICE_EXTENSION *devext, IRP *irp,
                           BOOLEAN *pending);
NTSTATUS hid_device_attributes(DEVICE_EXTENSION *devext, IRP *irp);
NTSTATUS hid_start(DEVICE_EXTENSION *devext);
NTSTATUS hid_stop(DEVICE_EXTENSION *devext);
NTSTATUS hid_get_feature(DEVICE_EXTENSION *devext, IRP *irp,
                         BOOLEAN *pending);
NTSTATUS hid_set_feature(DEVICE_EXTENSION *devext, IRP *irp,
                         BOOLEAN *pending);

#include <uxenhid-common.h>

#endif /* _UXENHID_H_ */
