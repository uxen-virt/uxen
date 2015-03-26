/*
 * Copyright 2015, Bromium, Inc.
 * SPDX-License-Identifier: ISC
 */

#include "uxenv4vlib_private.h"

static DRIVER_OBJECT *driver_object; // This isn't shared, only the original caller should use this
static DEVICE_OBJECT *v4v_fdo;  // This isn't shared, only the original caller should use this

static NTSTATUS (*other_dispatch_create) (PDEVICE_OBJECT fdo, PIRP irp);
static NTSTATUS (*other_dispatch_cleanup) (PDEVICE_OBJECT fdo, PIRP irp);
static NTSTATUS (*other_dispatch_close) (PDEVICE_OBJECT fdo, PIRP irp);
static NTSTATUS (*other_dispatch_device_control) (PDEVICE_OBJECT fdo, PIRP irp);
static NTSTATUS (*other_dispatch_read) (PDEVICE_OBJECT fdo, PIRP irp);
static NTSTATUS (*other_dispatch_write) (PDEVICE_OBJECT fdo, PIRP irp);

static NTSTATUS (*v4v_dispatch_create) (PDEVICE_OBJECT fdo, PIRP irp);
static NTSTATUS (*v4v_dispatch_cleanup) (PDEVICE_OBJECT fdo, PIRP irp);
static NTSTATUS (*v4v_dispatch_close) (PDEVICE_OBJECT fdo, PIRP irp);
static NTSTATUS (*v4v_dispatch_device_control) (PDEVICE_OBJECT fdo, PIRP irp);
static NTSTATUS (*v4v_dispatch_read) (PDEVICE_OBJECT fdo, PIRP irp);
static NTSTATUS (*v4v_dispatch_write) (PDEVICE_OBJECT fdo, PIRP irp);

NTSTATUS NTAPI dispatch_create(PDEVICE_OBJECT fdo, PIRP irp)
{
    if (fdo == v4v_fdo) {
        if (v4v_dispatch_create) return (*v4v_dispatch_create) (fdo, irp);
    } else {
        if (other_dispatch_create) return (*other_dispatch_create) (fdo, irp);
    }
    return STATUS_UNSUCCESSFUL;
}

NTSTATUS NTAPI dispatch_cleanup(PDEVICE_OBJECT fdo, PIRP irp)
{
    if (fdo == v4v_fdo) {
        if (v4v_dispatch_cleanup) return (*v4v_dispatch_cleanup) (fdo, irp);
    } else {
        if (other_dispatch_cleanup) return (*other_dispatch_cleanup) (fdo, irp);
    }
    return STATUS_UNSUCCESSFUL;
}

NTSTATUS NTAPI dispatch_close(PDEVICE_OBJECT fdo, PIRP irp)
{
    if (fdo == v4v_fdo) {
        if (v4v_dispatch_close) return (*v4v_dispatch_close) (fdo, irp);
    } else {
        if (v4v_dispatch_close) return (*other_dispatch_close) (fdo, irp);
    }
    return STATUS_UNSUCCESSFUL;
}

NTSTATUS NTAPI dispatch_device_control(PDEVICE_OBJECT fdo, PIRP irp)
{
    if (fdo == v4v_fdo) {
        if (v4v_dispatch_device_control) return (*v4v_dispatch_device_control) (fdo, irp);
    } else {
        if (other_dispatch_device_control) return (*other_dispatch_device_control) (fdo, irp);
    }
    return STATUS_UNSUCCESSFUL;
}

NTSTATUS NTAPI dispatch_read(PDEVICE_OBJECT fdo, PIRP irp)
{
    if (fdo == v4v_fdo) {
        if (v4v_dispatch_read) return (*v4v_dispatch_read) (fdo, irp);
    } else {
        if (other_dispatch_read) return (*other_dispatch_read) (fdo, irp);
    }
    return STATUS_UNSUCCESSFUL;
}

NTSTATUS NTAPI dispatch_write(PDEVICE_OBJECT fdo, PIRP irp)
{
    if (fdo == v4v_fdo) {
        if (v4v_dispatch_write) return (*v4v_dispatch_write) (fdo, irp);
    } else {
        if (other_dispatch_write) return (*other_dispatch_write) (fdo, irp);
    }
    return STATUS_UNSUCCESSFUL;
}




void
uxen_v4v_set_notify_fdo (PDEVICE_OBJECT fdo)
{
    v4v_fdo = fdo;
}


V4V_DLL_EXPORT void
uxen_v4vlib_init_driver_hook (PDRIVER_OBJECT pdo)
{
    DbgPrint ("uxen_v4v_init_driver_hook\n");
    if (driver_object)
        return;
    driver_object = pdo;

    other_dispatch_create = driver_object->MajorFunction[IRP_MJ_CREATE];
    other_dispatch_cleanup = driver_object->MajorFunction[IRP_MJ_CLEANUP];
    other_dispatch_close = driver_object->MajorFunction[IRP_MJ_CLOSE];
    other_dispatch_device_control = driver_object->MajorFunction[IRP_MJ_DEVICE_CONTROL];
    other_dispatch_read = driver_object->MajorFunction[IRP_MJ_READ];
    other_dispatch_write = driver_object->MajorFunction[IRP_MJ_WRITE];

    uxen_v4vlib_init_driver (driver_object);

    v4v_dispatch_create = driver_object->MajorFunction[IRP_MJ_CREATE];
    v4v_dispatch_cleanup = driver_object->MajorFunction[IRP_MJ_CLEANUP];
    v4v_dispatch_close = driver_object->MajorFunction[IRP_MJ_CLOSE];
    v4v_dispatch_device_control = driver_object->MajorFunction[IRP_MJ_DEVICE_CONTROL];
    v4v_dispatch_read = driver_object->MajorFunction[IRP_MJ_READ];
    v4v_dispatch_write = driver_object->MajorFunction[IRP_MJ_WRITE];

    driver_object->MajorFunction[IRP_MJ_CREATE] = dispatch_create;
    driver_object->MajorFunction[IRP_MJ_CLEANUP] = dispatch_cleanup;
    driver_object->MajorFunction[IRP_MJ_CLOSE] = dispatch_close;
    driver_object->MajorFunction[IRP_MJ_DEVICE_CONTROL] = dispatch_device_control;
    driver_object->MajorFunction[IRP_MJ_READ] = dispatch_read;
    driver_object->MajorFunction[IRP_MJ_WRITE] = dispatch_write;

}



V4V_DLL_EXPORT void
uxen_v4vlib_free_driver_unhook (void)
{
    DbgPrint ("uxen_v4v_free_driver_unhook\n");

    if (!driver_object)
        return;

    uxen_v4vlib_free_driver ();

    if (driver_object->MajorFunction[IRP_MJ_CREATE] == dispatch_create)
        driver_object->MajorFunction[IRP_MJ_CREATE] = other_dispatch_create;

    if (driver_object->MajorFunction[IRP_MJ_CLEANUP] == dispatch_cleanup)
        driver_object->MajorFunction[IRP_MJ_CLEANUP] = other_dispatch_cleanup;

    if (driver_object->MajorFunction[IRP_MJ_CLOSE] == dispatch_close)
        driver_object->MajorFunction[IRP_MJ_CLOSE] = other_dispatch_close;

    if (driver_object->MajorFunction[IRP_MJ_DEVICE_CONTROL] == dispatch_device_control)
        driver_object->MajorFunction[IRP_MJ_DEVICE_CONTROL] = other_dispatch_device_control;

    if (driver_object->MajorFunction[IRP_MJ_READ] == dispatch_read)
        driver_object->MajorFunction[IRP_MJ_READ] = other_dispatch_read;

    if (driver_object->MajorFunction[IRP_MJ_WRITE] == dispatch_write)
        driver_object->MajorFunction[IRP_MJ_WRITE] = other_dispatch_write;

    other_dispatch_create = NULL;
    other_dispatch_cleanup = NULL;
    other_dispatch_close = NULL;
    other_dispatch_device_control = NULL;
    other_dispatch_read = NULL;
    other_dispatch_write = NULL;

    v4v_dispatch_create = NULL;
    v4v_dispatch_cleanup = NULL;
    v4v_dispatch_close = NULL;
    v4v_dispatch_device_control = NULL;
    v4v_dispatch_read = NULL;
    v4v_dispatch_write = NULL;


    driver_object = NULL;

}
