/*
 * Copyright 2018, Bromium, Inc.
 * Author: Tomasz Wroblewski <tomasz.wroblewski@gmail.com>
 * SPDX-License-Identifier: ISC
 */

#include "proxy.h"

static DRIVER_OBJECT *driver_object; // This isn't shared, only the original caller should use this
static DEVICE_OBJECT *proxy_fdo;  // This isn't shared, only the original caller should use this

static NTSTATUS (*other_dispatch_create) (PDEVICE_OBJECT fdo, PIRP irp);
static NTSTATUS (*other_dispatch_cleanup) (PDEVICE_OBJECT fdo, PIRP irp);
static NTSTATUS (*other_dispatch_close) (PDEVICE_OBJECT fdo, PIRP irp);
static NTSTATUS (*other_dispatch_device_control) (PDEVICE_OBJECT fdo, PIRP irp);
static NTSTATUS (*other_dispatch_read) (PDEVICE_OBJECT fdo, PIRP irp);
static NTSTATUS (*other_dispatch_write) (PDEVICE_OBJECT fdo, PIRP irp);

static NTSTATUS (*proxy_dispatch_create) (PDEVICE_OBJECT fdo, PIRP irp);
static NTSTATUS (*proxy_dispatch_cleanup) (PDEVICE_OBJECT fdo, PIRP irp);
static NTSTATUS (*proxy_dispatch_close) (PDEVICE_OBJECT fdo, PIRP irp);
static NTSTATUS (*proxy_dispatch_device_control) (PDEVICE_OBJECT fdo, PIRP irp);
static NTSTATUS (*proxy_dispatch_read) (PDEVICE_OBJECT fdo, PIRP irp);
static NTSTATUS (*proxy_dispatch_write) (PDEVICE_OBJECT fdo, PIRP irp);

NTSTATUS NTAPI dispatch_create(PDEVICE_OBJECT fdo, PIRP irp)
{
    if (fdo == proxy_fdo) {
        if (proxy_dispatch_create) return (*proxy_dispatch_create) (fdo, irp);
    } else {
        if (other_dispatch_create) return (*other_dispatch_create) (fdo, irp);
    }
    return STATUS_UNSUCCESSFUL;
}

NTSTATUS NTAPI dispatch_cleanup(PDEVICE_OBJECT fdo, PIRP irp)
{
    if (fdo == proxy_fdo) {
        if (proxy_dispatch_cleanup) return (*proxy_dispatch_cleanup) (fdo, irp);
    } else {
        if (other_dispatch_cleanup) return (*other_dispatch_cleanup) (fdo, irp);
    }
    return STATUS_UNSUCCESSFUL;
}

NTSTATUS NTAPI dispatch_close(PDEVICE_OBJECT fdo, PIRP irp)
{
    if (fdo == proxy_fdo) {
        if (proxy_dispatch_close) return (*proxy_dispatch_close) (fdo, irp);
    } else {
        if (proxy_dispatch_close) return (*other_dispatch_close) (fdo, irp);
    }
    return STATUS_UNSUCCESSFUL;
}

NTSTATUS NTAPI dispatch_device_control(PDEVICE_OBJECT fdo, PIRP irp)
{
    if (fdo == proxy_fdo) {
        if (proxy_dispatch_device_control) return (*proxy_dispatch_device_control) (fdo, irp);
    } else {
        if (other_dispatch_device_control) return (*other_dispatch_device_control) (fdo, irp);
    }
    return STATUS_UNSUCCESSFUL;
}

NTSTATUS NTAPI dispatch_read(PDEVICE_OBJECT fdo, PIRP irp)
{
    if (fdo == proxy_fdo) {
        if (proxy_dispatch_read) return (*proxy_dispatch_read) (fdo, irp);
    } else {
        if (other_dispatch_read) return (*other_dispatch_read) (fdo, irp);
    }
    return STATUS_UNSUCCESSFUL;
}

NTSTATUS NTAPI dispatch_write(PDEVICE_OBJECT fdo, PIRP irp)
{
    if (fdo == proxy_fdo) {
        if (proxy_dispatch_write) return (*proxy_dispatch_write) (fdo, irp);
    } else {
        if (other_dispatch_write) return (*other_dispatch_write) (fdo, irp);
    }
    return STATUS_UNSUCCESSFUL;
}

void
proxy_set_notify_fdo (PDEVICE_OBJECT fdo)
{
    proxy_fdo = fdo;
}

PROXY_DLL_EXPORT void
uxen_v4vproxy_init_driver_hook (PDRIVER_OBJECT pdo)
{
    DbgPrint ("uxen_proxy_init_driver_hook\n");
    if (driver_object)
        return;
    driver_object = pdo;

    other_dispatch_create = driver_object->MajorFunction[IRP_MJ_CREATE];
    other_dispatch_cleanup = driver_object->MajorFunction[IRP_MJ_CLEANUP];
    other_dispatch_close = driver_object->MajorFunction[IRP_MJ_CLOSE];
    other_dispatch_device_control = driver_object->MajorFunction[IRP_MJ_DEVICE_CONTROL];
    other_dispatch_read = driver_object->MajorFunction[IRP_MJ_READ];
    other_dispatch_write = driver_object->MajorFunction[IRP_MJ_WRITE];

    proxy_load(driver_object);

    proxy_dispatch_create = driver_object->MajorFunction[IRP_MJ_CREATE];
    proxy_dispatch_cleanup = driver_object->MajorFunction[IRP_MJ_CLEANUP];
    proxy_dispatch_close = driver_object->MajorFunction[IRP_MJ_CLOSE];
    proxy_dispatch_device_control = driver_object->MajorFunction[IRP_MJ_DEVICE_CONTROL];
    proxy_dispatch_read = driver_object->MajorFunction[IRP_MJ_READ];
    proxy_dispatch_write = driver_object->MajorFunction[IRP_MJ_WRITE];

    driver_object->MajorFunction[IRP_MJ_CREATE] = dispatch_create;
    driver_object->MajorFunction[IRP_MJ_CLEANUP] = dispatch_cleanup;
    driver_object->MajorFunction[IRP_MJ_CLOSE] = dispatch_close;
    driver_object->MajorFunction[IRP_MJ_DEVICE_CONTROL] = dispatch_device_control;
    driver_object->MajorFunction[IRP_MJ_READ] = dispatch_read;
    driver_object->MajorFunction[IRP_MJ_WRITE] = dispatch_write;

}

PROXY_DLL_EXPORT void
uxen_v4vproxy_free_driver_unhook (void)
{
    DbgPrint ("uxen_proxy_free_driver_unhook\n");

    if (!driver_object)
        return;

    proxy_unload();

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

    proxy_dispatch_create = NULL;
    proxy_dispatch_cleanup = NULL;
    proxy_dispatch_close = NULL;
    proxy_dispatch_device_control = NULL;
    proxy_dispatch_read = NULL;
    proxy_dispatch_write = NULL;

    driver_object = NULL;
}
