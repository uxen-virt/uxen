/*
 * Copyright 2014-2016, Bromium, Inc.
 * Author: Julian Pidancet <julian@pidancet.net>
 * SPDX-License-Identifier: ISC
 */
#include <ntddk.h>
#include <hidport.h>

#include "uxenhid.h"
#include "version.h"

NTSTATUS DriverEntry(PDRIVER_OBJECT drvobj, PUNICODE_STRING regpath);
NTSTATUS uxenhid_create_close(PDEVICE_OBJECT devobj, PIRP irp);
NTSTATUS uxenhid_add_device(PDRIVER_OBJECT drvobj, PDEVICE_OBJECT devobj);
NTSTATUS uxenhid_system_control(PDEVICE_OBJECT devobj, PIRP irp);
NTSTATUS uxenhid_internal_ioctl(PDEVICE_OBJECT devobj, PIRP irp);
NTSTATUS uxenhid_pnp(PDEVICE_OBJECT devobj, PIRP irp);
NTSTATUS uxenhid_power(PDEVICE_OBJECT devobj, PIRP irp);
void uxenhid_unload(PDRIVER_OBJECT drvobj);

#ifdef ALLOC_PRAGMA
#pragma alloc_text(INIT, DriverEntry)
#endif

NTSTATUS
DriverEntry(PDRIVER_OBJECT drvobj, PUNICODE_STRING regpath)
{
    HID_MINIDRIVER_REGISTRATION registration;
    NTSTATUS status;

    uxen_msg("drvobj=0x%08x version: %s", drvobj, UXEN_DRIVER_VERSION_CHANGESET);

    drvobj->MajorFunction[IRP_MJ_CREATE] = uxenhid_create_close;
    drvobj->MajorFunction[IRP_MJ_CLOSE] = uxenhid_create_close;
    drvobj->MajorFunction[IRP_MJ_SYSTEM_CONTROL] = uxenhid_system_control;
    drvobj->MajorFunction[IRP_MJ_INTERNAL_DEVICE_CONTROL] = uxenhid_internal_ioctl;
    drvobj->MajorFunction[IRP_MJ_PNP] = uxenhid_pnp;
    drvobj->MajorFunction[IRP_MJ_POWER] = uxenhid_power;
    drvobj->DriverUnload = uxenhid_unload;
    drvobj->DriverExtension->AddDevice = uxenhid_add_device;

    RtlZeroMemory(&registration, sizeof (registration));
    registration.Revision = HID_REVISION;
    registration.DriverObject = drvobj;
    registration.RegistryPath = regpath;
    registration.DeviceExtensionSize = sizeof (DEVICE_EXTENSION);
    registration.DevicesArePolled = FALSE;

    status = HidRegisterMinidriver(&registration);
    if (!NT_SUCCESS(status)) {
        uxen_err("HidRegisterMinidriver() failed: 0x%08x", status);
        return status;
    }

    return STATUS_SUCCESS;
}

NTSTATUS
uxenhid_add_device(PDRIVER_OBJECT drvobj, PDEVICE_OBJECT devobj)
{
    DEVICE_EXTENSION *devext = DEVEXT(devobj);
    NTSTATUS status;

    UNREFERENCED_PARAMETER(drvobj);

    uxen_msg("devobj=0x%p", devobj);

    RtlZeroMemory(devext, sizeof (*devext));
    devext->devobj = devobj;
    devext->pdo = PDO(devobj);
    devext->nextdevobj = NEXT_DEVOBJ(devobj);
    IoInitializeRemoveLock(&devext->remove_lock, UXENHID_POOL_TAG, 0, 10);
    devext->power_state = PowerDeviceD0;

    status = hid_init(devext);
    if (!NT_SUCCESS(status))
        return status;

    devobj->Flags &= ~DO_DEVICE_INITIALIZING;
    devobj->Flags |= DO_POWER_PAGABLE;

    return status;
}

NTSTATUS
uxenhid_create_close(PDEVICE_OBJECT devobj, PIRP irp)
{
    UNREFERENCED_PARAMETER(devobj);

    irp->IoStatus.Information = 0;
    irp->IoStatus.Status = STATUS_SUCCESS;
    IoCompleteRequest(irp, IO_NO_INCREMENT);

    return STATUS_SUCCESS;
}

NTSTATUS
uxenhid_system_control(PDEVICE_OBJECT devobj, PIRP irp)
{
    NTSTATUS status;
    DEVICE_EXTENSION *devext = DEVEXT(devobj);

    status = IoAcquireRemoveLock(&devext->remove_lock, irp);
    if (!NT_SUCCESS(status)) {
        uxen_err("IoAcquireRemoveLock() failed: 0x%08x", status);

        irp->IoStatus.Information = 0;
        irp->IoStatus.Status = status;
        IoCompleteRequest(irp, IO_NO_INCREMENT);

        return status;
    }

    IoSkipCurrentIrpStackLocation(irp);
    status = IoCallDriver(devext->nextdevobj, irp);
    IoReleaseRemoveLock(&devext->remove_lock, irp);

    return status;
}

NTSTATUS
uxenhid_internal_ioctl(PDEVICE_OBJECT devobj, PIRP irp)
{
    NTSTATUS status;
    DEVICE_EXTENSION *devext = DEVEXT(devobj);
    PIO_STACK_LOCATION loc = IoGetCurrentIrpStackLocation(irp);
    BOOLEAN irp_pending = FALSE;

    status = IoAcquireRemoveLock(&devext->remove_lock, irp);
    if (!NT_SUCCESS(status)) {
        uxen_err("IoAcquireRemoveLock() failed: 0x%08x", status);

        irp->IoStatus.Information = 0;
        irp->IoStatus.Status = status;
        IoCompleteRequest(irp, IO_NO_INCREMENT);

        return status;
    }

    if (!(devext->flags & UXENHID_DEVICE_STARTED)) {
        uxen_err("device not started");

        status = STATUS_DEVICE_NOT_READY;
        irp->IoStatus.Information = 0;
        goto unlock;
    }

    switch (loc->Parameters.DeviceIoControl.IoControlCode) {
    case IOCTL_HID_GET_DEVICE_DESCRIPTOR:
        status = hid_device_descriptor(devext, irp, &irp_pending);
        break;
    case IOCTL_HID_GET_REPORT_DESCRIPTOR:
        status = hid_report_descriptor(devext, irp, &irp_pending);
        break;
    case IOCTL_HID_READ_REPORT:
        status = hid_read_report(devext, irp, &irp_pending);
        break;
    case IOCTL_HID_WRITE_REPORT:
        status = hid_write_report(devext, irp, &irp_pending);
        break;
    case IOCTL_HID_GET_STRING:
        status = hid_device_string(devext, irp, &irp_pending);
        break;
    case IOCTL_HID_GET_DEVICE_ATTRIBUTES:
        status = hid_device_attributes(devext, irp);
        break;
    case IOCTL_HID_SET_FEATURE:
        status = hid_set_feature(devext, irp, &irp_pending);
        break;
    case IOCTL_HID_GET_FEATURE:
        status = hid_get_feature(devext, irp, &irp_pending);
        break;
    case IOCTL_HID_ACTIVATE_DEVICE:
    case IOCTL_HID_DEACTIVATE_DEVICE:
        status = STATUS_SUCCESS;
        break;
    default:
        uxen_msg("Unsupported ioctl: 0x%08x",
                 loc->Parameters.DeviceIoControl.IoControlCode);
        status = STATUS_NOT_SUPPORTED;
    }

unlock:
    if (!irp_pending) {
        IoReleaseRemoveLock(&devext->remove_lock, irp);
        irp->IoStatus.Status = status;
        IoCompleteRequest(irp, IO_NO_INCREMENT);
    }

    return status;
}

static NTSTATUS
pnp_irp_complete(PDEVICE_OBJECT devobj, PIRP irp, void *event)
{
    UNREFERENCED_PARAMETER(devobj);

    if (irp->PendingReturned)
        KeSetEvent((KEVENT *)event, IO_NO_INCREMENT, FALSE);

    return STATUS_MORE_PROCESSING_REQUIRED;
}

static NTSTATUS
start_device(DEVICE_EXTENSION *devext, IRP *irp)
{
    KEVENT event;
    NTSTATUS status;

    KeInitializeEvent(&event, NotificationEvent, FALSE);
    IoCopyCurrentIrpStackLocationToNext(irp);
    IoSetCompletionRoutine(irp, pnp_irp_complete, &event, TRUE, TRUE, TRUE);

    status = IoCallDriver(devext->nextdevobj, irp);
    if (status == STATUS_PENDING)
        status = KeWaitForSingleObject(&event, Executive, KernelMode,
                                       FALSE, NULL);
    if (NT_SUCCESS(status))
        status = irp->IoStatus.Status;

    if (NT_SUCCESS(status) &&
        !(devext->flags & UXENHID_DEVICE_STARTED)) {
        status = hid_start(devext);
        if (NT_SUCCESS(status)) {
            uxen_msg("Device started");
            devext->flags |= UXENHID_DEVICE_STARTED;
        } else
            uxen_err("Failed to start device: 0x%08x", status);
    }

    irp->IoStatus.Information = 0;
    irp->IoStatus.Status = status;
    IoCompleteRequest(irp, IO_NO_INCREMENT);

    return status;
}

static NTSTATUS
remove_device(DEVICE_EXTENSION *devext, IRP *irp)
{
    NTSTATUS status;

    if (devext->flags & UXENHID_DEVICE_STARTED) {
        status = hid_stop(devext);
        if (NT_SUCCESS(status)) {
            uxen_msg("Device stopped");
            devext->flags &= ~UXENHID_DEVICE_STARTED;
        } else
            uxen_err("Failed to stop device: 0x%08x", status);
    }

    IoSkipCurrentIrpStackLocation(irp);
    status = IoCallDriver(devext->nextdevobj, irp);
    if (!NT_SUCCESS(status)) {
        uxen_err("IoCallDriver failed: 0x%08x", status);
        return status;
    }

    hid_cleanup(devext);
    IoReleaseRemoveLockAndWait(&devext->remove_lock, irp);

    return status;
}

static NTSTATUS
stop_device(DEVICE_EXTENSION *devext, IRP *irp)
{
    NTSTATUS status;

    if (devext->flags & UXENHID_DEVICE_STARTED) {
        status = hid_stop(devext);
        if (NT_SUCCESS(status)) {
            uxen_msg("Device stopped");
            devext->flags &= ~UXENHID_DEVICE_STARTED;
        } else
            uxen_err("Failed to stop device: 0x%08x", status);
    }

    IoSkipCurrentIrpStackLocation(irp);
    status = IoCallDriver(devext->nextdevobj, irp);
    if (!NT_SUCCESS(status))
        uxen_err("IoCallDriver failed: 0x%08x", status);

    return status;
}

static NTSTATUS
query_capabilities(DEVICE_EXTENSION *devext, IRP *irp, IO_STACK_LOCATION *loc)
{
    KEVENT event;
    NTSTATUS status;
    DEVICE_CAPABILITIES *devcaps;

    KeInitializeEvent(&event, NotificationEvent, FALSE);
    IoCopyCurrentIrpStackLocationToNext(irp);
    IoSetCompletionRoutine(irp, pnp_irp_complete, &event, TRUE, TRUE, TRUE);

    status = IoCallDriver(devext->nextdevobj, irp);
    if (status == STATUS_PENDING)
        status = KeWaitForSingleObject(&event, Executive, KernelMode,
                                       FALSE, NULL);

    if (NT_SUCCESS(status))
        status = irp->IoStatus.Status;

    if (NT_SUCCESS(status)) {
        devcaps = loc->Parameters.DeviceCapabilities.Capabilities;

        devcaps->SurpriseRemovalOK = TRUE;
        devcaps->SystemWake = PowerSystemUnspecified;
        devcaps->DeviceWake = PowerDeviceUnspecified;
        devcaps->WakeFromD0 = FALSE;
        devcaps->WakeFromD1 = FALSE;
        devcaps->WakeFromD2 = FALSE;
        devcaps->WakeFromD3 = FALSE;
        devcaps->DeviceState[PowerSystemWorking] = PowerDeviceD0;
        devcaps->DeviceState[PowerSystemSleeping1] = PowerDeviceD3;
        devcaps->DeviceState[PowerSystemSleeping2] = PowerDeviceD3;
        devcaps->DeviceState[PowerSystemSleeping3] = PowerDeviceD3;
        devcaps->DeviceState[PowerSystemHibernate] = PowerDeviceD3;
        devcaps->DeviceState[PowerSystemShutdown] = PowerDeviceD3;
    }

    irp->IoStatus.Status = status;
    IoCompleteRequest(irp, IO_NO_INCREMENT);

    return status;
}

NTSTATUS
uxenhid_pnp(PDEVICE_OBJECT devobj, PIRP irp)
{
    NTSTATUS status;
    DEVICE_EXTENSION *devext = DEVEXT(devobj);
    PIO_STACK_LOCATION loc = IoGetCurrentIrpStackLocation(irp);

    status = IoAcquireRemoveLock(&devext->remove_lock, irp);
    if (!NT_SUCCESS(status)) {
        uxen_err("IoAcquireRemoveLock() failed: 0x%08x", status);

        irp->IoStatus.Information = 0;
        irp->IoStatus.Status = status;
        IoCompleteRequest(irp, IO_NO_INCREMENT);

        return status;
    }

    switch (loc->MinorFunction) {
    case IRP_MN_START_DEVICE:
        uxen_msg("START_DEVICE");
        status = start_device(devext, irp);
        break;
    case IRP_MN_CANCEL_REMOVE_DEVICE:
        uxen_msg("CANCEL_REMOVE_DEVICE");
        status = start_device(devext, irp);
        break;
    case IRP_MN_REMOVE_DEVICE:
        uxen_msg("REMOVE_DEVICE");
        status = remove_device(devext, irp);
        if (NT_SUCCESS(status))
            return status;
        break;
    case IRP_MN_STOP_DEVICE:
        uxen_msg("STOP_DEVICE");
        status = stop_device(devext, irp);
        break;
    case IRP_MN_QUERY_REMOVE_DEVICE:
        uxen_msg("QUERY_REMOVE_DEVICE");
        status = stop_device(devext, irp);
        break;
    case IRP_MN_QUERY_CAPABILITIES:
        uxen_msg("QUERY_CAPABILITIES");
        status = query_capabilities(devext, irp, loc);
        break;
    default:
        IoSkipCurrentIrpStackLocation(irp);
        status = IoCallDriver(devext->nextdevobj, irp);
        break;
    }

    IoReleaseRemoveLock(&devext->remove_lock, irp);

    return status;
}

NTSTATUS
uxenhid_power(PDEVICE_OBJECT devobj, PIRP irp)
{
    NTSTATUS status;
    DEVICE_EXTENSION *devext = DEVEXT(devobj);

    status = IoAcquireRemoveLock(&devext->remove_lock, irp);
    if (!NT_SUCCESS(status)) {
        irp->IoStatus.Information = 0;
        irp->IoStatus.Status = status;
        IoCompleteRequest(irp, IO_NO_INCREMENT);

        return status;
    }

    IoSkipCurrentIrpStackLocation(irp);
    status = IoCallDriver(devext->nextdevobj, irp);

    IoReleaseRemoveLock(&devext->remove_lock, irp);

    return status;
}

void
uxenhid_unload(PDRIVER_OBJECT drvobj)
{
    UNREFERENCED_PARAMETER(drvobj);

    uxen_msg("drvobj=0x%08x", drvobj);

    return;
}
