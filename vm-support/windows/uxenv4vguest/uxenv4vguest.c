/*
 * Copyright 2015, Bromium, Inc.
 * SPDX-License-Identifier: ISC
 */

#include "uxenv4vguest_private.h"
#include "version.h"



NTSTATUS
UxvgInitializeDeviceExtension(
    IN PDEVICE_EXTENSION DevExt
)
{
    NTSTATUS    status;

    PAGED_CODE();

    status = UxvgInterruptCreate(DevExt);

    if (!NT_SUCCESS(status)) {
        return status;
    }

    return status;
}




NTSTATUS
UxvgSetIdleAndWakeSettings(
    IN PDEVICE_EXTENSION devExt
)
{
    WDF_DEVICE_POWER_POLICY_IDLE_SETTINGS idleSettings;
    WDF_DEVICE_POWER_POLICY_WAKE_SETTINGS wakeSettings;
    NTSTATUS    status = STATUS_SUCCESS;

    PAGED_CODE();

    uxen_msg("--> uxvgSetIdleAndWakeSettings");

    WDF_DEVICE_POWER_POLICY_IDLE_SETTINGS_INIT(&idleSettings, IdleCanWakeFromS0);
    idleSettings.IdleTimeout = 10000; // 10-sec

    status = WdfDeviceAssignS0IdleSettings(devExt->Device, &idleSettings);
    if ( !NT_SUCCESS(status)) {
        uxen_msg( "DeviceSetPowerPolicyS0IdlePolicy failed %x", status);
        return status;
    }

    WDF_DEVICE_POWER_POLICY_WAKE_SETTINGS_INIT(&wakeSettings);

    status = WdfDeviceAssignSxWakeSettings(devExt->Device, &wakeSettings);
    if (!NT_SUCCESS(status)) {
        uxen_err( "DeviceAssignSxWakeSettings failed %x", status);
        return status;
    }

    uxen_msg("<-- uxvgSetIdleAndWakeSettings");

    return status;
}



NTSTATUS
UxvgEvtDeviceAdd(
    IN WDFDRIVER        Driver,
    IN PWDFDEVICE_INIT  DeviceInit
)
{
    NTSTATUS                   status = STATUS_SUCCESS;
    WDF_PNPPOWER_EVENT_CALLBACKS pnpPowerCallbacks;
    WDF_OBJECT_ATTRIBUTES       attributes;
    WDFDEVICE                   device;
    PDEVICE_EXTENSION           devExt = NULL;

    UNREFERENCED_PARAMETER( Driver );

    PAGED_CODE();

    uxen_msg("> UxvgEvtDeviceAdd");

    WdfDeviceInitSetIoType(DeviceInit, WdfDeviceIoDirect);
    WdfDeviceInitSetPowerNotPageable(DeviceInit);

    WDF_PNPPOWER_EVENT_CALLBACKS_INIT(&pnpPowerCallbacks);

    pnpPowerCallbacks.EvtDevicePrepareHardware = UxvgEvtDevicePrepareHardware;
    pnpPowerCallbacks.EvtDeviceReleaseHardware = UxvgEvtDeviceReleaseHardware;

    pnpPowerCallbacks.EvtDeviceD0Entry         = UxvgEvtDeviceD0Entry;
    pnpPowerCallbacks.EvtDeviceD0Exit          = UxvgEvtDeviceD0Exit;

    WdfDeviceInitSetPnpPowerEventCallbacks(DeviceInit, &pnpPowerCallbacks);

    WDF_OBJECT_ATTRIBUTES_INIT_CONTEXT_TYPE(&attributes, DEVICE_EXTENSION);

    attributes.SynchronizationScope = WdfSynchronizationScopeDevice;

    status = WdfDeviceCreate( &DeviceInit, &attributes, &device );

    if (!NT_SUCCESS(status)) {
        uxen_err("device create failed %x", status);
        return status;
    }

    WdfDeviceSetSpecialFileSupport(device, WdfSpecialFilePaging, TRUE);
    WdfDeviceSetSpecialFileSupport(device, WdfSpecialFileHibernation, TRUE);
    WdfDeviceSetSpecialFileSupport(device, WdfSpecialFileDump, TRUE);

    devExt = UxvgGetDeviceContext(device);

    devExt->Device = device;

    uxen_debug ("AddDevice PDO (0x%p) FDO (0x%p), DevExt (0x%p)",
                WdfDeviceWdmGetPhysicalDevice(device),
                WdfDeviceWdmGetDeviceObject(device), NULL /*devExt*/);

    (void )UxvgSetIdleAndWakeSettings(devExt);

    status = UxvgInitializeDeviceExtension(devExt);

    if (!NT_SUCCESS(status)) {
        return status;
    }

    WdfDeviceStopIdle(device, FALSE);


    uxen_msg("< UxvgEvtDeviceAdd status=%x", status);

    return status;
}


VOID
UxvgEvtDriverContextCleanup(
    WDFOBJECT Driver
)
/*++
Routine Description:

    Free all the resources allocated in DriverEntry.

Arguments:

    Driver - handle to a WDF Driver object.

Return Value:

    VOID.

--*/
{
    PAGED_CODE ();
    UNREFERENCED_PARAMETER(Driver);


    uxen_msg( "PlxEvtDriverContextCleanup: enter");


    uxen_v4v_guest_undo_plumbing();
}



NTSTATUS
DriverEntry(
    IN PDRIVER_OBJECT  DriverObject,
    IN PUNICODE_STRING RegistryPath
)
/*++

Routine Description:

    Driver initialization entry point.
    This entry point is called directly by the I/O system.

Arguments:

    DriverObject - pointer to the driver object

    RegistryPath - pointer to a unicode string representing the path,
                   to driver-specific key in the registry.

Return Value:

    NTSTATUS    - if the status value is not STATUS_SUCCESS,
                        the driver will get unloaded immediately.

--*/
{
    NTSTATUS            status = STATUS_SUCCESS;
    WDF_DRIVER_CONFIG   config;
    WDF_OBJECT_ATTRIBUTES attributes;

    uxen_msg("> driver entry version: %s", UXEN_DRIVER_VERSION_CHANGESET);

    WDF_DRIVER_CONFIG_INIT( &config, UxvgEvtDeviceAdd );

    WDF_OBJECT_ATTRIBUTES_INIT(&attributes);
    attributes.EvtCleanupCallback = UxvgEvtDriverContextCleanup;

    status = WdfDriverCreate( DriverObject,
                              RegistryPath,
                              &attributes,
                              &config,
                              WDF_NO_HANDLE);

    if (!NT_SUCCESS(status)) {
        uxen_err("WdfDriverCreate() failed: 0x%08x", status);
    } else {
        uxen_v4v_guest_do_plumbing(DriverObject);
    }

    uxen_msg("< driver entry status=0x%x", status);

    return status;
}

