/*
 * Copyright 2015-2016, Bromium, Inc.
 * Author: Julian Pidancet <julian@pidancet.net>
 * SPDX-License-Identifier: ISC
 */

#include <initguid.h>
#include <ntddk.h>
#include <wdf.h>

#include "uxenvmlib.h"

#include "platform.h"
#include "platform_public.h"
#include <uxen/platform_interface.h>

#include "bus.h"

#ifdef ALLOC_PRAGMA
#pragma alloc_text(PAGE, bus_init)
#pragma alloc_text(PAGE, create_pdo)
#endif

static NTSTATUS
device_hardware_id(UCHAR deviceType, UCHAR deviceId, PUNICODE_STRING hwid)
{
    NTSTATUS status;

    if (deviceType >=
        (sizeof(uxenbus_device_names) / sizeof(uxenbus_device_names[0])))
        return STATUS_INVALID_PARAMETER;

    status = RtlUnicodeStringPrintf(hwid, L"uxenplatform\\%s%02d",
                                    uxenbus_device_names[deviceType],
                                    deviceId);

    return status;
}

static NTSTATUS
device_compat_id(UCHAR deviceType, UCHAR deviceId, PUNICODE_STRING compatid)
{
    NTSTATUS status;

    UNREFERENCED_PARAMETER(deviceId);

    if (deviceType >=
        (sizeof(uxenbus_device_names) / sizeof(uxenbus_device_names[0])))
        return STATUS_INVALID_PARAMETER;

    status = RtlUnicodeStringPrintf(compatid, L"uxenplatform\\%s",
                                    uxenbus_device_names[deviceType]);

    return status;
}

static NTSTATUS
device_description(UCHAR deviceType, UCHAR deviceId, PUNICODE_STRING desc)
{
    NTSTATUS status;

    if (deviceType >=
        (sizeof(uxenbus_device_names) / sizeof(uxenbus_device_names[0])))
        return STATUS_INVALID_PARAMETER;

    status = RtlUnicodeStringPrintf(desc, L"%s%02d",
                                    uxenbus_device_names[deviceType], deviceId);

    return status;
}

static NTSTATUS
bus_get_device_property(WDFDEVICE device, UCHAR property_id,
                        PVOID property, size_t *property_len)
{
    PPDO_DEVICE_DATA pdoData = NULL;
    PFDO_DATA fdoData;
    struct uxp_bus_device *d;
    struct uxp_bus_device_property *p;
    UCHAR prop_type;
    UCHAR len;

    pdoData = PdoGetData(device);
    fdoData = get_fdo_data(pdoData->parent);

    d = (void *)(fdoData->bus_conf + pdoData->slot *
                 UXENBUS_DEVICE_CONFIG_LENGTH);
    p = &d->prop_list;

    prop_type = bus_config_read8((void *)&p->property_type);
    while (prop_type != UXENBUS_PROPERTY_TYPE_LIST_END) {
        if ( prop_type == property_id)
            break;

        p = UXENBUS_PROP_NEXT_L(p, bus_config_read8((void *)&p->length));
        prop_type = bus_config_read8((void *)&p->property_type);
    }

    if (prop_type != property_id)
        return STATUS_NOT_FOUND;

    len = bus_config_read8((void *)&p->length);
    if (*property_len < len)
        return STATUS_BUFFER_TOO_SMALL;

    bus_config_read_buffer((void *)(p + 1), property, len);

    *property_len = len;

    return STATUS_SUCCESS;
}

static VOID
pdo_ioctl(WDFQUEUE Queue, WDFREQUEST Request,
          size_t OutputBufferLength, size_t InputBufferLength,
          ULONG IoControlCode)
{
    NTSTATUS status;
    WDFDEVICE device;
    size_t length = 0;

    UNREFERENCED_PARAMETER(OutputBufferLength);
    UNREFERENCED_PARAMETER(InputBufferLength);

    device = WdfIoQueueGetDevice(Queue);
    switch (IoControlCode) {
    case IOCTL_UXEN_PLATFORM_BUS_GET_DEVICE_PROPERTY: {
        UCHAR *property_id;
        void *property;
        size_t property_len = 0;

        status = WdfRequestRetrieveInputBuffer(Request, sizeof(UCHAR),
                                               (PVOID *)&property_id, NULL);
        if (!NT_SUCCESS(status)) {
            uxen_err("WdfRequestRetrieveInputBuffer failed - 0x%.08X", status);
            break;
        }
        status = WdfRequestRetrieveOutputBuffer(Request, 0,
                                                (PVOID *)&property,
                                                &property_len);
        if (!NT_SUCCESS(status)) {
            uxen_err("WdfRequestRetrieveOutputBuffer failed - 0x%.08X", status);
            break;
        }

        status = bus_get_device_property(device, *property_id, property,
                                         &property_len);
        if (!NT_SUCCESS(status)) {
            uxen_err("bus_get_device_property failed - 0x%.08X", status);
            break;
        }

        length = property_len;
        break;
    }
    default:
        uxen_err("invalid control code");
        status = STATUS_INVALID_DEVICE_REQUEST;
        break;
    }

    WdfRequestCompleteWithInformation(Request, status, length);
}

static NTSTATUS
create_pdo_helper(WDFDEVICE device,
                  PWDFDEVICE_INIT device_init,
                  ULONG slot,
                  UCHAR deviceType,
                  UCHAR deviceId)
{
    NTSTATUS                    status;
    PPDO_DEVICE_DATA            pdoData = NULL;
    WDFDEVICE                   hChild = NULL;
    WDF_QUERY_INTERFACE_CONFIG  qiConfig;
    WDF_OBJECT_ATTRIBUTES       pdoAttributes;
    WDF_DEVICE_PNP_CAPABILITIES pnpCaps;
    WDF_DEVICE_POWER_CAPABILITIES powerCaps;
    DECLARE_UNICODE_STRING_SIZE(buffer, 80);
    UXENBUS_INTERFACE_STANDARD  uXenBusInterface;
    DECLARE_CONST_UNICODE_STRING(deviceLocation, L"uXenBus");
    WDF_IO_QUEUE_CONFIG         queueConfig;
    WDFQUEUE                    queue;

    PAGED_CODE();

    WdfDeviceInitSetDeviceType(device_init, FILE_DEVICE_BUS_EXTENDER);

    status = device_hardware_id(deviceType, deviceId, &buffer);
    if (!NT_SUCCESS(status)) {
        uxen_err("device_hardware_id failed - 0x%.08X", status);
        return status;
    }

    status = WdfPdoInitAssignDeviceID(device_init, &buffer);
    if (!NT_SUCCESS(status)) {
        uxen_err("device_hardware_id failed - 0x%.08X", status);
        return status;
    }

    status = WdfPdoInitAddHardwareID(device_init, &buffer);
    if (!NT_SUCCESS(status)) {
        uxen_err("WdfPdoInitAddHardwareID failed - 0x%.08X", status);
        return status;
    }

    status = device_compat_id(deviceType, deviceId, &buffer);
    if (!NT_SUCCESS(status)) {
        uxen_err("device_compat_id failed - 0x%.08X", status);
        return status;
    }

    status = WdfPdoInitAddCompatibleID(device_init, &buffer);
    if (!NT_SUCCESS(status)) {
        uxen_err("WdfPdoInitAddCompatibleID failed - 0x%.08X", status);
        return status;
    }

    status =  RtlUnicodeStringPrintf(&buffer, L"%02d", deviceId);
    if (!NT_SUCCESS(status)) {
        uxen_err("RtlUnicodeStringPrintf failed - 0x%.08X", status);
        return status;
    }

    status = WdfPdoInitAssignInstanceID(device_init, &buffer);
    if (!NT_SUCCESS(status)) {
        uxen_err("WdfPdoInitAssignInstanceID failed - 0x%.08X", status);
        return status;
    }

    status = device_description(deviceType, deviceId, &buffer);
    if (!NT_SUCCESS(status)) {
        uxen_err("device_description failed - 0x%.08X", status);
        return status;
    }

    status = WdfPdoInitAddDeviceText(device_init, &buffer, &deviceLocation, 0x409);
    if (!NT_SUCCESS(status)) {
        uxen_err("WdfPdoInitAddDeviceText failed - 0x%.08X", status);
        return status;
    }

    WdfPdoInitSetDefaultLocale(device_init, 0x409);

    WDF_OBJECT_ATTRIBUTES_INIT_CONTEXT_TYPE(&pdoAttributes, PDO_DEVICE_DATA);

    status = WdfDeviceCreate(&device_init, &pdoAttributes, &hChild);
    if (!NT_SUCCESS(status)) {
        uxen_err("WdfDeviceCreate failed - 0x%.08X", status);
        return status;
    }

    WDF_IO_QUEUE_CONFIG_INIT_DEFAULT_QUEUE(&queueConfig,
                                           WdfIoQueueDispatchParallel);
    queueConfig.EvtIoDeviceControl = pdo_ioctl;
    status = WdfIoQueueCreate(hChild,
                              &queueConfig,
                              WDF_NO_OBJECT_ATTRIBUTES,
                              &queue);
    if (!NT_SUCCESS(status)) {
        uxen_err("WdfIoQueueCreate failed - 0x%.08X", status);
        return status;
    }

    pdoData = PdoGetData(hChild);

    pdoData->parent = device;
    pdoData->slot = slot;
    pdoData->deviceType = deviceType;
    pdoData->deviceId = deviceId;

    WDF_DEVICE_PNP_CAPABILITIES_INIT(&pnpCaps);
    pnpCaps.Removable         = WdfTrue;
    pnpCaps.EjectSupported    = WdfTrue;
    pnpCaps.SurpriseRemovalOK = WdfTrue;

    pnpCaps.Address  = deviceId;
    pnpCaps.UINumber = deviceId;

    WdfDeviceSetPnpCapabilities(hChild, &pnpCaps);

    WDF_DEVICE_POWER_CAPABILITIES_INIT(&powerCaps);

    powerCaps.DeviceD1 = WdfTrue;
    powerCaps.WakeFromD1 = WdfTrue;
    powerCaps.DeviceWake = PowerDeviceD1;

    powerCaps.DeviceState[PowerSystemWorking]   = PowerDeviceD1;
    powerCaps.DeviceState[PowerSystemSleeping1] = PowerDeviceD1;
    powerCaps.DeviceState[PowerSystemSleeping2] = PowerDeviceD2;
    powerCaps.DeviceState[PowerSystemSleeping3] = PowerDeviceD2;
    powerCaps.DeviceState[PowerSystemHibernate] = PowerDeviceD3;
    powerCaps.DeviceState[PowerSystemShutdown]  = PowerDeviceD3;

    WdfDeviceSetPowerCapabilities(hChild, &powerCaps);

    RtlZeroMemory(&uXenBusInterface, sizeof(uXenBusInterface));

    uXenBusInterface.interfaceHeader.Size = sizeof(uXenBusInterface);
    uXenBusInterface.interfaceHeader.Version = 1;
    uXenBusInterface.interfaceHeader.Context = (PVOID)hChild;

    uXenBusInterface.interfaceHeader.InterfaceReference = WdfDeviceInterfaceReferenceNoOp;
    uXenBusInterface.interfaceHeader.InterfaceDereference = WdfDeviceInterfaceDereferenceNoOp;

    WDF_QUERY_INTERFACE_CONFIG_INIT(&qiConfig,
                                    (PINTERFACE)&uXenBusInterface,
                                    &GUID_UXENBUS_INTERFACE_STANDARD,
                                    NULL);
    status = WdfDeviceAddQueryInterface(hChild, &qiConfig);

    if (!NT_SUCCESS(status)) {
        uxen_err("WdfDeviceAddQueryInterface failed - 0x%.08X", status);
        return status;
    }

    return STATUS_SUCCESS;
}

NTSTATUS
create_pdo(WDFCHILDLIST device_list,
           PWDF_CHILD_IDENTIFICATION_DESCRIPTION_HEADER desc,
           PWDFDEVICE_INIT child_init)
{
    PPDO_IDENTIFICATION_DESCRIPTION pdo_desc;

    PAGED_CODE();

    pdo_desc = CONTAINING_RECORD(desc, PDO_IDENTIFICATION_DESCRIPTION, header);

    return create_pdo_helper(WdfChildListGetDevice(device_list),
                             child_init,
                             pdo_desc->slot,
                             pdo_desc->deviceType,
                             pdo_desc->deviceId);
}

NTSTATUS
bus_enumerate(WDFDEVICE device)
{
    PDO_IDENTIFICATION_DESCRIPTION desc;
    PFDO_DATA fdo_data;
    int i;
    NTSTATUS status = STATUS_SUCCESS;
    WDFCHILDLIST child_list;

    fdo_data = get_fdo_data(device);

    child_list = WdfFdoGetDefaultChildList(device);

    uxen_msg("start enumerating platform devices");
    WdfChildListBeginScan(child_list);
    for (i = 0; i < UXENBUS_DEVICE_COUNT; i++) {
        UCHAR device_type;
        struct uxp_bus_device *d = (void *)(fdo_data->bus_conf +
                                            i * UXENBUS_DEVICE_CONFIG_LENGTH);

        device_type = bus_config_read8((void *)&d->device_type);
        if (device_type == UXENBUS_DEVICE_NOT_PRESENT)
            continue;

        WDF_CHILD_IDENTIFICATION_DESCRIPTION_HEADER_INIT(&desc.header, sizeof (desc));

        desc.slot = i;
        desc.deviceType = device_type;
        desc.deviceId = bus_config_read8((void *)&d->instance_id);

        uxen_msg("found device type=%02x id=%02x on slot %d", device_type, desc.deviceId, i);
        status = WdfChildListAddOrUpdateChildDescriptionAsPresent(
                    child_list,
                    &desc.header,
                    NULL);
        if (!NT_SUCCESS(status)) {
            uxen_err("WdfChildListAddOrUpdateChildDescriptionAsPresent failed - "
                     "slot %d device_type %02x device_id %02x status 0x%.08X",
                     i, desc.deviceType, desc.deviceId, status);
            break;
        }
    }
    WdfChildListEndScan(child_list);
    uxen_msg("done enumerating platform devices");

    return status;
}

static NTSTATUS
duplicate_description(WDFCHILDLIST device_list,
                      PWDF_CHILD_IDENTIFICATION_DESCRIPTION_HEADER srcdesc,
                      PWDF_CHILD_IDENTIFICATION_DESCRIPTION_HEADER dstdesc)
{
    PPDO_IDENTIFICATION_DESCRIPTION src, dst;

    UNREFERENCED_PARAMETER(device_list);

    src = CONTAINING_RECORD(srcdesc, PDO_IDENTIFICATION_DESCRIPTION, header);
    dst = CONTAINING_RECORD(dstdesc, PDO_IDENTIFICATION_DESCRIPTION, header);

    dst->slot = src->slot;
    dst->deviceType = src->deviceType;
    dst->deviceId = src->deviceId;

    return STATUS_SUCCESS;
}

static BOOLEAN
compare_description(WDFCHILDLIST device_list,
                    PWDF_CHILD_IDENTIFICATION_DESCRIPTION_HEADER desc1,
                    PWDF_CHILD_IDENTIFICATION_DESCRIPTION_HEADER desc2)
{
    PPDO_IDENTIFICATION_DESCRIPTION d1, d2;

    UNREFERENCED_PARAMETER(device_list);

    d1 = CONTAINING_RECORD(desc1, PDO_IDENTIFICATION_DESCRIPTION, header);
    d2 = CONTAINING_RECORD(desc2, PDO_IDENTIFICATION_DESCRIPTION, header);

    if (d1->slot != d2->slot)
        return FALSE;

    if (d1->deviceType != d2->deviceType)
        return FALSE;

    if (d1->deviceId != d2->deviceId)
        return FALSE;

    return TRUE;
}

static VOID
cleanup_description(WDFCHILDLIST device_list,
                    PWDF_CHILD_IDENTIFICATION_DESCRIPTION_HEADER desc)
{
    UNREFERENCED_PARAMETER(device_list);
    UNREFERENCED_PARAMETER(desc);
}

NTSTATUS
bus_init(PWDFDEVICE_INIT device_init)
{
    WDF_CHILD_LIST_CONFIG      config;

    PAGED_CODE();

    WdfDeviceInitSetDeviceType(device_init, FILE_DEVICE_BUS_EXTENDER);

    WDF_CHILD_LIST_CONFIG_INIT(&config,
                               sizeof(PDO_IDENTIFICATION_DESCRIPTION),
                               create_pdo);

    config.EvtChildListIdentificationDescriptionDuplicate = duplicate_description;
    config.EvtChildListIdentificationDescriptionCompare = compare_description;
    config.EvtChildListIdentificationDescriptionCleanup = cleanup_description;

    WdfFdoInitSetDefaultChildListConfig(device_init,
                                        &config,
                                        WDF_NO_OBJECT_ATTRIBUTES);

    return STATUS_SUCCESS;
}


NTSTATUS
bus_set_info(WDFDEVICE device)
{
    PNP_BUS_INFORMATION        busInfo;

    PAGED_CODE();

    busInfo.BusTypeGuid = GUID_DEVCLASS_UXENBUS;
    busInfo.LegacyBusType = PNPBus;
    busInfo.BusNumber = 0;

    WdfDeviceSetBusInformationForChildren(device, &busInfo);

    return STATUS_SUCCESS;
}
