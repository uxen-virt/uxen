/*
 * Copyright 2012-2015, Bromium, Inc.
 * Author: Christian Limpach <Christian.Limpach@gmail.com>
 * SPDX-License-Identifier: ISC
 */

#include "uxenmouse.h"
#include "uxenvmlib.h"
#include "version.h"

#ifdef ALLOC_PRAGMA
#pragma alloc_text (INIT, DriverEntry)
#pragma alloc_text (PAGE, uxenmouse_add)
#pragma alloc_text (PAGE, uxenmouse_ioctl)
#endif

#pragma warning(push)
#pragma warning(disable:4055) // type case from PVOID to PSERVICE_CALLBACK_ROUTINE
#pragma warning(disable:4152) // function/data pointer conversion in expression

VOID
uxenmouse_cb(IN PDEVICE_OBJECT device_object,
	     IN PMOUSE_INPUT_DATA input_data_start,
	     IN PMOUSE_INPUT_DATA input_data_end,
	     IN OUT PULONG input_data_consumed)
{
    PDEVICE_EXTENSION dev_ext;
    WDFDEVICE device;
    PMOUSE_INPUT_DATA p;
    PSERVICE_CALLBACK_ROUTINE cb;

    device = WdfWdmDeviceGetWdfDeviceHandle(device_object);
    dev_ext = FilterGetData(device);

    /* Publish shared page again if dm is sending deltas.  Probably
     * as a result of save/resume */
    if (input_data_start != input_data_end &&
	(input_data_start->LastX || input_data_start->LastY))
	__outdword(0x60, dev_ext->mouse_shared_mfn[0] << PAGE_SHIFT);

    /* Update LastX/LastY from structure shared with device model */
    for (p = input_data_start; p != input_data_end; p++) {
	p->Flags |= MOUSE_MOVE_ABSOLUTE;
	p->LastX = dev_ext->mouse_shared_page->x << 1;
	p->LastY = dev_ext->mouse_shared_page->y << 1;
    }

    cb = (PSERVICE_CALLBACK_ROUTINE)dev_ext->upper_connect_data.ClassService;
    (*cb)(dev_ext->upper_connect_data.ClassDeviceObject,
	  input_data_start, input_data_end, input_data_consumed);
}

VOID
uxenmouse_ioctl(IN WDFQUEUE queue, IN WDFREQUEST request,
		IN size_t output_buffer_length, IN size_t input_buffer_length,
		IN ULONG io_control_code)
{
    PDEVICE_EXTENSION dev_ext;
    PCONNECT_DATA connect_data;
    WDFDEVICE device;
    size_t length; 
    WDF_REQUEST_SEND_OPTIONS options;
    NTSTATUS status = STATUS_SUCCESS;
    BOOLEAN ret;

    UNREFERENCED_PARAMETER(output_buffer_length);
    UNREFERENCED_PARAMETER(input_buffer_length);

    PAGED_CODE();

    device = WdfIoQueueGetDevice(queue);
    dev_ext = FilterGetData(device);

    switch (io_control_code) {
    case IOCTL_INTERNAL_MOUSE_CONNECT:
	if (dev_ext->upper_connect_data.ClassService) {
            status = STATUS_SHARING_VIOLATION;
            break;
        }

	status = WdfRequestRetrieveInputBuffer(request, sizeof(CONNECT_DATA),
					       &connect_data, &length);
	if (!NT_SUCCESS(status)) {
	    uxen_err("WdfRequestRetrieveInputBuffer failed %x", status);
	    break;
	}

	dev_ext->upper_connect_data = *connect_data;

	connect_data->ClassDeviceObject = WdfDeviceWdmGetDeviceObject(device);
	connect_data->ClassService = uxenmouse_cb;
	break;

    case IOCTL_INTERNAL_MOUSE_DISCONNECT:
	status = STATUS_NOT_IMPLEMENTED;
        break;

    default:
	break;
    }

    if (!NT_SUCCESS(status)) {
	WdfRequestComplete(request, status);
	return;
    }

    WDF_REQUEST_SEND_OPTIONS_INIT(&options,
                                  WDF_REQUEST_SEND_OPTION_SEND_AND_FORGET);

    ret = WdfRequestSend(request, WdfDeviceGetIoTarget(device), &options);
    if (ret == FALSE) {
	status = WdfRequestGetStatus(request);
        uxen_err("WdfRequestSend failed: 0x%x", status);
        WdfRequestComplete(request, status);
    }    
}

NTSTATUS
uxenmouse_add(IN WDFDRIVER driver, IN PWDFDEVICE_INIT device_init)
{
    PDEVICE_EXTENSION dev_ext;
    WDF_OBJECT_ATTRIBUTES device_attributes;
    WDFDEVICE device;
    WDF_IO_QUEUE_CONFIG io_queue_config;
    NTSTATUS status;

    UNREFERENCED_PARAMETER(driver);

    PAGED_CODE();

    uxen_msg("begin");

    WdfFdoInitSetFilter(device_init);

    WdfDeviceInitSetDeviceType(device_init, FILE_DEVICE_MOUSE);

    WDF_OBJECT_ATTRIBUTES_INIT_CONTEXT_TYPE(&device_attributes,
					    DEVICE_EXTENSION);

    status = WdfDeviceCreate(&device_init, &device_attributes, &device);
    if (!NT_SUCCESS(status)) {
	uxen_err("WdfDeviceCreate failed with status code 0x%x", status);
	return status;
    }

    WDF_IO_QUEUE_CONFIG_INIT_DEFAULT_QUEUE(&io_queue_config,
					   WdfIoQueueDispatchParallel);

    io_queue_config.EvtIoInternalDeviceControl = uxenmouse_ioctl;

    status = WdfIoQueueCreate(device, &io_queue_config,
			      WDF_NO_OBJECT_ATTRIBUTES, WDF_NO_HANDLE);
    if (!NT_SUCCESS(status)) {
	uxen_err("WdfIoQueueCreate failed 0x%x", status);
	return status;
    }

    dev_ext = FilterGetData(device);
    dev_ext->mouse_shared_page = uxen_malloc_locked_pages(
	1, dev_ext->mouse_shared_mfn, 0);
    if (dev_ext->mouse_shared_page == NULL) {
	uxen_err("uxen_malloc_locked_pages failed");
	return STATUS_NO_MEMORY;
    }
    __outdword(0x60, dev_ext->mouse_shared_mfn[0] << PAGE_SHIFT);

    uxen_msg("end");

    return status;
}

NTSTATUS
DriverEntry(IN PDRIVER_OBJECT driver_object, IN PUNICODE_STRING registry_path)
{
    WDF_DRIVER_CONFIG config;
    NTSTATUS status;

    uxen_msg("begin version: %s", UXEN_DRIVER_VERSION_CHANGESET);

    WDF_DRIVER_CONFIG_INIT(&config, uxenmouse_add);

    status = WdfDriverCreate(driver_object, registry_path,
			     WDF_NO_OBJECT_ATTRIBUTES, &config, WDF_NO_HANDLE);
    if (!NT_SUCCESS(status)) {
	uxen_err("WdfDriverCreate failed with status 0x%x", status);
        return status;
    }

    uxen_msg("end");

    return status;
}

