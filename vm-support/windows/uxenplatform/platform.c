/*
 * Copyright 2013-2018, Bromium, Inc.
 * Author: Christian Limpach <Christian.Limpach@gmail.com>
 * SPDX-License-Identifier: ISC
 */

#include <initguid.h>
#include <ntddk.h>
#include <wdf.h>

#include "uxenvmlib.h"

#include "platform.h"
#include "platform_public.h"
#include <uxen/platform_interface.h>

#include "balloon.h"
#include "bus.h"
#include "version.h"
#include "zp.h"

NTSTATUS
DriverEntry(IN PDRIVER_OBJECT driver_object, IN PUNICODE_STRING registry_path)
{
    NTSTATUS status;
    WDF_DRIVER_CONFIG config;
    WDF_OBJECT_ATTRIBUTES attrib;
    WDFDRIVER driver;

    uxen_msg("begin version: %s", UXEN_DRIVER_VERSION_CHANGESET);

    WDF_OBJECT_ATTRIBUTES_INIT_CONTEXT_TYPE(&attrib, DRIVER_CONTEXT);

    attrib.EvtCleanupCallback = uxp_ev_driver_context_cleanup;

    WDF_DRIVER_CONFIG_INIT(&config, uxp_ev_driver_device_add);

    status = WdfDriverCreate(driver_object, registry_path, &attrib, &config,
                             &driver);
    if (!NT_SUCCESS(status)) {
        uxen_err("WdfDriverCreate failed: 0x%08X", status);
        return status;
    }

    uxen_msg("end");
    return status;
}

VOID
uxp_ev_driver_context_cleanup(IN WDFDRIVER driver)
{

    UNREFERENCED_PARAMETER(driver);
    PAGED_CODE();

    uxen_msg("called");
}

NTSTATUS
interrupt_enable(IN WDFINTERRUPT interrupt, IN WDFDEVICE associated_device)
{
    PFDO_DATA fdo_data;

    UNREFERENCED_PARAMETER(interrupt);

    uxen_msg("called");

    fdo_data = get_fdo_data(associated_device);
    WRITE_REGISTER_ULONG((PULONG)&fdo_data->ctl_mmio->cm_events_enabled,
            CTL_MMIO_EVENT_SYNC_TIME | CTL_MMIO_EVENT_SET_BALLOON |
            CTL_MMIO_EVENT_HOTPLUG);

    return STATUS_SUCCESS;
}

NTSTATUS
interrupt_disable(IN WDFINTERRUPT interrupt, IN WDFDEVICE associated_device)
{
    PFDO_DATA fdo_data;

    UNREFERENCED_PARAMETER(interrupt);

    uxen_msg("called");

    fdo_data = get_fdo_data(associated_device);
    WRITE_REGISTER_ULONG((PULONG)&fdo_data->ctl_mmio->cm_events_enabled, 0);

    return STATUS_SUCCESS;
}

BOOLEAN
interrupt_isr(IN WDFINTERRUPT interrupt, IN ULONG message_id)
{
    PFDO_DATA fdo_data;
    uint32_t pending_events;

    UNREFERENCED_PARAMETER(message_id);

    uxen_debug("called");

    fdo_data = get_fdo_data(WdfInterruptGetDevice(interrupt));

    pending_events = READ_REGISTER_ULONG((PULONG)&fdo_data->ctl_mmio->cm_events);
    fdo_data->pending_events |= pending_events;

    WdfInterruptQueueDpcForIsr(interrupt);

    return TRUE;
}

static EVT_WDF_INTERRUPT_SYNCHRONIZE fetch_pending;
static BOOLEAN
fetch_pending(IN WDFINTERRUPT interrupt, IN WDFCONTEXT context)
{
    PFDO_DATA fdo_data = (PFDO_DATA)context;

    UNREFERENCED_PARAMETER(interrupt);

    fdo_data->processing_events |= fdo_data->pending_events;
    fdo_data->pending_events = 0;

    return TRUE;
}

VOID
interrupt_dpc(IN WDFINTERRUPT interrupt, IN WDFOBJECT device)
{
    PFDO_DATA fdo_data;

    uxen_debug("called");

    fdo_data = get_fdo_data(device);

    WdfInterruptSynchronize(interrupt, fetch_pending, fdo_data);

    if (fdo_data->processing_events & CTL_MMIO_EVENT_SYNC_TIME) {
        uxen_debug("sync time event");
        if (fdo_data->time_update_event)
            KeSetEvent(fdo_data->time_update_event, 0, FALSE);
        fdo_data->processing_events &= ~CTL_MMIO_EVENT_SYNC_TIME;
    }

    if (fdo_data->processing_events & CTL_MMIO_EVENT_SET_BALLOON) {
        uxen_debug("set balloon event");
        fdo_data->balloon_min =
            READ_REGISTER_ULONG((PULONG)&fdo_data->ctl_mmio->cm_balloon_min);
        fdo_data->balloon_max =
            READ_REGISTER_ULONG((PULONG)&fdo_data->ctl_mmio->cm_balloon_max);
        if (fdo_data->balloon_update_event)
            KeSetEvent(fdo_data->balloon_update_event, 0, FALSE);
        fdo_data->processing_events &= ~CTL_MMIO_EVENT_SET_BALLOON;
    }

    if (fdo_data->processing_events & CTL_MMIO_EVENT_HOTPLUG) {
        uxen_debug("hotplug event");
        bus_enumerate(fdo_data->wdf_device);
        fdo_data->processing_events &= ~CTL_MMIO_EVENT_HOTPLUG;
    }

    if (fdo_data->processing_events) {
        uxen_err("unknown events 0x%x", fdo_data->processing_events);
        fdo_data->processing_events = 0;
    }
}

static NTSTATUS
setup_irq_handler(PFDO_DATA fdo_data)
{
    NTSTATUS status;
    WDF_INTERRUPT_CONFIG interrupt_config;

    PAGED_CODE();

    WDF_INTERRUPT_CONFIG_INIT(&interrupt_config, interrupt_isr, interrupt_dpc);

    interrupt_config.EvtInterruptEnable = interrupt_enable;
    interrupt_config.EvtInterruptDisable = interrupt_disable;

    status = WdfInterruptCreate(fdo_data->wdf_device, &interrupt_config,
                                WDF_NO_OBJECT_ATTRIBUTES,
                                &fdo_data->wdf_interrupt);
    if (!NT_SUCCESS(status)) {
        uxen_err("WdfInterruptCreate failed: 0x%08X", status);
        return status;
    }

    return status;
}

NTSTATUS
uxp_ev_driver_device_add(IN WDFDRIVER driver, IN PWDFDEVICE_INIT device_init)
{
    NTSTATUS status;
    WDF_FILEOBJECT_CONFIG file_config;
    WDF_OBJECT_ATTRIBUTES file_attributes;
    WDF_PNPPOWER_EVENT_CALLBACKS pnp_power_callbacks;
    WDF_OBJECT_ATTRIBUTES fdo_attributes;
    WDF_IO_QUEUE_CONFIG io_queue_config;
    PFDO_DATA fdo_data;
    WDFDEVICE device;

    UNREFERENCED_PARAMETER(driver);
    PAGED_CODE();

    uxen_msg("begin");

    WDF_FILEOBJECT_CONFIG_INIT(&file_config, NULL /* uxp_ev_file_create */,
                               NULL /* uxp_ev_file_close */,
                               uxp_ev_file_cleanup);

    WDF_OBJECT_ATTRIBUTES_INIT(&file_attributes);
    WDF_OBJECT_ATTRIBUTES_SET_CONTEXT_TYPE(&file_attributes, FILE_CONTEXT);

    WdfDeviceInitSetFileObjectConfig(device_init, &file_config,
                                     &file_attributes);

    WdfDeviceInitSetIoType(device_init, WdfDeviceIoDirect);

    WDF_PNPPOWER_EVENT_CALLBACKS_INIT(&pnp_power_callbacks);

    pnp_power_callbacks.EvtDevicePrepareHardware =
        uxp_ev_device_prepare_hardware;
    pnp_power_callbacks.EvtDeviceReleaseHardware =
        uxp_ev_device_release_hardware;

    WdfDeviceInitSetPnpPowerEventCallbacks(device_init, &pnp_power_callbacks);

    WDF_OBJECT_ATTRIBUTES_INIT_CONTEXT_TYPE(&fdo_attributes, FDO_DATA);

    fdo_attributes.EvtCleanupCallback = uxp_ev_device_context_cleanup;

    status = bus_init(device_init);
    if (!NT_SUCCESS(status)) {
        uxen_err("bus_init failed: 0x%08X", status);
        return status;
    }

    status = WdfDeviceCreate(&device_init, &fdo_attributes, &device);
    if (!NT_SUCCESS(status)) {
        uxen_err("WdfDeviceCreate failed: 0x%08X", status);
        return status;
    }

    fdo_data = get_fdo_data(device);
    fdo_data->wdf_device = device;

    WDF_IO_QUEUE_CONFIG_INIT(&io_queue_config, WdfIoQueueDispatchParallel);

    io_queue_config.EvtIoDeviceControl = uxp_ev_device_io_device_control;

    status = WdfIoQueueCreate(fdo_data->wdf_device, &io_queue_config,
                              WDF_NO_OBJECT_ATTRIBUTES, &fdo_data->ioctl_queue);
    if(!NT_SUCCESS (status)){
        uxen_err("WdfIoQueueCreate failed: 0x%08X", status);
        return status;
    }

    status = WdfDeviceConfigureRequestDispatching(fdo_data->wdf_device,
                                                  fdo_data->ioctl_queue,
                                                  WdfRequestTypeDeviceControl);
    if(!NT_SUCCESS (status)){
        uxen_err("WdfDeviceConfigureRequestDispatching failed: 0x%08X", status);
        return status;
    }

    WDF_IO_QUEUE_CONFIG_INIT(&io_queue_config, WdfIoQueueDispatchManual);

    status = WdfIoQueueCreate(fdo_data->wdf_device, &io_queue_config,
                              WDF_NO_OBJECT_ATTRIBUTES,
                              &fdo_data->pending_ioctl_queue);
    if(!NT_SUCCESS (status)){
        uxen_err("WdfIoQueueCreate(pending) failed: 0x%08X", status);
        return status;
    }

    status = setup_irq_handler(fdo_data);
    if (!NT_SUCCESS(status)) {
        uxen_err("setup_irq_handler failed: 0x%08X", status);
        return status;
    }

    status = WdfDeviceCreateDeviceInterface(
        device, (LPGUID)&GUID_DEVINTERFACE_UXENPLATFORM, NULL);
    if (!NT_SUCCESS (status)) {
        uxen_err("WdfDeviceCreateDeviceInterface failed: 0x%08X", status);
        return status;
    }

    status = balloon_init();
    if (!NT_SUCCESS (status)) {
        uxen_err("balloon_init failed: 0x%08X", status);
        return status;
    }

    status = bus_set_info(device);
    if (!NT_SUCCESS(status)) {
        uxen_err("bus_set_info failed: 0x%08X", status);
        return status;
    }

    uxen_msg("end");
    return status;
}

VOID
uxp_ev_device_context_cleanup(WDFDEVICE device)
{

    UNREFERENCED_PARAMETER(device);
    PAGED_CODE();

    uxen_msg("called");

    balloon_cleanup();
}

NTSTATUS
uxp_ev_device_prepare_hardware(WDFDEVICE device, WDFCMRESLIST resources,
                               WDFCMRESLIST resources_translated)
{
    PFDO_DATA fdo_data;
    PCM_PARTIAL_RESOURCE_DESCRIPTOR descriptor;
    ULONG i;
    ULONG mem_bar_no = 0;
    NTSTATUS status;

    UNREFERENCED_PARAMETER(resources);
    PAGED_CODE();

    uxen_msg("called");

    fdo_data = get_fdo_data(device);

    for (i = 0; i < WdfCmResourceListGetCount(resources_translated); i++) {
        descriptor = WdfCmResourceListGetDescriptor(resources_translated, i);
        if (!descriptor) {
            uxen_err("WdfCmResourceListGetDescriptor failed");
            return STATUS_DEVICE_CONFIGURATION_ERROR;
        }

        switch (descriptor->Type) {
        case CmResourceTypePort:
            uxen_debug("type port csr: %x len: %x",
                       descriptor->u.Port.Start.LowPart,
                       descriptor->u.Port.Length);
            break;
        case CmResourceTypeMemory:
            uxen_debug("type memory csr: %x:%x len: %x",
                       descriptor->u.Memory.Start.LowPart,
                       descriptor->u.Memory.Start.HighPart,
                       descriptor->u.Memory.Length);
	    switch (mem_bar_no) {
	        case 0:
                    fdo_data->ctl_mmio_phys = descriptor->u.Memory.Start;
                    fdo_data->ctl_mmio = MmMapIoSpace(descriptor->u.Memory.Start,
                                              descriptor->u.Memory.Length,
                                              MmNonCached);
                    uxen_debug("ctl_mmio=%p", fdo_data->ctl_mmio);
                    break;
	        case 1:
                    fdo_data->state_bar_phys = descriptor->u.Memory.Start;
                    fdo_data->state_bar = MmMapIoSpace(descriptor->u.Memory.Start,
                                              descriptor->u.Memory.Length,
                                              MmCached);
                    uxen_debug("state_bar=%p", fdo_data->state_bar);
                    break;
                case 2:
                    fdo_data->bus_conf_phys = descriptor->u.Memory.Start;
                    fdo_data->bus_conf = MmMapIoSpace(descriptor->u.Memory.Start,
                                                      descriptor->u.Memory.Length,
                                                      MmCached);
                    break;
	    }
	    mem_bar_no++;
            break;
        case CmResourceTypeInterrupt:
            uxen_debug("type interrupt level: %d vector: %d",
                       descriptor->u.Interrupt.Level,
                       descriptor->u.Interrupt.Vector);
            break;
        default:
            uxen_debug("type unknown: %d", descriptor->Type);
            break;
        }
    }

    uxen_hypercall_init();
    uxen_set_state_bar(fdo_data->state_bar);

    status = bus_enumerate(device);
    if (!NT_SUCCESS(status))
        return status;

    // FIXME: WHP zero-page
    if (!uxen_is_whp_present())
        zp_init();

    return STATUS_SUCCESS;
}

NTSTATUS
uxp_ev_device_release_hardware(IN WDFDEVICE device,
                               IN WDFCMRESLIST resources_translated)
{

    UNREFERENCED_PARAMETER(device);
    UNREFERENCED_PARAMETER(resources_translated);
    PAGED_CODE();

    uxen_msg("called");

    return STATUS_SUCCESS;
}

#define ICC(ctl) ((ctl) & ((1ULL << 32) - 1))

VOID
uxp_ev_device_io_device_control(IN WDFQUEUE queue, IN WDFREQUEST request,
                                IN size_t output_buffer_length,
                                IN size_t input_buffer_length,
                                IN ULONG io_control_code)
{
    PFDO_DATA fdo_data;
    size_t out_bytes = 0;
    NTSTATUS status;

    UNREFERENCED_PARAMETER(output_buffer_length);
    UNREFERENCED_PARAMETER(input_buffer_length);

    uxen_debug("called %lx", io_control_code);

    fdo_data = get_fdo_data(WdfIoQueueGetDevice(queue));

    switch (io_control_code) {
    case ICC(IOCTL_UXEN_PLATFORM_SET_TIME_UPDATE_EVENT): {
        PFILE_CONTEXT file_context;
        struct uxen_platform_set_time_update_event *d;

        uxen_debug("io control SET_TIME_UPDATE_EVENT");
        status = WdfRequestRetrieveInputBuffer(request, sizeof(*d),
                                               (PVOID *)&d, NULL);
        if (!NT_SUCCESS(status)) {
            uxen_err("SET_TIME_UPDATE_EVENT: "
                     "WdfRequestRetrieveInputBuffer failed - 0x%.08X",
                     status);
            goto out;
        }

        if (fdo_data->time_update_event) {
            uxen_err("SET_TIME_UPDATE_EVENT: event already set");
            status = STATUS_INSUFFICIENT_RESOURCES;
            goto out;
        }

        status = ObReferenceObjectByHandle(
            d->time_update_event, SYNCHRONIZE, *ExEventObjectType,
            UserMode, &fdo_data->time_update_event, NULL);
        if (!NT_SUCCESS(status)) {
            uxen_err("SET_TIME_UPDATE_EVENT: ObReferenceObjectByHandle failed"
                     " - 0x%.08X", status);
            fdo_data->time_update_event = NULL;
            goto out;
        }

        file_context = WdfObjectGet_FILE_CONTEXT(
            WdfRequestGetFileObject(request));
        file_context->fdo_data = fdo_data;
        break;
    }
    case ICC(IOCTL_UXEN_PLATFORM_SET_BALLOON_UPDATE_EVENT): {
        PFILE_CONTEXT file_context;
        struct uxen_platform_set_balloon_update_event *d;

        uxen_debug("io control SET_BALLOON_UPDATE_EVENT");
        status = WdfRequestRetrieveInputBuffer(request, sizeof(*d),
                                               (PVOID *)&d, NULL);
        if (!NT_SUCCESS(status)) {
            uxen_err("SET_BALLOON_UPDATE_EVENT: "
                     "WdfRequestRetrieveInputBuffer failed - 0x%.08X",
                     status);
            goto out;
        }

        if (fdo_data->balloon_update_event) {
            uxen_err("SET_BALLOON_UPDATE_EVENT: event already set");
            status = STATUS_INSUFFICIENT_RESOURCES;
            goto out;
        }

        status = ObReferenceObjectByHandle(
            d->balloon_update_event, SYNCHRONIZE, *ExEventObjectType,
            UserMode, &fdo_data->balloon_update_event, NULL);
        if (!NT_SUCCESS(status)) {
            uxen_err("SET_BALLOON_UPDATE_EVENT: "
                     "ObReferenceObjectByHandle failed - 0x%.08X", status);
            fdo_data->balloon_update_event = NULL;
            goto out;
        }

        file_context = WdfObjectGet_FILE_CONTEXT(
            WdfRequestGetFileObject(request));
        file_context->fdo_data = fdo_data;
        break;
    }
    case ICC(IOCTL_UXEN_PLATFORM_MAP_SHARED_INFO): {
        PFILE_CONTEXT file_context;
        struct uxen_platform_map_shared_info *d;

        uxen_debug("io control MAP_SHARED_INFO");
        status = WdfRequestRetrieveOutputBuffer(request, sizeof(*d),
                                                (PVOID *)&d, NULL);
        if (!NT_SUCCESS(status)) {
            uxen_err("MAP_SHARED_INFO: "
                     "WdfRequestRetrieveOutputBuffer failed - 0x%.08X",
                     status);
            goto out;
        }

        file_context = WdfObjectGet_FILE_CONTEXT(
            WdfRequestGetFileObject(request));
        if (!file_context->user_shared_info) {
            if (!fdo_data->shared_info)
                fdo_data->shared_info =
                    uxen_get_shared_info(&fdo_data->shared_info_gpfn);
            file_context->user_shared_info =
                uxen_user_map_page_range(1, &fdo_data->shared_info_gpfn,
                                         &file_context->user_shared_info_mdl);
            if (!file_context->user_shared_info) {
                uxen_err("MAP_SHARED_INFO: uxen_user_map_page_range failed");
                status = STATUS_INSUFFICIENT_RESOURCES;
                goto out;
            }
        }

        d->shared_info = file_context->user_shared_info;
        out_bytes = sizeof(*d);
        break;
    }

    /* Balloon IOCTL's */

    case ICC(IOCTL_UXEN_PLATFORM_BALLOON_GET_CONFIGURATION): {
        struct uxen_platform_balloon_configuration *d;

        uxen_debug("io control BALLOON_GET_CONFIGURATION");
        status = WdfRequestRetrieveOutputBuffer(request, sizeof(*d),
                                                (PVOID *)&d, NULL);
        if (!NT_SUCCESS(status)) {
            uxen_err("BALLOON_GET_CONFIGURATION: "
                     "WdfRequestRetrieveOutputBuffer failed - 0x%.08X",
                     status);
            goto out;
        }

        ASSERT(input_buffer_length == 0);
        ASSERT(output_buffer_length ==  sizeof(*d));
        if (output_buffer_length != sizeof(*d)) {
            uxen_err(
                "  output_buffer_length (%u) != "
                "sizeof(uxen_platform_balloon_configuration) (%zu)",
                output_buffer_length, sizeof(*d));
            status = STATUS_INVALID_PARAMETER;
            goto out;
        }

        status = balloon_get_configuration(d);
        if (NT_SUCCESS(status)) {
            out_bytes = sizeof(*d);
        }

        break;
    }
    case ICC(IOCTL_UXEN_PLATFORM_BALLOON_GET_STATISTICS): {
        struct uxen_platform_balloon_statistics *d;

        uxen_debug("io control BALLOON_GET_STATISTICS");
        status = WdfRequestRetrieveOutputBuffer(request, sizeof(*d),
                                                (PVOID *)&d, NULL);
        if (!NT_SUCCESS(status)) {
            uxen_err("BALLOON_GET_STATISTICS: "
                     "WdfRequestRetrieveOutputBuffer failed - 0x%.08X",
                     status);
            goto out;
        }
        
        ASSERT(input_buffer_length == 0);
        ASSERT(output_buffer_length == sizeof(*d));
        if (output_buffer_length != sizeof(*d)) {
            uxen_err(
                "  output_buffer_length (%u) != "
                "sizeof(uxen_platform_balloon_statistics) (%zu)\n",
                output_buffer_length, sizeof(*d));
            status = STATUS_INVALID_PARAMETER;
            goto out;
        }

        status = balloon_get_statistics(d);
        if (NT_SUCCESS(status)) {
            d->min_size_mb = fdo_data->balloon_min;
            d->max_size_mb = fdo_data->balloon_max;
            out_bytes = sizeof(*d);
        }
        break;
    }
    case ICC(IOCTL_UXEN_PLATFORM_BALLOON_SET_CONFIGURATION): {
        struct uxen_platform_balloon_configuration *d;

        uxen_debug("io control BALLOON_SET_CONFIGURATION");
        status = WdfRequestRetrieveInputBuffer(request, sizeof(*d),
                                               (PVOID *)&d, NULL);
        if (!NT_SUCCESS(status)) {
            uxen_err("BALLOON_SET_CONFIGURATION: "
                     "WdfRequestRetrieveInputBuffer failed - 0x%.08", status);
            goto out;
        }

        ASSERT(input_buffer_length == sizeof(*d));
        ASSERT(output_buffer_length == 0);
        if (input_buffer_length != sizeof(*d)) {
            uxen_err(
                "  input_buffer_length (%u) != "
                "sizeof(uxen_platform_balloon_statistics) (%zu)",
                input_buffer_length, sizeof(*d));
            status = STATUS_INVALID_PARAMETER;
            goto out;
        }

        /* Clamp balloon target within host-specified range. */
        if (d->target_size_mb < fdo_data->balloon_min) {
            d->target_size_mb = fdo_data->balloon_min;
        }
        if (d->target_size_mb > fdo_data->balloon_max) {
            d->target_size_mb = fdo_data->balloon_max;
        }
        status = balloon_set_configuration(d);
        if (NT_SUCCESS(status)) {
            struct uxen_platform_balloon_statistics stats;
            out_bytes = 0;
            status = balloon_get_statistics(&stats);

            /* Ack the new setting back to uxendm via BAR register. */
            if (NT_SUCCESS(status)) {
                WRITE_REGISTER_ULONG((PULONG)&fdo_data->ctl_mmio->cm_balloon_current,
                        stats.current_size_mb);
            }
        }
        break;
    }
    case ICC(IOCTL_UXEN_PLATFORM_GET_FTIME): {
        uint64_t *ft;

        status = WdfRequestRetrieveOutputBuffer(request, sizeof(*ft),
                                                (PVOID *)&ft, NULL);
        if (!NT_SUCCESS(status)) {
            uxen_err("GET_FTIME "
                     "WdfRequestRetrieveOutputBuffer failed - 0x%.08X",
                     status);
            goto out;
        }

        ASSERT(input_buffer_length == 0);
        ASSERT(output_buffer_length == sizeof(*ft));
        if (output_buffer_length != sizeof(*ft)) {
            uxen_err(
                "  output_buffer_length (%u) != "
                "sizeof(uxen_platform_ftime) (%zu)\n",
                output_buffer_length, sizeof(*ft));
            status = STATUS_INVALID_PARAMETER;
            goto out;
        }

        *ft = READ_REGISTER_ULONG((PULONG)&fdo_data->ctl_mmio->cm_filetime_low);
        *ft |= (uint64_t)READ_REGISTER_ULONG(
                (PULONG)&fdo_data->ctl_mmio->cm_filetime_high) << 32;

        out_bytes = sizeof(*ft);

        break;
    }
    default:
        uxen_err("unknown io control code: 0x%08lX", io_control_code);
        status = STATUS_INVALID_DEVICE_REQUEST;
        break;
    }

  out:
    WdfRequestCompleteWithInformation(request, status, out_bytes);
}

VOID
uxp_ev_file_cleanup(IN WDFFILEOBJECT file_object)
{
    PFILE_CONTEXT file_context;

    uxen_set_state_bar(NULL);

    uxen_debug("called");

    file_context = WdfObjectGet_FILE_CONTEXT(file_object);

    if (file_context->fdo_data && file_context->fdo_data->time_update_event) {
        ObDereferenceObject(file_context->fdo_data->time_update_event);
        file_context->fdo_data->time_update_event = NULL;
    }
    if (file_context->fdo_data && file_context->fdo_data->balloon_update_event) {
        ObDereferenceObject(file_context->fdo_data->balloon_update_event);
        file_context->fdo_data->balloon_update_event = NULL;
    }
    if (file_context->user_shared_info) {
        MmUnmapLockedPages(file_context->user_shared_info,
                           file_context->user_shared_info_mdl);
        IoFreeMdl(file_context->user_shared_info_mdl);
    }
}
