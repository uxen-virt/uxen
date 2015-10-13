/*
 * Copyright 2015, Bromium, Inc.
 * SPDX-License-Identifier: ISC
 */

#include "uxenstor.h"
#include "smbios.h"
#include "version.h"

extern PULONG InitSafeBootMode;

typedef struct _STOR_CONTEXT {
    PSTORAGE_DEVICE_DESCRIPTOR storage_dev_desc;
    ULONG storage_dev_desc_size;
    ULONG allow_attach;
    BOOLEAN v4v_storage;
} STOR_CONTEXT, *PSTOR_CONTEXT;

static
STOR_CONTEXT uxenstor_ctx = {0};

DRIVER_INITIALIZE DriverEntry;
static DRIVER_ADD_DEVICE stor_add_device;

static  __drv_dispatchType(IRP_MJ_DEVICE_CONTROL)
DRIVER_DISPATCH stor_dispatch_device_control;

static __drv_dispatchType_other
DRIVER_DISPATCH stor_dispatch_pass_thru;

static __drv_dispatchType(IRP_MJ_PNP)
DRIVER_DISPATCH stor_dispatch_pnp;

static __drv_dispatchType(IRP_MJ_POWER)
DRIVER_DISPATCH stor_dispatch_power;

static 
__drv_dispatchType(IRP_MJ_CREATE) 
__drv_dispatchType(IRP_MJ_CLOSE)
DRIVER_DISPATCH stor_dispatch_create_close;

static DRIVER_UNLOAD stor_unload;

static IO_COMPLETION_ROUTINE stor_device_usage_notification_compl;
static IO_COMPLETION_ROUTINE stor_start_device_compl;

static
void extract_storage_device_data()
{
    NTSTATUS status = STATUS_UNSUCCESSFUL;
    struct smbios_struct_header *smbios_struct = NULL;
    size_t smbios_struct_size = 0;

    PHYSICAL_ADDRESS smbios_range_start_phys_addr;
    PCHAR smbios_range_start = NULL;
    size_t smbios_range_len = 0xFFFF;

    PHYSICAL_ADDRESS smbios_struct_table_phys_addr;
    PCHAR smbios_struct_table = NULL;
    size_t smbios_struct_table_size = 0;

    ULONG storage_dev_desc_size = 0;
    USHORT struct_handle = 0;
    PUCHAR dest = NULL;

    ASSERT_IRQL_BE(DISPATCH_LEVEL);

    smbios_range_start_phys_addr.QuadPart = 0x000F0000;
    smbios_range_start = MmMapIoSpace(smbios_range_start_phys_addr,
                                     smbios_range_len,
                                     MmCached);
    if (!smbios_range_start) {
        uxen_err("Failed to map 0xF0000-0xFFFFF");
        goto out;
    }

    if (0 == smbios_find_struct_table(
                smbios_range_start,
                smbios_range_len,
                (uint64_t *)&smbios_struct_table_phys_addr.QuadPart,
                &smbios_struct_table_size))
    {
        uxen_err("SMBios struct table not found");
        goto out;
    }

    smbios_struct_table = MmMapIoSpace(smbios_struct_table_phys_addr,
                                       smbios_struct_table_size,
                                       MmCached);
    if (!smbios_struct_table) {
        uxen_err("Failed to map SMBios physical range");
        goto out;
    }

    /* calculate total data size */
    struct_handle = 0xF080;
    smbios_struct = smbios_get_struct(smbios_struct_table,
                                      smbios_struct_table_size,
                                      0xE9,
                                      struct_handle,
                                      &smbios_struct_size);
    while (smbios_struct) {
        storage_dev_desc_size +=
            (smbios_struct->length - sizeof(*smbios_struct));
        struct_handle++;
        smbios_struct = smbios_get_struct(smbios_struct_table,
                                          smbios_struct_table_size,
                                          0xE9,
                                          struct_handle,
                                          &smbios_struct_size);
    }
    if (0 == storage_dev_desc_size) {
        uxen_msg("Storage descriptor SMBios table (0xE9) not found");
        goto out;
    }

    uxenstor_ctx.storage_dev_desc = ExAllocatePoolWithTag(NonPagedPool,
                                                      storage_dev_desc_size,
                                                      MEMTAG_STOR_DESC);
    if (!uxenstor_ctx.storage_dev_desc) {
        uxen_err("Failed to allocate storage descriptor");
        goto out;
    }

    /* copy data */
    dest = (PUCHAR)uxenstor_ctx.storage_dev_desc;
    struct_handle = 0xF080;
    smbios_struct = smbios_get_struct(smbios_struct_table,
                                      smbios_struct_table_size,
                                      0xE9,
                                      struct_handle,
                                      &smbios_struct_size);
    while (smbios_struct) {
        RtlCopyMemory(dest,
                      smbios_struct + 1,
                      smbios_struct->length - sizeof(*smbios_struct));
        dest += (smbios_struct->length - sizeof(*smbios_struct));
        struct_handle++;
        smbios_struct = smbios_get_struct(smbios_struct_table,
                                          smbios_struct_table_size,
                                          0xE9,
                                          struct_handle,
                                          &smbios_struct_size);
    }

    uxenstor_ctx.storage_dev_desc_size = storage_dev_desc_size;

    status = STATUS_SUCCESS;

  out:
    if (!NT_SUCCESS(status) && uxenstor_ctx.storage_dev_desc) {
        ExFreePoolWithTag(uxenstor_ctx.storage_dev_desc, MEMTAG_STOR_DESC);
        uxenstor_ctx.storage_dev_desc = NULL;
        uxenstor_ctx.storage_dev_desc_size = 0;
    }
    if (smbios_struct_table)
        MmUnmapIoSpace(smbios_struct_table, smbios_struct_table_size);
    if (smbios_range_start)
        MmUnmapIoSpace(smbios_range_start, smbios_range_len);
}

NTSTATUS DriverEntry(PDRIVER_OBJECT drv_obj,
                     PUNICODE_STRING svc_reg_path)
{
    ULONG i;

    UNREFERENCED_PARAMETER(svc_reg_path);

    uxen_msg("begin version: %s", UXEN_DRIVER_VERSION_CHANGESET);

    for (i = 0; i <= IRP_MJ_MAXIMUM_FUNCTION; i++)
        drv_obj->MajorFunction[i] = stor_dispatch_pass_thru;

    drv_obj->MajorFunction[IRP_MJ_DEVICE_CONTROL] = stor_dispatch_device_control;
    drv_obj->MajorFunction[IRP_MJ_SCSI] = stor_dispatch_scsi;
    drv_obj->MajorFunction[IRP_MJ_PNP] = stor_dispatch_pnp;
    drv_obj->MajorFunction[IRP_MJ_POWER] = stor_dispatch_power;
    drv_obj->MajorFunction[IRP_MJ_CREATE] = stor_dispatch_create_close;
    drv_obj->MajorFunction[IRP_MJ_CLOSE] = stor_dispatch_create_close;

    drv_obj->DriverExtension->AddDevice = stor_add_device;
    drv_obj->DriverUnload = stor_unload;

    RtlZeroMemory(&uxenstor_ctx, sizeof(uxenstor_ctx));
    uxenstor_ctx.allow_attach = 16;
#if USE_UXENSTOR
    uxenstor_ctx.v4v_storage = !!READ_PORT_USHORT((PUSHORT)0x330);
#else
    uxenstor_ctx.v4v_storage = FALSE;
#endif

    extract_storage_device_data();

    trace_init();

    uxen_msg("end");

    return STATUS_SUCCESS;
}

void stor_unload(PDRIVER_OBJECT drv_obj)
{
    UNREFERENCED_PARAMETER(drv_obj);

    trace_destroy();
}

NTSTATUS stor_add_device(PDRIVER_OBJECT drv_obj,
                         PDEVICE_OBJECT phys_dev_obj)
{
    NTSTATUS status;
    PDEVICE_OBJECT dev_obj = NULL;
    PUXENSTOR_DEV_EXT dev_ext;

    uxen_msg("begin: 0x%p", phys_dev_obj);

    if (*InitSafeBootMode > 0) {
        /* Disable when booting in safe mode */
        uxen_msg("Booting safe mode - back off");
        status = STATUS_UNSUCCESSFUL;
        goto out;
    }

    if (uxenstor_ctx.allow_attach == 0) {
        /* Exceeded allowed number of devices we can attach to */
        uxen_msg("Max attached devices exceeded");
        status = STATUS_UNSUCCESSFUL;
        goto out;
    }
    uxenstor_ctx.allow_attach--;

    status = IoCreateDevice(drv_obj,
                            sizeof(UXENSTOR_DEV_EXT),
                            NULL,
                            FILE_DEVICE_UNKNOWN,
                            FILE_DEVICE_SECURE_OPEN,
                            FALSE,
                            &dev_obj);
    if (!NT_SUCCESS(status)) {
        uxen_err("IoCreateDevice() failed: 0x%08x", status);
        goto out;
    }

    dev_ext = (PUXENSTOR_DEV_EXT)dev_obj->DeviceExtension;
    RtlZeroMemory(dev_ext, sizeof(*dev_ext));

    status = IoCsqInitialize(&dev_ext->io_queue,
                             csq_insert_irp, csq_remove_irp, csq_peek_next_irp,
                             csq_acquire_lock, csq_release_lock,
                             csq_complete_cancelled_irp);
    if (!NT_SUCCESS(status)) {
        uxen_err("IoCsqInitialize() failed: 0x%08x", status);
        goto out;
    }
    
    dev_ext->lower_dev_obj = IoAttachDeviceToDeviceStack(dev_obj,
                                                         phys_dev_obj);
    if (!dev_ext->lower_dev_obj) {
        uxen_err("Failed to attach filter");
        status = STATUS_UNSUCCESSFUL;
        goto out;
    }

    dev_obj->Flags |= dev_ext->lower_dev_obj->Flags & 
                      (DO_BUFFERED_IO | DO_DIRECT_IO | DO_POWER_PAGABLE);
    dev_obj->DeviceType = dev_ext->lower_dev_obj->DeviceType;
    dev_obj->Characteristics = dev_ext->lower_dev_obj->Characteristics;

    IoInitializeRemoveLock(&dev_ext->remove_lock, MEMTAG_REMOVE_LOCK, 1, 100);
    
    InitializeListHead(&dev_ext->pending_irp_list);
    KeInitializeSpinLock(&dev_ext->io_queue_lock);
    KeInitializeSpinLock(&dev_ext->v4v_lock);

    if (uxenstor_ctx.v4v_storage) {
        acquire_stor_v4v_addr(dev_ext);
        dev_ext->v4v_ring = uxen_v4v_ring_bind(dev_ext->v4v_addr.port, 
                                               dev_ext->v4v_addr.domain,
                                               V4V_STOR_RING_LEN,
                                               stor_v4v_callback,
                                               dev_ext, NULL);
        if (dev_ext->v4v_ring) {
            dev_ext->v4v_resume_lock = 0;
            KeInitializeDpc(&dev_ext->v4v_resume_dpc,
                            stor_v4v_resume_callback, dev_ext);
            uxen_v4vlib_set_resume_dpc(&dev_ext->v4v_resume_dpc, NULL);
            uxen_msg("using v4v storage stack");
        } else {
            uxen_err("failed to bound v4v ring (%d:0x%x)",
                     dev_ext->v4v_addr.domain, dev_ext->v4v_addr.port);
            release_stor_v4v_addr(dev_ext);
        }
    } else {
        dev_ext->v4v_ring = NULL;
        uxen_msg("using native storage stack");
    }

    dev_obj->Flags &= ~DO_DEVICE_INITIALIZING;

    status = STATUS_SUCCESS;
  
    uxen_msg("end: 0x%p", dev_obj);

  out:
    if (!NT_SUCCESS(status) && dev_obj)
        IoDeleteDevice(dev_obj);

    return status;
}

#if MONITOR_IOCTL_RESULTS
static
NTSTATUS stor_ioctl_completion_routine(PDEVICE_OBJECT dev_obj, PIRP irp,
                                       PVOID ctx)
{
    PUXENSTOR_DEV_EXT dev_ext;

    UNREFERENCED_PARAMETER(ctx);

    dev_ext = (PUXENSTOR_DEV_EXT)dev_obj->DeviceExtension;

    if (irp->PendingReturned)
        IoMarkIrpPending(irp);

    if (!NT_SUCCESS(irp->IoStatus.Status))
        uxen_debug("[0x%p:0x%p] ioctl_request failed: 0x%x",
                   dev_obj, irp, irp->IoStatus.Status);

    IoReleaseRemoveLock(&dev_ext->remove_lock, irp); 

    return STATUS_CONTINUE_COMPLETION;
}
#endif /* MONITOR_IOCTL_RESULTS */

NTSTATUS stor_dispatch_device_control(PDEVICE_OBJECT dev_obj,
                                      PIRP irp)
{
    NTSTATUS status;
    PUXENSTOR_DEV_EXT dev_ext;
    PIO_STACK_LOCATION io_stack;
    ULONG out_buffer_len, in_buffer_len;
    PSTORAGE_PROPERTY_QUERY prop_query;

    dev_ext = (PUXENSTOR_DEV_EXT)dev_obj->DeviceExtension;
    status = IoAcquireRemoveLock(&dev_ext->remove_lock, irp);
    if (!NT_SUCCESS(status)) {
        uxen_debug("[0x%p:0x%p] IoAcquireRemoveLock() failed: 0x%08x",
                   dev_obj, irp, status);
        irp->IoStatus.Status = status;
        IoCompleteRequest(irp, IO_NO_INCREMENT);
        goto out;
    }

    io_stack = IoGetCurrentIrpStackLocation(irp);
    out_buffer_len = io_stack->Parameters.DeviceIoControl.OutputBufferLength;
    in_buffer_len = io_stack->Parameters.DeviceIoControl.InputBufferLength;

    switch (io_stack->Parameters.DeviceIoControl.IoControlCode) {
    case IOCTL_STORAGE_QUERY_PROPERTY:
        if ((!irp->AssociatedIrp.SystemBuffer) ||
            (in_buffer_len < RTL_SIZEOF_THROUGH_FIELD(STORAGE_PROPERTY_QUERY,
                                                      PropertyId)))
        {
            uxen_msg("[0x%p:0x%p] Invalid IOCTL_STORAGE_QUERY_PROPERTY params: "
                     "sys_buf:0x%p, in_buf_len:0x%x",
                     dev_obj, irp,
                     irp->AssociatedIrp.SystemBuffer, in_buffer_len);
            break;
        }

        prop_query = (PSTORAGE_PROPERTY_QUERY)irp->AssociatedIrp.SystemBuffer;

        uxen_debug("[0x%p:0x%p] IOCTL_STORAGE_QUERY_PROPERTY: %d [%s]",
                   dev_obj, irp,
                   prop_query->PropertyId,
                   stor_prop_name(prop_query->PropertyId));

        if (uxenstor_ctx.storage_dev_desc &&
            prop_query->PropertyId == StorageDeviceProperty)
        {
            if (out_buffer_len < sizeof(STORAGE_DESCRIPTOR_HEADER)) {
                status = STATUS_INVALID_PARAMETER;
                irp->IoStatus.Information = 0;
            } else {
                const ULONG bytes_to_copy = min(
                    out_buffer_len,
                    uxenstor_ctx.storage_dev_desc_size);

                RtlCopyMemory(irp->AssociatedIrp.SystemBuffer,
                                uxenstor_ctx.storage_dev_desc,
                                bytes_to_copy);
                status = STATUS_SUCCESS;
                irp->IoStatus.Information = bytes_to_copy;
            }

            irp->IoStatus.Status = status;
            IoCompleteRequest(irp, IO_NO_INCREMENT);
            IoReleaseRemoveLock(&dev_ext->remove_lock, irp); 
            goto out;
        }
        break;

#if DROP_UNSUPPORTED_IOCTLS
    case IOCTL_ACPI_ASYNC_EVAL_METHOD:
    case FT_BALANCED_READ_MODE:
    case IOCTL_STORAGE_MANAGE_DATA_SET_ATTRIBUTES:
    case 0x2d5190:
    case 0x2d5928:
    case 0x4d0010:
    case 0x6d70c050:
        if (!uxenstor_ctx.v4v_storage)
            break;
        perfcnt_inc(dropped_ioctls);
        status = STATUS_NOT_IMPLEMENTED;
        irp->IoStatus.Status = status;
        IoCompleteRequest(irp, IO_NO_INCREMENT);
        IoReleaseRemoveLock(&dev_ext->remove_lock, irp); 
        goto out;
#endif /* DROP_UNSUPPORTED_IOCTLS */

#if LOG_IOCTL_UNHANDLED
    default:
        if (uxenstor_ctx.v4v_storage) {
            uxen_msg("[0x%p:0x%p] %s: 0x%x [%s]",
                     dev_obj, irp,
                     (IRP_MJ_DEVICE_CONTROL == io_stack->MajorFunction) ?
                         "IRP_MJ_DEVICE_CONTROL" : "IRP_MJ_SCSI",
                     io_stack->Parameters.DeviceIoControl.IoControlCode,
                     ioctl_name(io_stack->Parameters.DeviceIoControl.IoControlCode));
        }
#endif /* LOG_IOCTL_UNHANDLED */
    }

    if (ahci_state) {
#if MONITOR_IOCTL_RESULTS
        IoCopyCurrentIrpStackLocationToNext(irp);
        IoSetCompletionRoutine(irp,
                               stor_ioctl_completion_routine, NULL,
                               TRUE, TRUE, TRUE);
        status = IoCallDriver(dev_ext->lower_dev_obj, irp);
#else /* MONITOR_IOCTL_RESULTS */
        IoSkipCurrentIrpStackLocation(irp);
        status = IoCallDriver(dev_ext->lower_dev_obj, irp);
        IoReleaseRemoveLock(&dev_ext->remove_lock, irp); 
#endif /* MONITOR_IOCTL_RESULTS */
    } else {
        perfcnt_inc(dropped_ahci_requests);
#if LOG_DROPPED_AHCI_REQUESTS
        uxen_msg("[0x%p:0x%p] dropping %s: 0x%x [%s]",
            dev_obj, irp,
            (IRP_MJ_DEVICE_CONTROL == io_stack->MajorFunction) ?
            "IRP_MJ_DEVICE_CONTROL" : "IRP_MJ_SCSI",
            io_stack->Parameters.DeviceIoControl.IoControlCode,
            ioctl_name(io_stack->Parameters.DeviceIoControl.IoControlCode));
#endif /* LOG_DROPPED_AHCI_REQUESTS */
        status = STATUS_NOT_IMPLEMENTED;
        irp->IoStatus.Status = status;
        IoCompleteRequest(irp, IO_NO_INCREMENT);
        IoReleaseRemoveLock(&dev_ext->remove_lock, irp);
    }

  out:
    return status;
}

NTSTATUS stor_dispatch_pass_thru(PDEVICE_OBJECT dev_obj,
                                 PIRP irp)
{
    NTSTATUS status;
    PUXENSTOR_DEV_EXT dev_ext;

    ASSERT(dev_obj);
    ASSERT(irp);
    
    dev_ext = (PUXENSTOR_DEV_EXT)dev_obj->DeviceExtension;
    status = IoAcquireRemoveLock(&dev_ext->remove_lock, irp);
    if (!NT_SUCCESS(status)) {
        uxen_debug("[0x%p:0x%p] IoAcquireRemoveLock() failed: 0x%08x",
                   dev_obj, irp, status);
        irp->IoStatus.Status = status;
        IoCompleteRequest(irp, IO_NO_INCREMENT);
    } else {
        uxen_debug("[0x%p:0x%p] called: 0x%x, 0x%x",
            dev_obj, irp,
            IoGetCurrentIrpStackLocation(irp)->MajorFunction,
            IoGetCurrentIrpStackLocation(irp)->MinorFunction);

        if (ahci_state) {
            IoSkipCurrentIrpStackLocation(irp);
            status = IoCallDriver(dev_ext->lower_dev_obj, irp);
            IoReleaseRemoveLock(&dev_ext->remove_lock, irp); 
        } else {
            perfcnt_inc(dropped_ahci_requests);
#if LOG_DROPPED_AHCI_REQUESTS
            uxen_msg("[0x%p:0x%p] dropping: 0x%x, 0x%x",
                dev_obj, irp,
                IoGetCurrentIrpStackLocation(irp)->MajorFunction,
                IoGetCurrentIrpStackLocation(irp)->MinorFunction);
#endif /* LOG_DROPPED_AHCI_REQUESTS */
            status = STATUS_NOT_IMPLEMENTED;
            irp->IoStatus.Status = status;
            IoCompleteRequest(irp, IO_NO_INCREMENT);
            IoReleaseRemoveLock(&dev_ext->remove_lock, irp);
        }
    }

    return status;
}

NTSTATUS stor_dispatch_pnp(PDEVICE_OBJECT dev_obj,
                           PIRP irp)
{
    NTSTATUS status = STATUS_UNSUCCESSFUL;
    PUXENSTOR_DEV_EXT dev_ext;
    PIO_STACK_LOCATION io_stack;
    KEVENT event;

    ASSERT(dev_obj);
    ASSERT(irp);

    io_stack = IoGetCurrentIrpStackLocation(irp);
    if (!ahci_state) {
        uxen_debug("[0x%p:0x%p] dropping: 0x%x",
                   dev_obj, irp, io_stack->MinorFunction);
        status = STATUS_UNSUCCESSFUL;
        irp->IoStatus.Status = status;
        IoCompleteRequest(irp, IO_NO_INCREMENT);
        goto out;
    }

    dev_ext = (PUXENSTOR_DEV_EXT)dev_obj->DeviceExtension;
    status = IoAcquireRemoveLock(&dev_ext->remove_lock, irp);
    if (!NT_SUCCESS(status)) {
        uxen_debug("[0x%p:0x%p] IoAcquireRemoveLock() failed: 0x%08x",
                   dev_obj, irp, status);
        irp->IoStatus.Status = status;
        IoCompleteRequest(irp, IO_NO_INCREMENT);
        goto out;
    }

    uxen_debug("[0x%p:0x%p] called: 0x%x",
               dev_obj, irp, io_stack->MinorFunction);
    
    switch (io_stack->MinorFunction) {
    case IRP_MN_START_DEVICE:
        KeInitializeEvent(&event, NotificationEvent, FALSE);

        uxen_msg("[0x%p:0x%p] IRP_MN_START_DEVICE begin", dev_obj, irp);

        IoCopyCurrentIrpStackLocationToNext(irp);
        IoSetCompletionRoutine(irp,
                               stor_start_device_compl,
                               &event,
                               TRUE, TRUE, TRUE);

        status = IoCallDriver(dev_ext->lower_dev_obj, irp);

        if (STATUS_PENDING == status) {
           KeWaitForSingleObject(&event, Executive, KernelMode, FALSE, NULL);          
           status = irp->IoStatus.Status;
        }

        if (NT_SUCCESS(status))
            dev_obj->Characteristics |= 
                dev_ext->lower_dev_obj->Characteristics & FILE_REMOVABLE_MEDIA;
        
        irp->IoStatus.Status = status;
        IoCompleteRequest(irp, IO_NO_INCREMENT);
        IoReleaseRemoveLock(&dev_ext->remove_lock, irp); 

        uxen_msg("[0x%p:0x%p] IRP_MN_START_DEVICE end", dev_obj, irp);
        goto out;

    case IRP_MN_REMOVE_DEVICE:
        uxen_msg("[0x%p:0x%p] IRP_MN_REMOVE_DEVICE begin", dev_obj, irp);

        IoReleaseRemoveLockAndWait(&dev_ext->remove_lock, irp);

        if (dev_ext->v4v_ring) {
            uxen_v4v_ring_free(dev_ext->v4v_ring);
            release_stor_v4v_addr(dev_ext);
        }

        IoSkipCurrentIrpStackLocation(irp);

        status = IoCallDriver(dev_ext->lower_dev_obj, irp);

        IoDetachDevice(dev_ext->lower_dev_obj);
        IoDeleteDevice(dev_obj);

        uxen_msg("[0x%p:0x%p] IRP_MN_REMOVE_DEVICE end", dev_obj, irp);
        goto out;

    case IRP_MN_DEVICE_USAGE_NOTIFICATION:
        uxen_msg("[0x%p:0x%p] IRP_MN_DEVICE_USAGE_NOTIFICATION begin",
                 dev_obj, irp);

        if (!dev_obj->AttachedDevice ||
            (dev_obj->AttachedDevice->Flags & DO_POWER_PAGABLE))
            dev_obj->Flags |= DO_POWER_PAGABLE;

        IoCopyCurrentIrpStackLocationToNext(irp);
        IoSetCompletionRoutine(irp,
                               stor_device_usage_notification_compl,
                               NULL,
                               TRUE, TRUE, TRUE);
        status = IoCallDriver(dev_ext->lower_dev_obj, irp);
        goto out;

    case IRP_MN_QUERY_STOP_DEVICE:
    case IRP_MN_CANCEL_STOP_DEVICE:
    case IRP_MN_STOP_DEVICE:
    case IRP_MN_QUERY_REMOVE_DEVICE:
    case IRP_MN_SURPRISE_REMOVAL:
        uxen_msg("[0x%p:0x%p] PNP minor: 0x%x",
                 dev_obj, irp, io_stack->MinorFunction);
        status = STATUS_SUCCESS;
        break;

    default:
        status = irp->IoStatus.Status;
    }

    irp->IoStatus.Status = status;
    IoSkipCurrentIrpStackLocation(irp);
    status = IoCallDriver(dev_ext->lower_dev_obj, irp);

    IoReleaseRemoveLock(&dev_ext->remove_lock, irp);

  out:
    return status;
}

NTSTATUS stor_start_device_compl(PDEVICE_OBJECT dev_obj,
                                 PIRP irp,
                                 PVOID ctx)
{
    PKEVENT event;

    UNREFERENCED_PARAMETER(dev_obj);

    ASSERT(ctx);

    uxen_msg("[0x%p:0x%p] called", dev_obj, irp);

    event = (PKEVENT)ctx;
    if (irp->PendingReturned)
        KeSetEvent(event, IO_NO_INCREMENT, FALSE);

    return STATUS_MORE_PROCESSING_REQUIRED;
}

NTSTATUS stor_device_usage_notification_compl(PDEVICE_OBJECT dev_obj,
                                              PIRP irp,
                                              PVOID ctx)
{
    PUXENSTOR_DEV_EXT dev_ext;

    UNREFERENCED_PARAMETER(ctx);

    dev_ext = (PUXENSTOR_DEV_EXT)dev_obj->DeviceExtension;

    if (irp->PendingReturned)
        IoMarkIrpPending(irp);

    if (!(dev_ext->lower_dev_obj->Flags & DO_POWER_PAGABLE))
        dev_obj->Flags &= ~DO_POWER_PAGABLE;

    IoReleaseRemoveLock(&dev_ext->remove_lock, irp); 

    uxen_msg("[0x%p:0x%p] IRP_MN_DEVICE_USAGE_NOTIFICATION end",
             dev_obj, irp);

    return STATUS_CONTINUE_COMPLETION;
}

NTSTATUS stor_dispatch_power(PDEVICE_OBJECT dev_obj, PIRP irp)
{
    NTSTATUS status;
    PUXENSTOR_DEV_EXT dev_ext;

    ASSERT(dev_obj);
    ASSERT(irp);
    
    uxen_debug("[0x%p:0x%p] called: 0x%x",
               dev_obj, irp,
               IoGetCurrentIrpStackLocation(irp)->MinorFunction);

    dev_ext = (PUXENSTOR_DEV_EXT)dev_obj->DeviceExtension;
    status = IoAcquireRemoveLock(&dev_ext->remove_lock, irp);
    if (!NT_SUCCESS(status)) {
        uxen_debug("[0x%p:0x%p] IoAcquireRemoveLock() failed: 0x%08x",
                   dev_obj, irp, status);
        irp->IoStatus.Status = status;
        IoCompleteRequest(irp, IO_NO_INCREMENT);
        goto out;
    }

    IoSkipCurrentIrpStackLocation(irp);
    status = IoCallDriver(dev_ext->lower_dev_obj, irp);

    IoReleaseRemoveLock(&dev_ext->remove_lock, irp); 

  out:
    return status;
}

NTSTATUS stor_dispatch_create_close(PDEVICE_OBJECT dev_obj, PIRP irp)
{
    PUXENSTOR_DEV_EXT dev_ext;
    NTSTATUS status;

    ASSERT(dev_obj);
    ASSERT(irp);

    dev_ext = (PUXENSTOR_DEV_EXT)dev_obj->DeviceExtension;
    status = IoAcquireRemoveLock(&dev_ext->remove_lock, irp);
    if (!NT_SUCCESS(status))
        uxen_debug("[0x%p:0x%p] IoAcquireRemoveLock() failed: 0x%08x",
                   dev_obj, irp, status);
    else
        status = STATUS_SUCCESS;

    irp->IoStatus.Status = status;
    IoCompleteRequest(irp, IO_NO_INCREMENT);

    return status;
}
