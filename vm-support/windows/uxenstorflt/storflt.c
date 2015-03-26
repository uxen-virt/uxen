/*
 * Copyright 2013-2015, Bromium, Inc.
 * Author: Kris Uchronski <kuchronski@gmail.com>
 * SPDX-License-Identifier: ISC
 */

#include "storflt.h"
#include "smbios.h"


extern PULONG InitSafeBootMode;


typedef struct _STORFLT_CONTEXT {
    PSTORAGE_DEVICE_DESCRIPTOR  pStorageDevDesc;
    ULONG                       cbStorageDevDescSize;

    ULONG                       allowAttach;
} STORFLT_CONTEXT, *PSTORFLT_CONTEXT;

static STORFLT_CONTEXT g_storfltCtx = {0};


DRIVER_INITIALIZE DriverEntry;

DRIVER_ADD_DEVICE StorfltAddDevice;

__drv_dispatchType(IRP_MJ_DEVICE_CONTROL)
DRIVER_DISPATCH StorfltDispatchDeviceControl;

__drv_dispatchType_other
DRIVER_DISPATCH StroportDispatchPassThru;

__drv_dispatchType(IRP_MJ_PNP)
DRIVER_DISPATCH StorfltDispatchPnp;

__drv_dispatchType(IRP_MJ_POWER)
DRIVER_DISPATCH StorfltDispatchPower;

DRIVER_UNLOAD StorfltUnload;

#ifdef SMART_RCV_MONITORING_ENABLED
IO_COMPLETION_ROUTINE
StorfltSmartCompletionRoutine;
#endif /* SMART_RCV_MONITORING_ENABLED */

IO_COMPLETION_ROUTINE
StorfltDeviceUsageNotificationCompletionRoutine;

IO_COMPLETION_ROUTINE
StorfltStartDeviceCompletionRoutine;


static
VOID ExtractStorageDeviceData()
{
    NTSTATUS status = STATUS_UNSUCCESSFUL;
    struct smbios_struct_header *pSMBiosStruct = NULL;
    size_t cbSMBiosStructSize = 0;

    PHYSICAL_ADDRESS SMBiosRangeStartPhysAddr;
    PCHAR pSMBiosRangeStart = NULL;
    size_t cbSMBiosRangeLen = 0xFFFF;

    PHYSICAL_ADDRESS SMBiosStructTablePhysAddr;
    PCHAR pSMBiosStructTable = NULL;
    size_t cbSMBiosStructTableSize = 0;

    ULONG cbStorageDevDescSize = 0;
    USHORT structHandle = 0;
    PUCHAR pDest = NULL;

    SMBiosRangeStartPhysAddr.QuadPart = 0x000F0000;
    pSMBiosRangeStart = MmMapIoSpace(SMBiosRangeStartPhysAddr,
                                     cbSMBiosRangeLen,
                                     MmCached);
    if (NULL == pSMBiosRangeStart) {
        uxen_err("Failed to map 0xF0000-0xFFFFF\n");
        goto out;
    }

    if (0 == smbios_find_struct_table(pSMBiosRangeStart,
                                      cbSMBiosRangeLen,
                                      (uint64_t *)&SMBiosStructTablePhysAddr.QuadPart,
                                      &cbSMBiosStructTableSize))
    {
        uxen_err("SMBios struct table not found\n");
        goto out;
    }

    pSMBiosStructTable = MmMapIoSpace(SMBiosStructTablePhysAddr,
                                      cbSMBiosStructTableSize,
                                      MmCached);
    if (NULL == pSMBiosStructTable) {
        uxen_err("Failed to map SMBios physical range\n");
        goto out;
    }

    /* calculate total data size */
    structHandle = 0xF080;
    pSMBiosStruct = smbios_get_struct(pSMBiosStructTable,
                                      cbSMBiosStructTableSize,
                                      0xE9,
                                      structHandle,
                                      &cbSMBiosStructSize);
    while (NULL != pSMBiosStruct) {
        cbStorageDevDescSize += (pSMBiosStruct->length - sizeof(*pSMBiosStruct));
        structHandle++;
        pSMBiosStruct = smbios_get_struct(pSMBiosStructTable,
                                          cbSMBiosStructTableSize,
                                          0xE9,
                                          structHandle,
                                          &cbSMBiosStructSize);
    }
    if (0 == cbStorageDevDescSize) {
        uxen_msg("Storage descriptor SMBios table (0xE9) not found\n");
        goto out;
    }

    g_storfltCtx.pStorageDevDesc = ExAllocatePoolWithTag(NonPagedPool,
                                                         cbStorageDevDescSize,
                                                         MEMTAG_STOR_DESC);
    if (NULL == g_storfltCtx.pStorageDevDesc) {
        uxen_err("Failed to allocate storage descriptor\n");
        goto out;
    }

    /* copy data */
    pDest = (PUCHAR)g_storfltCtx.pStorageDevDesc;
    structHandle = 0xF080;
    pSMBiosStruct = smbios_get_struct(pSMBiosStructTable,
                                      cbSMBiosStructTableSize,
                                      0xE9,
                                      structHandle,
                                      &cbSMBiosStructSize);
    while (NULL != pSMBiosStruct) {
        RtlCopyMemory(pDest,
                      pSMBiosStruct + 1,
                      pSMBiosStruct->length - sizeof(*pSMBiosStruct));
        pDest += (pSMBiosStruct->length - sizeof(*pSMBiosStruct));
        structHandle++;
        pSMBiosStruct = smbios_get_struct(pSMBiosStructTable,
                                          cbSMBiosStructTableSize,
                                          0xE9,
                                          structHandle,
                                          &cbSMBiosStructSize);
    }

    g_storfltCtx.cbStorageDevDescSize = cbStorageDevDescSize;

    status = STATUS_SUCCESS;

  out:
    if (!NT_SUCCESS(status)) {
        if (NULL != g_storfltCtx.pStorageDevDesc) {
            ExFreePoolWithTag(g_storfltCtx.pStorageDevDesc, MEMTAG_STOR_DESC);
            g_storfltCtx.pStorageDevDesc = NULL;
            g_storfltCtx.cbStorageDevDescSize = 0;
        }
    }
    if (NULL != pSMBiosStructTable) {
        MmUnmapIoSpace(pSMBiosStructTable, cbSMBiosStructTableSize);
    }
    if (NULL != pSMBiosRangeStart) {
        MmUnmapIoSpace(pSMBiosRangeStart, cbSMBiosRangeLen);
    }
}

NTSTATUS DriverEntry(
    __in PDRIVER_OBJECT pDrvObj,
    __in PUNICODE_STRING pRegistryPath)
{
    ULONG i;

    UNREFERENCED_PARAMETER(pRegistryPath);

    uxen_msg("begin");

    for (i = 0; i <= IRP_MJ_MAXIMUM_FUNCTION; i++) {
        pDrvObj->MajorFunction[i] = StroportDispatchPassThru;
    }

    pDrvObj->MajorFunction[IRP_MJ_DEVICE_CONTROL] = StorfltDispatchDeviceControl;
    pDrvObj->MajorFunction[IRP_MJ_PNP] = StorfltDispatchPnp;
    pDrvObj->MajorFunction[IRP_MJ_POWER] = StorfltDispatchPower;

    pDrvObj->DriverExtension->AddDevice = StorfltAddDevice;
    pDrvObj->DriverUnload = StorfltUnload;

    RtlZeroMemory(&g_storfltCtx, sizeof(g_storfltCtx));

    /* We only want to attach to first disk */
    g_storfltCtx.allowAttach = 1;

    ExtractStorageDeviceData();

    uxen_msg("end");

    return STATUS_SUCCESS;
}

VOID StorfltUnload(__in PDRIVER_OBJECT pDrvObj)
{
    UNREFERENCED_PARAMETER(pDrvObj);

    uxen_msg("called");
}

NTSTATUS StorfltAddDevice(
    __in PDRIVER_OBJECT pDrvObj,
    __in PDEVICE_OBJECT pPhysicalDevObj)
{
    NTSTATUS status = STATUS_UNSUCCESSFUL;
    PDEVICE_OBJECT pDevObj = NULL;
    PDEVICE_EXTENSION pDevExt = NULL;
    ULONG deviceType = FILE_DEVICE_UNKNOWN;

    uxen_msg("begin");

    if (*InitSafeBootMode > 0) {
        /* Disable when booting in safe mode */
        status = STATUS_UNSUCCESSFUL;
        goto out;
    }

    if (0 == g_storfltCtx.allowAttach) {
        /* Exceeded allowed number of devices we can attach to */
        status = STATUS_UNSUCCESSFUL;
        goto out;
    }
    g_storfltCtx.allowAttach--;

    status = IoCreateDevice(pDrvObj,
                            sizeof(DEVICE_EXTENSION),
                            NULL,
                            deviceType,
                            FILE_DEVICE_SECURE_OPEN,
                            FALSE,
                            &pDevObj);
    if (!NT_SUCCESS(status)) {
        uxen_err("IoCreateDevice() failed: 0x%08x\n", status);
        goto out;
    }

    pDevExt = (PDEVICE_EXTENSION)pDevObj->DeviceExtension;
    
    pDevExt->pNextLowerDriver = IoAttachDeviceToDeviceStack(
        pDevObj,
        pPhysicalDevObj);
    if (NULL == pDevExt->pNextLowerDriver) {
        uxen_err("Failed to attach filter\n");
        status = STATUS_UNSUCCESSFUL;
        goto out;
    }

    pDevObj->Flags |= pDevExt->pNextLowerDriver->Flags & 
                      (DO_BUFFERED_IO | DO_DIRECT_IO | DO_POWER_PAGABLE);
    pDevObj->DeviceType = pDevExt->pNextLowerDriver->DeviceType;
    pDevObj->Characteristics = pDevExt->pNextLowerDriver->Characteristics;

    IoInitializeRemoveLock(&pDevExt->removeLock,
                           MEMTAG_REMOVE_LOCK, 1, 100);

    pDevObj->Flags &= ~DO_DEVICE_INITIALIZING;

    status = STATUS_SUCCESS;
  
    uxen_msg("end");

  out:
    if (!NT_SUCCESS(status)) {
        if (NULL != pDevObj) {
            IoDeleteDevice(pDevObj);
        }
    }

    return status;
}

NTSTATUS StorfltDispatchDeviceControl(
    __in PDEVICE_OBJECT pDevObj,
    __inout PIRP pIrp)
{
    NTSTATUS status = STATUS_UNSUCCESSFUL;
    PDEVICE_EXTENSION pDevExt = NULL;
    PIO_STACK_LOCATION pIoStack = NULL;
    ULONG cbOutputBufferLength = 0;
    ULONG cbInputBufferLength = 0;

    ASSERT(NULL != pDevObj);
    ASSERT(NULL != pIrp);

    pIoStack = IoGetCurrentIrpStackLocation(pIrp);
    cbOutputBufferLength = pIoStack->Parameters.DeviceIoControl.OutputBufferLength;
    cbInputBufferLength = pIoStack->Parameters.DeviceIoControl.InputBufferLength;

    pDevExt = (PDEVICE_EXTENSION)pDevObj->DeviceExtension;
    status = IoAcquireRemoveLock(&pDevExt->removeLock, pIrp);
    if (!NT_SUCCESS(status)) {
        pIrp->IoStatus.Status = status;
        IoCompleteRequest(pIrp, IO_NO_INCREMENT);
        goto out;
    }

    uxen_debug("IOCTL(0x%x), devobj:0x%p, irp:0x%p\n",
               pIoStack->Parameters.DeviceIoControl.IoControlCode,
               pDevObj, pIoStack);
    
    switch (pIoStack->Parameters.DeviceIoControl.IoControlCode) {

#ifdef SMART_RCV_MONITORING_ENABLED
    case SMART_RCV_DRIVE_DATA: {
        PSENDCMDINPARAMS pSmartCmdInParams = NULL;

        if ((NULL == pIrp->AssociatedIrp.SystemBuffer) ||
            (cbInputBufferLength <
             RTL_SIZEOF_THROUGH_FIELD(SENDCMDINPARAMS,
                                      irDriveRegs.bCommandReg)) ||
            (cbOutputBufferLength < sizeof(SENDCMDOUTPARAMS)))
        {
            uxen_debug("Invalid SMART_RCV_DRIVE_DATA params: "
                       "sys_buf:0x%p, in_buf_len:0x%x, out_buf_len:0x%x\n",
                       pIrp->AssociatedIrp.SystemBuffer,
                       cbInputBufferLength, cbOutputBufferLength);
            break;
        }

        pSmartCmdInParams = (PSENDCMDINPARAMS)pIrp->AssociatedIrp.SystemBuffer;

        uxen_debug("SMART_RCV_DRIVE_DATA: cmdReq: 0x%02x\n",
                   pSmartCmdInParams->irDriveRegs.bCommandReg);

        if (0xEC == pSmartCmdInParams->irDriveRegs.bCommandReg) {
            /* We want to dump ATA IDENTIFY_DEVICE result */
            IoCopyCurrentIrpStackLocationToNext(pIrp);
            IoSetCompletionRoutine(pIrp,
                                   StorfltSmartCompletionRoutine, NULL,
                                   TRUE, TRUE, TRUE);
            status = IoCallDriver(pDevExt->pNextLowerDriver, pIrp);

            goto out;
        }
        break;
    }
#endif /* SMART_RCV_MONITORING_ENABLED */

    case IOCTL_STORAGE_QUERY_PROPERTY:
        if ((NULL == pIrp->AssociatedIrp.SystemBuffer) ||
            (cbInputBufferLength < RTL_SIZEOF_THROUGH_FIELD(STORAGE_PROPERTY_QUERY,
                                                            PropertyId)))
        {
            uxen_debug("Invalid IOCTL_STORAGE_QUERY_PROPERTY params: "
                       "sys_buf:0x%p, in_buf_len:0x%x\n",
                       pIrp->AssociatedIrp.SystemBuffer, cbInputBufferLength);
            break;
        }

        if (NULL != g_storfltCtx.pStorageDevDesc) {
            PSTORAGE_PROPERTY_QUERY pQuery =
                (PSTORAGE_PROPERTY_QUERY)pIrp->AssociatedIrp.SystemBuffer;
                 
            if (StorageDeviceProperty == pQuery->PropertyId) {
                if (cbOutputBufferLength < g_storfltCtx.cbStorageDevDescSize) {
                    status = STATUS_INFO_LENGTH_MISMATCH;
                    pIrp->IoStatus.Status = status;
                    pIrp->IoStatus.Information = g_storfltCtx.cbStorageDevDescSize;
                    IoCompleteRequest(pIrp, IO_NO_INCREMENT);
                    
                    goto out;
                } else {
                    RtlCopyMemory(pIrp->AssociatedIrp.SystemBuffer,
                                  g_storfltCtx.pStorageDevDesc,
                                  g_storfltCtx.cbStorageDevDescSize);
                    pIrp->IoStatus.Status = STATUS_SUCCESS;
                    pIrp->IoStatus.Information = g_storfltCtx.cbStorageDevDescSize;
                    IoCompleteRequest(pIrp, IO_NO_INCREMENT);
                    
                    goto out;
                }

                goto out;
            }
        }
        break;
    }

    IoSkipCurrentIrpStackLocation(pIrp);
    status = IoCallDriver(pDevExt->pNextLowerDriver, pIrp);
    IoReleaseRemoveLock(&pDevExt->removeLock, pIrp); 

  out:

    return status;
}

#ifdef SMART_RCV_MONITORING_ENABLED
NTSTATUS StorfltSmartCompletionRoutine(
    __in PDEVICE_OBJECT pDevObj,
    __in PIRP pIrp,
    __in PVOID pCtx)
{
    PDEVICE_EXTENSION pDevExt = pDevObj->DeviceExtension;

    UNREFERENCED_PARAMETER(pCtx);

    if (pIrp->PendingReturned) {
        IoMarkIrpPending(pIrp);
    }

    if (NT_SUCCESS(pIrp->IoStatus.Status)) {
        uxen_debug("Dumping ATA IDENTIFY_DEVICE bits (0x%p)\n", pIrp);
        if (pIrp->IoStatus.Information >= 20 + 20) {
            uxen_debug("serial:\n");
            StorfltLogHex((char*)pIrp->AssociatedIrp.SystemBuffer + 20, 20);
        }
        if (pIrp->IoStatus.Information >= 46 + 8) {
            uxen_debug("version:\n");
            StorfltLogHex((char*)pIrp->AssociatedIrp.SystemBuffer + 46, 8);
        }
        if (pIrp->IoStatus.Information >= 54 + 40) {
            uxen_debug("model:\n");
            StorfltLogHex((char*)pIrp->AssociatedIrp.SystemBuffer + 54, 40);
        }
    }

    IoReleaseRemoveLock(&pDevExt->removeLock, pIrp); 

    return STATUS_CONTINUE_COMPLETION;
}
#endif /* SMART_RCV_MONITORING_ENABLED */

NTSTATUS StroportDispatchPassThru(
    __in PDEVICE_OBJECT pDevObj,
    __inout PIRP pIrp)
{
    NTSTATUS status = STATUS_UNSUCCESSFUL;
    PDEVICE_EXTENSION pDevExt = NULL;

    ASSERT(NULL != pDevObj);
    ASSERT(NULL != pIrp);
    
    pDevExt = (PDEVICE_EXTENSION)pDevObj->DeviceExtension;
    status = IoAcquireRemoveLock(&pDevExt->removeLock, pIrp);
    if (!NT_SUCCESS(status)) {
        pIrp->IoStatus.Status = status;
        IoCompleteRequest(pIrp, IO_NO_INCREMENT);
        goto out;
    }

    IoSkipCurrentIrpStackLocation(pIrp);
    status = IoCallDriver(pDevExt->pNextLowerDriver, pIrp);
    
    IoReleaseRemoveLock(&pDevExt->removeLock, pIrp); 

  out:

    return status;
}

NTSTATUS StorfltDispatchPnp(
    __in PDEVICE_OBJECT pDevObj,
    __inout PIRP pIrp)
{
    NTSTATUS status = STATUS_UNSUCCESSFUL;
    PDEVICE_EXTENSION pDevExt = NULL;
    PIO_STACK_LOCATION pIoStack = NULL;
    KEVENT event;

    ASSERT(NULL != pDevObj);
    ASSERT(NULL != pIrp);

    pDevExt = (PDEVICE_EXTENSION)pDevObj->DeviceExtension;
    pIoStack = IoGetCurrentIrpStackLocation(pIrp);

    status = IoAcquireRemoveLock(&pDevExt->removeLock, pIrp);
    if (!NT_SUCCESS(status)) {
        pIrp->IoStatus.Status = status;
        IoCompleteRequest(pIrp, IO_NO_INCREMENT);
        goto out;
    }

    switch (pIoStack->MinorFunction) {
    case IRP_MN_START_DEVICE:
        KeInitializeEvent(&event, NotificationEvent, FALSE);

        uxen_msg("IRP_MN_START_DEVICE begin");

        IoCopyCurrentIrpStackLocationToNext(pIrp);
        IoSetCompletionRoutine(pIrp,
                               StorfltStartDeviceCompletionRoutine,
                               &event,
                               TRUE,
                               TRUE,
                               TRUE);

        status = IoCallDriver(pDevExt->pNextLowerDriver, pIrp);

        if (STATUS_PENDING == status) {
           KeWaitForSingleObject(&event, Executive, KernelMode, FALSE, NULL);          
           status = pIrp->IoStatus.Status;
        }

        if (NT_SUCCESS(status)) {
            if (pDevExt->pNextLowerDriver->Characteristics & FILE_REMOVABLE_MEDIA) {
                pDevObj->Characteristics |= FILE_REMOVABLE_MEDIA;
            }
        }
        
        pIrp->IoStatus.Status = status;
        IoCompleteRequest(pIrp, IO_NO_INCREMENT);
        IoReleaseRemoveLock(&pDevExt->removeLock, pIrp); 

        uxen_msg("IRP_MN_START_DEVICE end");
        goto out;

    case IRP_MN_REMOVE_DEVICE:
        uxen_msg("IRP_MN_REMOVE_DEVICE begin");

        IoReleaseRemoveLockAndWait(&pDevExt->removeLock, pIrp);

        IoSkipCurrentIrpStackLocation(pIrp);

        status = IoCallDriver(pDevExt->pNextLowerDriver, pIrp);

        IoDetachDevice(pDevExt->pNextLowerDriver);
        IoDeleteDevice(pDevObj);

        uxen_msg("IRP_MN_REMOVE_DEVICE end");
        goto out;

    case IRP_MN_DEVICE_USAGE_NOTIFICATION:
        if ((NULL == pDevObj->AttachedDevice) ||
            (pDevObj->AttachedDevice->Flags & DO_POWER_PAGABLE))
        {
            pDevObj->Flags |= DO_POWER_PAGABLE;
        }

        IoCopyCurrentIrpStackLocationToNext(pIrp);
        IoSetCompletionRoutine(pIrp,
                               StorfltDeviceUsageNotificationCompletionRoutine,
                               NULL,
                               TRUE, TRUE, TRUE);
        status = IoCallDriver(pDevExt->pNextLowerDriver, pIrp);

        goto out;

    case IRP_MN_QUERY_STOP_DEVICE:
    case IRP_MN_CANCEL_STOP_DEVICE:
    case IRP_MN_STOP_DEVICE:
    case IRP_MN_QUERY_REMOVE_DEVICE:
    case IRP_MN_SURPRISE_REMOVAL:
        uxen_msg("PNP request: 0x%x", pIoStack->MinorFunction);
        status = STATUS_SUCCESS;
        break;

    default:
        status = pIrp->IoStatus.Status;
        break;
    }

    pIrp->IoStatus.Status = status;
    IoSkipCurrentIrpStackLocation(pIrp);
    status = IoCallDriver(pDevExt->pNextLowerDriver, pIrp);

    IoReleaseRemoveLock(&pDevExt->removeLock, pIrp);

  out:

    return status;
}

NTSTATUS StorfltStartDeviceCompletionRoutine(
    __in PDEVICE_OBJECT pDevObj,
    __in PIRP pIrp,
    __in PVOID pCtx)
{
    PKEVENT pEvent = NULL;

    UNREFERENCED_PARAMETER(pDevObj);

    ASSERT(NULL != pIrp);
    ASSERT(NULL != pCtx);

    uxen_msg("called");

    pEvent = (PKEVENT)pCtx;
    if (pIrp->PendingReturned) {
        KeSetEvent(pEvent, IO_NO_INCREMENT, FALSE);
    }

    return STATUS_MORE_PROCESSING_REQUIRED;
}

NTSTATUS StorfltDeviceUsageNotificationCompletionRoutine(
    __in PDEVICE_OBJECT pDevObj,
    __in PIRP pIrp,
    __in PVOID pCtx)
{
    PDEVICE_EXTENSION pDevExt = NULL;

    UNREFERENCED_PARAMETER(pCtx);

    ASSERT(NULL != pDevObj);
    ASSERT(NULL != pIrp);

    pDevExt = (PDEVICE_EXTENSION)pDevObj->DeviceExtension;

    if (pIrp->PendingReturned) {
        IoMarkIrpPending(pIrp);
    }

    if (!(pDevExt->pNextLowerDriver->Flags & DO_POWER_PAGABLE)) {
        pDevObj->Flags &= ~DO_POWER_PAGABLE;
    }

    IoReleaseRemoveLock(&pDevExt->removeLock, pIrp); 

    return STATUS_CONTINUE_COMPLETION;
}

NTSTATUS StorfltDispatchPower(
    __in PDEVICE_OBJECT pDevObj,
    __inout PIRP pIrp)
{
    PDEVICE_EXTENSION pDevExt = NULL;
    NTSTATUS status = STATUS_UNSUCCESSFUL;

    ASSERT(NULL != pDevObj);
    ASSERT(NULL != pIrp);

    uxen_debug("called");
    
    pDevExt = (PDEVICE_EXTENSION)pDevObj->DeviceExtension;
    status = IoAcquireRemoveLock(&pDevExt->removeLock, pIrp);
    if (!NT_SUCCESS(status)) {
        pIrp->IoStatus.Status = status;
        PoStartNextPowerIrp(pIrp);
        IoCompleteRequest(pIrp, IO_NO_INCREMENT);
        goto out;
    }

    PoStartNextPowerIrp(pIrp);
    IoSkipCurrentIrpStackLocation(pIrp);
    status = PoCallDriver(pDevExt->pNextLowerDriver, pIrp);

    IoReleaseRemoveLock(&pDevExt->removeLock, pIrp); 

  out:

    return status;
}
