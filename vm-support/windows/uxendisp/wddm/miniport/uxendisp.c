/*
 * Copyright 2015, Bromium, Inc.
 * Author: Julian Pidancet <julian@pidancet.net>
 * SPDX-License-Identifier: ISC
 */

#include <ntddk.h>
#include <ntstrsafe.h>
#include <dispmprt.h>
#include <dderror.h>
#include <devioctl.h>

#include <debug.h>

#include "uxendisp.h"
#include "version.h"

NTSTATUS APIENTRY
uXenDispAddDevice(CONST PDEVICE_OBJECT pPhysicalDeviceObject,
                  PVOID *ppMiniportDeviceContext);
NTSTATUS APIENTRY
uXenDispStartDevice(CONST PVOID pMiniportDeviceContext,
                    PDXGK_START_INFO pDxgkStartInfo,
                    PDXGKRNL_INTERFACE pDxgkInterface,
                    PULONG pNumberOfViews,
                    PULONG pNumberOfChildren);
NTSTATUS APIENTRY
uXenDispStopDevice(CONST PVOID pMiniportDeviceContext);
NTSTATUS APIENTRY
uXenDispRemoveDevice(CONST PVOID pMiniportDeviceContext);
NTSTATUS APIENTRY
uXenDispDispatchIoRequest(CONST PVOID pMiniportDeviceContext,
                          ULONG ViewIndex,
                          PVIDEO_REQUEST_PACKET pVideoRequestPacket);
NTSTATUS APIENTRY
uXenDispQueryChildRelations(CONST PVOID pMiniportDeviceContext,
                            PDXGK_CHILD_DESCRIPTOR pChildRelations,
                            ULONG ChildRelationsSize);
NTSTATUS APIENTRY
uXenDispQueryChildStatus(CONST PVOID pMiniportDeviceContext,
                         PDXGK_CHILD_STATUS pChildStatus,
                         BOOLEAN NonDestructiveOnly);
NTSTATUS APIENTRY
uXenDispQueryDeviceDescriptor(CONST PVOID pMiniportDeviceContext,
                              ULONG ChildUid,
                              PDXGK_DEVICE_DESCRIPTOR pDeviceDescriptor);
NTSTATUS APIENTRY
uXenDispSetPowerState(CONST PVOID pMiniportDeviceContext,
                      ULONG HardwareUid,
                      DEVICE_POWER_STATE DevicePowerState,
                      POWER_ACTION ActionType);
VOID APIENTRY
uXenDispUnload(VOID);
NTSTATUS APIENTRY
uXenDispQueryInterface(CONST PVOID pMiniportDeviceContext,
                       PQUERY_INTERFACE pQueryInterface);
NTSTATUS
DriverEntry(PDRIVER_OBJECT pDriverObject,
            PUNICODE_STRING pRegistryPath);


#ifdef ALLOC_PRAGMA
#pragma alloc_text(PAGE,uXenDispAddDevice)
#pragma alloc_text(PAGE,uXenDispStartDevice)
#pragma alloc_text(PAGE,uXenDispStopDevice)
#pragma alloc_text(PAGE,uXenDispRemoveDevice)
#pragma alloc_text(PAGE,uXenDispDispatchIoRequest)
#pragma alloc_text(PAGE,uXenDispQueryChildRelations)
#pragma alloc_text(PAGE,uXenDispQueryChildStatus)
#pragma alloc_text(PAGE,uXenDispQueryDeviceDescriptor)
#pragma alloc_text(PAGE,uXenDispSetPowerState)
#pragma alloc_text(PAGE,uXenDispUnload)
#pragma alloc_text(PAGE,uXenDispQueryInterface)
#pragma alloc_text(INIT,DriverEntry)
#endif

NTSTATUS APIENTRY
uXenDispAddDevice(CONST PDEVICE_OBJECT pPhysicalDeviceObject,
                  PVOID *ppMiniportDeviceContext)
{
    DEVICE_EXTENSION *dev;

    PAGED_CODE();
    uxen_msg("Enter");

    if (!ARGUMENT_PRESENT(pPhysicalDeviceObject) ||
        !ARGUMENT_PRESENT(ppMiniportDeviceContext))
        return STATUS_INVALID_PARAMETER;

    dev = ExAllocatePoolWithTag(NonPagedPool, sizeof(DEVICE_EXTENSION),
                                UXENDISP_TAG);

    if (!dev)
        return STATUS_INSUFFICIENT_RESOURCES;

    RtlZeroMemory(dev, sizeof(DEVICE_EXTENSION));

    *ppMiniportDeviceContext = dev;

    uxen_msg("Leave");
    return STATUS_SUCCESS;
}

static void
uXenDispFreeResources(DEVICE_EXTENSION *dev)
{
    ULONG i;
    uxen_msg("Enter");

    for (i = 0; i < dev->crtc_count; i++) {
        UXENDISP_CRTC *crtc = &dev->crtcs[i];

        if (crtc->edid)
            ExFreePoolWithTag(crtc->edid, UXENDISP_TAG);
    }
    if (i)
        ExFreePoolWithTag(dev->crtcs, UXENDISP_TAG);
    ExFreePoolWithTag(dev->sources, UXENDISP_TAG);
    if (dev->mmio)
        MmUnmapIoSpace(dev->mmio, dev->mmio_len);
    dev->pdo = NULL;
    dev->dxgkhdl = NULL;
    uxen_msg("Leave");
}

static void
ChildStatusChangeDpc(KDPC *dpc,
                     VOID *deferred_context,
                     VOID *system_argument1,
                     VOID *system_argument2)
{
    DEVICE_EXTENSION *dev = deferred_context;;
    uxen_msg("Enter");

    UNREFERENCED_PARAMETER(dpc);
    UNREFERENCED_PARAMETER(system_argument1);
    UNREFERENCED_PARAMETER(system_argument2);

    uXenDispDetectChildStatusChanges(dev);
    uxen_msg("Leave");
}

NTSTATUS APIENTRY
uXenDispStartDevice(CONST PVOID pMiniportDeviceContext,
                    PDXGK_START_INFO pDxgkStartInfo,
                    PDXGKRNL_INTERFACE pDxgkInterface,
                    PULONG pNumberOfVideoPresentSources,
                    PULONG pNumberOfChildren)
{
    DEVICE_EXTENSION *dev = pMiniportDeviceContext;
    DXGK_DEVICE_INFO DeviceInfo;
    NTSTATUS status;
    PCM_PARTIAL_RESOURCE_DESCRIPTOR pPRList;
    ULONG c, i, Magic, Rev;
    ULONG memres_index = 0;
    PAGED_CODE();
    uxen_msg("Enter");

    if (!ARGUMENT_PRESENT(pMiniportDeviceContext) ||
        !ARGUMENT_PRESENT(pDxgkStartInfo) ||
        !ARGUMENT_PRESENT(pDxgkInterface) ||
        !ARGUMENT_PRESENT(pNumberOfVideoPresentSources) ||
        !ARGUMENT_PRESENT(pNumberOfChildren))
        return STATUS_INVALID_PARAMETER;

    dev->dxgkhdl = pDxgkInterface->DeviceHandle;
    RtlCopyMemory(&dev->dxgksi, pDxgkStartInfo, sizeof(DXGK_START_INFO));
    RtlCopyMemory(&dev->dxgkif, pDxgkInterface, sizeof(DXGKRNL_INTERFACE));

    status = dev->dxgkif.DxgkCbGetDeviceInformation(dev->dxgkhdl, &DeviceInfo);
    if (!NT_SUCCESS(status)) {
        uxen_err("DlGetDeviceInformation() failed - error: 0x%x", status);
        return status;
    }
    dev->pdo = DeviceInfo.PhysicalDeviceObject;

    /*
     * Get the translated hardware resources.
     * There should be one full resource list entry
     * for the PCI bus where uxendisp is located.
     */
    if (DeviceInfo.TranslatedResourceList->Count != 1) {
        uxen_err("TranslatedResourceList->Count == %d, expected 1??",
                 DeviceInfo.TranslatedResourceList->Count);
        uXenDispFreeResources(dev);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    if (!DeviceInfo.TranslatedResourceList->List[0].PartialResourceList.Count) {
        uxen_err("TranslatedResourceList->List[0].PartialResourceList.Count == 0, expected > 0??");
        uXenDispFreeResources(dev);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    c = DeviceInfo.TranslatedResourceList->List[0].PartialResourceList.Count;
    pPRList = &DeviceInfo.TranslatedResourceList->List[0].PartialResourceList.PartialDescriptors[0];
    for (i = 0; i < c; i++, pPRList++) {
        switch (pPRList->Type) {
        case CmResourceTypeMemory:
            switch (memres_index) {
            case 0: /* VRAM */
                dev->vram_phys = pPRList->u.Memory.Start;
                dev->vram_len = pPRList->u.Memory.Length;
                break;
            case 1: /* MMIO regs */
                dev->mmio_phys = pPRList->u.Memory.Start;
                dev->mmio_len = pPRList->u.Memory.Length;
                break;
            default:
                break;
            }
            memres_index++;
            break;
        case CmResourceTypeInterrupt:
            /* The interrupt is hooked up by the DirectX framework for us. */
            break;
        case CmResourceTypePort:
            /* This is a Port I/O resource for accessing the MMIO registers via PIO. */
        default:
            break;
        }
    }

    dev->mmio = MmMapIoSpace(dev->mmio_phys, dev->mmio_len, MmNonCached);
    if (!dev->mmio) {
        uxen_err("MmMapIoSpace(MMIO register range) failed!");
        uXenDispFreeResources(dev);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    if (uxdisp_read(dev, UXDISP_REG_MAGIC) != UXDISP_MAGIC) {
        uxen_err("Invalid Magic");
        uXenDispFreeResources(dev);
        return STATUS_INVALID_PARAMETER;
    }

    dev->crtc_count = uxdisp_read(dev, UXDISP_REG_CRTC_COUNT);

    KeInitializeSpinLock(&dev->crtc_lock);

    dev->crtcs = ExAllocatePoolWithTag(NonPagedPool,
                                       dev->crtc_count * sizeof(UXENDISP_CRTC),
                                       UXENDISP_TAG);
    if (!dev->crtcs) {
        uXenDispFreeResources(dev);
        return STATUS_NO_MEMORY;
    }
    for (i = 0; i < dev->crtc_count; i++) {
        UXENDISP_CRTC *crtc = &dev->crtcs[i];

        crtc->crtcid = i;
        crtc->connected = FALSE;
        crtc->edid_len = 0;
        crtc->edid = NULL;
        crtc->mode_set = NULL;
        crtc->sourceid = D3DDDI_ID_UNINITIALIZED;
        crtc->staged_modeidx = -1;
        crtc->staged_sourceid = D3DDDI_ID_UNINITIALIZED;
        crtc->staged_fmt = -1;
        crtc->staged_flags = 0;
    }

    /*
     * This sets up the set of VidPN sources which will later be
     * identified by 0..(N-1) where N = dev->crtc_count
     */
    *pNumberOfVideoPresentSources = dev->crtc_count;
    *pNumberOfChildren = dev->crtc_count;
    dev->sources = ExAllocatePoolWithTag(NonPagedPool,
                                         dev->crtc_count * sizeof(UXENDISP_SOURCE),
                                         UXENDISP_TAG);
    if (!dev->sources) {
        uxen_err("%s Failed to allocate Sources array!");
        uXenDispFreeResources(dev);
        return STATUS_NO_MEMORY;
    }
    RtlZeroMemory(dev->sources, dev->crtc_count * sizeof(UXENDISP_SOURCE));
    KeInitializeSpinLock(&dev->sources_lock);

    KeInitializeDpc(&dev->child_status_dpc,
                    ChildStatusChangeDpc,
                    dev);

    /* Device is up, switch to initialized */
    InterlockedExchange(&dev->initialized, 1);

    /* Enable interrupts and switch off VGA mode */
    uxdisp_write(dev, UXDISP_REG_MODE, UXDISP_MODE_VGA_DISABLED);

    /* Configure all the child devices once up front. */
    uXenDispDetectChildStatusChanges(dev);
    uxen_msg("Leave");

    return STATUS_SUCCESS;
}

NTSTATUS APIENTRY
uXenDispStopDevice(CONST PVOID pMiniportDeviceContext)
{
    DEVICE_EXTENSION *dev = pMiniportDeviceContext;

    PAGED_CODE();
    uxen_msg("Enter");

    if (!ARGUMENT_PRESENT(pMiniportDeviceContext))
        return STATUS_INVALID_PARAMETER;

    /* Device stopped, switch to uninitialized */
    InterlockedExchange(&dev->initialized, 0);

    /* Disable the interrupt and switch back to VGA mode */
    uxdisp_write(dev, UXDISP_REG_MODE, 0);

    /* Free all resources allocated in start routine */
    uXenDispFreeResources(dev);

    /* Clear any remaining state */
    RtlZeroMemory(dev, sizeof(DEVICE_EXTENSION));

    uxen_msg("Leave");
    return STATUS_SUCCESS;
}

NTSTATUS APIENTRY
uXenDispRemoveDevice(CONST PVOID pMiniportDeviceContext)
{
    PAGED_CODE();
    uxen_msg("Enter");

    if (!ARGUMENT_PRESENT(pMiniportDeviceContext))
        return STATUS_INVALID_PARAMETER;

    ExFreePoolWithTag(pMiniportDeviceContext, UXENDISP_TAG);

    uxen_msg("Leave");
    return STATUS_SUCCESS;
}

NTSTATUS APIENTRY
uXenDispDispatchIoRequest(CONST PVOID pMiniportDeviceContext,
                          ULONG ViewIndex,
                          PVIDEO_REQUEST_PACKET pVideoRequestPacket)
{
    PAGED_CODE();
    uxen_msg("Leave");

    if (!ARGUMENT_PRESENT(pMiniportDeviceContext) ||
        !ARGUMENT_PRESENT(pVideoRequestPacket)||
        (ViewIndex > 0)) {
        return STATUS_INVALID_PARAMETER;
    }

    pVideoRequestPacket->StatusBlock->Status = ERROR_INVALID_FUNCTION;

    /* Only IOCTL_VIDEO_QUERY_COLOR_CAPABILITIES and IOCTL_VIDEO_HANDLE_VIDEOPARAMETERS  */
    /* are used - no support for either. */

    uxen_msg("Leave");
    return STATUS_UNSUCCESSFUL;
}

BOOLEAN APIENTRY
uXenDispInterruptRoutine(CONST PVOID pMiniportDeviceContext,
                         ULONG MessageNumber)
{
    DEVICE_EXTENSION *dev = pMiniportDeviceContext;
    ULONG isr;
    BOOLEAN handled = FALSE;

    UNREFERENCED_PARAMETER(MessageNumber); /* line-based IRQ */
    uxen_msg("Enter");

    if (!ARGUMENT_PRESENT(pMiniportDeviceContext))
        return FALSE;

    if (!InterlockedExchangeAdd(&dev->initialized, 0))
        return FALSE;

    isr = uxdisp_read(dev, UXDISP_REG_INTERRUPT);
    if (isr & UXDISP_INTERRUPT_HOTPLUG) {
        uxdisp_write(dev, UXDISP_REG_INTERRUPT, UXDISP_INTERRUPT_HOTPLUG);
        KeInsertQueueDpc(&dev->child_status_dpc, NULL, NULL);
        handled = TRUE;
    }
    if (isr & UXDISP_INTERRUPT_VBLANK) {
        uxdisp_write(dev, UXDISP_REG_INTERRUPT, UXDISP_INTERRUPT_VBLANK);
#if 0
        ULONG i;
        DXGKARGCB_NOTIFY_INTERRUPT_DATA NotifyInt = {0};

        NotifyInt.InterruptType = DXGK_INTERRUPT_CRTC_VSYNC;
        NotifyInt.CrtcVsync.VidPnTargetId = pCrtc->VidPnTargetId;
        NotifyInt.CrtcVsync.PhysicalAddress = dev->GraphicsApertureDescriptor.u.Memory.Start;
        NotifyInt.CrtcVsync.PhysicalAddress.QuadPart += pCrtc->PrimaryAddress.QuadPart;
        NotifyInt.CrtcVsync.PhysicalAdapterMask = 0;
        dev->dxgkif.DxgkCbNotifyInterrupt(dev->dxgkhdl, &NotifyInt);
        dev->dxgkif.DxgkCbQueueDpc(dev->dxgkhdl);
#endif
        handled = TRUE;
    }
    uxen_msg("Leave");

    return handled;
}

VOID APIENTRY
uXenDispDpcRoutine(CONST PVOID pMiniportDeviceContext)
{
    DEVICE_EXTENSION *dev = pMiniportDeviceContext;
    uxen_msg("Enter");

    /* The DDI DPC is used to ACK DMA and V-Sync interrupts are fully serviced. */
    dev->dxgkif.DxgkCbNotifyDpc(dev->dxgkhdl);

    uxen_msg("Leave");
}

NTSTATUS APIENTRY
uXenDispQueryChildRelations(CONST PVOID pMiniportDeviceContext,
                            PDXGK_CHILD_DESCRIPTOR pChildRelations,
                            ULONG ChildRelationsSize)
{
    DEVICE_EXTENSION *dev = pMiniportDeviceContext;
    ULONG i;

    PAGED_CODE();
    uxen_msg("Enter");

    if (ChildRelationsSize <= (dev->crtc_count * sizeof(PDXGK_CHILD_DESCRIPTOR)))
        return STATUS_BUFFER_TOO_SMALL;

    /*
     * This sets up the set of VidPN targets which will later be
     * identified by the ChildUid. Since there will be a 1 - 1
     * mapping of source->CRTC->target, the target and source IDs
     * used in the VidPN will range from 0 to dev->crtc_count also.
     * N.B. hopefully specifying VGA will not make the directx
     * kernel think we do not generate hotplug interrupts.
     */
    for (i = 0; i < dev->crtc_count; i++) {
        pChildRelations[i].AcpiUid = 0;
        pChildRelations[i].ChildUid = i;
        pChildRelations[i].ChildDeviceType = TypeVideoOutput;
        pChildRelations[i].ChildCapabilities.HpdAwareness = HpdAwarenessInterruptible;
        pChildRelations[i].ChildCapabilities.Type.VideoOutput.InterfaceTechnology = D3DKMDT_VOT_HD15;
        pChildRelations[i].ChildCapabilities.Type.VideoOutput.MonitorOrientationAwareness = D3DKMDT_MOA_NONE;
        pChildRelations[i].ChildCapabilities.Type.VideoOutput.SupportsSdtvModes = FALSE;
    }

    uxen_msg("Leave");
    return STATUS_SUCCESS;
}

NTSTATUS APIENTRY
uXenDispQueryChildStatus(CONST PVOID pMiniportDeviceContext,
                         PDXGK_CHILD_STATUS pChildStatus,
                         BOOLEAN NonDestructiveOnly)
{
    DEVICE_EXTENSION *dev = pMiniportDeviceContext;
    UXENDISP_CRTC *crtc;

    PAGED_CODE();
    uxen_msg("Enter");

    if (!ARGUMENT_PRESENT(pMiniportDeviceContext) ||
        !ARGUMENT_PRESENT(pChildStatus))
        return STATUS_INVALID_PARAMETER;

    UNREFERENCED_PARAMETER(NonDestructiveOnly); /* We cause no destruction */

    if (pChildStatus->ChildUid >= dev->crtc_count) {
        uxen_err("Invalid ChildUid specified: %d", pChildStatus->ChildUid);
        return STATUS_INVALID_PARAMETER;
    }

    switch (pChildStatus->Type) {
    case StatusConnection:
        crtc = &dev->crtcs[pChildStatus->ChildUid];
        pChildStatus->HotPlug.Connected = crtc->connected;
        break;
    case StatusRotation:
        pChildStatus->Rotation.Angle = 0;
        break;
    default:
        uxen_msg("Invalid ChildStatus type: %d", pChildStatus->Type);
        break;
    };

    uxen_msg("Leave");
    return STATUS_SUCCESS;
}

static NTSTATUS
uXenDispGetChildDescriptor(PDEVICE_EXTENSION dev,
                           PUXENDISP_CRTC crtc,
                           PDXGK_DEVICE_DESCRIPTOR pDeviceDescriptor)
{
    KIRQL       irql;
    NTSTATUS    status;
    ULONG       to_copy;

    uxen_msg("Enter");
    KeAcquireSpinLock(&dev->crtc_lock, &irql);

    do {
        status = STATUS_MONITOR_NO_MORE_DESCRIPTOR_DATA;

        if (pDeviceDescriptor->DescriptorOffset >= crtc->edid_len)
            break;

        if (!pDeviceDescriptor->DescriptorLength)
            break;

        to_copy = crtc->edid_len - pDeviceDescriptor->DescriptorOffset;
        if (to_copy > pDeviceDescriptor->DescriptorLength)
            to_copy = pDeviceDescriptor->DescriptorLength;

        /* Valid hunk of descriptor requested */
        RtlMoveMemory(pDeviceDescriptor->DescriptorBuffer,
                      ((UCHAR *)crtc->edid) + pDeviceDescriptor->DescriptorOffset,
                      to_copy);

        status = STATUS_SUCCESS;
    } while (FALSE);

    KeReleaseSpinLock(&dev->crtc_lock, irql);
    uxen_msg("Leave");

    return status;
}

NTSTATUS APIENTRY
uXenDispQueryDeviceDescriptor(CONST PVOID pMiniportDeviceContext,
                              ULONG ChildUid,
                              PDXGK_DEVICE_DESCRIPTOR pDeviceDescriptor)
{
    DEVICE_EXTENSION *dev = pMiniportDeviceContext;
    UXENDISP_CRTC *crtc;
    NTSTATUS status;

    PAGED_CODE();
    uxen_msg("Enter");

    /* These failures should not occur */
    if (!ARGUMENT_PRESENT(pMiniportDeviceContext) ||
        !ARGUMENT_PRESENT(pDeviceDescriptor))
        return STATUS_INVALID_PARAMETER;

    if (ChildUid >= dev->crtc_count) {
        uxen_err("Invalid ChildUid specified: %d", ChildUid);
        return STATUS_INVALID_PARAMETER;
    }

    crtc = &dev->crtcs[ChildUid];
    status = uXenDispGetChildDescriptor(dev, crtc, pDeviceDescriptor);
    uxen_msg("Leave");

    return status;
}

NTSTATUS APIENTRY
uXenDispSetPowerState(CONST PVOID pMiniportDeviceContext,
                      ULONG HardwareUid,
                      DEVICE_POWER_STATE DevicePowerState,
                      POWER_ACTION ActionType)
{
    UNREFERENCED_PARAMETER(pMiniportDeviceContext);

    PAGED_CODE();
    uxen_msg("Enter");

    uxen_debug("HW UID: %d DEVICE_POWER_STATE: %d POWER_ACTION: %d",
               HardwareUid, DevicePowerState, ActionType);

    uxen_msg("Leave");
    return STATUS_SUCCESS;
}

VOID APIENTRY
uXenDispResetDevice(CONST PVOID pMiniportDeviceContext)
{
    DEVICE_EXTENSION *dev = pMiniportDeviceContext;

    uxen_msg("Enter");
    /* Disable the interrupt and switch back to VGA mode */
    uxdisp_write(dev, UXDISP_REG_MODE, 0);
    uxen_msg("Leave");
}

VOID APIENTRY
uXenDispUnload(VOID)
{
    PAGED_CODE();
    uxen_msg("Enter");

    uxen_msg("Leave");
    /* Nothing to do */
}

NTSTATUS APIENTRY
uXenDispQueryInterface(CONST PVOID pMiniportDeviceContext,
                       PQUERY_INTERFACE pQueryInterface)
{
    UNREFERENCED_PARAMETER(pMiniportDeviceContext);
    UNREFERENCED_PARAMETER(pQueryInterface);
    PAGED_CODE();

    uxen_msg("Enter");
    uxen_msg("Leave");
    return STATUS_NOT_SUPPORTED;
}

NTSTATUS
DriverEntry(PDRIVER_OBJECT pDriverObject, PUNICODE_STRING pRegistryPath)
{
    DRIVER_INITIALIZATION_DATA DriverInitializationData = {0};
    uxen_msg("Enter version: %s", UXEN_DRIVER_VERSION_CHANGESET);

    DriverInitializationData.Version                                = DXGKDDI_INTERFACE_VERSION;

    /* Miniport */
    DriverInitializationData.DxgkDdiAddDevice                       = uXenDispAddDevice;
    DriverInitializationData.DxgkDdiStartDevice                     = uXenDispStartDevice;
    DriverInitializationData.DxgkDdiStopDevice                      = uXenDispStopDevice;
    DriverInitializationData.DxgkDdiRemoveDevice                    = uXenDispRemoveDevice;
    DriverInitializationData.DxgkDdiDispatchIoRequest               = uXenDispDispatchIoRequest;
    DriverInitializationData.DxgkDdiInterruptRoutine                = uXenDispInterruptRoutine;
    DriverInitializationData.DxgkDdiDpcRoutine                      = uXenDispDpcRoutine;
    DriverInitializationData.DxgkDdiQueryChildRelations             = uXenDispQueryChildRelations;
    DriverInitializationData.DxgkDdiQueryChildStatus                = uXenDispQueryChildStatus;
    DriverInitializationData.DxgkDdiQueryDeviceDescriptor           = uXenDispQueryDeviceDescriptor;
    DriverInitializationData.DxgkDdiSetPowerState                   = uXenDispSetPowerState;
    DriverInitializationData.DxgkDdiNotifyAcpiEvent                 = NULL; /* optional, not currently used */
    DriverInitializationData.DxgkDdiResetDevice                     = uXenDispResetDevice;
    DriverInitializationData.DxgkDdiUnload                          = uXenDispUnload;
    DriverInitializationData.DxgkDdiQueryInterface                  = uXenDispQueryInterface;
    /* DDI */
    DriverInitializationData.DxgkDdiControlEtwLogging               = uXenDispControlEtwLogging;
    DriverInitializationData.DxgkDdiQueryAdapterInfo                = uXenDispQueryAdapterInfo;
    DriverInitializationData.DxgkDdiCreateDevice                    = uXenDispCreateDevice;
    DriverInitializationData.DxgkDdiCreateAllocation                = uXenDispCreateAllocation;
    DriverInitializationData.DxgkDdiDestroyAllocation               = uXenDispDestroyAllocation;
    DriverInitializationData.DxgkDdiDescribeAllocation              = uXenDispDescribeAllocation;
    DriverInitializationData.DxgkDdiGetStandardAllocationDriverData = uXenDispGetStandardAllocationDriverData;
    DriverInitializationData.DxgkDdiAcquireSwizzlingRange           = uXenDispAcquireSwizzlingRange;
    DriverInitializationData.DxgkDdiReleaseSwizzlingRange           = uXenDispReleaseSwizzlingRange;
    DriverInitializationData.DxgkDdiPatch                           = uXenDispPatch;
    DriverInitializationData.DxgkDdiSubmitCommand                   = uXenDispSubmitCommand;
    DriverInitializationData.DxgkDdiPreemptCommand                  = uXenDispPreemptCommand;
    DriverInitializationData.DxgkDdiBuildPagingBuffer               = uXenDispBuildPagingBuffer;
    DriverInitializationData.DxgkDdiSetPalette                      = uXenDispSetPalette;
    DriverInitializationData.DxgkDdiSetPointerPosition              = uXenDispSetPointerPosition;
    DriverInitializationData.DxgkDdiSetPointerShape                 = uXenDispSetPointerShape;
    DriverInitializationData.DxgkDdiResetFromTimeout                = uXenDispResetFromTimeout;
    DriverInitializationData.DxgkDdiRestartFromTimeout              = uXenDispRestartFromTimeout;
    DriverInitializationData.DxgkDdiEscape                          = uXenDispEscape;
    DriverInitializationData.DxgkDdiCollectDbgInfo                  = uXenDispCollectDbgInfo;
    DriverInitializationData.DxgkDdiQueryCurrentFence               = uXenDispQueryCurrentFence;
    /* VidPn */
    DriverInitializationData.DxgkDdiIsSupportedVidPn                = uXenDispIsSupportedVidPn;
    DriverInitializationData.DxgkDdiRecommendFunctionalVidPn        = uXenDispRecommendFunctionalVidPn;
    DriverInitializationData.DxgkDdiEnumVidPnCofuncModality         = uXenDispEnumVidPnCofuncModality;
    DriverInitializationData.DxgkDdiSetVidPnSourceAddress           = uXenDispSetVidPnSourceAddress;
    DriverInitializationData.DxgkDdiSetVidPnSourceVisibility        = uXenDispSetVidPnSourceVisibility;
    DriverInitializationData.DxgkDdiCommitVidPn                     = uXenDispCommitVidPn;
    DriverInitializationData.DxgkDdiUpdateActiveVidPnPresentPath    = uXenDispUpdateActiveVidPnPresentPath;
    DriverInitializationData.DxgkDdiRecommendMonitorModes           = uXenDispRecommendMonitorModes;
    DriverInitializationData.DxgkDdiRecommendVidPnTopology          = uXenDispRecommendVidPnTopology;
    DriverInitializationData.DxgkDdiGetScanLine                     = uXenDispGetScanLine;
    /* DDI */
    DriverInitializationData.DxgkDdiStopCapture                     = uXenDispStopCapture;
    DriverInitializationData.DxgkDdiControlInterrupt                = uXenDispControlInterrupt;
    DriverInitializationData.DxgkDdiCreateOverlay                   = NULL; /* not supported */
    DriverInitializationData.DxgkDdiDestroyDevice                   = uXenDispDestroyDevice;
    DriverInitializationData.DxgkDdiOpenAllocation                  = uXenDispOpenAllocation;
    DriverInitializationData.DxgkDdiCloseAllocation                 = uXenDispCloseAllocation;
    DriverInitializationData.DxgkDdiRender                          = uXenDispRender;
    DriverInitializationData.DxgkDdiPresent                         = uXenDispPresent;
    DriverInitializationData.DxgkDdiUpdateOverlay                   = NULL; /* not supported */
    DriverInitializationData.DxgkDdiFlipOverlay                     = NULL; /* not supported */
    DriverInitializationData.DxgkDdiDestroyOverlay                  = NULL; /* not supported */
    DriverInitializationData.DxgkDdiCreateContext                   = uXenDispCreateContext;
    DriverInitializationData.DxgkDdiDestroyContext                  = uXenDispDestroyContext;
    DriverInitializationData.DxgkDdiLinkDevice                      = NULL; /* not supported */
    DriverInitializationData.DxgkDdiSetDisplayPrivateDriverFormat   = NULL; /* not supported */

    uxen_msg("Leave");
    return DxgkInitialize(pDriverObject, pRegistryPath, &DriverInitializationData);
}
