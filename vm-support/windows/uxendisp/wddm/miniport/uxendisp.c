/*
 * Copyright 2015, Bromium, Inc.
 * Author: Julian Pidancet <julian@pidancet.net>
 * SPDX-License-Identifier: ISC
 */

#include "uxendisp.h"

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

BOOLEAN g_dod = FALSE;

NTSTATUS APIENTRY
uXenDispAddDevice(CONST PDEVICE_OBJECT pPhysicalDeviceObject,
                  PVOID *ppMiniportDeviceContext)
{
    DEVICE_EXTENSION *dev;

    PAGED_CODE();

    if (!ARGUMENT_PRESENT(pPhysicalDeviceObject) ||
        !ARGUMENT_PRESENT(ppMiniportDeviceContext))
        return STATUS_INVALID_PARAMETER;

    dev = ExAllocatePoolWithTag(NonPagedPool, sizeof(DEVICE_EXTENSION),
                                UXENDISP_TAG);

    if (!dev)
        return STATUS_INSUFFICIENT_RESOURCES;

    RtlZeroMemory(dev, sizeof(DEVICE_EXTENSION));

    *ppMiniportDeviceContext = dev;

    return STATUS_SUCCESS;
}

static void
uXenDispFreeResources(DEVICE_EXTENSION *dev)
{
    if (dev->crtc_count)
        ExFreePoolWithTag(dev->crtcs, UXENDISP_TAG);
    ExFreePoolWithTag(dev->sources, UXENDISP_TAG);
    if (dev->mmio)
        MmUnmapIoSpace(dev->mmio, dev->mmio_len);
    dev->pdo = NULL;
    dev->dxgkhdl = NULL;
}

static VOID
uXenDispCrtcDisablePageTracking(DEVICE_EXTENSION *dev)
{
    ULONG val = uxdisp_read(dev, UXDISP_REG_MODE);
    val |= UXDISP_MODE_PAGE_TRACKING_DISABLED;
    uxdisp_write(dev, UXDISP_REG_MODE, val);
}

static VOID
uXenDispDetectChildStatusChanges(DEVICE_EXTENSION *dev)
{
    KIRQL irql;
    ULONG i;
    DXGK_CHILD_STATUS child_status;

    if (!InterlockedExchangeAdd(&dev->initialized, 0))
        return;

    KeAcquireSpinLock(&dev->crtc_lock, &irql);
    for (i = 0; i < dev->crtc_count; i++) {
        UXENDISP_CRTC *crtc = &dev->crtcs[i];
        ULONG status;

        status = uxdisp_crtc_read(dev, crtc->crtcid, UXDISP_REG_CRTC_STATUS);
        if (status) {
            if (!crtc->connected) {
                child_status.ChildUid = crtc->crtcid;
                child_status.Type = StatusConnection;
                child_status.HotPlug.Connected = TRUE;
                crtc->connected = TRUE;
                dev->dxgkif.DxgkCbIndicateChildStatus(dev->dxgkhdl, &child_status);
            }
        } else {
            if (crtc->connected) {
                child_status.ChildUid = crtc->crtcid;
                child_status.Type = StatusConnection;
                child_status.HotPlug.Connected = FALSE;
                crtc->connected = FALSE;
                dev->dxgkif.DxgkCbIndicateChildStatus(dev->dxgkhdl, &child_status);
            }
        }
    }
    KeReleaseSpinLock(&dev->crtc_lock, irql);
}

static VOID
vsync_routine(KDPC *dpc, PVOID ctx, PVOID unused1, PVOID unused2)
{
    DEVICE_EXTENSION *dev = ctx;
    DXGKARGCB_NOTIFY_INTERRUPT_DATA NotifyInt = {0};
    KIRQL irql;

    NotifyInt.InterruptType = DXGK_INTERRUPT_CRTC_VSYNC;
    NotifyInt.CrtcVsync.VidPnTargetId = 0;
    NotifyInt.CrtcVsync.PhysicalAddress = dev->vram_phys;

    KeRaiseIrql(DISPATCH_LEVEL + 1, &irql);
    dev->dxgkif.DxgkCbNotifyInterrupt(dev->dxgkhdl, &NotifyInt);
    dev->dxgkif.DxgkCbQueueDpc(dev->dxgkhdl);
    KeLowerIrql(irql);
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
    LARGE_INTEGER DueTime = { 0 };
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
        RtlZeroMemory(crtc, sizeof *crtc);

        crtc->crtcid = i;
        crtc->connected = FALSE;
        crtc->sourceid = D3DDDI_ID_UNINITIALIZED;
        crtc->staged_sourceid = D3DDDI_ID_UNINITIALIZED;
        crtc->staged_flags = 0;

        crtc->next_mode.xres = 1024;
        crtc->next_mode.yres = 768;
        crtc->next_mode.stride = 1024 * 4;
        crtc->next_mode.fmt = 0;
        crtc->next_mode.flags = UXENDISP_MODE_FLAG_PREFERRED;
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

    /* Device is up, switch to initialized */
    InterlockedExchange(&dev->initialized, 1);

    /* Enable interrupts and switch off VGA mode */
    uxdisp_write(dev, UXDISP_REG_MODE, UXDISP_MODE_VGA_DISABLED);

    /* Configure all the child devices once up front. */
    uXenDispDetectChildStatusChanges(dev);

    dev->dr_ctx = dr_init(dev, uXenDispCrtcDisablePageTracking);
    if (!dev->dr_ctx) {
        uxen_err("%s Failed to init dirty rect tracking!");
        uXenDispFreeResources(dev);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    KeInitializeDpc(&dev->vsync_dpc, vsync_routine, dev);
    KeInitializeTimerEx(&dev->vsync_timer, SynchronizationTimer);

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

    KeCancelTimer(&dev->vsync_timer);

    dr_deinit(dev->dr_ctx);

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

    if (!ARGUMENT_PRESENT(pMiniportDeviceContext))
        return STATUS_INVALID_PARAMETER;

    ExFreePoolWithTag(pMiniportDeviceContext, UXENDISP_TAG);

    return STATUS_SUCCESS;
}

NTSTATUS APIENTRY
uXenDispDispatchIoRequest(CONST PVOID pMiniportDeviceContext,
                          ULONG ViewIndex,
                          PVIDEO_REQUEST_PACKET pVideoRequestPacket)
{
    PAGED_CODE();

    if (!ARGUMENT_PRESENT(pMiniportDeviceContext) ||
        !ARGUMENT_PRESENT(pVideoRequestPacket)||
        (ViewIndex > 0)) {
        return STATUS_INVALID_PARAMETER;
    }

    pVideoRequestPacket->StatusBlock->Status = ERROR_INVALID_FUNCTION;

    /* Only IOCTL_VIDEO_QUERY_COLOR_CAPABILITIES and IOCTL_VIDEO_HANDLE_VIDEOPARAMETERS  */
    /* are used - no support for either. */

    return STATUS_UNSUCCESSFUL;
}

BOOLEAN APIENTRY
uXenDispInterruptRoutine(CONST PVOID pMiniportDeviceContext,
                         ULONG MessageNumber)
{
    return FALSE;
}

VOID APIENTRY
uXenDispDpcRoutine(CONST PVOID pMiniportDeviceContext)
{
    DEVICE_EXTENSION *dev = pMiniportDeviceContext;

    /* The DDI DPC is used to ACK DMA and V-Sync interrupts are fully serviced. */
    dev->dxgkif.DxgkCbNotifyDpc(dev->dxgkhdl);
}

NTSTATUS APIENTRY
uXenDispQueryChildRelations(CONST PVOID pMiniportDeviceContext,
                            PDXGK_CHILD_DESCRIPTOR pChildRelations,
                            ULONG ChildRelationsSize)
{
    DEVICE_EXTENSION *dev = pMiniportDeviceContext;
    ULONG i;

    PAGED_CODE();

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
        pChildRelations[i].ChildCapabilities.Type.VideoOutput.InterfaceTechnology = D3DKMDT_VOT_OTHER;
        pChildRelations[i].ChildCapabilities.Type.VideoOutput.MonitorOrientationAwareness = D3DKMDT_MOA_NONE;
        pChildRelations[i].ChildCapabilities.Type.VideoOutput.SupportsSdtvModes = FALSE;
    }

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

    return STATUS_SUCCESS;
}

NTSTATUS APIENTRY
uXenDispQueryDeviceDescriptor(CONST PVOID pMiniportDeviceContext,
                              ULONG ChildUid,
                              PDXGK_DEVICE_DESCRIPTOR pDeviceDescriptor)
{
    PAGED_CODE();
    return STATUS_MONITOR_NO_DESCRIPTOR;
}

NTSTATUS APIENTRY
uXenDispSetPowerState(CONST PVOID pMiniportDeviceContext,
                      ULONG HardwareUid,
                      DEVICE_POWER_STATE DevicePowerState,
                      POWER_ACTION ActionType)
{
    UNREFERENCED_PARAMETER(pMiniportDeviceContext);

    PAGED_CODE();

    uxen_debug("HW UID: %d DEVICE_POWER_STATE: %d POWER_ACTION: %d",
               HardwareUid, DevicePowerState, ActionType);

    return STATUS_SUCCESS;
}

VOID APIENTRY
uXenDispResetDevice(CONST PVOID pMiniportDeviceContext)
{
    DEVICE_EXTENSION *dev = pMiniportDeviceContext;
    /* Disable the interrupt and switch back to VGA mode */
    uxdisp_write(dev, UXDISP_REG_MODE, 0);
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
    return STATUS_NOT_SUPPORTED;
}

NTSTATUS APIENTRY
uXenDispSystemDisplayEnable(
    VOID* pDeviceContext,
    D3DDDI_VIDEO_PRESENT_TARGET_ID TargetId,
    PDXGKARG_SYSTEM_DISPLAY_ENABLE_FLAGS Flags,
    UINT* Width,
    UINT* Height,
    D3DDDIFORMAT* ColorFormat)
{
    DEVICE_EXTENSION *dev = pDeviceContext;
    UNREFERENCED_PARAMETER(Flags);

    *Width = dev->crtcs[TargetId].curr_mode.xres;
    *Height = dev->crtcs[TargetId].curr_mode.yres;
    *ColorFormat = D3DDDIFMT_A8R8G8B8;

    return STATUS_SUCCESS;
}

VOID APIENTRY
uXenDispSystemDisplayWrite(
    VOID* pDeviceContext,
    VOID* Source,
    UINT SourceWidth,
    UINT SourceHeight,
    UINT SourceStride,
    UINT PositionX,
    UINT PositionY)
{
}

NTSTATUS APIENTRY
uXenDispStopDeviceAndReleasePostDisplayOwnership(
    VOID* pDeviceContext,
    D3DDDI_VIDEO_PRESENT_TARGET_ID TargetId,
    DXGK_DISPLAY_INFORMATION* DisplayInfo)
{
    return STATUS_SUCCESS;
}

NTSTATUS
DriverEntry(PDRIVER_OBJECT pDriverObject, PUNICODE_STRING pRegistryPath)
{
    NTSTATUS Status;
    RTL_OSVERSIONINFOW VersionInformation = { sizeof VersionInformation };
    uxen_msg("Enter version: %s", UXEN_DRIVER_VERSION_CHANGESET);

    Status = RtlGetVersion(&VersionInformation);
    if (!NT_SUCCESS(Status)) {
        uxen_err("RtlGetVersion failed 0x%x", Status);
    }

    if (NT_SUCCESS(Status)) {
        if ((VersionInformation.dwMajorVersion == 6) &&
            (VersionInformation.dwMinorVersion == 1)) {
            DRIVER_INITIALIZATION_DATA InitialData = {0};

            InitialData.Version                                = DXGKDDI_INTERFACE_VERSION_VISTA;

            /* Miniport */
            InitialData.DxgkDdiAddDevice                       = uXenDispAddDevice;
            InitialData.DxgkDdiStartDevice                     = uXenDispStartDevice;
            InitialData.DxgkDdiStopDevice                      = uXenDispStopDevice;
            InitialData.DxgkDdiRemoveDevice                    = uXenDispRemoveDevice;
            InitialData.DxgkDdiDispatchIoRequest               = uXenDispDispatchIoRequest;
            InitialData.DxgkDdiInterruptRoutine                = uXenDispInterruptRoutine;
            InitialData.DxgkDdiDpcRoutine                      = uXenDispDpcRoutine;
            InitialData.DxgkDdiQueryChildRelations             = uXenDispQueryChildRelations;
            InitialData.DxgkDdiQueryChildStatus                = uXenDispQueryChildStatus;
            InitialData.DxgkDdiQueryDeviceDescriptor           = uXenDispQueryDeviceDescriptor;
            InitialData.DxgkDdiSetPowerState                   = uXenDispSetPowerState;
            InitialData.DxgkDdiNotifyAcpiEvent                 = NULL; /* optional, not currently used */
            InitialData.DxgkDdiResetDevice                     = uXenDispResetDevice;
            InitialData.DxgkDdiUnload                          = uXenDispUnload;
            InitialData.DxgkDdiQueryInterface                  = uXenDispQueryInterface;
            /* DDI */
            InitialData.DxgkDdiControlEtwLogging               = uXenDispControlEtwLogging;
            InitialData.DxgkDdiQueryAdapterInfo                = uXenDispQueryAdapterInfo;
            InitialData.DxgkDdiCreateDevice                    = uXenDispCreateDevice;
            InitialData.DxgkDdiCreateAllocation                = uXenDispCreateAllocation;
            InitialData.DxgkDdiDestroyAllocation               = uXenDispDestroyAllocation;
            InitialData.DxgkDdiDescribeAllocation              = uXenDispDescribeAllocation;
            InitialData.DxgkDdiGetStandardAllocationDriverData = uXenDispGetStandardAllocationDriverData;
            InitialData.DxgkDdiAcquireSwizzlingRange           = uXenDispAcquireSwizzlingRange;
            InitialData.DxgkDdiReleaseSwizzlingRange           = uXenDispReleaseSwizzlingRange;
            InitialData.DxgkDdiPatch                           = uXenDispPatch;
            InitialData.DxgkDdiSubmitCommand                   = uXenDispSubmitCommand;
            InitialData.DxgkDdiPreemptCommand                  = uXenDispPreemptCommand;
            InitialData.DxgkDdiBuildPagingBuffer               = uXenDispBuildPagingBuffer;
            InitialData.DxgkDdiSetPalette                      = uXenDispSetPalette;
            InitialData.DxgkDdiSetPointerPosition              = uXenDispSetPointerPosition;
            InitialData.DxgkDdiSetPointerShape                 = uXenDispSetPointerShape;
            InitialData.DxgkDdiResetFromTimeout                = uXenDispResetFromTimeout;
            InitialData.DxgkDdiRestartFromTimeout              = uXenDispRestartFromTimeout;
            InitialData.DxgkDdiEscape                          = uXenDispEscape;
            InitialData.DxgkDdiCollectDbgInfo                  = uXenDispCollectDbgInfo;
            InitialData.DxgkDdiQueryCurrentFence               = uXenDispQueryCurrentFence;
            /* VidPn */
            InitialData.DxgkDdiIsSupportedVidPn                = uXenDispIsSupportedVidPn;
            InitialData.DxgkDdiRecommendFunctionalVidPn        = uXenDispRecommendFunctionalVidPn;
            InitialData.DxgkDdiEnumVidPnCofuncModality         = uXenDispEnumVidPnCofuncModality;
            InitialData.DxgkDdiSetVidPnSourceAddress           = uXenDispSetVidPnSourceAddress;
            InitialData.DxgkDdiSetVidPnSourceVisibility        = uXenDispSetVidPnSourceVisibility;
            InitialData.DxgkDdiCommitVidPn                     = uXenDispCommitVidPn;
            InitialData.DxgkDdiUpdateActiveVidPnPresentPath    = uXenDispUpdateActiveVidPnPresentPath;
            InitialData.DxgkDdiRecommendMonitorModes           = uXenDispRecommendMonitorModes;
            InitialData.DxgkDdiRecommendVidPnTopology          = uXenDispRecommendVidPnTopology;
            InitialData.DxgkDdiGetScanLine                     = uXenDispGetScanLine;
            /* DDI */
            InitialData.DxgkDdiStopCapture                     = uXenDispStopCapture;
            InitialData.DxgkDdiControlInterrupt                = uXenDispControlInterrupt;
            InitialData.DxgkDdiCreateOverlay                   = NULL; /* not supported */
            InitialData.DxgkDdiDestroyDevice                   = uXenDispDestroyDevice;
            InitialData.DxgkDdiOpenAllocation                  = uXenDispOpenAllocation;
            InitialData.DxgkDdiCloseAllocation                 = uXenDispCloseAllocation;
            InitialData.DxgkDdiRender                          = uXenDispRender;
            InitialData.DxgkDdiPresent                         = uXenDispPresent;
            InitialData.DxgkDdiUpdateOverlay                   = NULL; /* not supported */
            InitialData.DxgkDdiFlipOverlay                     = NULL; /* not supported */
            InitialData.DxgkDdiDestroyOverlay                  = NULL; /* not supported */
            InitialData.DxgkDdiCreateContext                   = uXenDispCreateContext;
            InitialData.DxgkDdiDestroyContext                  = uXenDispDestroyContext;
            InitialData.DxgkDdiLinkDevice                      = NULL; /* not supported */
            InitialData.DxgkDdiSetDisplayPrivateDriverFormat   = NULL; /* not supported */

            Status = DxgkInitialize(pDriverObject, pRegistryPath, &InitialData);
        } else {
            KMDDOD_INITIALIZATION_DATA InitialData = {0};

            InitialData.Version                             = DXGKDDI_INTERFACE_VERSION_WIN8;
            InitialData.DxgkDdiAddDevice                    = uXenDispAddDevice;
            InitialData.DxgkDdiStartDevice                  = uXenDispStartDevice;
            InitialData.DxgkDdiStopDevice                   = uXenDispStopDevice;
            InitialData.DxgkDdiResetDevice                  = uXenDispResetDevice;
            InitialData.DxgkDdiRemoveDevice                 = uXenDispRemoveDevice;
            InitialData.DxgkDdiDispatchIoRequest            = uXenDispDispatchIoRequest;
            InitialData.DxgkDdiInterruptRoutine             = uXenDispInterruptRoutine;
            InitialData.DxgkDdiDpcRoutine                   = uXenDispDpcRoutine;
            InitialData.DxgkDdiQueryChildRelations          = uXenDispQueryChildRelations;
            InitialData.DxgkDdiQueryChildStatus             = uXenDispQueryChildStatus;
            InitialData.DxgkDdiQueryDeviceDescriptor        = uXenDispQueryDeviceDescriptor;
            InitialData.DxgkDdiSetPowerState                = uXenDispSetPowerState;
            InitialData.DxgkDdiUnload                       = uXenDispUnload;
            InitialData.DxgkDdiQueryAdapterInfo             = uXenDispQueryAdapterInfo;
            InitialData.DxgkDdiSetPointerPosition           = uXenDispSetPointerPosition;
            InitialData.DxgkDdiSetPointerShape              = uXenDispSetPointerShape;
            InitialData.DxgkDdiEscape                       = uXenDispEscape;
            InitialData.DxgkDdiIsSupportedVidPn             = uXenDispIsSupportedVidPn;
            InitialData.DxgkDdiRecommendFunctionalVidPn     = uXenDispRecommendFunctionalVidPn;
            InitialData.DxgkDdiEnumVidPnCofuncModality      = uXenDispEnumVidPnCofuncModality;
            InitialData.DxgkDdiSetVidPnSourceVisibility     = uXenDispSetVidPnSourceVisibility;
            InitialData.DxgkDdiCommitVidPn                  = uXenDispCommitVidPn;
            InitialData.DxgkDdiUpdateActiveVidPnPresentPath = uXenDispUpdateActiveVidPnPresentPath;
            InitialData.DxgkDdiRecommendMonitorModes        = uXenDispRecommendMonitorModes;
            InitialData.DxgkDdiQueryVidPnHWCapability       = uXenDispQueryVidPnHWCapability;
            InitialData.DxgkDdiPresentDisplayOnly           = uXenDispPresentDisplayOnly;
            InitialData.DxgkDdiStopDeviceAndReleasePostDisplayOwnership = uXenDispStopDeviceAndReleasePostDisplayOwnership;
            InitialData.DxgkDdiSystemDisplayEnable          = uXenDispSystemDisplayEnable;
            InitialData.DxgkDdiSystemDisplayWrite           = uXenDispSystemDisplayWrite;

            Status = DxgkInitializeDisplayOnlyDriver(pDriverObject, pRegistryPath, &InitialData);

            g_dod = TRUE;
        }
        if (!NT_SUCCESS(Status)) {
            uxen_err("Initialisation(%d, %d) failed 0x%x",
                     VersionInformation.dwMajorVersion,
                     VersionInformation.dwMinorVersion,
                     Status);
        }
    }

    uxen_msg("Leave");
    return Status;
}
