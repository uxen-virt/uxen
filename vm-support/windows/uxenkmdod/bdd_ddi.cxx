/******************************Module*Header*******************************\
* Module Name: BDD_DDI.cxx
*
* Basic Display Driver DDI entry points redirects
*
*
* Copyright (c) 2010 Microsoft Corporation
\**************************************************************************/
/*
 * uXen changes:
 *
 * Copyright 2014-2016, Bromium, Inc.
 * Author: Kris Uchronski <kuchronski@gmail.com>
 * SPDX-License-Identifier: ISC
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
 * SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION
 * OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
 * CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include "BDD.hxx"
#include "version.h"

#ifdef ALLOC_PRAGMA
#pragma alloc_text(INIT, DriverEntry)
#endif

extern "C" NTSTATUS
DriverEntry(
    _In_  DRIVER_OBJECT*  pDriverObject,
    _In_  UNICODE_STRING* pRegistryPath)
{
    KMDDOD_INITIALIZATION_DATA InitialData = {0};

    uxen_msg("begin version: %s", UXEN_DRIVER_VERSION_CHANGESET);

    InitialData.Version = DXGKDDI_INTERFACE_VERSION_WIN8;
    InitialData.DxgkDdiAddDevice                    = BddDdiAddDevice;
    InitialData.DxgkDdiStartDevice                  = BddDdiStartDevice;
    InitialData.DxgkDdiStopDevice                   = BddDdiStopDevice;
    InitialData.DxgkDdiResetDevice                  = BddDdiResetDevice;
    InitialData.DxgkDdiRemoveDevice                 = BddDdiRemoveDevice;
    InitialData.DxgkDdiDispatchIoRequest            = BddDdiDispatchIoRequest;
    InitialData.DxgkDdiInterruptRoutine             = BddDdiInterruptRoutine;
    InitialData.DxgkDdiDpcRoutine                   = BddDdiDpcRoutine;
    InitialData.DxgkDdiQueryChildRelations          = BddDdiQueryChildRelations;
    InitialData.DxgkDdiQueryChildStatus             = BddDdiQueryChildStatus;
    InitialData.DxgkDdiQueryDeviceDescriptor        = BddDdiQueryDeviceDescriptor;
    InitialData.DxgkDdiSetPowerState                = BddDdiSetPowerState;
    InitialData.DxgkDdiUnload                       = BddDdiUnload;
    InitialData.DxgkDdiQueryAdapterInfo             = BddDdiQueryAdapterInfo;
    InitialData.DxgkDdiSetPointerPosition           = BddDdiSetPointerPosition;
    InitialData.DxgkDdiSetPointerShape              = BddDdiSetPointerShape;
    InitialData.DxgkDdiEscape                       = BddDdiEscape;
    InitialData.DxgkDdiIsSupportedVidPn             = BddDdiIsSupportedVidPn;
    InitialData.DxgkDdiRecommendFunctionalVidPn     = BddDdiRecommendFunctionalVidPn;
    InitialData.DxgkDdiEnumVidPnCofuncModality      = BddDdiEnumVidPnCofuncModality;
    InitialData.DxgkDdiSetVidPnSourceVisibility     = BddDdiSetVidPnSourceVisibility;
    InitialData.DxgkDdiCommitVidPn                  = BddDdiCommitVidPn;
    InitialData.DxgkDdiUpdateActiveVidPnPresentPath = BddDdiUpdateActiveVidPnPresentPath;
    InitialData.DxgkDdiRecommendMonitorModes        = BddDdiRecommendMonitorModes;
    InitialData.DxgkDdiQueryVidPnHWCapability       = BddDdiQueryVidPnHWCapability;
    InitialData.DxgkDdiPresentDisplayOnly           = BddDdiPresentDisplayOnly;
    InitialData.DxgkDdiStopDeviceAndReleasePostDisplayOwnership = BddDdiStopDeviceAndReleasePostDisplayOwnership;
    InitialData.DxgkDdiSystemDisplayEnable          = BddDdiSystemDisplayEnable;
    InitialData.DxgkDdiSystemDisplayWrite           = BddDdiSystemDisplayWrite;

    NTSTATUS Status = DxgkInitializeDisplayOnlyDriver(pDriverObject, pRegistryPath, &InitialData);
    if (!NT_SUCCESS(Status))
        uxen_err("DxgkInitializeDisplayOnlyDriver failed with Status: 0x%I64x", Status);
    else
        uxen_msg("end");

    return Status;
}


//
// PnP DDIs
//

VOID
BddDdiUnload(VOID)
{
    perfcnt_inc(DxgkDdiUnload);
    uxen_msg("called");
    perfcnt_dump();
}

NTSTATUS
BddDdiAddDevice(
    _In_ DEVICE_OBJECT* pPhysicalDeviceObject,
    _Outptr_ PVOID*  ppDeviceContext)
{
    perfcnt_inc(DxgkDdiAddDevice);
    uxen_msg("called");

    BASIC_DISPLAY_DRIVER *pBDD;

    if ((pPhysicalDeviceObject == NULL) ||
        (ppDeviceContext == NULL))
    {
        uxen_err("One of pPhysicalDeviceObject (0x%I64x), ppDeviceContext (0x%I64x) is NULL",
                        pPhysicalDeviceObject, ppDeviceContext);
        return STATUS_INVALID_PARAMETER;
    }
    *ppDeviceContext = NULL;

    pBDD = (BASIC_DISPLAY_DRIVER *)ExAllocatePoolWithTag(NonPagedPool,
                                                         sizeof(*pBDD),
                                                         BDDTAG);
    if (pBDD == NULL)
    {
        uxen_err("BDD failed to be allocated (0x%x)", sizeof(*pBDD));
        return STATUS_NO_MEMORY;
    }

    pBDD->Init(pPhysicalDeviceObject);

    *ppDeviceContext = pBDD;

    return STATUS_SUCCESS;
}

NTSTATUS
BddDdiRemoveDevice(
    _In_  VOID* pDeviceContext)
{
    perfcnt_inc(DxgkDdiRemoveDevice);
    uxen_msg("called");

    BASIC_DISPLAY_DRIVER *pBDD = (BASIC_DISPLAY_DRIVER *)(pDeviceContext);

    if (pBDD) {
        pBDD->CleanUp();
        ExFreePool(pBDD);
    }

    return STATUS_SUCCESS;
}

NTSTATUS
BddDdiStartDevice(
    _In_  VOID*              pDeviceContext,
    _In_  DXGK_START_INFO*   pDxgkStartInfo,
    _In_  DXGKRNL_INTERFACE* pDxgkInterface,
    _Out_ ULONG*             pNumberOfViews,
    _Out_ ULONG*             pNumberOfChildren)
{
    ASSERT(pDeviceContext != NULL);

    perfcnt_inc(DxgkDdiStartDevice);
    uxen_msg("called");

    BASIC_DISPLAY_DRIVER* pBDD = (BASIC_DISPLAY_DRIVER*)(pDeviceContext);
    return pBDD->StartDevice(pDxgkStartInfo, pDxgkInterface, pNumberOfViews, pNumberOfChildren);
}

NTSTATUS
BddDdiStopDevice(
    _In_  VOID* pDeviceContext)
{
    ASSERT(pDeviceContext != NULL);

    perfcnt_inc(DxgkDdiStopDevice);
    uxen_msg("called");

    BASIC_DISPLAY_DRIVER* pBDD = (BASIC_DISPLAY_DRIVER*)(pDeviceContext);
    return pBDD->StopDevice();
}


NTSTATUS
BddDdiDispatchIoRequest(
    _In_  VOID*                 pDeviceContext,
    _In_  ULONG                 VidPnSourceId,
    _In_  VIDEO_REQUEST_PACKET* pVideoRequestPacket)
{
    ASSERT(pDeviceContext != NULL);

    perfcnt_inc(DxgkDdiDispatchIoRequest);

    BASIC_DISPLAY_DRIVER* pBDD = (BASIC_DISPLAY_DRIVER*)(pDeviceContext);
    if (!pBDD->IsDriverActive())
    {
        ASSERT_FAIL("BDD (0x%I64x) is being called when not active!", pBDD);
        return STATUS_UNSUCCESSFUL;
    }
    return pBDD->DispatchIoRequest(VidPnSourceId, pVideoRequestPacket);
}

NTSTATUS
BddDdiSetPowerState(
    _In_  VOID*              pDeviceContext,
    _In_  ULONG              HardwareUid,
    _In_  DEVICE_POWER_STATE DevicePowerState,
    _In_  POWER_ACTION       ActionType)
{
    ASSERT(pDeviceContext != NULL);

    perfcnt_inc(DxgkDdiSetPowerState);

    BASIC_DISPLAY_DRIVER* pBDD = (BASIC_DISPLAY_DRIVER*)(pDeviceContext);
    if (!pBDD->IsDriverActive())
    {
        // If the driver isn't active, SetPowerState can still be called, however in BDD's case
        // this shouldn't do anything, as it could for instance be called on BDD Fallback after
        // Fallback has been stopped and BDD PnP is being started. Fallback doesn't have control
        // of the hardware in this case.
        return STATUS_SUCCESS;
    }
    return pBDD->SetPowerState(HardwareUid, DevicePowerState, ActionType);
}

NTSTATUS
BddDdiQueryChildRelations(
    _In_                             VOID*                  pDeviceContext,
    _Out_writes_bytes_(ChildRelationsSize) DXGK_CHILD_DESCRIPTOR* pChildRelations,
    _In_                             ULONG                  ChildRelationsSize)
{
    ASSERT(pDeviceContext != NULL);

    perfcnt_inc(DxgkDdiQueryChildRelations);

    BASIC_DISPLAY_DRIVER* pBDD = (BASIC_DISPLAY_DRIVER*)(pDeviceContext);
    return pBDD->QueryChildRelations(pChildRelations, ChildRelationsSize);
}

NTSTATUS
BddDdiQueryChildStatus(
    _In_    VOID*              pDeviceContext,
    _Inout_ DXGK_CHILD_STATUS* pChildStatus,
    _In_    BOOLEAN            NonDestructiveOnly)
{
    ASSERT(pDeviceContext != NULL);

    perfcnt_inc(DxgkDdiQueryChildStatus);

    BASIC_DISPLAY_DRIVER* pBDD = (BASIC_DISPLAY_DRIVER*)(pDeviceContext);
    return pBDD->QueryChildStatus(pChildStatus, NonDestructiveOnly);
}

NTSTATUS
BddDdiQueryDeviceDescriptor(
    _In_  VOID*                     pDeviceContext,
    _In_  ULONG                     ChildUid,
    _Inout_ DXGK_DEVICE_DESCRIPTOR* pDeviceDescriptor)
{
    ASSERT(pDeviceContext != NULL);

    perfcnt_inc(DxgkDdiQueryDeviceDescriptor);

    BASIC_DISPLAY_DRIVER* pBDD = (BASIC_DISPLAY_DRIVER*)(pDeviceContext);
    if (!pBDD->IsDriverActive())
    {
        // During stress testing of PnPStop, it is possible for BDD Fallback to get called to start then stop in quick succession.
        // The first call queues a worker thread item indicating that it now has a child device, the second queues a worker thread
        // item that it no longer has any child device. This function gets called based on the first worker thread item, but after
        // the driver has been stopped. Therefore instead of asserting like other functions, we only warn.
        uxen_debug("BDD (0x%I64x) is being called when not active!", pBDD);
        return STATUS_UNSUCCESSFUL;
    }
    return pBDD->QueryDeviceDescriptor(ChildUid, pDeviceDescriptor);
}


//
// WDDM Display Only Driver DDIs
//

NTSTATUS
APIENTRY
BddDdiQueryAdapterInfo(
    _In_ CONST HANDLE                    hAdapter,
    _In_ CONST DXGKARG_QUERYADAPTERINFO* pQueryAdapterInfo)
{
    ASSERT(hAdapter != NULL);

    perfcnt_inc(DxgkDdiQueryAdapterInfo);

    BASIC_DISPLAY_DRIVER* pBDD = (BASIC_DISPLAY_DRIVER*)(hAdapter);
    return pBDD->QueryAdapterInfo(pQueryAdapterInfo);
}

NTSTATUS
APIENTRY
BddDdiSetPointerPosition(
    _In_ CONST HANDLE                      hAdapter,
    _In_ CONST DXGKARG_SETPOINTERPOSITION* pSetPointerPosition)
{
    ASSERT(hAdapter != NULL);

    perfcnt_inc(DxgkDdiSetPointerPosition);

    BASIC_DISPLAY_DRIVER* pBDD = (BASIC_DISPLAY_DRIVER*)(hAdapter);
    if (!pBDD->IsDriverActive())
    {
        ASSERT_FAIL("BDD (0x%I64x) is being called when not active!", pBDD);
        return STATUS_UNSUCCESSFUL;
    }
    return pBDD->SetPointerPosition(pSetPointerPosition);
}

NTSTATUS
APIENTRY
BddDdiSetPointerShape(
    _In_ CONST HANDLE                   hAdapter,
    _In_ CONST DXGKARG_SETPOINTERSHAPE* pSetPointerShape)
{
    ASSERT(hAdapter != NULL);

    perfcnt_inc(DxgkDdiSetPointerShape);

    BASIC_DISPLAY_DRIVER* pBDD = (BASIC_DISPLAY_DRIVER*)(hAdapter);
    if (!pBDD->IsDriverActive())
    {
        ASSERT_FAIL("BDD (0x%I64x) is being called when not active!", pBDD);
        return STATUS_UNSUCCESSFUL;
    }
    return pBDD->SetPointerShape(pSetPointerShape);
}


NTSTATUS BddDdiEscape(
    IN_CONST_HANDLE hAdapter,
    IN_CONST_PDXGKARG_ESCAPE pEscape)
{
    NTSTATUS status = STATUS_SUCCESS;
    UXENDISPCustomMode mode;

    ASSERT(hAdapter != NULL);

    perfcnt_inc(DxgkDdiEscape);

    BASIC_DISPLAY_DRIVER* pBDD = (BASIC_DISPLAY_DRIVER*)(hAdapter);
    if (!pBDD->IsDriverActive())
    {
        ASSERT_FAIL("BDD (0x%I64x) is being called when not active!", pBDD);
        return STATUS_UNSUCCESSFUL;
    }

    /* for now we can just assume that there is only one kind of escape calls */
    if (pEscape->PrivateDriverDataSize == sizeof(mode)) {
        mode = *((UXENDISPCustomMode*)pEscape->pPrivateDriverData);
        switch (mode.esc_code) {
        case UXENDISP_ESCAPE_SET_CUSTOM_MODE:
            status = pBDD->SetNextMode(&mode);
            break;
        case UXENDISP_ESCAPE_SET_VIRTUAL_MODE:
            status = pBDD->SetVirtMode(&mode);
            break;
        case UXENDISP_ESCAPE_IS_VIRT_MODE_ENABLED:
            status = pBDD->IsVirtModeEnabled();
            break;
        };
    } else
        status = STATUS_INVALID_PARAMETER;

    return status;
}


NTSTATUS
APIENTRY
BddDdiPresentDisplayOnly(
    _In_ CONST HANDLE                       hAdapter,
    _In_ CONST DXGKARG_PRESENT_DISPLAYONLY* pPresentDisplayOnly)
{
    ASSERT(hAdapter != NULL);

    perfcnt_inc(DxgkDdiPresentDisplayOnly);

    BASIC_DISPLAY_DRIVER* pBDD = (BASIC_DISPLAY_DRIVER*)(hAdapter);
    if (!pBDD->IsDriverActive())
    {
        ASSERT_FAIL("BDD (0x%I64x) is being called when not active!", pBDD);
        return STATUS_UNSUCCESSFUL;
    }
    return pBDD->PresentDisplayOnly(pPresentDisplayOnly);
}

NTSTATUS
APIENTRY
BddDdiStopDeviceAndReleasePostDisplayOwnership(
    _In_  VOID*                          pDeviceContext,
    _In_  D3DDDI_VIDEO_PRESENT_TARGET_ID TargetId,
    _Out_ DXGK_DISPLAY_INFORMATION*      DisplayInfo)
{
    ASSERT(pDeviceContext != NULL);

    perfcnt_inc(DxgkDdiStopDeviceAndReleasePostDisplayOwnership);

    BASIC_DISPLAY_DRIVER* pBDD = (BASIC_DISPLAY_DRIVER*)(pDeviceContext);
    return pBDD->StopDeviceAndReleasePostDisplayOwnership(TargetId, DisplayInfo);
}

NTSTATUS
APIENTRY
BddDdiIsSupportedVidPn(
    _In_ CONST HANDLE                 hAdapter,
    _Inout_ DXGKARG_ISSUPPORTEDVIDPN* pIsSupportedVidPn)
{
    ASSERT(hAdapter != NULL);

    perfcnt_inc(DxgkDdiIsSupportedVidPn);

    BASIC_DISPLAY_DRIVER* pBDD = (BASIC_DISPLAY_DRIVER*)(hAdapter);
    if (!pBDD->IsDriverActive())
    {
        // This path might hit because win32k/dxgport doesn't check that an adapter is active when taking the adapter lock.
        // The adapter lock is the main thing BDD Fallback relies on to not be called while it's inactive. It is still a rare
        // timing issue around PnpStart/Stop and isn't expected to have any effect on the stability of the system.
        uxen_debug("BDD (0x%I64x) is being called when not active!", pBDD);
        return STATUS_UNSUCCESSFUL;
    }
    return pBDD->IsSupportedVidPn(pIsSupportedVidPn);
}

NTSTATUS
APIENTRY
BddDdiRecommendFunctionalVidPn(
    _In_ CONST HANDLE                                  hAdapter,
    _In_ CONST DXGKARG_RECOMMENDFUNCTIONALVIDPN* CONST pRecommendFunctionalVidPn)
{
    ASSERT(hAdapter != NULL);

    perfcnt_inc(DxgkDdiRecommendFunctionalVidPn);

    BASIC_DISPLAY_DRIVER* pBDD = (BASIC_DISPLAY_DRIVER*)(hAdapter);
    if (!pBDD->IsDriverActive())
    {
        ASSERT_FAIL("BDD (0x%I64x) is being called when not active!", pBDD);
        return STATUS_UNSUCCESSFUL;
    }
    return pBDD->RecommendFunctionalVidPn(pRecommendFunctionalVidPn);
}

NTSTATUS
APIENTRY
BddDdiRecommendMonitorModes(
    _In_ CONST HANDLE                                hAdapter,
    _In_ CONST DXGKARG_RECOMMENDMONITORMODES* CONST  pRecommendMonitorModes)
{
    ASSERT(hAdapter != NULL);

    perfcnt_inc(DxgkDdiRecommendMonitorModes);

    BASIC_DISPLAY_DRIVER* pBDD = (BASIC_DISPLAY_DRIVER*)(hAdapter);
    if (!pBDD->IsDriverActive())
    {
        ASSERT_FAIL("BDD (0x%I64x) is being called when not active!", pBDD);
        return STATUS_UNSUCCESSFUL;
    }
    return pBDD->RecommendMonitorModes(pRecommendMonitorModes);
}

NTSTATUS
APIENTRY
BddDdiEnumVidPnCofuncModality(
    _In_ CONST HANDLE                                 hAdapter,
    _In_ CONST DXGKARG_ENUMVIDPNCOFUNCMODALITY* CONST pEnumCofuncModality)
{
    ASSERT(hAdapter != NULL);

    perfcnt_inc(DxgkDdiEnumVidPnCofuncModality);

    BASIC_DISPLAY_DRIVER* pBDD = (BASIC_DISPLAY_DRIVER*)(hAdapter);
    if (!pBDD->IsDriverActive())
    {
        ASSERT_FAIL("BDD (0x%I64x) is being called when not active!", pBDD);
        return STATUS_UNSUCCESSFUL;
    }
    return pBDD->EnumVidPnCofuncModality(pEnumCofuncModality);
}

NTSTATUS
APIENTRY
BddDdiSetVidPnSourceVisibility(
    _In_ CONST HANDLE                            hAdapter,
    _In_ CONST DXGKARG_SETVIDPNSOURCEVISIBILITY* pSetVidPnSourceVisibility)
{
    ASSERT(hAdapter != NULL);

    perfcnt_inc(DxgkDdiSetVidPnSourceVisibility);

    BASIC_DISPLAY_DRIVER* pBDD = (BASIC_DISPLAY_DRIVER*)(hAdapter);
    if (!pBDD->IsDriverActive())
    {
        ASSERT_FAIL("BDD (0x%I64x) is being called when not active!", pBDD);
        return STATUS_UNSUCCESSFUL;
    }
    return pBDD->SetVidPnSourceVisibility(pSetVidPnSourceVisibility);
}

NTSTATUS
APIENTRY
BddDdiCommitVidPn(
    _In_ CONST HANDLE                     hAdapter,
    _In_ CONST DXGKARG_COMMITVIDPN* CONST pCommitVidPn)
{
    ASSERT(hAdapter != NULL);

    perfcnt_inc(DxgkDdiCommitVidPn);

    BASIC_DISPLAY_DRIVER* pBDD = (BASIC_DISPLAY_DRIVER*)(hAdapter);
    if (!pBDD->IsDriverActive())
    {
        ASSERT_FAIL("BDD (0x%I64x) is being called when not active!", pBDD);
        return STATUS_UNSUCCESSFUL;
    }
    return pBDD->CommitVidPn(pCommitVidPn);
}

NTSTATUS
APIENTRY
BddDdiUpdateActiveVidPnPresentPath(
    _In_ CONST HANDLE                                      hAdapter,
    _In_ CONST DXGKARG_UPDATEACTIVEVIDPNPRESENTPATH* CONST pUpdateActiveVidPnPresentPath)
{
    ASSERT(hAdapter != NULL);

    perfcnt_inc(DxgkDdiUpdateActiveVidPnPresentPath);

    BASIC_DISPLAY_DRIVER* pBDD = (BASIC_DISPLAY_DRIVER*)(hAdapter);
    if (!pBDD->IsDriverActive())
    {
        ASSERT_FAIL("BDD (0x%I64x) is being called when not active!", pBDD);
        return STATUS_UNSUCCESSFUL;
    }
    return pBDD->UpdateActiveVidPnPresentPath(pUpdateActiveVidPnPresentPath);
}

NTSTATUS
APIENTRY
BddDdiQueryVidPnHWCapability(
    _In_ CONST HANDLE                       hAdapter,
    _Inout_ DXGKARG_QUERYVIDPNHWCAPABILITY* pVidPnHWCaps)
{
    ASSERT(hAdapter != NULL);

    perfcnt_inc(DxgkDdiQueryVidPnHWCapability);

    BASIC_DISPLAY_DRIVER* pBDD = (BASIC_DISPLAY_DRIVER*)(hAdapter);
    if (!pBDD->IsDriverActive())
    {
        ASSERT_FAIL("BDD (0x%I64x) is being called when not active!", pBDD);
        return STATUS_UNSUCCESSFUL;
    }
    return pBDD->QueryVidPnHWCapability(pVidPnHWCaps);
}

VOID
BddDdiDpcRoutine(
    _In_  VOID* pDeviceContext)
{
    ASSERT(pDeviceContext != NULL);

    perfcnt_inc(DxgkDdiDpcRoutine);

    BASIC_DISPLAY_DRIVER* pBDD = (BASIC_DISPLAY_DRIVER*)(pDeviceContext);
    if (!pBDD->IsDriverActive())
    {
        ASSERT_FAIL("BDD (0x%I64x) is being called when not active!", pBDD);
        return;
    }
    pBDD->DpcRoutine();
}

BOOLEAN
BddDdiInterruptRoutine(
    _In_  VOID* pDeviceContext,
    _In_  ULONG MessageNumber)
{
    ASSERT(pDeviceContext != NULL);

    perfcnt_inc(DxgkDdiInterruptRoutine);

    BASIC_DISPLAY_DRIVER* pBDD = (BASIC_DISPLAY_DRIVER*)(pDeviceContext);
    return pBDD->InterruptRoutine(MessageNumber);
}

VOID
BddDdiResetDevice(
    _In_  VOID* pDeviceContext)
{
    ASSERT(pDeviceContext != NULL);

    perfcnt_inc(DxgkDdiResetDevice);
    uxen_msg("called");

    BASIC_DISPLAY_DRIVER* pBDD = (BASIC_DISPLAY_DRIVER*)(pDeviceContext);
    pBDD->ResetDevice();
}

NTSTATUS
APIENTRY
BddDdiSystemDisplayEnable(
    _In_  VOID* pDeviceContext,
    _In_  D3DDDI_VIDEO_PRESENT_TARGET_ID TargetId,
    _In_  PDXGKARG_SYSTEM_DISPLAY_ENABLE_FLAGS Flags,
    _Out_ UINT* Width,
    _Out_ UINT* Height,
    _Out_ D3DDDIFORMAT* ColorFormat)
{
    ASSERT(pDeviceContext != NULL);

    perfcnt_inc(DxgkDdiSystemDisplayEnable);

    BASIC_DISPLAY_DRIVER* pBDD = (BASIC_DISPLAY_DRIVER*)(pDeviceContext);
    return pBDD->SystemDisplayEnable(TargetId, Flags, Width, Height, ColorFormat);
}

VOID
APIENTRY
BddDdiSystemDisplayWrite(
    _In_  VOID* pDeviceContext,
    _In_  VOID* Source,
    _In_  UINT  SourceWidth,
    _In_  UINT  SourceHeight,
    _In_  UINT  SourceStride,
    _In_  UINT  PositionX,
    _In_  UINT  PositionY)
{
    ASSERT(pDeviceContext != NULL);

    perfcnt_inc(DxgkDdiSystemDisplayWrite);

    BASIC_DISPLAY_DRIVER* pBDD = (BASIC_DISPLAY_DRIVER*)(pDeviceContext);
    pBDD->SystemDisplayWrite(Source, SourceWidth, SourceHeight, SourceStride, PositionX, PositionY);
}
