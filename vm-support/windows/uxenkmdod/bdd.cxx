/******************************Module*Header*******************************\
* Module Name: bdd.cxx
*
* Basic Display Driver functions implementation
*
*
* Copyright (c) 2010 Microsoft Corporation
\**************************************************************************/
/*
 * uXen changes:
 *
 * Copyright 2014-2017, Bromium, Inc.
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
#include "hw.h"
#include "perfcnt.h"
#include "user_vram.h"
extern "C"
{
    #include <uxenvmlib.h>
    #include <uxenv4vlib.h>
}

extern int use_pv_vblank;

static void
bdd_resume(PKDPC dpc, PVOID deferred_context, PVOID arg1, PVOID arg2)
{
    BASIC_DISPLAY_DRIVER *bdd = (BASIC_DISPLAY_DRIVER*) deferred_context;

    dpc; arg1; arg2;

    bdd->Resume();
}

VOID BASIC_DISPLAY_DRIVER::Init(_In_ DEVICE_OBJECT* pPhysicalDeviceObject)
{
    *((UINT*)&m_Flags) = 0;
    m_Flags._LastFlag = TRUE;
    RtlZeroMemory(&m_DxgkInterface, sizeof(m_DxgkInterface));
    RtlZeroMemory(&m_StartInfo, sizeof(m_StartInfo));
    RtlZeroMemory(m_CurrentModes, sizeof(m_CurrentModes));
    RtlZeroMemory(&m_DeviceInfo, sizeof(m_DeviceInfo));
    RtlZeroMemory(&m_HwResources, sizeof(m_HwResources));

    m_track_vblank = 0;
    m_pPhysicalDevice = pPhysicalDeviceObject;
    m_MonitorPowerState = PowerDeviceD0;
    m_AdapterPowerState = PowerDeviceD0;

    for (UINT i=0;i<MAX_VIEWS;i++)
    {
        m_HardwareBlt[i].Init();
        m_HardwareBlt[i].Initialize(this,i);
    }

    m_NextMode.width = 1024;
    m_NextMode.height = 768;
    m_VirtMode = m_NextMode;
    KeInitializeSemaphore(&m_PresentLock, 1, 1);
    KeInitializeDpc(&m_resume_dpc, bdd_resume, this);
}

NTSTATUS BASIC_DISPLAY_DRIVER::GetResources(_In_ PCM_RESOURCE_LIST pResList)
{
    PCM_FULL_RESOURCE_DESCRIPTOR list = NULL;
    BOOLEAN VideoMemoryReady = FALSE;
    BOOLEAN MmioMemoryReady = FALSE;

    ASSERT(NULL != pResList);
    ASSERT(1 == pResList->Count);

    list = pResList->List;
    for (ULONG jx = 0; jx < list->PartialResourceList.Count; ++jx) {
        PCM_PARTIAL_RESOURCE_DESCRIPTOR desc;

        desc = list->PartialResourceList.PartialDescriptors + jx;
        if (desc->Type == CmResourceTypeMemory) {
            PHYSICAL_ADDRESS startAddress = {0};
            ULONGLONG length = 0;

            length = RtlCmDecodeMemIoResource(desc, (PULONGLONG)&startAddress.QuadPart);
            if ((length > 0) && (startAddress.QuadPart > 0))
            {
                if (!VideoMemoryReady) {
                    m_CurrentModes[0].VideoMemory = startAddress;
                    m_CurrentModes[0].VideoMemoryLength = length;
                    VideoMemoryReady = TRUE;
                }
                else if (!MmioMemoryReady) {
                    m_HwResources.mmioPhysicalAddress = startAddress;
                    m_HwResources.mmioLength = length;
                    MmioMemoryReady = TRUE;
                }
            }
        }
    }

    return (VideoMemoryReady && MmioMemoryReady) ? STATUS_SUCCESS : STATUS_UNSUCCESSFUL;
}

static void
log_tdr_values(void)
{
    PSTR keys[] = {
        "TdrLevel",
        "TdrDelay",
        "TdrDdiDelay",
        "TdrDodVSyncDelay",
        "TdrDodPresentDelay",
        "TdrLimitCount",
        NULL };
    const PWSTR path = L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Control\\GraphicsDrivers";
    int i;
    WCHAR buffer[64];
    UNICODE_STRING ustr;
    ANSI_STRING astr;
    NTSTATUS status;

    for (i = 0; keys[i]; i++) {
        ULONG  val = 0xFFFFFFFF;
        size_t len = 0;

        status = RtlStringCbLengthA(keys[i], 32, &len);
        if (status != STATUS_SUCCESS) {
            uxen_err("unexpected %x\n", (int)status);
            break;
        }

        RtlZeroMemory(&buffer[0], sizeof(buffer));
        ustr.Length = 0;
        ustr.MaximumLength = sizeof(buffer);
        ustr.Buffer = &buffer[0];

        astr.Length = (USHORT)len;
        astr.MaximumLength = (USHORT)len;
        astr.Buffer = keys[i];

        status = RtlAnsiStringToUnicodeString(&ustr, &astr, FALSE);
        if (status != STATUS_SUCCESS) {
            uxen_err("failed to get unicode string %x\n", (int)status);
            break;
        }
        status = RegGetDWORD(RTL_REGISTRY_ABSOLUTE, path, &buffer[0], &val);
        if (status != STATUS_SUCCESS) {
            uxen_err("failed to read registry key %s %x\n", keys[i], (int)status);
            break;
        }
        uxen_msg("tdr key %s = %d\n", keys[i], (int)val);
    }
}

NTSTATUS BASIC_DISPLAY_DRIVER::StartDevice(_In_  DXGK_START_INFO*   pDxgkStartInfo,
                                           _In_  DXGKRNL_INTERFACE* pDxgkInterface,
                                           _Out_ ULONG*             pNumberOfViews,
                                           _Out_ ULONG*             pNumberOfChildren)
{
    ASSERT(pDxgkStartInfo != NULL);
    ASSERT(pDxgkInterface != NULL);
    ASSERT(pNumberOfViews != NULL);
    ASSERT(pNumberOfChildren != NULL);

    RtlCopyMemory(&m_StartInfo, pDxgkStartInfo, sizeof(m_StartInfo));
    RtlCopyMemory(&m_DxgkInterface, pDxgkInterface, sizeof(m_DxgkInterface));
    RtlZeroMemory(m_CurrentModes, sizeof(m_CurrentModes));
    RtlZeroMemory(&m_HwMode, sizeof(m_HwMode));
    m_CurrentModes[0].DispInfo.TargetId = D3DDDI_ID_UNINITIALIZED;

    m_comp_rects_nb = 0;
    m_comp_mode = DISP_COMPOSE_MODE_NONE;

    // Get device information from OS.
    NTSTATUS Status = m_DxgkInterface.DxgkCbGetDeviceInformation(m_DxgkInterface.DeviceHandle, &m_DeviceInfo);
    if (!NT_SUCCESS(Status))
    {
        ASSERT_FAIL("DxgkCbGetDeviceInformation failed with status 0x%I64x",
                           Status);
        return Status;
    }

    // This sample driver only uses the frame buffer of the POST device. DxgkCbAcquirePostDisplayOwnership 
    // gives you the frame buffer address and ensures that no one else is drawing to it. Be sure to give it back!
    Status = m_DxgkInterface.DxgkCbAcquirePostDisplayOwnership(m_DxgkInterface.DeviceHandle, &(m_CurrentModes[0].DispInfo));
    if (!NT_SUCCESS(Status) || m_CurrentModes[0].DispInfo.Width == 0)
    {
        // The most likely cause of failure is that the driver is simply not running on a POST device, or we are running
        // after a pre-WDDM 1.2 driver. Since we can't draw anything, we should fail to start.
        return STATUS_UNSUCCESSFUL;
    }
    m_Flags.DriverStarted = TRUE;
    *pNumberOfViews = MAX_VIEWS;
    *pNumberOfChildren = MAX_CHILDREN;

    Status = GetResources(m_DeviceInfo.TranslatedResourceList);
    if (!NT_SUCCESS(Status))
    {
        uxen_err("GetResources failed. Unable to find all required resources.");
        return Status;
    }

    // Sanity check. Address given to us by PnP manager is the POST framebuffer.
    ASSERT(m_CurrentModes[0].DispInfo.PhysicAddress.QuadPart == m_CurrentModes[0].VideoMemory.QuadPart);

    Status = hw_init(&m_HwResources);
    if (!NT_SUCCESS(Status))
    {
        uxen_err("hw_init failed. Unable to communicate with hardware.");
        return Status;
    }

    m_DrContext = dr_init(&m_HwResources, (disable_tracking_ptr)hw_disable_page_tracking);
    if (!m_DrContext)
    {
        uxen_err("dr_init failed. Unable to communicate with hardware.");
        return STATUS_UNSUCCESSFUL;
    }

    m_VSync = use_pv_vblank;
    if (!m_vram_mapper.init(this, m_CurrentModes[0].VideoMemory, (SIZE_T)m_CurrentModes[0].VideoMemoryLength)) {
        uxen_err("user_vram_init failed. Unable to map vram.");
        return STATUS_UNSUCCESSFUL;
    }

    log_tdr_values();

    uxen_v4vlib_set_resume_dpc(&m_resume_dpc, NULL);

    return STATUS_SUCCESS;
}

NTSTATUS BASIC_DISPLAY_DRIVER::StopDevice(VOID)
{
    m_vram_mapper.cleanup();

    dr_deinit(m_DrContext);
    m_DrContext = NULL;

    hw_enable_page_tracking(&m_HwResources);
    hw_cleanup(&m_HwResources);
    CleanUp();

    m_Flags.DriverStarted = FALSE;

    return STATUS_SUCCESS;
}

VOID BASIC_DISPLAY_DRIVER::CleanUp()
{
    for (UINT Source = 0; Source < MAX_VIEWS; ++Source)
    {
        if (m_CurrentModes[Source].FrameBuffer.Ptr)
        {
            UnmapFrameBuffer(m_CurrentModes[Source].FrameBuffer.Ptr, m_CurrentModes[Source].DispInfo.Height * m_CurrentModes[Source].DispInfo.Pitch);
            m_CurrentModes[Source].FrameBuffer.Ptr = NULL;
            m_CurrentModes[Source].Flags.FrameBufferIsActive = FALSE;
        }
        m_HardwareBlt[Source].CleanUp();
    }
}

void BASIC_DISPLAY_DRIVER::Resume()
{
    dr_resume(m_DrContext);
}

NTSTATUS BASIC_DISPLAY_DRIVER::DispatchIoRequest(_In_  ULONG                 VidPnSourceId,
                                                 _In_  VIDEO_REQUEST_PACKET* pVideoRequestPacket)
{
    UNREFERENCED_PARAMETER(VidPnSourceId);
    UNREFERENCED_PARAMETER(pVideoRequestPacket);

    ASSERT(pVideoRequestPacket != NULL);
    ASSERT(VidPnSourceId < MAX_VIEWS);

    return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS BASIC_DISPLAY_DRIVER::SetPowerState(_In_  ULONG              HardwareUid,
                                             _In_  DEVICE_POWER_STATE DevicePowerState,
                                             _In_  POWER_ACTION       ActionType)
{
    UNREFERENCED_PARAMETER(ActionType);

    ASSERT((HardwareUid < MAX_CHILDREN) || (HardwareUid == DISPLAY_ADAPTER_HW_ID));

    if (HardwareUid == DISPLAY_ADAPTER_HW_ID)
    {
        if (DevicePowerState == PowerDeviceD0)
        {

            // When returning from D3 the device visibility defined to be off for all targets
            if (m_AdapterPowerState == PowerDeviceD3)
            {
                DXGKARG_SETVIDPNSOURCEVISIBILITY Visibility;
                Visibility.VidPnSourceId = D3DDDI_ID_ALL;
                Visibility.Visible = FALSE;
                SetVidPnSourceVisibility(&Visibility);
            }
        }

        // Store new adapter power state
        m_AdapterPowerState = DevicePowerState;

        // There is nothing to do to specifically power up/down the display adapter
        return STATUS_SUCCESS;
    }
    else
    {
        // TODO: This is where the specified monitor should be powered up/down
        NOTHING;
        return STATUS_SUCCESS;
    }
}

NTSTATUS BASIC_DISPLAY_DRIVER::QueryChildRelations(_Out_writes_bytes_(ChildRelationsSize) DXGK_CHILD_DESCRIPTOR* pChildRelations,
                                                   _In_                             ULONG                  ChildRelationsSize)
{
    ASSERT(pChildRelations != NULL);

    // The last DXGK_CHILD_DESCRIPTOR in the array of pChildRelations must remain zeroed out, so we subtract this from the count
    ULONG ChildRelationsCount = (ChildRelationsSize / sizeof(DXGK_CHILD_DESCRIPTOR)) - 1;
    ASSERT(ChildRelationsCount <= MAX_CHILDREN);

    for (UINT ChildIndex = 0; ChildIndex < ChildRelationsCount; ++ChildIndex)
    {
        pChildRelations[ChildIndex].ChildDeviceType = TypeVideoOutput;
        pChildRelations[ChildIndex].ChildCapabilities.HpdAwareness = HpdAwarenessInterruptible;
        pChildRelations[ChildIndex].ChildCapabilities.Type.VideoOutput.InterfaceTechnology = m_CurrentModes[0].Flags.IsInternal ? D3DKMDT_VOT_INTERNAL : D3DKMDT_VOT_OTHER;
        pChildRelations[ChildIndex].ChildCapabilities.Type.VideoOutput.MonitorOrientationAwareness = D3DKMDT_MOA_NONE;
        pChildRelations[ChildIndex].ChildCapabilities.Type.VideoOutput.SupportsSdtvModes = FALSE;
        // TODO: Replace 0 with the actual ACPI ID of the child device, if available
        pChildRelations[ChildIndex].AcpiUid = 0;
        pChildRelations[ChildIndex].ChildUid = ChildIndex;
    }

    return STATUS_SUCCESS;
}

NTSTATUS BASIC_DISPLAY_DRIVER::QueryChildStatus(_Inout_ DXGK_CHILD_STATUS* pChildStatus,
                                                _In_    BOOLEAN            NonDestructiveOnly)
{
    UNREFERENCED_PARAMETER(NonDestructiveOnly);
    ASSERT(pChildStatus != NULL);
    ASSERT(pChildStatus->ChildUid < MAX_CHILDREN);

    switch (pChildStatus->Type)
    {
        case StatusConnection:
        {
            // HpdAwarenessInterruptible was reported since HpdAwarenessNone is deprecated.
            // However, BDD has no knowledge of HotPlug events, so just always return connected.
            pChildStatus->HotPlug.Connected = IsDriverActive();
            return STATUS_SUCCESS;
        }

        case StatusRotation:
        {
            // D3DKMDT_MOA_NONE was reported, so this should never be called
            uxen_err("Child status being queried for StatusRotation even though D3DKMDT_MOA_NONE was reported");
            return STATUS_INVALID_PARAMETER;
        }

        default:
        {
            uxen_debug("Unknown pChildStatus->Type (0x%I64x) requested.", pChildStatus->Type);
            return STATUS_NOT_SUPPORTED;
        }
    }
}

// EDID retrieval
NTSTATUS BASIC_DISPLAY_DRIVER::QueryDeviceDescriptor(_In_    ULONG                   ChildUid,
                                                     _Inout_ DXGK_DEVICE_DESCRIPTOR* pDeviceDescriptor)
{
    ASSERT(pDeviceDescriptor != NULL);
    ASSERT(ChildUid < MAX_CHILDREN);

    // If we haven't successfully retrieved an EDID yet (invalid ones are ok, so long as it was retrieved)
    if (!m_Flags.EDID_Attempted)
    {
        GetEdid(ChildUid);

    }

    /* FIXME: what sets these? */
    if (!m_Flags.EDID_Retrieved || !m_Flags.EDID_ValidHeader || !m_Flags.EDID_ValidChecksum)
    {
        // Report no EDID if a valid one wasn't retrieved
        return STATUS_GRAPHICS_CHILD_DESCRIPTOR_NOT_SUPPORTED;
    }
    else if (pDeviceDescriptor->DescriptorOffset == 0)
    {
        // Only the base block is supported
        RtlCopyMemory(pDeviceDescriptor->DescriptorBuffer,
                      m_EDIDs[ChildUid],
                      min(pDeviceDescriptor->DescriptorLength, EDID_V1_BLOCK_SIZE));

        return STATUS_SUCCESS;
    }
    else
    {
        return STATUS_MONITOR_NO_MORE_DESCRIPTOR_DATA;
    }
}

NTSTATUS BASIC_DISPLAY_DRIVER::GetScanLine(_In_ DXGKARG_GETSCANLINE* pGetScanLine)
{
    if (!m_VSync)
        return STATUS_NOT_IMPLEMENTED;

    uxen_debug("GetScanLine");
    pGetScanLine->InVerticalBlank = TRUE;
    pGetScanLine->ScanLine = 0;
    return STATUS_SUCCESS;
}

NTSTATUS BASIC_DISPLAY_DRIVER::ControlInterrupt(_In_ CONST DXGK_INTERRUPT_TYPE InterruptType, _In_ BOOLEAN Enable)
{
    if (!m_VSync)
        return STATUS_NOT_IMPLEMENTED;

    uxen_debug("InterruptType: %d -> %s", (int)InterruptType, (Enable) ? "Enable" : "Disable");
    if (InterruptType == DXGK_INTERRUPT_DISPLAYONLY_VSYNC) {
        if (Enable) {
            DXGKARGCB_NOTIFY_INTERRUPT_DATA data = { DXGK_INTERRUPT_DISPLAYONLY_VSYNC, 0 };
            m_DxgkInterface.DxgkCbNotifyInterrupt((HANDLE)m_DxgkInterface.DeviceHandle, &data);
            m_DxgkInterface.DxgkCbQueueDpc((HANDLE)m_DxgkInterface.DeviceHandle);

            m_track_vblank = 1;
            hw_pv_vblank_enable(&m_HwResources, 1);
        } else {
            m_track_vblank = 0;
            hw_pv_vblank_enable(&m_HwResources, 0);
        }
    }
    return STATUS_SUCCESS;
}

NTSTATUS BASIC_DISPLAY_DRIVER::QueryAdapterInfo(_In_ CONST DXGKARG_QUERYADAPTERINFO* pQueryAdapterInfo)
{
    ASSERT(pQueryAdapterInfo != NULL);

    switch (pQueryAdapterInfo->Type)
    {
        case DXGKQAITYPE_DRIVERCAPS:
        {
            if (pQueryAdapterInfo->OutputDataSize < sizeof(DXGK_DRIVERCAPS))
            {
                uxen_err("pQueryAdapterInfo->OutputDataSize (0x%I64x) is smaller than sizeof(DXGK_DRIVERCAPS) (0x%I64x)", pQueryAdapterInfo->OutputDataSize, sizeof(DXGK_DRIVERCAPS));
                return STATUS_BUFFER_TOO_SMALL;
            }

            DXGK_DRIVERCAPS* pDriverCaps = (DXGK_DRIVERCAPS*)pQueryAdapterInfo->pOutputData;

            // Nearly all fields must be initialized to zero, so zero out to start and then change those that are non-zero.
            // Fields are zero since BDD is Display-Only and therefore does not support any of the render related fields.
            // It also doesn't support hardware interrupts, gamma ramps, etc.
            RtlZeroMemory(pDriverCaps, sizeof(DXGK_DRIVERCAPS));

            pDriverCaps->WDDMVersion = DXGKDDI_WDDMv1_2;
            pDriverCaps->HighestAcceptableAddress.QuadPart = -1;

            pDriverCaps->SupportNonVGA = TRUE;
            pDriverCaps->SupportSmoothRotation = TRUE;

            hw_query_mouse_pointer_caps(pDriverCaps);

            return STATUS_SUCCESS;
        }

        default:
        {
            // BDD does not need to support any other adapter information types
            uxen_debug("Unknown QueryAdapterInfo Type (0x%I64x) requested", pQueryAdapterInfo->Type);
            return STATUS_NOT_SUPPORTED;
        }
    }
}

NTSTATUS BASIC_DISPLAY_DRIVER::SetPointerPosition(_In_ CONST DXGKARG_SETPOINTERPOSITION* pSetPointerPosition)
{
    ASSERT(pSetPointerPosition != NULL);
    ASSERT(pSetPointerPosition->VidPnSourceId < MAX_VIEWS);

    return hw_pointer_setpos(&m_HwResources, pSetPointerPosition);
}

NTSTATUS BASIC_DISPLAY_DRIVER::SetPointerShape(_In_ CONST DXGKARG_SETPOINTERSHAPE* pSetPointerShape)
{
    NTSTATUS status = STATUS_SUCCESS;

    ASSERT(pSetPointerShape != NULL);

    status = hw_pointer_update(&m_HwResources, pSetPointerShape);
    if (!NT_SUCCESS(status)) {
        uxen_err("Setting cursor has failed. Most likely the size is too big: %dx%d",
                pSetPointerShape->Width, pSetPointerShape->Height);
    }
    return status;
}


NTSTATUS BASIC_DISPLAY_DRIVER::PresentDisplayOnly(_In_ CONST DXGKARG_PRESENT_DISPLAYONLY* pPresentDisplayOnly)
{
    NTSTATUS status;

    ASSERT(pPresentDisplayOnly != NULL);
    ASSERT(pPresentDisplayOnly->VidPnSourceId < MAX_VIEWS);

    if (pPresentDisplayOnly->BytesPerPixel < MIN_BYTES_PER_PIXEL_REPORTED)
    {
        // Only >=32bpp modes are reported, therefore this Present should never pass anything less than 4 bytes per pixel
        uxen_err("pPresentDisplayOnly->BytesPerPixel is 0x%I64x, which is lower than the allowed.", pPresentDisplayOnly->BytesPerPixel);
        return STATUS_INVALID_PARAMETER;
    }

    if (m_Flags.UserDraw)
        return STATUS_SUCCESS;

    // If it is in monitor off state or source is not supposed to be visible, don't present anything to the screen
    if ((m_MonitorPowerState > PowerDeviceD0) ||
        (m_CurrentModes[pPresentDisplayOnly->VidPnSourceId].Flags.SourceNotVisible))
    {
        return STATUS_SUCCESS;
    }

    // Present is only valid if the target is actively connected to this source
    if (m_CurrentModes[pPresentDisplayOnly->VidPnSourceId].Flags.FrameBufferIsActive)
    {

        // If actual pixels are coming through, will need to completely zero out physical address next time in BlackOutScreen
        m_CurrentModes[pPresentDisplayOnly->VidPnSourceId].ZeroedOutStart.QuadPart = 0;
        m_CurrentModes[pPresentDisplayOnly->VidPnSourceId].ZeroedOutEnd.QuadPart = 0;


        D3DKMDT_VIDPN_PRESENT_PATH_ROTATION RotationNeededByFb = pPresentDisplayOnly->Flags.Rotate ?
                                                                 m_CurrentModes[pPresentDisplayOnly->VidPnSourceId].Rotation :
                                                                 D3DKMDT_VPPR_IDENTITY;
        BYTE* pDst = (BYTE*)GetDWMFramebufferPtr(pPresentDisplayOnly->VidPnSourceId);
        UINT DstBitPerPixel = BPPFromPixelFormat(m_CurrentModes[pPresentDisplayOnly->VidPnSourceId].DispInfo.ColorFormat);
        if (m_CurrentModes[pPresentDisplayOnly->VidPnSourceId].Scaling == D3DKMDT_VPPS_CENTERED)
        {
            UINT CenterShift = (m_CurrentModes[pPresentDisplayOnly->VidPnSourceId].DispInfo.Height -
                m_CurrentModes[pPresentDisplayOnly->VidPnSourceId].SrcModeHeight)*m_CurrentModes[pPresentDisplayOnly->VidPnSourceId].DispInfo.Pitch;
            CenterShift += (m_CurrentModes[pPresentDisplayOnly->VidPnSourceId].DispInfo.Width -
                m_CurrentModes[pPresentDisplayOnly->VidPnSourceId].SrcModeWidth)*DstBitPerPixel/8;
            pDst += (int)CenterShift/2;
        }

        status = KeWaitForSingleObject(&m_PresentLock, Executive, KernelMode, FALSE, NULL);
        if (status != STATUS_SUCCESS) {
            uxen_err("wait interrupted: %x\n", status);
            return STATUS_SUCCESS;
        }

        for (unsigned int i = 0; i < pPresentDisplayOnly->NumMoves; ++i) {
            POINT *pt = &pPresentDisplayOnly->pMoves[i].SourcePoint;
            RECT *rct = &pPresentDisplayOnly->pMoves[i].DestRect;
            int diff;

            if ((pt->x >= (int)m_VirtMode.width) || (pt->y >= (int)m_VirtMode.height) ||
                (rct->left >= (int)m_VirtMode.width) || (rct->top >= (int)m_VirtMode.height)) {
                RtlZeroMemory(&pPresentDisplayOnly->pMoves[i], sizeof pPresentDisplayOnly->pMoves[i]);
                continue;
            }

            rct->right = min(rct->right, (int)m_VirtMode.width);
            rct->bottom = min(rct->bottom, (int)m_VirtMode.height);

            diff = pt->x + rct->right - rct->left - m_VirtMode.width;
            if (diff > 0)
                rct->right -= diff;
            diff = pt->y + rct->bottom - rct->top - m_VirtMode.height;
            if (diff > 0)
                rct->bottom -= diff;
        }

        for (unsigned int i = 0; i < pPresentDisplayOnly->NumDirtyRects; ++i) {
            pPresentDisplayOnly->pDirtyRect[i].left = min(pPresentDisplayOnly->pDirtyRect[i].left, (int)m_VirtMode.width);
            pPresentDisplayOnly->pDirtyRect[i].top = min(pPresentDisplayOnly->pDirtyRect[i].top, (int)m_VirtMode.height);
            pPresentDisplayOnly->pDirtyRect[i].right = min(pPresentDisplayOnly->pDirtyRect[i].right, (int)m_VirtMode.width);
            pPresentDisplayOnly->pDirtyRect[i].bottom = min(pPresentDisplayOnly->pDirtyRect[i].bottom, (int)m_VirtMode.height);
        }

        if (!m_Flags.StopCopy) {
            status = m_HardwareBlt[pPresentDisplayOnly->VidPnSourceId].ExecutePresentDisplayOnly(pDst,
                                                                    DstBitPerPixel,
                                                                    m_VirtMode.width * 4,
                                                                    (BYTE*)pPresentDisplayOnly->pSource,
                                                                    pPresentDisplayOnly->BytesPerPixel,
                                                                    pPresentDisplayOnly->Pitch,
                                                                    pPresentDisplayOnly->NumMoves,
                                                                    pPresentDisplayOnly->pMoves,
                                                                    pPresentDisplayOnly->NumDirtyRects,
                                                                    pPresentDisplayOnly->pDirtyRect,
                                                                    RotationNeededByFb);
        }

        /* compose into display buffer before sending update, if in composing mode */
        if (m_comp_mode == DISP_COMPOSE_MODE_OVERLAY_DWM_RECTS) {
            int crtc = pPresentDisplayOnly->VidPnSourceId;

            for (unsigned int i = 0; i < pPresentDisplayOnly->NumDirtyRects; ++i) {
                RECT *r = &pPresentDisplayOnly->pDirtyRect[i];
                /* the diffs should be +1 in theory but it makes things unhappy, these calcs few doznes lines
                 * above are screwed in similar fashion */
                /* update: it's required because the calculation on the backend side expects right/bottom to be +1 */
                ComposeDWMRects(crtc, r->left, r->top,
                    r->right - r->left, r->bottom - r->top);
            }
            for (unsigned int i = 0; i < pPresentDisplayOnly->NumMoves; ++i) {
                RECT *r = &pPresentDisplayOnly->pMoves[i].DestRect;
                ComposeDWMRects(crtc, r->left, r->top,
                    r->right - r->left, r->bottom - r->top);
            }
        }

        dr_send(m_DrContext,
                  pPresentDisplayOnly->NumMoves,
                  pPresentDisplayOnly->pMoves,
                  pPresentDisplayOnly->NumDirtyRects,
                  pPresentDisplayOnly->pDirtyRect);
        if (m_Flags.StopCopy)
            dr_flush(m_DrContext);

        KeReleaseSemaphore(&m_PresentLock, 0, 1, FALSE);

        return status;
    }

    return STATUS_SUCCESS;
}

static UINT CompBufferOffset(UINT buf_idx, UINT h, UINT stride)
{
    UINT off = h * stride * buf_idx;

    off +=   PAGE_SIZE-1;
    off &= ~(PAGE_SIZE-1);

    return off;
}

static void CopyRect(BYTE *dst, BYTE *src, UINT stride,
    UINT x, UINT y, UINT w, UINT h)
{
    UINT w_4 = w * 4;

    dst = dst + y * stride + x * 4;
    src = src + y * stride + x * 4;

    while (h--) {
        RtlCopyMemory(dst, src, w_4);
        dst += stride;
        src += stride;
    }
}

void* BASIC_DISPLAY_DRIVER::GetDWMFramebufferPtr(int crtc)
{
    BYTE* p = (BYTE*)m_CurrentModes[crtc].FrameBuffer.Ptr;

    if (m_comp_mode == DISP_COMPOSE_MODE_OVERLAY_DWM_RECTS) {
        /* dwm redirected to secondary fb */
        p += CompBufferOffset(1, m_HwMode.VisScreenHeight, m_HwMode.ScreenStride);
    }

    return p;
}

NTSTATUS BASIC_DISPLAY_DRIVER::ComposeDWMRects(int crtc, int x, int y, int w, int h)
{
    UINT screen_h = m_HwMode.VisScreenHeight;
    UINT stride = m_HwMode.ScreenStride;
    BYTE* fb_composed = (BYTE*)m_CurrentModes[crtc].FrameBuffer.Ptr;
    BYTE* fb_dwm = fb_composed + CompBufferOffset(1, screen_h, stride);

    if (x < 0) x = 0;
    if (y < 0) y = 0;
    if (x > (int)m_HwMode.VisScreenWidth-1 ) x = (int)m_HwMode.VisScreenWidth-1;
    if (y > (int)m_HwMode.VisScreenHeight-1) y = (int)m_HwMode.VisScreenHeight-1;

    /* compose rectangles in buffer 1 (dwm) over buffer 0 (display) */
    for (UINT i = 0; i < m_comp_rects_nb; ++i) {
        UXENDISPComposedRect *rc = &m_comp_rects[i];

        int x0 = rc->x;
        int y0 = rc->y;
        int x1 = rc->x + rc->w - 1;
        int y1 = rc->y + rc->h - 1;

        if (x0 < x) x0 = x;
        if (y0 < y) y0 = y;
        if (x1 > x + w - 1) x1 = x + w - 1;
        if (y1 > y + h - 1) y1 = y + h - 1;
        int w_ = x1 - x0 + 1;
        int h_ = y1 - y0 + 1;

        if (w_ > 0 && h_ > 0 && w_ < 8192 && h_ < 8192) {
            CopyRect(fb_composed, fb_dwm, stride, x0, y0, w_, h_);
        }
    }

    return STATUS_SUCCESS;
}

NTSTATUS BASIC_DISPLAY_DRIVER::UpdateRect(int x, int y, int w, int h)
{
    RECT r = { };

    if (m_comp_mode == DISP_COMPOSE_MODE_OVERLAY_DWM_RECTS) {
        NTSTATUS status = KeWaitForSingleObject(&m_PresentLock, Executive, KernelMode, FALSE, NULL);
        if (status != STATUS_SUCCESS)
            uxen_err("wait interrupted: %x\n", status);
        ComposeDWMRects(0, x, y, w, h);
        KeReleaseSemaphore(&m_PresentLock, 0, 1, FALSE);
    }

    r.left = x;
    r.top = y;
    /* backend expects sent rect right/bottom to be +1 rather than exact coord */
    r.right = x + w;
    r.bottom = y + h;

    dr_send(m_DrContext, 0, NULL, 1, &r);

    return STATUS_SUCCESS;
}

UINT BASIC_DISPLAY_DRIVER::GetFBMapLength(int crtc)
{
    /* fb mapping length is double of the screen size to accomodate secondary buffer. Page aligned. */
    UINT screen_bytes = m_CurrentModes[crtc].DispInfo.Pitch * m_CurrentModes[crtc].DispInfo.Height;

    return ((screen_bytes + PAGE_SIZE-1) & ~(PAGE_SIZE-1)) + screen_bytes;
}

UINT BASIC_DISPLAY_DRIVER::GetCRTCOffset(int crtc, VIDEO_MODE_INFORMATION *mode)
{
    crtc;
    mode;

    return 0;
}

UINT BASIC_DISPLAY_DRIVER::GetCRTCBuffers(int crtc)
{
    crtc;
    if (m_comp_mode == DISP_COMPOSE_MODE_OVERLAY_DWM_RECTS)
        return 2;
    return 1;
}

NTSTATUS BASIC_DISPLAY_DRIVER::UpdateComposedRects(UINT count, UXENDISPComposedRect *rects)
{
    if (count > DISP_COMPOSE_RECT_MAX)
        count = DISP_COMPOSE_RECT_MAX;

    NTSTATUS status = KeWaitForSingleObject(&m_PresentLock, Executive, KernelMode, FALSE, NULL);
    if (status != STATUS_SUCCESS)
        uxen_err("wait interrupted: %x\n", status);

    RtlCopyMemory(&m_comp_rects, rects, sizeof(UXENDISPComposedRect) * count);

    m_comp_rects_nb = count;

    KeReleaseSemaphore(&m_PresentLock, 0, 1, FALSE);

    return STATUS_SUCCESS;
}

NTSTATUS BASIC_DISPLAY_DRIVER::SetComposeMode(UINT mode)
{
    int crtc = 0;
    UINT off, buffers;
    NTSTATUS status;

    status = KeWaitForSingleObject(&m_PresentLock, Executive, KernelMode, FALSE, NULL);
    if (status != STATUS_SUCCESS)
        uxen_err("wait interrupted: %x\n", status);

    if (mode == m_comp_mode) {
        KeReleaseSemaphore(&m_PresentLock, 0, 1, FALSE);
        return STATUS_SUCCESS;
    }

    off = 0;
    buffers = (mode == DISP_COMPOSE_MODE_OVERLAY_DWM_RECTS) ? 2 : 1;

    uxen_msg("changing compose mode: %d, offset %x, buffers %d\n", mode, off, buffers);

    UINT h = m_HwMode.VisScreenHeight;
    UINT stride = m_HwMode.ScreenStride;
    UINT fbsize = h * stride;
    BYTE* fb = (BYTE*)m_CurrentModes[crtc].FrameBuffer.Ptr;

    if (mode == DISP_COMPOSE_MODE_NONE) {
        /* migrate DWM framebuffer: 1 -> 0 */
        RtlCopyMemory(
            fb+CompBufferOffset(0, h, stride),
            fb+CompBufferOffset(1, h, stride),
            fbsize);
    }

    hw_update_crtc_buffers(&m_HwResources, crtc, buffers);
    /* needs to be after buffers update to do crtc flush */
    hw_update_crtc_offset(&m_HwResources, crtc, off);

    if (mode == DISP_COMPOSE_MODE_OVERLAY_DWM_RECTS) {
        /* migrate DWM framebuffer: 0 -> 1 */
        RtlCopyMemory(
            fb+CompBufferOffset(1, h, stride),
            fb+CompBufferOffset(0, h, stride),
            fbsize);
    }
    m_comp_mode = mode;

    KeReleaseSemaphore(&m_PresentLock, 0, 1, FALSE);

    uxen_msg("changing compose mode: %d, offset %x, buffers %d DONE\n", mode, off, buffers);
    return STATUS_SUCCESS;
}

NTSTATUS BASIC_DISPLAY_DRIVER::GetUserDrawOnly(BOOLEAN *ud)
{
    *ud = !!m_Flags.UserDraw;

    return STATUS_SUCCESS;
}

NTSTATUS BASIC_DISPLAY_DRIVER::SetUserDrawOnly(BOOLEAN ud)
{
    if (ud && !hw_is_user_draw_capable(&m_HwResources)) {
        uxen_err("cannot set user draw, no backend capability\n");
        return STATUS_UNSUCCESSFUL;
    }
    hw_user_draw_enable(&m_HwResources, ud);
    m_Flags.UserDraw = ud;
    uxen_msg("set user draw %d\n", (int)ud);

    return STATUS_SUCCESS;
}

NTSTATUS BASIC_DISPLAY_DRIVER::GetNoPresentCopy(BOOLEAN *nocopy)
{
    *nocopy = !!m_Flags.StopCopy;

    return STATUS_SUCCESS;
}

NTSTATUS BASIC_DISPLAY_DRIVER::SetNoPresentCopy(BOOLEAN nocopy)
{
    m_Flags.StopCopy = nocopy;

    uxen_msg("set no present copy %d\n", (int)nocopy);
    return STATUS_SUCCESS;
}

NTSTATUS BASIC_DISPLAY_DRIVER::Flush()
{
    dr_flush(m_DrContext);

    return STATUS_SUCCESS;
}

NTSTATUS BASIC_DISPLAY_DRIVER::ScratchifyProcess(HANDLE pid, int enable)
{
    return m_vram_mapper.process_scratchify(pid, enable);
}

NTSTATUS BASIC_DISPLAY_DRIVER::StopDeviceAndReleasePostDisplayOwnership(_In_  D3DDDI_VIDEO_PRESENT_TARGET_ID TargetId,
                                                                        _Out_ DXGK_DISPLAY_INFORMATION*      pDisplayInfo)
{
    ASSERT(TargetId < MAX_CHILDREN);


    D3DDDI_VIDEO_PRESENT_SOURCE_ID SourceId = FindSourceForTarget(TargetId, TRUE);

    // In case BDD is the next driver to run, the monitor should not be off, since
    // this could cause the BIOS to hang when the EDID is retrieved on Start.
    if (m_MonitorPowerState > PowerDeviceD0)
    {
        SetPowerState(TargetId, PowerDeviceD0, PowerActionNone);
    }

    // The driver has to black out the display and ensure it is visible when releasing ownership
    BlackOutScreen(SourceId, 0);

    *pDisplayInfo = m_CurrentModes[SourceId].DispInfo;

    return StopDevice();
}

NTSTATUS BASIC_DISPLAY_DRIVER::QueryVidPnHWCapability(_Inout_ DXGKARG_QUERYVIDPNHWCAPABILITY* pVidPnHWCaps)
{
    ASSERT(pVidPnHWCaps != NULL);
    ASSERT(pVidPnHWCaps->SourceId < MAX_VIEWS);
    ASSERT(pVidPnHWCaps->TargetId < MAX_CHILDREN);

    pVidPnHWCaps->VidPnHWCaps.DriverRotation             = 1; // BDD does rotation in software
    pVidPnHWCaps->VidPnHWCaps.DriverScaling              = 0; // BDD does not support scaling
    pVidPnHWCaps->VidPnHWCaps.DriverCloning              = 0; // BDD does not support clone
    pVidPnHWCaps->VidPnHWCaps.DriverColorConvert         = 1; // BDD does color conversions in software
    pVidPnHWCaps->VidPnHWCaps.DriverLinkedAdapaterOutput = 0; // BDD does not support linked adapters
    pVidPnHWCaps->VidPnHWCaps.DriverRemoteDisplay        = 0; // BDD does not support remote displays

    return STATUS_SUCCESS;
}

NTSTATUS BASIC_DISPLAY_DRIVER::GetEdid(D3DDDI_VIDEO_PRESENT_TARGET_ID TargetId)
{
    ASSERT(!m_Flags.EDID_Attempted);

    NTSTATUS Status = STATUS_SUCCESS;
    RtlZeroMemory(m_EDIDs[TargetId], sizeof(m_EDIDs[TargetId]));


    m_Flags.EDID_Attempted = TRUE;

    return Status;
}


VOID BASIC_DISPLAY_DRIVER::BlackOutScreen(D3DDDI_VIDEO_PRESENT_SOURCE_ID SourceId, BYTE c)
{
    perfcnt_inc(BlackOutScreen);

    UINT ScreenHeight = m_CurrentModes[SourceId].DispInfo.Height;
    UINT ScreenPitch = m_CurrentModes[SourceId].DispInfo.Pitch;

    PHYSICAL_ADDRESS NewPhysAddrStart = m_CurrentModes[SourceId].DispInfo.PhysicAddress;
    PHYSICAL_ADDRESS NewPhysAddrEnd;
    NewPhysAddrEnd.QuadPart = NewPhysAddrStart.QuadPart + (ScreenHeight * ScreenPitch);

    if (m_CurrentModes[SourceId].Flags.FrameBufferIsActive)
    {
        BYTE* MappedAddr = (BYTE*)(m_CurrentModes[SourceId].FrameBuffer.Ptr);

        // Zero any memory at the start that hasn't been zeroed recently
        if (NewPhysAddrStart.QuadPart < m_CurrentModes[SourceId].ZeroedOutStart.QuadPart)
        {
            if (NewPhysAddrEnd.QuadPart < m_CurrentModes[SourceId].ZeroedOutStart.QuadPart)
            {
                // No overlap
                RtlFillMemory(MappedAddr, ScreenHeight * ScreenPitch, c);
            }
            else
            {
                RtlFillMemory(MappedAddr, (UINT)(m_CurrentModes[SourceId].ZeroedOutStart.QuadPart - NewPhysAddrStart.QuadPart), c);
            }
        }

        // Zero any memory at the end that hasn't been zeroed recently
        if (NewPhysAddrEnd.QuadPart > m_CurrentModes[SourceId].ZeroedOutEnd.QuadPart)
        {
            if (NewPhysAddrStart.QuadPart > m_CurrentModes[SourceId].ZeroedOutEnd.QuadPart)
            {
                // No overlap
                // NOTE: When actual pixels were the most recent thing drawn, ZeroedOutStart & ZeroedOutEnd will both be 0
                // and this is the path that will be used to black out the current screen.
                RtlFillMemory(MappedAddr, ScreenHeight * ScreenPitch, c);
            }
            else
            {
                RtlFillMemory(MappedAddr, (UINT)(NewPhysAddrEnd.QuadPart - m_CurrentModes[SourceId].ZeroedOutEnd.QuadPart), c);
            }
        }
    }

    m_CurrentModes[SourceId].ZeroedOutStart.QuadPart = NewPhysAddrStart.QuadPart;
    m_CurrentModes[SourceId].ZeroedOutEnd.QuadPart = NewPhysAddrEnd.QuadPart;
}

NTSTATUS BASIC_DISPLAY_DRIVER::WriteHWInfoStr(_In_ HANDLE DevInstRegKeyHandle, _In_ PCWSTR pszwValueName, _In_ PCSTR pszValue)
{
    NTSTATUS Status;
    ANSI_STRING AnsiStrValue;
    UNICODE_STRING UnicodeStrValue;
    UNICODE_STRING UnicodeStrValueName;

    // ZwSetValueKey wants the ValueName as a UNICODE_STRING
    RtlInitUnicodeString(&UnicodeStrValueName, pszwValueName);

    // REG_SZ is for WCHARs, there is no equivalent for CHARs
    // Use the ansi/unicode conversion functions to get from PSTR to PWSTR
    RtlInitAnsiString(&AnsiStrValue, pszValue);
    Status = RtlAnsiStringToUnicodeString(&UnicodeStrValue, &AnsiStrValue, TRUE);
    if (!NT_SUCCESS(Status))
    {
        uxen_err("RtlAnsiStringToUnicodeString failed with Status: 0x%I64x", Status);
        return Status;
    }

    // Write the value to the registry
    Status = ZwSetValueKey(DevInstRegKeyHandle,
                           &UnicodeStrValueName,
                           0,
                           REG_SZ,
                           UnicodeStrValue.Buffer,
                           UnicodeStrValue.MaximumLength);

    // Free the earlier allocated unicode string
    RtlFreeUnicodeString(&UnicodeStrValue);

    if (!NT_SUCCESS(Status))
    {
        uxen_err("ZwSetValueKey failed with Status: 0x%I64x", Status);
    }

    return Status;
}

D3DDDI_VIDEO_PRESENT_SOURCE_ID BASIC_DISPLAY_DRIVER::FindSourceForTarget(D3DDDI_VIDEO_PRESENT_TARGET_ID TargetId, BOOLEAN DefaultToZero)
{
    UNREFERENCED_PARAMETER(TargetId);
    ASSERT(TargetId < MAX_CHILDREN);

    for (UINT SourceId = 0; SourceId < MAX_VIEWS; ++SourceId)
    {
        if (m_CurrentModes[SourceId].FrameBuffer.Ptr != NULL)
        {
            return SourceId;
        }
    }

    return DefaultToZero ? 0 : D3DDDI_ID_UNINITIALIZED;
}

VOID BASIC_DISPLAY_DRIVER::DpcRoutine(VOID)
{
    m_DxgkInterface.DxgkCbNotifyDpc((HANDLE)m_DxgkInterface.DeviceHandle);
}

BOOLEAN BASIC_DISPLAY_DRIVER::InterruptRoutine(_In_  ULONG MessageNumber)
{
    UNREFERENCED_PARAMETER(MessageNumber);

    if (m_track_vblank) {
        DXGKRNL_INTERFACE *dxgk_iface = &m_DxgkInterface;
        DXGKARGCB_NOTIFY_INTERRUPT_DATA data = { DXGK_INTERRUPT_DISPLAYONLY_VSYNC, 0 };

        dxgk_iface->DxgkCbNotifyInterrupt((HANDLE)dxgk_iface->DeviceHandle, &data);
        dxgk_iface->DxgkCbQueueDpc((HANDLE)dxgk_iface->DeviceHandle);
    }

    hw_clearvblankirq(&m_HwResources);

    return TRUE;
}

VOID BASIC_DISPLAY_DRIVER::ResetDevice(VOID)
{
}

NTSTATUS BASIC_DISPLAY_DRIVER::IsVirtModeEnabled()
{
    return hw_is_virt_mode_enabled(&m_HwResources);
}

// Must be Non-Paged, as it sets up the display for a bugcheck
NTSTATUS BASIC_DISPLAY_DRIVER::SystemDisplayEnable(_In_  D3DDDI_VIDEO_PRESENT_TARGET_ID TargetId,
                                                   _In_  PDXGKARG_SYSTEM_DISPLAY_ENABLE_FLAGS Flags,
                                                   _Out_ UINT* pWidth,
                                                   _Out_ UINT* pHeight,
                                                   _Out_ D3DDDIFORMAT* pColorFormat)
{
    UNREFERENCED_PARAMETER(Flags);

    m_SystemDisplaySourceId = D3DDDI_ID_UNINITIALIZED;

    ASSERT((TargetId < MAX_CHILDREN) || (TargetId == D3DDDI_ID_UNINITIALIZED));

    // Find the frame buffer for displaying the bugcheck, if it was successfully mapped
    if (TargetId == D3DDDI_ID_UNINITIALIZED)
    {
        for (UINT SourceIdx = 0; SourceIdx < MAX_VIEWS; ++SourceIdx)
        {
            if (m_CurrentModes[SourceIdx].FrameBuffer.Ptr != NULL)
            {
                m_SystemDisplaySourceId = SourceIdx;
                break;
            }
        }
    }
    else
    {
        m_SystemDisplaySourceId = FindSourceForTarget(TargetId, FALSE);
    }

    if (m_SystemDisplaySourceId == D3DDDI_ID_UNINITIALIZED)
    {
        {
            return STATUS_UNSUCCESSFUL;
        }
    }

    if ((m_CurrentModes[m_SystemDisplaySourceId].Rotation == D3DKMDT_VPPR_ROTATE90) ||
        (m_CurrentModes[m_SystemDisplaySourceId].Rotation == D3DKMDT_VPPR_ROTATE270))
    {
        *pHeight = m_CurrentModes[m_SystemDisplaySourceId].DispInfo.Width;
        *pWidth = m_CurrentModes[m_SystemDisplaySourceId].DispInfo.Height;
    }
    else
    {
        *pWidth = m_CurrentModes[m_SystemDisplaySourceId].DispInfo.Width;
        *pHeight = m_CurrentModes[m_SystemDisplaySourceId].DispInfo.Height;
    }

    *pColorFormat = m_CurrentModes[m_SystemDisplaySourceId].DispInfo.ColorFormat;


    return STATUS_SUCCESS;
}

// Must be Non-Paged, as it is called to display the bugcheck screen
VOID BASIC_DISPLAY_DRIVER::SystemDisplayWrite(_In_reads_bytes_(SourceHeight * SourceStride) VOID* pSource,
                                              _In_ UINT SourceWidth,
                                              _In_ UINT SourceHeight,
                                              _In_ UINT SourceStride,
                                              _In_ INT PositionX,
                                              _In_ INT PositionY)
{

    // Rect will be Offset by PositionX/Y in the src to reset it back to 0
    RECT Rect;
    Rect.left = PositionX;
    Rect.top = PositionY;
    Rect.right =  Rect.left + SourceWidth;
    Rect.bottom = Rect.top + SourceHeight;

    // Set up destination blt info
    BLT_INFO DstBltInfo;
    DstBltInfo.pBits = m_CurrentModes[m_SystemDisplaySourceId].FrameBuffer.Ptr;
    DstBltInfo.Pitch = m_CurrentModes[m_SystemDisplaySourceId].DispInfo.Pitch;
    DstBltInfo.BitsPerPel = BPPFromPixelFormat(m_CurrentModes[m_SystemDisplaySourceId].DispInfo.ColorFormat);
    DstBltInfo.Offset.x = 0;
    DstBltInfo.Offset.y = 0;
    DstBltInfo.Rotation = m_CurrentModes[m_SystemDisplaySourceId].Rotation;
    DstBltInfo.Width = m_CurrentModes[m_SystemDisplaySourceId].DispInfo.Width;
    DstBltInfo.Height = m_CurrentModes[m_SystemDisplaySourceId].DispInfo.Height;

    // Set up source blt info
    BLT_INFO SrcBltInfo;
    SrcBltInfo.pBits = pSource;
    SrcBltInfo.Pitch = SourceStride;
    SrcBltInfo.BitsPerPel = 32;

    SrcBltInfo.Offset.x = -PositionX;
    SrcBltInfo.Offset.y = -PositionY;
    SrcBltInfo.Rotation = D3DKMDT_VPPR_IDENTITY;
    SrcBltInfo.Width = SourceWidth;
    SrcBltInfo.Height = SourceHeight;

    BltBits(&DstBltInfo,
            &SrcBltInfo,
            1, // NumRects
            &Rect);
}

