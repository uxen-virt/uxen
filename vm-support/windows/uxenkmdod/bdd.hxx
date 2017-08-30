/******************************Module*Header*******************************\
* Module Name: BDD.hxx
*
* Basic Display Driver header file
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

#ifndef _BDD_HXX_
#define _BDD_HXX_

#include <no_sal2.h>

extern "C"
{
    #define __CPLUSPLUS

    // Standard C-runtime headers
    #include <stddef.h>
    #include <string.h>
    #include <stdarg.h>
    #include <stdio.h>
    #include <stdlib.h>

    #include <initguid.h>

    // NTOS headers
    #include <ntddk.h>
    #include <wdmsec.h>

    #ifndef FAR
    #define FAR
    #endif

    // Windows headers
    #include <windef.h>
    #include <winerror.h>

    // Windows GDI headers
    #include <wingdi.h>

    // Windows DDI headers
    #include <winddi.h>
    #include <ntddvdeo.h>

    #include <d3dkmddi.h>
    #include <d3dkmthk.h>

    #include <ntstrsafe.h>
    #include <ntintsafe.h>

    #include <dispmprt.h>
};
#include <uxendisp-common.h>
#include "../common/debug.h"
#include "perfcnt.h"
#include "dirty_rect.h"
#include "user_vram.h"

#define MIN_BYTES_PER_PIXEL_REPORTED   4

#define BITS_PER_BYTE                  8
#define EDID_V1_BLOCK_SIZE           128

extern DXGKRNL_INTERFACE g_DxgkInterface;

typedef struct _BLT_INFO
{
    PVOID pBits;
    UINT Pitch;
    UINT BitsPerPel;
    POINT Offset; // To unrotated top-left of dirty rects
    D3DKMDT_VIDPN_PRESENT_PATH_ROTATION Rotation;
    UINT Width; // For the unrotated image
    UINT Height; // For the unrotated image
} BLT_INFO;

#define MAX_CHILDREN                   1
#define MAX_VIEWS                      1

typedef struct _BDD_FLAGS
{
    UINT DriverStarted           : 1; // ( 1) 1 after StartDevice and 0 after StopDevice
    UINT EDID_Retrieved          : 1; // ( 2) EDID was successfully retrieved
    UINT EDID_ValidChecksum      : 1; // ( 3) Retrieved EDID has a valid checksum
    UINT EDID_ValidHeader        : 1; // ( 4) Retrieved EDID has a valid header
    UINT EDID_Attempted          : 1; // ( 5) 1 if an attempt was made to retrieve the EDID, successful or not
    UINT StopCopy                : 1; // ( 6) Stop doing memcpy in Present call
    UINT UserDraw                : 1; // ( 7) Stop doing any drawing in Present call, userspace draws via mapped fb
    // IMPORTANT: All new flags must be added to just before _LastFlag (i.e. right above this comment), this allows different versions of diagnostics to still be useful.
    UINT _LastFlag               : 1; // ( 8) Always set to 1, is used to ensure that diagnostic version matches binary version
    UINT Unused                  : 24;
} BDD_FLAGS;

// Represents the current mode, may not always be set (i.e. frame buffer mapped) if representing the mode passed in on single mode setups.
typedef struct _CURRENT_BDD_MODE
{
    // The source mode currently set for HW Framebuffer
    // For sample driver this info filled in StartDevice by the OS and never changed.
    DXGK_DISPLAY_INFORMATION             DispInfo;

    // The rotation of the current mode. Rotation is performed in software during Present call
    D3DKMDT_VIDPN_PRESENT_PATH_ROTATION  Rotation;

    D3DKMDT_VIDPN_PRESENT_PATH_SCALING Scaling;
    // This mode might be different from one which are supported for HW frame buffer
    // Scaling/displasment might be needed (if supported)
    UINT SrcModeWidth;
    UINT SrcModeHeight;

    // Various boolean flags the struct uses
    struct _CURRENT_BDD_MODE_FLAGS
    {
        UINT SourceNotVisible     : 1; // 0 if source is visible
        UINT FullscreenPresent    : 1; // 0 if should use dirty rects for present
        UINT FrameBufferIsActive  : 1; // 0 if not currently active (i.e. target not connected to source)
        UINT DoNotMapOrUnmap      : 1; // 1 if the FrameBuffer should not be (un)mapped during normal execution
        UINT IsInternal           : 1; // 1 if it was determined (i.e. through ACPI) that an internal panel is being driven
        UINT Unused               : 27;
    } Flags;

    // The start and end of physical memory known to be all zeroes. Used to optimize the BlackOutScreen function to not write
    // zeroes to memory already known to be zero. (Physical address is located in DispInfo)
    PHYSICAL_ADDRESS ZeroedOutStart;
    PHYSICAL_ADDRESS ZeroedOutEnd;

    PHYSICAL_ADDRESS VideoMemory;
    ULONGLONG VideoMemoryLength;

    // Linear frame buffer pointer
    // A union with a ULONG64 is used here to ensure this struct looks the same on 32bit and 64bit builds
    // since the size of a VOID* changes depending on the build.
    union
    {
        VOID*                            Ptr;
        ULONG64                          Force8Bytes;
    } FrameBuffer;
} CURRENT_BDD_MODE;

class BASIC_DISPLAY_DRIVER;

class BDD_HWBLT
{
public:
    D3DDDI_VIDEO_PRESENT_SOURCE_ID  m_SourceId;
    BASIC_DISPLAY_DRIVER*           m_DevExt;
    HANDLE                          m_hPresentWorkerThread;
    PVOID                           m_pPresentWorkerThread;

    //  Events to contol thread execution
    KEVENT                          m_hThreadStartupEvent;
    KEVENT                          m_hThreadSuspendEvent;

    void Init();
    void CleanUp();

    void Initialize(_In_ BASIC_DISPLAY_DRIVER* DevExt, _In_ UINT IdSrc) { m_DevExt = DevExt; m_SourceId = IdSrc; }
    void SetPresentWorkerThreadInfo(HANDLE hWorkerThread);
    NTSTATUS ExecutePresentDisplayOnly(_In_ BYTE*             DstAddr,
                                       _In_ UINT              DstBitPerPixel,
                                       _In_ LONG              DstPitch,
                                       _In_ BYTE*             SrcAddr,
                                       _In_ UINT              SrcBytesPerPixel,
                                       _In_ LONG              SrcPitch,
                                       _In_ ULONG             NumMoves,
                                       _In_ D3DKMT_MOVE_RECT* pMoves,
                                       _In_ ULONG             NumDirtyRects,
                                       _In_ RECT*             pDirtyRect,
                                       _In_ D3DKMDT_VIDPN_PRESENT_PATH_ROTATION Rotation);

};

typedef struct _UXEN_HW_RESOURCES {
    PHYSICAL_ADDRESS mmioPhysicalAddress;
    ULONGLONG mmioLength;
    PCHAR pMmio;
    ULONG hwptrFlags;
} UXEN_HW_RESOURCES, *PUXEN_HW_RESOURCES;

class BASIC_DISPLAY_DRIVER
{
public:
  int m_track_vblank;
  DXGKRNL_INTERFACE m_DxgkInterface;

private:
    DEVICE_OBJECT* m_pPhysicalDevice;

    // Information passed in by StartDevice DDI
    DXGK_START_INFO m_StartInfo;


    // Array of EDIDs, currently only supporting base block, hence EDID_V1_BLOCK_SIZE for size of each EDID
    BYTE m_EDIDs[MAX_CHILDREN][EDID_V1_BLOCK_SIZE];

    CURRENT_BDD_MODE m_CurrentModes[MAX_VIEWS];

    UXENDISPCustomMode m_NextMode;

    UXENDISPCustomMode m_VirtMode;

    VIDEO_MODE_INFORMATION m_HwMode;

    KSEMAPHORE         m_PresentLock;

    BDD_HWBLT        m_HardwareBlt[MAX_VIEWS];

    // Current monitorpower state (this needs to be changed if MAX_CHILDREN != 1)
    DEVICE_POWER_STATE m_MonitorPowerState;

    // Current adapter power state
    DEVICE_POWER_STATE m_AdapterPowerState;

    // Source ID to be used by SystemDisplay functions
    D3DDDI_VIDEO_PRESENT_SOURCE_ID m_SystemDisplaySourceId;

    // Various boolean flags the class uses
    BDD_FLAGS m_Flags;

    // Device information
    DXGK_DEVICE_INFO m_DeviceInfo;

    int m_VSync;

    UXEN_HW_RESOURCES m_HwResources;

    dr_ctx_t m_DrContext;

    UserVramMapper m_vram_mapper;

    LARGE_INTEGER due_time;

    KDPC m_resume_dpc;

    UXENDISPComposedRect m_comp_rects[DISP_COMPOSE_RECT_MAX];

    UINT m_comp_rects_nb;

    UINT m_comp_mode;

public:
    VOID Init(_In_ DEVICE_OBJECT* pPhysicalDeviceObject);
    VOID CleanUp();

    BOOLEAN IsDriverActive() const
    {
        return m_Flags.DriverStarted;
    }

    NTSTATUS StartDevice(_In_  DXGK_START_INFO*   pDxgkStartInfo,
                         _In_  DXGKRNL_INTERFACE* pDxgkInterface,
                         _Out_ ULONG*             pNumberOfViews,
                         _Out_ ULONG*             pNumberOfChildren);

    NTSTATUS StopDevice(VOID);

    // Must be Non-Paged
    VOID ResetDevice(VOID);

    void Resume();

    const CURRENT_BDD_MODE* GetCurrentMode(UINT SourceId) const
    {
        return (SourceId < MAX_VIEWS)?&m_CurrentModes[SourceId]:NULL;
    }
    const DXGKRNL_INTERFACE* GetDxgkInterface() const { return &m_DxgkInterface;}

    // Not implemented since no IOCTLs currently handled.
    NTSTATUS DispatchIoRequest(_In_  ULONG                 VidPnSourceId,
                               _In_  VIDEO_REQUEST_PACKET* pVideoRequestPacket);

    // Used to either turn off/on monitor (if possible), or mark that system is going into hibernate
    NTSTATUS SetPowerState(_In_  ULONG              HardwareUid,
                           _In_  DEVICE_POWER_STATE DevicePowerState,
                           _In_  POWER_ACTION       ActionType);

    // Report back child capabilities
    NTSTATUS QueryChildRelations(_Out_writes_bytes_(ChildRelationsSize) DXGK_CHILD_DESCRIPTOR* pChildRelations,
                                 _In_                             ULONG                  ChildRelationsSize);

    NTSTATUS QueryChildStatus(_Inout_ DXGK_CHILD_STATUS* pChildStatus,
                              _In_    BOOLEAN            NonDestructiveOnly);

    // Return EDID if previously retrieved
    NTSTATUS QueryDeviceDescriptor(_In_    ULONG                   ChildUid,
                                   _Inout_ DXGK_DEVICE_DESCRIPTOR* pDeviceDescriptor);

    // Must be Non-Paged
    // BDD doesn't have interrupts, so just returns false
    BOOLEAN InterruptRoutine(_In_  ULONG MessageNumber);

    VOID DpcRoutine(VOID);

    // Return DriverCaps, doesn't support other queries though
    NTSTATUS QueryAdapterInfo(_In_ CONST DXGKARG_QUERYADAPTERINFO* pQueryAdapterInfo);

    NTSTATUS SetPointerPosition(_In_ CONST DXGKARG_SETPOINTERPOSITION* pSetPointerPosition);

    NTSTATUS SetPointerShape(_In_ CONST DXGKARG_SETPOINTERSHAPE* pSetPointerShape);

    NTSTATUS PresentDisplayOnly(_In_ CONST DXGKARG_PRESENT_DISPLAYONLY* pPresentDisplayOnly);

    NTSTATUS IsSupportedVidPn(_Inout_ DXGKARG_ISSUPPORTEDVIDPN* pIsSupportedVidPn);

    NTSTATUS RecommendFunctionalVidPn(_In_ CONST DXGKARG_RECOMMENDFUNCTIONALVIDPN* CONST pRecommendFunctionalVidPn);

    NTSTATUS RecommendMonitorModes(_In_ CONST DXGKARG_RECOMMENDMONITORMODES* CONST pRecommendMonitorModes);

    NTSTATUS EnumVidPnCofuncModality(_In_ CONST DXGKARG_ENUMVIDPNCOFUNCMODALITY* CONST pEnumCofuncModality);

    NTSTATUS SetVidPnSourceVisibility(_In_ CONST DXGKARG_SETVIDPNSOURCEVISIBILITY* pSetVidPnSourceVisibility);

    NTSTATUS CommitVidPn(_In_ CONST DXGKARG_COMMITVIDPN* CONST pCommitVidPn);

    NTSTATUS GetScanLine(_In_ DXGKARG_GETSCANLINE* pGetScanLine);

    NTSTATUS ControlInterrupt(_In_ CONST DXGK_INTERRUPT_TYPE InterruptType, _In_ BOOLEAN Enable);

    NTSTATUS UpdateActiveVidPnPresentPath(_In_ CONST DXGKARG_UPDATEACTIVEVIDPNPRESENTPATH* CONST pUpdateActiveVidPnPresentPath);

    NTSTATUS QueryVidPnHWCapability(_Inout_ DXGKARG_QUERYVIDPNHWCAPABILITY* pVidPnHWCaps);

    // Part of PnPStop (PnP instance only), returns current mode information (which will be passed to fallback instance by dxgkrnl)
    NTSTATUS StopDeviceAndReleasePostDisplayOwnership(_In_  D3DDDI_VIDEO_PRESENT_TARGET_ID TargetId,
                                                      _Out_ DXGK_DISPLAY_INFORMATION*      pDisplayInfo);

    // Must be Non-Paged
    // Call to initialize as part of bugcheck
    NTSTATUS SystemDisplayEnable(_In_  D3DDDI_VIDEO_PRESENT_TARGET_ID       TargetId,
                                 _In_  PDXGKARG_SYSTEM_DISPLAY_ENABLE_FLAGS Flags,
                                 _Out_ UINT*                                pWidth,
                                 _Out_ UINT*                                pHeight,
                                 _Out_ D3DDDIFORMAT*                        pColorFormat);

    // Must be Non-Paged
    // Write out pixels as part of bugcheck
    VOID SystemDisplayWrite(_In_reads_bytes_(SourceHeight * SourceStride) VOID* pSource,
                            _In_                                     UINT  SourceWidth,
                            _In_                                     UINT  SourceHeight,
                            _In_                                     UINT  SourceStride,
                            _In_                                     INT   PositionX,
                            _In_                                     INT   PositionY);

    // Inject new mode and trigger mode change
    NTSTATUS SetNextMode(UXENDISPCustomMode* pNewMode);

    NTSTATUS SetVirtMode(UXENDISPCustomMode* pNewMode);

    NTSTATUS IsVirtModeEnabled();

    NTSTATUS MapUserVram(void **data);

    NTSTATUS UnmapUserVram(void *data);

    NTSTATUS MapScratchVram(void **data);

    NTSTATUS UnmapScratchVram(void *data);

    NTSTATUS UpdateRect(int x, int y, int w, int h);

    NTSTATUS GetUserDrawOnly(BOOLEAN *ud);

    NTSTATUS SetUserDrawOnly(BOOLEAN ud);

    NTSTATUS GetNoPresentCopy(BOOLEAN *nocopy);

    NTSTATUS SetNoPresentCopy(BOOLEAN nocopy);

    NTSTATUS Flush();

    // Replace all user framebuffer mappings in a given process with scratch mappings
    NTSTATUS ScratchifyProcess(HANDLE pid, int enable);

    NTSTATUS UpdateComposedRects(UINT count, UXENDISPComposedRect *rects);

    NTSTATUS SetComposeMode(UINT mode);

private:

    NTSTATUS CommonStart();

    NTSTATUS GetEdid(D3DDDI_VIDEO_PRESENT_TARGET_ID TargetId);

    NTSTATUS GetResources(_In_ PCM_RESOURCE_LIST pResList);

    // Given pixel format, give back the bits per pixel. Only supports pixel formats expected by BDD
    // (i.e. the ones found below in PixelFormatFromBPP or that may come in from FallbackStart)
    // This is because these two functions combine to allow BDD to store the bpp of a VBE mode in the
    // ColorFormat field of a DispInfo
    UINT BPPFromPixelFormat(D3DDDIFORMAT Format) const
    {
        switch (Format)
        {
            case D3DDDIFMT_UNKNOWN: return 0;
            case D3DDDIFMT_P8: return 8;
            case D3DDDIFMT_R5G6B5: return 16;
            case D3DDDIFMT_R8G8B8: return 24;
            case D3DDDIFMT_X8R8G8B8: // fall through
            case D3DDDIFMT_A8R8G8B8: return 32;
            default: ASSERT_FAIL("Unknown D3DDDIFORMAT 0x%I64x", Format); return 0;
        }
    }

    // Given bits per pixel, return the pixel format at the same bpp
    D3DDDIFORMAT PixelFormatFromBPP(UINT BPP) const
    {
        switch (BPP)
        {
            case  8: return D3DDDIFMT_P8;
            case 16: return D3DDDIFMT_R5G6B5;
            case 24: return D3DDDIFMT_R8G8B8;
            case 32: return D3DDDIFMT_X8R8G8B8;
            default: ASSERT_FAIL("A bit per pixel of 0x%I64x is not supported.", BPP); return D3DDDIFMT_UNKNOWN;
        }
    }

#ifdef VERIFY_VIDPN
    // These two functions make checks on the values of some of the fields of their respective structures to ensure
    // that the specified fields are supported by BDD, i.e. gamma ramp must be D3DDDI_GAMMARAMP_DEFAULT
    NTSTATUS IsVidPnPathFieldsValid(CONST D3DKMDT_VIDPN_PRESENT_PATH* pPath) const;
    NTSTATUS IsVidPnSourceModeFieldsValid(CONST D3DKMDT_VIDPN_SOURCE_MODE* pSourceMode) const;
#endif  /* VERIFY_VIDPN */

    VOID BlackOutScreen(D3DDDI_VIDEO_PRESENT_SOURCE_ID SourceId, BYTE c);

    // Returns the index into gBddBiosData.BddModes of the VBE mode that matches the given VidPnSourceMode.
    // If such a mode cannot be found, returns a number outside of [0, gBddBiosData.CountBddModes)
    UINT FindMatchingVBEMode(CONST D3DKMDT_VIDPN_SOURCE_MODE* pSourceMode) const;

    // Must be Non-Paged
    // Returns the SourceId that has TargetId as a valid frame buffer or D3DDDI_ID_UNINITIALIZED if no such SourceId exists
    D3DDDI_VIDEO_PRESENT_SOURCE_ID FindSourceForTarget(D3DDDI_VIDEO_PRESENT_TARGET_ID TargetId, BOOLEAN DefaultToZero);

    // Set the given source mode on the given path
    NTSTATUS SetSourceModeAndPath(CONST D3DKMDT_VIDPN_SOURCE_MODE* pSourceMode,
                                  CONST D3DKMDT_VIDPN_PRESENT_PATH* pPath);


    // Add the current mode to the given monitor source mode set
    NTSTATUS AddSingleMonitorMode(_In_ CONST DXGKARG_RECOMMENDMONITORMODES* CONST pRecommendMonitorModes);

    // Add the current mode to the given VidPn source mode set
    NTSTATUS AddSingleSourceMode(_In_ CONST DXGK_VIDPNSOURCEMODESET_INTERFACE* pVidPnSourceModeSetInterface,
                                 D3DKMDT_HVIDPNSOURCEMODESET hVidPnSourceModeSet,
                                 D3DDDI_VIDEO_PRESENT_SOURCE_ID SourceId);

    // Add the current mode (or the matching to pinned source mode) to the give VidPn target mode set
    NTSTATUS AddSingleTargetMode(_In_ CONST DXGK_VIDPNTARGETMODESET_INTERFACE* pVidPnTargetModeSetInterface,
                                 D3DKMDT_HVIDPNTARGETMODESET hVidPnTargetModeSet,
                                 _In_opt_ CONST D3DKMDT_VIDPN_SOURCE_MODE* pVidPnPinnedSourceModeInfo,
                                 D3DDDI_VIDEO_PRESENT_SOURCE_ID SourceId);

    // Helper function for RegisterHWInfo
    NTSTATUS WriteHWInfoStr(_In_ HANDLE DevInstRegKeyHandle, _In_ PCWSTR pszwValueName, _In_ PCSTR pszValue);

    // Set the information in the registry as described here: http://msdn.microsoft.com/en-us/library/windows/hardware/ff569240(v=vs.85).aspx
    NTSTATUS RegisterHWInfo();

    NTSTATUS ComposeDWMRects(int crtc, int x, int y, int w, int h);

    void* GetDWMFramebufferPtr(int crtc);

    UINT GetFBMapLength(int crtc);

    UINT GetCRTCOffset(int crtc, VIDEO_MODE_INFORMATION *mode);

    UINT GetCRTCBuffers(int crtc);
};

//
// Blt functions
//

// Must be Non-Paged
VOID BltBits(
    BLT_INFO* pDst,
    CONST BLT_INFO* pSrc,
    UINT  NumRects,
    _In_reads_(NumRects) CONST RECT *pRects);

//
// Driver Entry point
//

extern "C"
DRIVER_INITIALIZE DriverEntry;

//
// PnP DDIs
//

VOID
BddDdiUnload(VOID);

// If uncommenting ENABLE_DXGK_SAL in the sources file, all the below function prototypes should be updated to use
// the function typedef's from the header files. Additionally, annotations on the function definitions can be removed
// as they are inherited from the prototype definition here. As an example the entire 4-line prototype for BddDdiAddDevice
// is replaced by the single commented line below:
// DXGKDDI_ADD_DEVICE BddDdiAddDevice;
NTSTATUS
BddDdiAddDevice(
    _In_ DEVICE_OBJECT* pPhysicalDeviceObject,
    _Outptr_ PVOID*  ppDeviceContext);

NTSTATUS
BddDdiRemoveDevice(
    _In_  VOID* pDeviceContext);

NTSTATUS
BddDdiStartDevice(
    _In_  VOID*              pDeviceContext,
    _In_  DXGK_START_INFO*   pDxgkStartInfo,
    _In_  DXGKRNL_INTERFACE* pDxgkInterface,
    _Out_ ULONG*             pNumberOfViews,
    _Out_ ULONG*             pNumberOfChildren);

NTSTATUS
BddDdiStopDevice(
    _In_  VOID* pDeviceContext);

VOID
BddDdiResetDevice(
    _In_  VOID* pDeviceContext);


NTSTATUS
BddDdiDispatchIoRequest(
    _In_  VOID*                 pDeviceContext,
    _In_  ULONG                 VidPnSourceId,
    _In_  VIDEO_REQUEST_PACKET* pVideoRequestPacket);

NTSTATUS
BddDdiSetPowerState(
    _In_  VOID*              pDeviceContext,
    _In_  ULONG              HardwareUid,
    _In_  DEVICE_POWER_STATE DevicePowerState,
    _In_  POWER_ACTION       ActionType);

NTSTATUS
BddDdiQueryChildRelations(
    _In_                             VOID*                  pDeviceContext,
    _Out_writes_bytes_(ChildRelationsSize) DXGK_CHILD_DESCRIPTOR* pChildRelations,
    _In_                             ULONG                  ChildRelationsSize);

NTSTATUS
BddDdiQueryChildStatus(
    _In_    VOID*              pDeviceContext,
    _Inout_ DXGK_CHILD_STATUS* pChildStatus,
    _In_    BOOLEAN            NonDestructiveOnly);

NTSTATUS
BddDdiQueryDeviceDescriptor(
    _In_  VOID*                     pDeviceContext,
    _In_  ULONG                     ChildUid,
    _Inout_ DXGK_DEVICE_DESCRIPTOR* pDeviceDescriptor);

// Must be Non-Paged
BOOLEAN
BddDdiInterruptRoutine(
    _In_  VOID* pDeviceContext,
    _In_  ULONG MessageNumber);

VOID
BddDdiDpcRoutine(
    _In_  VOID* pDeviceContext);

//
// WDDM Display Only Driver DDIs
//

NTSTATUS
APIENTRY
BddDdiQueryAdapterInfo(
    _In_ CONST HANDLE                         hAdapter,
    _In_ CONST DXGKARG_QUERYADAPTERINFO*      pQueryAdapterInfo);

NTSTATUS
APIENTRY
BddDdiSetPointerPosition(
    _In_ CONST HANDLE                         hAdapter,
    _In_ CONST DXGKARG_SETPOINTERPOSITION*    pSetPointerPosition);

NTSTATUS 
APIENTRY
BddDdiEscape(
    IN_CONST_HANDLE                           hAdapter,
    IN_CONST_PDXGKARG_ESCAPE                  pEscape);

NTSTATUS
APIENTRY
BddDdiSetPointerShape(
    _In_ CONST HANDLE                         hAdapter,
    _In_ CONST DXGKARG_SETPOINTERSHAPE*       pSetPointerShape);

NTSTATUS
APIENTRY
BddDdiPresentDisplayOnly(
    _In_ CONST HANDLE                         hAdapter,
    _In_ CONST DXGKARG_PRESENT_DISPLAYONLY*   pPresentDisplayOnly);

NTSTATUS
APIENTRY
BddDdiIsSupportedVidPn(
    _In_ CONST HANDLE                         hAdapter,
    _Inout_ DXGKARG_ISSUPPORTEDVIDPN*         pIsSupportedVidPn);

NTSTATUS
APIENTRY
BddDdiRecommendFunctionalVidPn(
    _In_ CONST HANDLE                                   hAdapter,
    _In_ CONST DXGKARG_RECOMMENDFUNCTIONALVIDPN* CONST  pRecommendFunctionalVidPn);

NTSTATUS
APIENTRY
BddDdiRecommendVidPnTopology(
    _In_ CONST HANDLE                                 hAdapter,
    _In_ CONST DXGKARG_RECOMMENDVIDPNTOPOLOGY* CONST  pRecommendVidPnTopology);

NTSTATUS
APIENTRY
BddDdiRecommendMonitorModes(
    _In_ CONST HANDLE                                hAdapter,
    _In_ CONST DXGKARG_RECOMMENDMONITORMODES* CONST  pRecommendMonitorModes);

NTSTATUS
APIENTRY
BddDdiEnumVidPnCofuncModality(
    _In_ CONST HANDLE                                  hAdapter,
    _In_ CONST DXGKARG_ENUMVIDPNCOFUNCMODALITY* CONST  pEnumCofuncModality);

NTSTATUS
APIENTRY
BddDdiSetVidPnSourceVisibility(
    _In_ CONST HANDLE                             hAdapter,
    _In_ CONST DXGKARG_SETVIDPNSOURCEVISIBILITY*  pSetVidPnSourceVisibility);

NTSTATUS
APIENTRY
BddDdiCommitVidPn(
    _In_ CONST HANDLE                         hAdapter,
    _In_ CONST DXGKARG_COMMITVIDPN* CONST     pCommitVidPn);

NTSTATUS
APIENTRY
BddDdiGetScanLine(
    _In_ CONST HANDLE                     hAdapter,
    _In_ DXGKARG_GETSCANLINE*             pGetScanLine);

NTSTATUS
APIENTRY
BddDdiControlInterrupt(
    _In_ CONST HANDLE                     hAdapter,
    _In_ CONST DXGK_INTERRUPT_TYPE        InterruptType,
    _In_       BOOLEAN                    Enable);

NTSTATUS
APIENTRY
BddDdiUpdateActiveVidPnPresentPath(
    _In_ CONST HANDLE                                       hAdapter,
    _In_ CONST DXGKARG_UPDATEACTIVEVIDPNPRESENTPATH* CONST  pUpdateActiveVidPnPresentPath);

NTSTATUS
APIENTRY
BddDdiQueryVidPnHWCapability(
    _In_ CONST HANDLE                         hAdapter,
    _Inout_ DXGKARG_QUERYVIDPNHWCAPABILITY*   pVidPnHWCaps);

NTSTATUS
APIENTRY
BddDdiStopDeviceAndReleasePostDisplayOwnership(
    _In_  VOID*                          pDeviceContext,
    _In_  D3DDDI_VIDEO_PRESENT_TARGET_ID TargetId,
    _Out_ DXGK_DISPLAY_INFORMATION*      DisplayInfo);

// Must be Non-Paged
NTSTATUS
APIENTRY
BddDdiSystemDisplayEnable(
    _In_  VOID* pDeviceContext,
    _In_  D3DDDI_VIDEO_PRESENT_TARGET_ID TargetId,
    _In_  PDXGKARG_SYSTEM_DISPLAY_ENABLE_FLAGS Flags,
    _Out_ UINT* Width,
    _Out_ UINT* Height,
    _Out_ D3DDDIFORMAT* ColorFormat);

// Must be Non-Paged
VOID
APIENTRY
BddDdiSystemDisplayWrite(
    _In_  VOID* pDeviceContext,
    _In_  VOID* Source,
    _In_  UINT  SourceWidth,
    _In_  UINT  SourceHeight,
    _In_  UINT  SourceStride,
    _In_  UINT  PositionX,
    _In_  UINT  PositionY);

//
// Frame buffer map/unmap
//

NTSTATUS
MapFrameBuffer(
    _In_                       PHYSICAL_ADDRESS    PhysicalAddress,
    _In_                       ULONG               Length,
    _Outptr_result_bytebuffer_(Length) VOID**              VirtualAddress);

NTSTATUS
UnmapFrameBuffer(
    _In_reads_bytes_(Length) VOID* VirtualAddress,
    _In_                ULONG Length);


#ifdef VERIFY_EDID
BOOLEAN
IsEdidHeaderValid(const BYTE* pEdid);

BOOLEAN
IsEdidChecksumValid(const BYTE* pEdid);
#endif  /* VERIFY_EDID */

NTSTATUS
RegGetDWORD(ULONG RelativeTo, PWSTR Path, PWSTR  ParameterName, PULONG ParameterValue);

// Pool allocation tag for the Sample Display Driver. All allocations use this tag.
#define BDDTAG 'DDBS'

#endif // _BDD_HXX_


