/*
 * Copyright 2015-2016, Bromium, Inc.
 * Author: Julian Pidancet <julian@pidancet.net>
 * SPDX-License-Identifier: ISC
 */

#ifndef _UXENDISP_H_
#define _UXENDISP_H_

#include <no_sal2.h>
#include <initguid.h>

// NTOS headers
#include <ntddk.h>

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

#include <debug.h>
#include <uxendisp-common.h>
#include "dirty_rect.h"
#include "version.h"

/* PCI vendor and device IDs. */
#define UXENDISP_PCI_VEN    0x5853
#define UXENDISP_PCI_DEV    0x5102

#define UXENDISP_REFRESH_RATE 60

extern BOOLEAN g_dod;

struct _UXENDISP_DRIVER_ALLOCATION;

// Zero is unused by D3DKMDT_STANDARDALLOCATION_TYPE
typedef enum _UXENDISP_STANDARDALLOCATION_TYPE {
    UXENDISP_USERALLOCATION_TYPE       = 0,
    UXENDISP_SHAREDPRIMARYSURFACE_TYPE = 1,
    UXENDISP_SHADOWSURFACE_TYPE        = 2,
    UXENDISP_STAGINGSURFACE_TYPE       = 3
} UXENDISP_STANDARDALLOCATION_TYPE;

#define UXENDISP_ALLOCATION_STATE_NONE         0x00000000
#define UXENDISP_ALLOCATION_STATE_ASSIGNED     0x00000001
#define UXENDISP_ALLOCATION_STATE_VISIBLE      0x00000002

typedef struct _UXENDISP_SURFACE_DESC {
    ULONG XResolution;
    ULONG YResolution;
    ULONG BytesPerPixel;
    ULONG Stride;
    D3DDDIFORMAT Format;
    D3DDDI_RATIONAL RefreshRate;
} UXENDISP_SURFACE_DESC, *PUXENDISP_SURFACE_DESC;

typedef struct _UXENDISP_D3D_ALLOCATION {
    UXENDISP_STANDARDALLOCATION_TYPE Type;
    BOOLEAN Primary;
    D3DDDI_VIDEO_PRESENT_SOURCE_ID VidPnSourceId;
    UXENDISP_SURFACE_DESC SurfaceDesc;
    ULONG ByteAlignment; // StrideAlignment + 1 for alignment bytes
} UXENDISP_D3D_ALLOCATION, *PUXENDISP_D3D_ALLOCATION;

typedef struct _UXENDISP_SOURCE{
    BOOLEAN in_use;
    struct _UXENDISP_DRIVER_ALLOCATION *primary_allocation;
} UXENDISP_SOURCE, *PUXENDISP_SOURCE;

typedef struct _UXENDISP_MODE {
    ULONG xres;
    ULONG yres;
    LONG stride;
    ULONG fmt;
#define UXENDISP_MODE_FLAG_PREFERRED 0x1
    ULONG flags;
} UXENDISP_MODE, *PUXENDISP_MODE;

typedef struct _UXENDISP_CRTC {
    ULONG crtcid;
    BOOLEAN connected;
    UXENDISP_MODE curr_mode;
    UXENDISP_MODE next_mode;
    D3DDDI_VIDEO_PRESENT_SOURCE_ID sourceid;
    PHYSICAL_ADDRESS primary_address;
    PVOID fb;
    D3DDDI_VIDEO_PRESENT_SOURCE_ID staged_sourceid;
#define UXENDISP_CRTC_STAGED_FLAG_DISABLE 0x1
#define UXENDISP_CRTC_STAGED_FLAG_SKIP 0x2
    ULONG staged_flags;
} UXENDISP_CRTC, *PUXENDISP_CRTC;

typedef struct _DEVICE_EXTENSION {
    volatile ULONG initialized;
    HANDLE dxgkhdl;
    DXGK_START_INFO dxgksi;
    DXGKRNL_INTERFACE dxgkif;
    DEVICE_OBJECT *pdo;
    PHYSICAL_ADDRESS vram_phys;
    ULONG vram_len;
    PHYSICAL_ADDRESS mmio_phys;
    ULONG mmio_len;
    UINT8 *mmio;
    ULONG crtc_count;
    KSPIN_LOCK crtc_lock;
    UXENDISP_CRTC *crtcs;
    UXENDISP_SOURCE *sources;
    KSPIN_LOCK sources_lock;
    BOOLEAN cursor_visible;
    UINT current_fence;
    void *dr_ctx;
    KDPC vsync_dpc;
    KTIMER vsync_timer;
} DEVICE_EXTENSION, *PDEVICE_EXTENSION;

typedef struct _UXENDISP_D3D_DEVICE {
    HANDLE devhdl;
    DEVICE_EXTENSION *dev;
} UXENDISP_D3D_DEVICE, *PUXENDISP_D3D_DEVICE;

typedef struct _UXENDISP_DRIVER_ALLOCATION {
    UXENDISP_STANDARDALLOCATION_TYPE type;
    ULONG state;
    D3DDDI_VIDEO_PRESENT_SOURCE_ID sourceid;
    UXENDISP_SURFACE_DESC surface_desc;
    ULONG align;
    D3DKMT_HANDLE allochdl;
    PHYSICAL_ADDRESS addr;
} UXENDISP_DRIVER_ALLOCATION, *PUXENDISP_DRIVER_ALLOCATION;

typedef enum _UXENDISP_CONTEXT_TYPE {
    UXENDISP_CONTEXT_TYPE_NONE      = 0,
    UXENDISP_CONTEXT_TYPE_SYSTEM    = 1,
    UXENDISP_CONTEXT_TYPE_GDI       = 2,
} UXENDISP_CONTEXT_TYPE, *PUXENDISP_CONTEXT_TYPE;

typedef struct _UXENDISP_D3D_CONTEXT {
    UXENDISP_D3D_DEVICE *d3ddev;
    UXENDISP_CONTEXT_TYPE type;
    UINT node_ordinal;
    UINT engine_affinity;
} UXENDISP_D3D_CONTEXT, *PUXENDISP_D3D_CONTEXT;

#define UXENDISP_TAG 'uXdi'

#include "../../../../../dm/hw/uxdisp_hw.h" /* XXX */

static INLINE ULONG
uxdisp_read(PDEVICE_EXTENSION dev, ULONG reg)
{
    return READ_REGISTER_ULONG((ULONG *)(dev->mmio + reg));
}

static INLINE void
uxdisp_write(PDEVICE_EXTENSION dev, ULONG reg, ULONG val)
{
    WRITE_REGISTER_ULONG((ULONG *)(dev->mmio + reg), val);
}

static INLINE ULONG
uxdisp_crtc_read(PDEVICE_EXTENSION dev, ULONG crtc, ULONG reg)
{
    return uxdisp_read(dev, UXDISP_REG_CRTC(crtc) + reg);
}

static INLINE void
uxdisp_crtc_write(PDEVICE_EXTENSION dev, ULONG crtc, ULONG reg, ULONG val)
{
    uxdisp_write(dev, UXDISP_REG_CRTC(crtc) + reg, val);
}

/* DDI */
VOID uXenDispControlEtwLogging(BOOLEAN Enable, ULONG Flags, UCHAR Level);
NTSTATUS APIENTRY uXenDispQueryAdapterInfo(CONST HANDLE hAdapter,
                                           CONST DXGKARG_QUERYADAPTERINFO *pQueryAdapterInfo);
NTSTATUS APIENTRY uXenDispCreateDevice(CONST HANDLE hAdapter,
                                       DXGKARG_CREATEDEVICE *pCreateDevice);
NTSTATUS APIENTRY uXenDispCreateAllocation(CONST HANDLE hAdapter,
                                           DXGKARG_CREATEALLOCATION *pCreateAllocation);
NTSTATUS APIENTRY uXenDispDestroyAllocation(CONST HANDLE hAdapter,
                                            CONST DXGKARG_DESTROYALLOCATION *pDestroyAllocation);
NTSTATUS APIENTRY uXenDispDescribeAllocation(CONST HANDLE hAdapter,
                                             DXGKARG_DESCRIBEALLOCATION *pDescribeAlloc);
NTSTATUS APIENTRY uXenDispGetStandardAllocationDriverData(CONST HANDLE hAdapter,
                                                          DXGKARG_GETSTANDARDALLOCATIONDRIVERDATA *pStandardAllocationDriverData);
NTSTATUS APIENTRY uXenDispAcquireSwizzlingRange(CONST HANDLE hAdapter,
                                                DXGKARG_ACQUIRESWIZZLINGRANGE *pAcquireSwizzlingRange);
NTSTATUS APIENTRY uXenDispReleaseSwizzlingRange(CONST HANDLE hAdapter,
                                                CONST DXGKARG_RELEASESWIZZLINGRANGE *pReleaseSwizzlingRange);
NTSTATUS APIENTRY uXenDispPatch(CONST HANDLE hAdapter,
                                CONST DXGKARG_PATCH *pPatch);
NTSTATUS APIENTRY uXenDispSubmitCommand(CONST HANDLE hAdapter,
                                        CONST DXGKARG_SUBMITCOMMAND *pSubmitCommand);
NTSTATUS APIENTRY uXenDispPreemptCommand(CONST HANDLE hAdapter,
                                         CONST DXGKARG_PREEMPTCOMMAND *pPreemptCommand);
NTSTATUS APIENTRY uXenDispBuildPagingBuffer(CONST HANDLE hAdapter,
                                            DXGKARG_BUILDPAGINGBUFFER *pBuildPagingBuffer);
NTSTATUS APIENTRY uXenDispSetPalette(CONST HANDLE hAdapter,
                                     CONST DXGKARG_SETPALETTE *pSetPalette);
NTSTATUS APIENTRY uXenDispSetPointerPosition(CONST HANDLE hAdapter,
                                             CONST DXGKARG_SETPOINTERPOSITION *pSetPointerPosition);
NTSTATUS APIENTRY uXenDispSetPointerShape(CONST HANDLE hAdapter,
                                          CONST DXGKARG_SETPOINTERSHAPE *pSetPointerShape);
NTSTATUS APIENTRY CALLBACK uXenDispResetFromTimeout(CONST HANDLE hAdapter);
NTSTATUS APIENTRY CALLBACK uXenDispRestartFromTimeout(CONST HANDLE hAdapter);
NTSTATUS APIENTRY uXenDispEscape(CONST HANDLE hAdapter, CONST DXGKARG_ESCAPE *pEscape);
NTSTATUS APIENTRY uXenDispCollectDbgInfo(HANDLE hAdapter,
                                         CONST DXGKARG_COLLECTDBGINFO *pCollectDbgInfo);
NTSTATUS APIENTRY uXenDispQueryCurrentFence(CONST HANDLE hAdapter,
                                            DXGKARG_QUERYCURRENTFENCE *pCurrentFence);
NTSTATUS APIENTRY uXenDispGetScanLine(CONST HANDLE hAdapter,
                                      DXGKARG_GETSCANLINE *pGetScanLine);
NTSTATUS APIENTRY uXenDispStopCapture(CONST HANDLE hAdapter,
                                      CONST DXGKARG_STOPCAPTURE *pStopCapture);
NTSTATUS APIENTRY uXenDispControlInterrupt(CONST HANDLE hAdapter,
                                           CONST DXGK_INTERRUPT_TYPE InterruptType,
                                           BOOLEAN Enable);
NTSTATUS APIENTRY uXenDispDestroyDevice(CONST HANDLE hDevice);
NTSTATUS APIENTRY uXenDispOpenAllocation(CONST HANDLE hDevice,
                                         CONST DXGKARG_OPENALLOCATION *pOpenAllocation);
NTSTATUS APIENTRY uXenDispCloseAllocation(CONST HANDLE hDevice,
                                          CONST DXGKARG_CLOSEALLOCATION *pCloseAllocation);
NTSTATUS APIENTRY uXenDispRender(CONST HANDLE hContext,
                                 DXGKARG_RENDER *pRender);
NTSTATUS APIENTRY uXenDispPresent(CONST HANDLE hContext,
                                  DXGKARG_PRESENT *pPresent);
NTSTATUS APIENTRY uXenDispPresentDisplayOnly(HANDLE hDevice,
                                  CONST DXGKARG_PRESENT_DISPLAYONLY* pPresentDisplayOnly);
NTSTATUS APIENTRY uXenDispCreateContext(CONST HANDLE hDevice,
                                        DXGKARG_CREATECONTEXT *pCreateContext);
NTSTATUS APIENTRY uXenDispDestroyContext(CONST HANDLE hContext);

/* VidPN */
NTSTATUS APIENTRY uXenDispIsSupportedVidPn(CONST HANDLE  hAdapter,
                                           DXGKARG_ISSUPPORTEDVIDPN *pIsSupportedVidPn);
NTSTATUS APIENTRY uXenDispRecommendFunctionalVidPn(CONST HANDLE hAdapter,
                                                   CONST DXGKARG_RECOMMENDFUNCTIONALVIDPN *CONST pRecommendFunctionalVidPn);
NTSTATUS APIENTRY uXenDispEnumVidPnCofuncModality(CONST HANDLE hAdapter,
                                                  CONST DXGKARG_ENUMVIDPNCOFUNCMODALITY *CONST pEnumCofuncModality);
NTSTATUS APIENTRY uXenDispSetVidPnSourceAddress(CONST HANDLE hAdapter,
                                                CONST DXGKARG_SETVIDPNSOURCEADDRESS *pSetVidPnSourceAddress);
NTSTATUS APIENTRY uXenDispSetVidPnSourceVisibility(CONST HANDLE hAdapter,
                                                   CONST DXGKARG_SETVIDPNSOURCEVISIBILITY *pSetVidPnSourceVisibility);
NTSTATUS APIENTRY uXenDispCommitVidPn(CONST HANDLE hAdapter,
                                      CONST DXGKARG_COMMITVIDPN *CONST pCommitVidPn);
NTSTATUS APIENTRY uXenDispUpdateActiveVidPnPresentPath(CONST HANDLE hAdapter,
                                                       CONST DXGKARG_UPDATEACTIVEVIDPNPRESENTPATH *CONST pUpdateActiveVidPnPresentPath);
NTSTATUS APIENTRY uXenDispRecommendMonitorModes(CONST HANDLE hAdapter,
                                                CONST DXGKARG_RECOMMENDMONITORMODES *CONST pRecommendMonitorModes);
NTSTATUS APIENTRY uXenDispRecommendVidPnTopology(CONST HANDLE hAdapter,
                                                 CONST DXGKARG_RECOMMENDVIDPNTOPOLOGY *CONST pRecommendVidPnTopology);
NTSTATUS APIENTRY uXenDispQueryVidPnHWCapability(CONST HANDLE hAdapter,
                                                 DXGKARG_QUERYVIDPNHWCAPABILITY* pVidPnHWCaps);
/* Crtc */
VOID uXenDispDetectChildStatusChanges(DEVICE_EXTENSION *dev);
VOID uXenDispCrtcDisablePageTracking(DEVICE_EXTENSION *dev);
NTSTATUS uXenDispCrtcDisable(DEVICE_EXTENSION *dev, UXENDISP_CRTC *crtc);
NTSTATUS uXenDispCrtcEnable(DEVICE_EXTENSION *dev, UXENDISP_CRTC *crtc);

/* Edid */
LONG edid_get_modes(UCHAR *edid, SIZE_T edid_len,
                    UXENDISP_MODE *modes, ULONG max_modes);

#endif /* _UXENDISP_H_ */
