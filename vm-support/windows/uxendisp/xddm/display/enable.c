/*
 * Copyright 2012-2016, Bromium, Inc.
 * Author: Julian Pidancet <julian@pidancet.net>
 * SPDX-License-Identifier: ISC
 */

#include "driver.h"

#include <uxendisp_esc.h>
#include "perfcnt.h"

// The driver function table with all function index/address pairs

static DRVFN gadrvfn[] =
{
    {   INDEX_DrvEnablePDEV,            (PFN) DrvEnablePDEV         },
    {   INDEX_DrvCompletePDEV,          (PFN) DrvCompletePDEV       },
    {   INDEX_DrvDisablePDEV,           (PFN) DrvDisablePDEV        },
    {   INDEX_DrvEnableSurface,         (PFN) DrvEnableSurface      },
    {   INDEX_DrvOffset,                (PFN) DrvOffset             },
    {   INDEX_DrvDisableSurface,        (PFN) DrvDisableSurface     },
    {   INDEX_DrvAssertMode,            (PFN) DrvAssertMode         },
    {   INDEX_DrvSetPalette,            (PFN) DrvSetPalette         },
    {   INDEX_DrvMovePointer,           (PFN) DrvMovePointer        },
    {   INDEX_DrvSetPointerShape,       (PFN) DrvSetPointerShape    },
    {   INDEX_DrvDitherColor,           (PFN) DrvDitherColor        },
    {   INDEX_DrvGetModes,              (PFN) DrvGetModes           },
    {   INDEX_DrvDisableDriver,         (PFN) DrvDisableDriver      },
    {   INDEX_DrvEscape,                (PFN) DrvEscape             },
    {   INDEX_DrvSynchronize,           (PFN) DrvSynchronize        },
    {   INDEX_DrvTextOut,               (PFN) DrvTextOut            },
    {   INDEX_DrvBitBlt,                (PFN) DrvBitBlt             },
    {   INDEX_DrvCopyBits,              (PFN) DrvCopyBits           },
    {   INDEX_DrvStrokePath,            (PFN) DrvStrokePath         },
    {   INDEX_DrvLineTo,                (PFN) DrvLineTo             },
    {   INDEX_DrvFillPath,              (PFN) DrvFillPath           },
    {   INDEX_DrvStretchBlt,            (PFN) DrvStretchBlt         },
};

// Define the functions you want to hook for 8/16/24/32 pel formats
#define flGlobalHooks  HOOK_BITBLT|HOOK_TEXTOUT|HOOK_COPYBITS|HOOK_STROKEPATH|HOOK_LINETO|HOOK_FILLPATH|HOOK_STRETCHBLT|HOOK_SYNCHRONIZE

#define HOOKS_BMF8BPP flGlobalHooks

#define HOOKS_BMF16BPP flGlobalHooks

#define HOOKS_BMF24BPP flGlobalHooks

#define HOOKS_BMF32BPP flGlobalHooks

#define USHRT_MAX 0xffff

ULONG DrvEscape(SURFOBJ *pso, ULONG iEsc, ULONG cjIn, PVOID pvIn,
                ULONG cjOut, PVOID pvOut)
{
    PDEV*   ppdev = (PDEV *)pso->dhpdev;
    UXENDISPCustomMode *mode = (UXENDISPCustomMode *)pvIn;
    ULONG   ret = 0;
    ULONG   len;

    perfcnt_inc(DrvEscape);

    switch (iEsc) {
    case UXENDISP_ESCAPE_SET_CUSTOM_MODE: {
            if ((cjIn < sizeof *mode) || !pvIn) {
                DISPDBG((0, "%s: ioctl failed wrong input size\n", __FUNCTION__));
                break;
            }

            DISPDBG((0, "%s: SET_CUSTOM_MODE\n", __FUNCTION__));
            EngWaitForSingleObject(ppdev->virt_lock, NULL);

            if (EngDeviceIoControl(ppdev->hDriver, IOCTL_UXENDISP_SET_CUSTOM_MODE,
                                   pvIn, cjIn, NULL, 0, &len)) {
                DISPDBG((0, "%s: ioctl IOCTL_UXENDISP_SET_CUSTOM_MODE failed\n", __FUNCTION__));
                EngSetEvent(ppdev->virt_lock);
                break;
            }

            ppdev->virt_w = mode->width;
            ppdev->virt_h = mode->height;

            EngSetEvent(ppdev->virt_lock);
            ret = 1;
        }
        break;
    case UXENDISP_ESCAPE_SET_VIRTUAL_MODE: {
            if ((cjIn < sizeof *mode) || !pvIn) {
                DISPDBG((0, "%s: ioctl failed wrong input size\n", __FUNCTION__));
                break;
            }

            EngWaitForSingleObject(ppdev->virt_lock, NULL);

            if (EngDeviceIoControl(ppdev->hDriver, IOCTL_UXENDISP_SET_VIRTUAL_MODE,
                                   pvIn, cjIn, NULL, 0, &len)) {
                DISPDBG((0, "%s: ioctl IOCTL_UXENDISP_SET_VIRTUAL_MODE failed\n", __FUNCTION__));
                EngSetEvent(ppdev->virt_lock);
                break;
            }

            ppdev->virt_w = mode->width;
            ppdev->virt_h = mode->height;
            ppdev->psoBitmap->lDelta = mode->width * 4;

            EngSetEvent(ppdev->virt_lock);
            ret = 1;
        }
        break;
    case UXENDISP_ESCAPE_IS_VIRT_MODE_ENABLED:
        if (!EngDeviceIoControl(ppdev->hDriver, IOCTL_UXENDISP_IS_VIRT_MODE_ENABLED, NULL, 0, NULL, 0, &len))
            ret = 1;
        break;
    default:
        DISPDBG((0, "Unhandled escape code %x\n", iEsc));
    }

    return ret;
}

/******************************Public*Routine******************************\
* DrvEnableDriver
*
* Enables the driver by retrieving the drivers function table and version.
*
\**************************************************************************/

BOOL DrvEnableDriver(
ULONG iEngineVersion,
ULONG cj,
PDRVENABLEDATA pded)
{
// Engine Version is passed down so future drivers can support previous
// engine versions.  A next generation driver can support both the old
// and new engine conventions if told what version of engine it is
// working with.  For the first version the driver does nothing with it.

    iEngineVersion;

    perfcnt_inc(DrvEnableDriver);

// Fill in as much as we can.

    if (cj >= sizeof(DRVENABLEDATA))
        pded->pdrvfn = gadrvfn;

    if (cj >= (sizeof(ULONG) * 2))
        pded->c = sizeof(gadrvfn) / sizeof(DRVFN);

// DDI version this driver was targeted for is passed back to engine.
// Future graphic's engine may break calls down to old driver format.

    if (cj >= sizeof(ULONG))
        pded->iDriverVersion = DDI_DRIVER_VERSION_NT4;

    return(TRUE);
}

/******************************Public*Routine******************************\
* DrvDisableDriver
*
* Tells the driver it is being disabled. Release any resources allocated in
* DrvEnableDriver.
*
\**************************************************************************/

VOID DrvDisableDriver(VOID)
{
    perfcnt_inc(DrvDisableDriver);

    return;
}

/******************************Public*Routine******************************\
* DrvEnablePDEV
*
* DDI function, Enables the Physical Device.
*
* Return Value: device handle to pdev.
*
\**************************************************************************/

DHPDEV DrvEnablePDEV(
DEVMODEW   *pDevmode,       // Pointer to DEVMODE
PWSTR       pwszLogAddress, // Logical address
ULONG       cPatterns,      // number of patterns
HSURF      *ahsurfPatterns, // return standard patterns
ULONG       cjGdiInfo,      // Length of memory pointed to by pGdiInfo
ULONG      *pGdiInfo,       // Pointer to GdiInfo structure
ULONG       cjDevInfo,      // Length of following PDEVINFO structure
DEVINFO    *pDevInfo,       // physical device information structure
HDEV        hdev,           // HDEV, used for callbacks
PWSTR       pwszDeviceName, // DeviceName - not used
HANDLE      hDriver)        // Handle to base driver
{
    GDIINFO GdiInfo;
    DEVINFO DevInfo;
    PPDEV   ppdev = (PPDEV) NULL;
    DWORD Len;

    UNREFERENCED_PARAMETER(pwszLogAddress);
    UNREFERENCED_PARAMETER(pwszDeviceName);

    perfcnt_inc(DrvEnablePDEV);

    // Allocate a physical device structure.

    ppdev = (PPDEV) EngAllocMem(FL_ZERO_MEMORY, sizeof(PDEV), ALLOC_TAG);

    if (ppdev == (PPDEV) NULL)
    {
        DISPDBG((0, "DISP DrvEnablePDEV failed EngAllocMem\n"));
        return((DHPDEV) 0);
    }

    memset(ppdev, 0, sizeof(PDEV));

    // Save the screen handle in the PDEV.

    ppdev->hDriver = hDriver;

    // Get the current screen mode information.  Set up device caps and devinfo.

    if (!bInitPDEV(ppdev, pDevmode, &GdiInfo, &DevInfo))
    {
        DISPDBG((0,"DISP DrvEnablePDEV failed\n"));
        goto error_free;
    }

    // Initialize the cursor information.

    if (!bInitPointer(ppdev, &DevInfo))
    {
        // Not a fatal error...
        DISPDBG((0, "DrvEnablePDEV failed bInitPointer\n"));
    }

    // Initialize palette information.

    if (!bInitPaletteInfo(ppdev, &DevInfo))
    {
        DISPDBG((0, "DrvEnablePDEV failed bInitPalette\n"));
        goto error_free;
    }

    // Copy the devinfo into the engine buffer.

    memcpy(pDevInfo, &DevInfo, min(sizeof(DEVINFO), cjDevInfo));

    // Set the pdevCaps with GdiInfo we have prepared to the list of caps for this
    // pdev.

    memcpy(pGdiInfo, &GdiInfo, min(cjGdiInfo, sizeof(GDIINFO)));

    if (EngDeviceIoControl(ppdev->hDriver,
        IOCTL_UXENDISP_GET_UPDATE_RECT,
        NULL,
        0,
        &ppdev->updateRect,
        sizeof(ppdev->updateRect),
        &Len))
    {
        DISPDBG((0, "DISP IOCTL_UXENDISP_GET_UPDATE_RECT failed IOCTL\n"));
        goto error_free;
    }

    EngCreateEvent(&ppdev->virt_lock);

    return((DHPDEV) ppdev);

    // Error case for failure.
error_free:
    EngFreeMem(ppdev);
    return((DHPDEV) 0);
}

/******************************Public*Routine******************************\
* DrvCompletePDEV
*
* Store the HPDEV, the engines handle for this PDEV, in the DHPDEV.
*
\**************************************************************************/

VOID DrvCompletePDEV(
DHPDEV dhpdev,
HDEV  hdev)
{
    perfcnt_inc(DrvCompletePDEV);

    ((PPDEV) dhpdev)->hdevEng = hdev;
}

/******************************Public*Routine******************************\
* DrvDisablePDEV
*
* Release the resources allocated in DrvEnablePDEV.  If a surface has been
* enabled DrvDisableSurface will have already been called.
*
\**************************************************************************/

VOID DrvDisablePDEV(
DHPDEV dhpdev)
{
    perfcnt_inc(DrvDisablePDEV);
    EngDeleteEvent(((PPDEV)dhpdev)->virt_lock);
    vDisablePalette((PPDEV) dhpdev);
    EngFreeMem(dhpdev);
}

/******************************Public*Routine******************************\
* VOID DrvOffset
*
* DescriptionText
*
\**************************************************************************/

BOOL DrvOffset(
SURFOBJ*    pso,
LONG        x,
LONG        y,
FLONG       flReserved)
{
    PDEV*   ppdev = (PDEV*) pso->dhpdev;

    // Add back last offset that we subtracted.  I could combine the next
    // two statements, but I thought this was more clear.  It's not
    // performance critical anyway.

    perfcnt_inc(DrvOffset);

    ppdev->pjScreen += ((ppdev->ptlOrg.y * ppdev->lDeltaScreen) +
                        (ppdev->ptlOrg.x * ((ppdev->ulBitCount+1) >> 3)));

    // Subtract out new offset

    ppdev->pjScreen -= ((y * ppdev->lDeltaScreen) +
                        (x * ((ppdev->ulBitCount+1) >> 3)));

    ppdev->ptlOrg.x = x;
    ppdev->ptlOrg.y = y;

    return(TRUE);
}

/******************************Public*Routine******************************\
* DrvEnableSurface
*
* Enable the surface for the device.  Hook the calls this driver supports.
*
* Return: Handle to the surface if successful, 0 for failure.
*
\**************************************************************************/

HSURF DrvEnableSurface(
DHPDEV dhpdev)
{
    PPDEV ppdev;
    HSURF hsurf;
    SIZEL sizl;
    ULONG ulBitmapType;
    FLONG flHooks;

    perfcnt_inc(DrvEnableSurface);

    // Create engine bitmap around frame buffer.

    ppdev = (PPDEV) dhpdev;

    ppdev->ptlOrg.x = 0;
    ppdev->ptlOrg.y = 0;

    if (!bInitSURF(ppdev, TRUE))
    {
        DISPDBG((0, "DISP DrvEnableSurface failed bInitSURF\n"));
        return(FALSE);
    }

    sizl.cx = ppdev->cxScreen;
    sizl.cy = ppdev->cyScreen;

    if (ppdev->ulBitCount == 8)
    {
        if (!bInit256ColorPalette(ppdev)) {
            DISPDBG((0, "DISP DrvEnableSurface failed to init the 8bpp palette\n"));
            return(FALSE);
        }
        ulBitmapType = BMF_8BPP;
        flHooks = HOOKS_BMF8BPP;
    }
    else if (ppdev->ulBitCount == 16)
    {
        ulBitmapType = BMF_16BPP;
        flHooks = HOOKS_BMF16BPP;
    }
    else if (ppdev->ulBitCount == 24)
    {
        ulBitmapType = BMF_24BPP;
        flHooks = HOOKS_BMF24BPP;
    }
    else
    {
        ulBitmapType = BMF_32BPP;
        flHooks = HOOKS_BMF32BPP;
    }

    ppdev->flHooks = flHooks;

    ppdev->hBitmap = EngCreateBitmap(sizl, ppdev->lDeltaScreen, ulBitmapType,
                                     ppdev->lDeltaScreen > 0 ? BMF_TOPDOWN : 0,
                                     ppdev->pjScreen);
    if (!ppdev->hBitmap)
    {
        DISPDBG((0, "DISP DrvEnableSurface failed EngCreateBitmap\n"));
        return(FALSE);
    }

    ppdev->psoBitmap = EngLockSurface((HSURF)ppdev->hBitmap);

    hsurf = (HSURF)EngCreateDeviceSurface((DHSURF)ppdev,
                                           sizl,
                                           ulBitmapType);

    if (hsurf == (HSURF) 0)
    {
        DISPDBG((0, "DISP DrvEnableSurface failed EngCreateDeviceSurface\n"));
        return(FALSE);
    }

    /* Associate created surface with our device */
    if (!EngAssociateSurface(hsurf, ppdev->hdevEng, flHooks))
    {
        DISPDBG((0, "DISP DrvEnableSurface failed EngAssociateSurface\n"));
        return(FALSE);
    }

    ppdev->hsurfEng = hsurf;

    return(hsurf);
}

/******************************Public*Routine******************************\
* DrvDisableSurface
*
* Free resources allocated by DrvEnableSurface.  Release the surface.
*
\**************************************************************************/

VOID DrvDisableSurface(
DHPDEV dhpdev)
{
    PPDEV ppdev = (PPDEV) dhpdev;

    perfcnt_inc(DrvDisableSurface);

    if (ppdev->hsurfEng)
    {
        EngDeleteSurface(ppdev->hsurfEng);
        ppdev->hsurfEng = NULL;
    }
    if (ppdev->psoBitmap)
    {
        EngUnlockSurface(ppdev->psoBitmap);
        ppdev->psoBitmap = NULL;
    }
    if (ppdev->hBitmap)
    {
        EngDeleteSurface((HSURF) ppdev->hBitmap);
        ppdev->hBitmap = NULL;
    }

    vDisableSURF(ppdev);
}

/******************************Public*Routine******************************\
* DrvAssertMode
*
* This asks the device to reset itself to the mode of the pdev passed in.
*
\**************************************************************************/

BOOL DrvAssertMode(
DHPDEV dhpdev,
BOOL bEnable)
{
    PPDEV   ppdev = (PPDEV) dhpdev;
    ULONG   ulReturn;
    PBYTE   pjScreen;

    perfcnt_inc(DrvAssertMode);

    if (bEnable)
    {

        //
        // The screen must be reenabled, reinitialize the device to clean state.
        //

        pjScreen = ppdev->pjScreen;

        if (!bInitSURF(ppdev, FALSE))
        {
            DISPDBG((0, "DISP DrvAssertMode failed bInitSURF\n"));
            return (FALSE);
        }

        if (pjScreen != ppdev->pjScreen) {

            if (!EngAssociateSurface((HSURF)ppdev->hBitmap, ppdev->hdevEng, 0))
            {
                DISPDBG((0, "DISP DrvAssertMode failed EngAssociateSurface on bitmap\n"));
                return FALSE;
            }

            if (!EngAssociateSurface(ppdev->hsurfEng, ppdev->hdevEng, ppdev->flHooks))
            {
                DISPDBG((0, "DISP DrvAssertMode failed EngAssociateSurface on surface\n"));
                return FALSE;
            }
        }

        return (TRUE);
    }
    else
    {
        //
        // We must give up the display.
        // Call the kernel driver to reset the device to a known state.
        //

        if (EngDeviceIoControl(ppdev->hDriver,
                               IOCTL_VIDEO_RESET_DEVICE,
                               NULL,
                               0,
                               NULL,
                               0,
                               &ulReturn))
        {
            DISPDBG((0, "DISP DrvAssertMode failed IOCTL\n"));
            return FALSE;
        }
        else
        {
            return TRUE;
        }
    }
}

/******************************Public*Routine******************************\
* DrvGetModes
*
* Returns the list of available modes for the device.
*
\**************************************************************************/

ULONG DrvGetModes(
HANDLE hDriver,
ULONG cjSize,
DEVMODEW *pdm)

{

    DWORD cModes;
    DWORD cbOutputSize;
    PVIDEO_MODE_INFORMATION pVideoModeInformation, pVideoTemp;
    DWORD cOutputModes = cjSize / (sizeof(DEVMODEW) + DRIVER_EXTRA_SIZE);
    DWORD cbModeSize;

    DISPDBG((3, "DrvGetModes\n"));

    perfcnt_inc(DrvGetModes);

    cModes = getAvailableModes(hDriver,
                               (PVIDEO_MODE_INFORMATION *) &pVideoModeInformation,
                               &cbModeSize);

    if (cModes == 0)
    {
        DISPDBG((0, "DrvGetModes failed to get mode information"));
        return 0;
    }

    if (pdm == NULL)
    {
        cbOutputSize = cModes * (sizeof(DEVMODEW) + DRIVER_EXTRA_SIZE);
    }
    else
    {
        //
        // Now copy the information for the supported modes back into the output
        // buffer
        //

        cbOutputSize = 0;

        pVideoTemp = pVideoModeInformation;

        do
        {
            if (pVideoTemp->Length != 0)
            {
                if (cOutputModes == 0)
                {
                    break;
                }

                //
                // Zero the entire structure to start off with.
                //

                memset(pdm, 0, sizeof(DEVMODEW));

                //
                // Set the name of the device to the name of the DLL.
                //

                memcpy(pdm->dmDeviceName, DLL_NAME, sizeof(DLL_NAME));

                pdm->dmSpecVersion      = DM_SPECVERSION;
                pdm->dmDriverVersion    = DM_SPECVERSION;
                pdm->dmSize             = sizeof(DEVMODEW);
                pdm->dmDriverExtra      = DRIVER_EXTRA_SIZE;

                pdm->dmBitsPerPel       = pVideoTemp->NumberOfPlanes *
                                          pVideoTemp->BitsPerPlane;
                pdm->dmPelsWidth        = pVideoTemp->VisScreenWidth;
                pdm->dmPelsHeight       = pVideoTemp->VisScreenHeight;
                pdm->dmDisplayFrequency = pVideoTemp->Frequency;
                pdm->dmDisplayFlags     = 0;

                pdm->dmFields           = DM_BITSPERPEL       |
                                          DM_PELSWIDTH        |
                                          DM_PELSHEIGHT       |
                                          DM_DISPLAYFREQUENCY |
                                          DM_DISPLAYFLAGS     ;

                //
                // Go to the next DEVMODE entry in the buffer.
                //

                cOutputModes--;

                pdm = (LPDEVMODEW) ( ((ULONG_PTR)pdm) + sizeof(DEVMODEW)
                                                     + DRIVER_EXTRA_SIZE);

                cbOutputSize += (sizeof(DEVMODEW) + DRIVER_EXTRA_SIZE);

            }

            pVideoTemp = (PVIDEO_MODE_INFORMATION)
                (((PUCHAR)pVideoTemp) + cbModeSize);

        } while (--cModes);
    }

    EngFreeMem(pVideoModeInformation);

    return cbOutputSize;

}

VOID DrvSynchronize(DHPDEV dhpdev, RECTL *prcl)
{
    PDEV* ppdev = (PDEV *)dhpdev;

    ppdev->updateRect.safe_to_draw(ppdev->updateRect.dev);
}

void UpdateRect(PDEV* ppdev, RECTL *rect)
{
    struct rect out = {0};

    perfcnt_inc(UpdateRect);

    if (rect) {
        if (rect->left < rect->right) {
            out.left = rect->left;
            out.right = rect->right;
        } else {
            out.left = rect->right;
            out.right = rect->left;
        }
        if (rect->top < rect->bottom) {
            out.top = rect->top;
            out.bottom = rect->bottom;
        } else {
            out.top = rect->bottom;
            out.bottom = rect->top;
        }
    } else if (ppdev) {
        out.right = ppdev->virt_w;
        out.bottom = ppdev->virt_h;
    }

    if (ppdev) {
        out.left = min(out.left, (ULONG)ppdev->virt_w);
        out.top = min(out.top, (ULONG)ppdev->virt_h);
        out.right = min(out.right, (ULONG)ppdev->virt_w);
        out.bottom = min(out.bottom, (ULONG)ppdev->virt_h);
    }

    ppdev->updateRect.update(ppdev->updateRect.dev, &out);
}

__inline SURFOBJ *getSurfObj(SURFOBJ *pso)
{
    if (pso)
    {
        PPDEV ppdev = (PPDEV)pso->dhpdev;

        if (ppdev)
        {
            if (ppdev->psoBitmap && pso->hsurf == ppdev->hsurfEng)
            {
                pso = ppdev->psoBitmap;
            }
        }
    }

    return pso;
}

static CLIPOBJ clip = {0, {0, 0, 1024, 768}, DC_RECT, FC_RECT, TC_RECTANGLES, 0};

__inline VOID clipToVirtRes(PDEV* ppdev, CLIPOBJ **ppco)
{
    CLIPOBJ *pco;

    if (!*ppco)
        *ppco = &clip;
    pco = *ppco;

    if (ppdev) {
        clip.rclBounds.right = ppdev->virt_w;
        clip.rclBounds.bottom = ppdev->virt_h;
        if (pco->iDComplexity == DC_TRIVIAL)
            pco->iDComplexity = DC_RECT;
        pco->rclBounds.left = min(pco->rclBounds.left, ppdev->virt_w);
        pco->rclBounds.top = min(pco->rclBounds.top, ppdev->virt_h);
        pco->rclBounds.right = min(pco->rclBounds.right, ppdev->virt_w);
        pco->rclBounds.bottom = min(pco->rclBounds.bottom, ppdev->virt_h);
    }
}

BOOL DrvTextOut(
    IN SURFOBJ *psoDst,
    IN STROBJ *pstro,
    IN FONTOBJ *pfo,
    IN CLIPOBJ *pco,
    IN RECTL *prclExtra,
    IN RECTL *prclOpaque,
    IN BRUSHOBJ *pboFore,
    IN BRUSHOBJ *pboOpaque,
    IN POINTL *pptlOrg,
    IN MIX mix)
{
    BOOL Result;
    PDEV* ppdev = (PDEV *)psoDst->dhpdev;

    if (ppdev) {
        LARGE_INTEGER timeout = {0};
        if (!EngWaitForSingleObject(ppdev->virt_lock, &timeout))
            return TRUE;
    }

    clipToVirtRes(ppdev, &pco);

    perfcnt_inc(DrvTextOut);

    Result = EngTextOut(
        getSurfObj(psoDst), pstro, pfo, pco, prclExtra, prclOpaque,
        pboFore, pboOpaque, pptlOrg, mix);
    if (Result && ppdev)
    {
        UpdateRect(ppdev, &pstro->rclBkGround);
        if (prclOpaque)
        {
            UpdateRect(ppdev, prclOpaque);
        }
        if (prclExtra)
        {
            UpdateRect(ppdev, prclExtra);
        }
    }

    if (ppdev)
        EngSetEvent(ppdev->virt_lock);

    return Result;
}

BOOL DrvBitBlt(
    IN SURFOBJ *psoDst,
    IN SURFOBJ *psoSrc,
    IN SURFOBJ *psoMask,
    IN CLIPOBJ *pco,
    IN XLATEOBJ *pxlo,
    IN RECTL *prclDst,
    IN POINTL *pptlSrc,
    IN POINTL *pptlMask,
    IN BRUSHOBJ *pbo,
    IN POINTL *pptlBrush,
    IN ROP4 rop4)
{
    BOOL Result;
    PDEV* ppdev = (PDEV *)psoDst->dhpdev;

    if (ppdev) {
        LARGE_INTEGER timeout = {0};
        if (!EngWaitForSingleObject(ppdev->virt_lock, &timeout))
            return TRUE;
    }

    clipToVirtRes(ppdev, &pco);

    perfcnt_inc(DrvBitBlt);

    Result = EngBitBlt(getSurfObj(psoDst), getSurfObj(psoSrc), psoMask, pco, pxlo, prclDst,
        pptlSrc, pptlMask, pbo, pptlBrush, rop4);
    if (Result && ppdev)
    {
        UpdateRect(ppdev, prclDst);
    }

    if (ppdev)
        EngSetEvent(ppdev->virt_lock);

    return Result;
}

BOOL DrvCopyBits(
    OUT SURFOBJ *psoDst,
    IN SURFOBJ *psoSrc,
    IN CLIPOBJ *pco,
    IN XLATEOBJ *pxlo,
    IN RECTL *prclDst,
    IN POINTL *pptlSrc)
{
    BOOL Result;
    PDEV* ppdev = (PDEV *)psoDst->dhpdev;

    if (ppdev) {
        LARGE_INTEGER timeout = {0};
        if (!EngWaitForSingleObject(ppdev->virt_lock, &timeout))
            return TRUE;
    }

    clipToVirtRes(ppdev, &pco);

    perfcnt_inc(DrvCopyBits);

    Result = EngCopyBits(getSurfObj(psoDst), getSurfObj(psoSrc), pco, pxlo, prclDst, pptlSrc);
    if (Result && ppdev)
    {
        UpdateRect(ppdev, prclDst);
    }

    if (ppdev)
        EngSetEvent(ppdev->virt_lock);

    return Result;
}

BOOL DrvStrokePath(
    SURFOBJ*   psoDst,
    PATHOBJ*   ppo,
    CLIPOBJ*   pco,
    XFORMOBJ*  pxo,
    BRUSHOBJ*  pbo,
    POINTL*    pptlBrush,
    LINEATTRS* pLineAttrs,
    MIX        mix)
{
    BOOL Result;
    PDEV* ppdev = (PDEV *)psoDst->dhpdev;

    if (ppdev) {
        LARGE_INTEGER timeout = {0};
        if (!EngWaitForSingleObject(ppdev->virt_lock, &timeout))
            return TRUE;
    }

    clipToVirtRes(ppdev, &pco);

    perfcnt_inc(DrvStrokePath);

    Result = EngStrokePath(getSurfObj(psoDst), ppo, pco, pxo, pbo,
        pptlBrush, pLineAttrs, mix);
    if (Result && ppdev)
    {
        UpdateRect(ppdev, NULL);
    }

    if (ppdev)
        EngSetEvent(ppdev->virt_lock);

    return Result;
}

BOOL DrvLineTo(
    SURFOBJ   *psoDst,
    CLIPOBJ   *pco,
    BRUSHOBJ  *pbo,
    LONG       x1,
    LONG       y1,
    LONG       x2,
    LONG       y2,
    RECTL     *prclBounds,
    MIX        mix)
{
    BOOL Result;
    PDEV* ppdev = (PDEV *)psoDst->dhpdev;

    if (ppdev) {
        LARGE_INTEGER timeout = {0};
        if (!EngWaitForSingleObject(ppdev->virt_lock, &timeout))
            return TRUE;
    }

    clipToVirtRes(ppdev, &pco);

    perfcnt_inc(DrvLineTo);

    Result = EngLineTo(getSurfObj(psoDst), pco, pbo, x1, y1, x2, y2, prclBounds, mix);
    if (Result && ppdev)
    {
        UpdateRect(ppdev, prclBounds);
    }

    if (ppdev)
        EngSetEvent(ppdev->virt_lock);

    return Result;
}

BOOL DrvFillPath(
    SURFOBJ  *psoDst,
    PATHOBJ  *ppo,
    CLIPOBJ  *pco,
    BRUSHOBJ *pbo,
    PPOINTL   pptlBrushOrg,
    MIX       mix,
    FLONG     flOptions)
{
    BOOL Result;
    PDEV* ppdev = (PDEV *)psoDst->dhpdev;

    if (ppdev) {
        LARGE_INTEGER timeout = {0};
        if (!EngWaitForSingleObject(ppdev->virt_lock, &timeout))
            return TRUE;
    }

    clipToVirtRes(ppdev, &pco);

    perfcnt_inc(DrvFillPath);

    Result = EngFillPath(getSurfObj(psoDst), ppo, pco, pbo, pptlBrushOrg, mix, flOptions);
    if (Result && ppdev)
    {
        UpdateRect(ppdev, NULL);
    }

    if (ppdev)
        EngSetEvent(ppdev->virt_lock);

    return Result;
}

BOOL DrvStretchBlt(
    SURFOBJ*            psoDst,
    SURFOBJ*            psoSrc,
    SURFOBJ*            psoMsk,
    CLIPOBJ*            pco,
    XLATEOBJ*           pxlo,
    COLORADJUSTMENT*    pca,
    POINTL*             pptlHTOrg,
    RECTL*              prclDst,
    RECTL*              prclSrc,
    POINTL*             pptlMsk,
    ULONG               iMode)
{
    BOOL Result;
    PDEV* ppdev = (PDEV *)psoDst->dhpdev;

    if (ppdev) {
        LARGE_INTEGER timeout = {0};
        if (!EngWaitForSingleObject(ppdev->virt_lock, &timeout))
            return TRUE;
    }

    clipToVirtRes(ppdev, &pco);

    perfcnt_inc(DrvStretchBlt);

    Result = EngStretchBlt(getSurfObj(psoDst), getSurfObj(psoSrc), psoMsk, pco, pxlo, pca,
        pptlHTOrg, prclDst, prclSrc, pptlMsk, iMode);
    if (Result && ppdev)
    {
        UpdateRect(ppdev, prclDst);
    }

    if (ppdev)
        EngSetEvent(ppdev->virt_lock);

    return Result;
}
