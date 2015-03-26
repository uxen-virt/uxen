/*
 * Copyright 2012-2015, Bromium, Inc.
 * Author: Julian Pidancet <julian@pidancet.net>
 * SPDX-License-Identifier: ISC
 */

#include "driver.h"

BOOL bCopyColorPointer(
PPDEV ppdev,
SURFOBJ *psoScreen,
SURFOBJ *psoMask,
SURFOBJ *psoColor,
XLATEOBJ *pxlo,
FLONG fl);

BOOL bCopyMonoPointer(
PPDEV ppdev,
SURFOBJ *psoMask);

BOOL bSetHardwarePointerShape(
SURFOBJ  *pso,
SURFOBJ  *psoMask,
SURFOBJ  *psoColor,
XLATEOBJ *pxlo,
LONG      x,
LONG      y,
FLONG     fl);

/******************************Public*Routine******************************\
* DrvMovePointer
*
* Moves the hardware pointer to a new position.
*
\**************************************************************************/

VOID DrvMovePointer
(
    SURFOBJ *pso,
    LONG     x,
    LONG     y,
    RECTL   *prcl
)
{
    PPDEV ppdev = (PPDEV) pso->dhpdev;
    DWORD returnedDataLength;
    VIDEO_POINTER_POSITION NewPointerPosition;
    static int removed = 0;

    // We don't use the exclusion rectangle because we only support
    // hardware Pointers. If we were doing our own Pointer simulations
    // we would want to update prcl so that the engine would call us
    // to exclude out pointer before drawing to the pixels in prcl.

    UNREFERENCED_PARAMETER(prcl);

    // Convert the pointer's position from relative to absolute
    // coordinates (this is only significant for multiple board
    // support).

    x -= ppdev->ptlOrg.x;
    y -= ppdev->ptlOrg.y;

    // If x is -1 after the offset then take down the cursor.

    if (x == -1)
    {
        //
        // A new position of (-1,-1) means hide the pointer.
        //

        if (EngDeviceIoControl(ppdev->hDriver,
                               IOCTL_VIDEO_DISABLE_POINTER,
                               NULL,
                               0,
                               NULL,
                               0,
                               &returnedDataLength))
        {
            //
            // Not the end of the world, print warning in checked build.
            //

            DISPDBG((1, "DISP vMoveHardwarePointer failed IOCTL_VIDEO_DISABLE_POINTER\n"));
        }

        removed = 1;
    }
    else
    {
        NewPointerPosition.Column = (SHORT) x - (SHORT) (ppdev->ptlHotSpot.x);
        NewPointerPosition.Row    = (SHORT) y - (SHORT) (ppdev->ptlHotSpot.y);

        if (removed) {
            EngDeviceIoControl(ppdev->hDriver,
                               IOCTL_VIDEO_ENABLE_POINTER,
                               NULL,
                               0,
                               NULL,
                               0,
                               &returnedDataLength);
            removed = 0;
        }

        //
        // Call miniport driver to move Pointer.
        //

        if (EngDeviceIoControl(ppdev->hDriver,
                               IOCTL_VIDEO_SET_POINTER_POSITION,
                               &NewPointerPosition,
                               sizeof(VIDEO_POINTER_POSITION),
                               NULL,
                               0,
                               &returnedDataLength))
        {
            //
            // Not the end of the world, print warning in checked build.
            //

            DISPDBG((1, "DISP vMoveHardwarePointer failed IOCTL_VIDEO_SET_POINTER_POSITION\n"));
        }
    }
}

/******************************Public*Routine******************************\
* DrvSetPointerShape
*
* Sets the new pointer shape.
*
\**************************************************************************/

ULONG DrvSetPointerShape
(
    SURFOBJ  *pso,
    SURFOBJ  *psoMask,
    SURFOBJ  *psoColor,
    XLATEOBJ *pxlo,
    LONG      xHot,
    LONG      yHot,
    LONG      x,
    LONG      y,
    RECTL    *prcl,
    FLONG     fl
)
{
    PPDEV   ppdev = (PPDEV) pso->dhpdev;
    DWORD   returnedDataLength;

    // We don't use the exclusion rectangle because we only support
    // hardware Pointers. If we were doing our own Pointer simulations
    // we would want to update prcl so that the engine would call us
    // to exclude out pointer before drawing to the pixels in prcl.
    UNREFERENCED_PARAMETER(prcl);

    if (ppdev->pPointerAttributes == NULL)
    {
        // Mini-port has no hardware Pointer support.
        return(SPS_ERROR);
    }

    // See if we are being asked to hide the pointer

    if ((psoMask == (SURFOBJ *) NULL) && !(fl & SPS_ALPHA))
    {
        if (EngDeviceIoControl(ppdev->hDriver,
                               IOCTL_VIDEO_DISABLE_POINTER,
                               NULL,
                               0,
                               NULL,
                               0,
                               &returnedDataLength))
        {
            //
            // It should never be possible to fail.
            // Message supplied for debugging.
            //

            DISPDBG((1, "DISP bSetHardwarePointerShape failed IOCTL_VIDEO_DISABLE_POINTER\n"));
        }

        return(TRUE);
    }

    ppdev->ptlHotSpot.x = xHot;
    ppdev->ptlHotSpot.y = yHot;

    if (!bSetHardwarePointerShape(pso,psoMask,psoColor,pxlo,x,y,fl))
    {
            if (ppdev->fHwCursorActive) {
                ppdev->fHwCursorActive = FALSE;

                if (EngDeviceIoControl(ppdev->hDriver,
                                       IOCTL_VIDEO_DISABLE_POINTER,
                                       NULL,
                                       0,
                                       NULL,
                                       0,
                                       &returnedDataLength)) {

                    DISPDBG((1, "DISP bSetHardwarePointerShape failed IOCTL_VIDEO_DISABLE_POINTER\n"));
                }
            }

            //
            // Mini-port declines to realize this Pointer
            //

            return(SPS_DECLINE);
    }
    else
    {
        ppdev->fHwCursorActive = TRUE;
    }

    return(SPS_ACCEPT_NOEXCLUDE);
}

/******************************Public*Routine******************************\
* bSetHardwarePointerShape
*
* Changes the shape of the Hardware Pointer.
*
* Returns: True if successful, False if Pointer shape can't be hardware.
*
\**************************************************************************/

BOOL bSetHardwarePointerShape(
SURFOBJ  *pso,
SURFOBJ  *psoMask,
SURFOBJ  *psoColor,
XLATEOBJ *pxlo,
LONG      x,
LONG      y,
FLONG     fl)
{
    PPDEV     ppdev = (PPDEV) pso->dhpdev;
    PVIDEO_POINTER_ATTRIBUTES pPointerAttributes = ppdev->pPointerAttributes;
    DWORD     returnedDataLength;

    pPointerAttributes->Flags &= ~(VIDEO_MODE_COLOR_POINTER |
                                   VIDEO_MODE_MONO_POINTER);

    if (psoColor != (SURFOBJ *) NULL)
    {
        if ((ppdev->PointerCapabilities.Flags & VIDEO_MODE_COLOR_POINTER) &&
                bCopyColorPointer(ppdev, pso, psoMask, psoColor, pxlo, fl))
        {
            pPointerAttributes->Flags |= VIDEO_MODE_COLOR_POINTER;
        } else {
            return(FALSE);
        }

    } else {
        if ((ppdev->PointerCapabilities.Flags & VIDEO_MODE_MONO_POINTER) &&
                bCopyMonoPointer(ppdev, psoMask))
        {
            pPointerAttributes->Flags |= VIDEO_MODE_MONO_POINTER;
        } else {
            return(FALSE);
        }
    }

    //
    // Initialize Pointer attributes and position
    //

    pPointerAttributes->Enable = 1;

    //
    // if x,y = -1,-1 then pass them directly to the miniport so that
    // the cursor will be disabled

    pPointerAttributes->Column = (SHORT)(x);
    pPointerAttributes->Row    = (SHORT)(y);

    if ((x != -1) || (y != -1)) {
#if 0
        pPointerAttributes->Column -= (SHORT)(ppdev->ptlHotSpot.x);
        pPointerAttributes->Row    -= (SHORT)(ppdev->ptlHotSpot.y);
#else
        /*
         * Don't care about the actual position of the pointer, we're
         * only interested in the hotspot position.
         */
        pPointerAttributes->Column = (SHORT)(ppdev->ptlHotSpot.x);
        pPointerAttributes->Row    = (SHORT)(ppdev->ptlHotSpot.y);
#endif
    }

    //
    // set animate flags
    //

    if (fl & SPS_ANIMATESTART) {
        pPointerAttributes->Flags |= VIDEO_MODE_ANIMATE_START;
    } else if (fl & SPS_ANIMATEUPDATE) {
        pPointerAttributes->Flags |= VIDEO_MODE_ANIMATE_UPDATE;
    }

    //
    // Set the new Pointer shape.
    //

    if (EngDeviceIoControl(ppdev->hDriver,
                           IOCTL_VIDEO_SET_POINTER_ATTR,
                           pPointerAttributes,
                           ppdev->cjPointerAttributes,
                           NULL,
                           0,
                           &returnedDataLength)) {

        DISPDBG((1, "DISP:Failed IOCTL_VIDEO_SET_POINTER_ATTR call\n"));
        return(FALSE);
    }

    return(TRUE);
}

/******************************Public*Routine******************************\
* bCopyMonoPointer
*
* Copies two monochrome masks into a buffer of the maximum size handled by the
* miniport, with any extra bits set to 0.  The masks are converted to topdown
* form if they aren't already.  Returns TRUE if we can handle this pointer in
* hardware, FALSE if not.
*
\**************************************************************************/

BOOL bCopyMonoPointer(
    PPDEV    ppdev,
    SURFOBJ *pso)
{
    PBYTE pjSrc = NULL;
    ULONG cy = 0;
    PVIDEO_POINTER_ATTRIBUTES pPointerAttributes = ppdev->pPointerAttributes;
    PBYTE pjDst = pPointerAttributes->Pixels;
    ULONG cjAnd = 0;
    ULONG cxSrc = pso->sizlBitmap.cx;
    ULONG cySrc = pso->sizlBitmap.cy / 2; /* /2 because both masks are in there */

    // Make sure the new pointer isn't too big to handle,
    if (cxSrc > ppdev->PointerCapabilities.MaxWidth ||
        cySrc > ppdev->PointerCapabilities.MaxHeight)
    {
        return FALSE;
    }

    /* Size of AND mask in bytes */
    cjAnd = ((cxSrc + 7) / 8) * cySrc;

    pPointerAttributes->Width = cxSrc;
    pPointerAttributes->Height = cySrc;
    pPointerAttributes->WidthInBytes = (cxSrc + 7) / 8;

    /* Init AND mask to 1 */
    RtlFillMemory (pjDst, cjAnd, 0xFF);

    pjSrc = (PBYTE)pso->pvScan0;

    for (cy = 0; cy < (cySrc * 2); cy++)
    {
        RtlCopyMemory (pjDst, pjSrc, (cxSrc + 7) / 8);

        pjSrc += pso->lDelta;
        pjDst += (cxSrc + 7) / 8;
    }

    return(TRUE);
}

/******************************Public*Routine******************************\
* bCopyColorPointer
*
* Copies the mono and color masks into the buffer of maximum size
* handled by the miniport with any extra bits set to 0. Color translation
* is handled at this time. The masks are converted to topdown form if they
* aren't already.  Returns TRUE if we can handle this pointer in  hardware,
* FALSE if not.
*
\**************************************************************************/
BOOL bCopyColorPointer(
PPDEV ppdev,
SURFOBJ *psoScreen,
SURFOBJ *psoMask,
SURFOBJ *psoColor,
XLATEOBJ *pxlo,
FLONG fl)
{
    /* Format of "hardware" pointer is:
     * 1 bpp AND mask with byte aligned scanlines,
     * B G R A bytes of XOR mask that starts on the next 4 byte aligned offset after AND mask.
     *
     * If fl & SPS_ALPHA then A bytes contain alpha channel information.
     * Otherwise A bytes are undefined (but will be 0).
     *
     */

    /* To simplify this function we use the following method:
     *   for pointers with alpha channel
     *     we have BGRA values in psoColor and will simply copy them to pPointerAttributes->Pixels
     *   for color pointers
     *     always convert supplied bitmap to 32 bit BGR0
     *     copy AND mask and new BGR0 XOR mask to pPointerAttributes->Pixels
     */

    HSURF hsurf32bpp  = NULL;
    SURFOBJ *pso32bpp = NULL;

    PBYTE pjSrcAnd = NULL;
    PBYTE pjSrcXor = NULL;

    ULONG cy = 0;

    PVIDEO_POINTER_ATTRIBUTES pPointerAttributes = ppdev->pPointerAttributes;

    PBYTE pjDstAnd = pPointerAttributes->Pixels;
    ULONG cjAnd = 0;
    PBYTE pjDstXor = pPointerAttributes->Pixels;

    ULONG cxSrc = psoColor->sizlBitmap.cx;
    ULONG cySrc = psoColor->sizlBitmap.cy;

    // Make sure the new pointer isn't too big to handle,
    // strip the size to 64x64 if necessary
    if (cxSrc > ppdev->PointerCapabilities.MaxWidth)
    {
        cxSrc = ppdev->PointerCapabilities.MaxWidth;
    }

    if (cySrc > ppdev->PointerCapabilities.MaxHeight)
    {
        cySrc = ppdev->PointerCapabilities.MaxWidth;
    }

    /* Size of AND mask in bytes */
    cjAnd = ((cxSrc + 7) / 8) * cySrc;

    /* Pointer to XOR mask is 4-bytes aligned */
    pjDstXor += (cjAnd + 3) & ~3;

    pPointerAttributes->Width = cxSrc;
    pPointerAttributes->Height = cySrc;
    pPointerAttributes->WidthInBytes = cxSrc * 4;

    /* Init AND mask to 1 */
    RtlFillMemory (pjDstAnd, cjAnd, 0xFF);

    if (fl & SPS_ALPHA)
    {
        PBYTE pjSrcAlpha = (PBYTE)psoColor->pvScan0;

        pso32bpp = psoColor;

        /*
         * Emulate AND mask to provide viewable mouse pointer for
         * hardware which does not support alpha channel.
         */

        for (cy = 0; cy < cySrc; cy++)
        {
            ULONG cx;

            UCHAR bitmask = 0x80;

            for (cx = 0; cx < cxSrc; cx++, bitmask >>= 1)
            {
                if (bitmask == 0)
                {
                    bitmask = 0x80;
                }

                if (pjSrcAlpha[cx * 4 + 3] > 0x7f)
                {
                    pjDstAnd[cx / 8] &= ~bitmask;
                }
            }

            // Point to next source and dest scans
            pjSrcAlpha += pso32bpp->lDelta;
            pjDstAnd += (cxSrc + 7) / 8;
        }
    }
    else
    {
        if (!psoMask)
        {
            /* This can not be, mask must be supplied for a color pointer. */
            return (FALSE);
        }

        /*
         * Copy AND mask.
         */

        pjSrcAnd = (PBYTE)psoMask->pvScan0;

        for (cy = 0; cy < cySrc; cy++)
        {
            RtlCopyMemory (pjDstAnd, pjSrcAnd, (cxSrc + 7) / 8);

            // Point to next source and dest scans
            pjSrcAnd += psoMask->lDelta;
            pjDstAnd += (cxSrc + 7) / 8;
        }

        /*
         * Convert given psoColor to 32 bit BGR0.
         */

        if (psoColor->iType == STYPE_BITMAP
            && psoColor->iBitmapFormat == BMF_32BPP)
        {
            /* The psoColor is already in desired format */
            pso32bpp = psoColor;
        }
        else
        {
            HSURF hsurfBitmap  = NULL;
            SURFOBJ *psoBitmap = NULL;

            SIZEL sizl = psoColor->sizlBitmap;

            if ((pxlo != NULL && pxlo->flXlate != XO_TRIVIAL)
                || (psoColor->iType != STYPE_BITMAP))
            {
                /* Convert the unknown format to a screen format bitmap. */

                RECTL rclDst;
                POINTL ptlSrc;

                hsurfBitmap = (HSURF)EngCreateBitmap (sizl, 0, psoScreen->iBitmapFormat, BMF_TOPDOWN, NULL);

                if (hsurfBitmap == NULL)
                {
                    return FALSE;
                }

                psoBitmap = EngLockSurface (hsurfBitmap);

                if (psoBitmap == NULL)
                {
                    EngDeleteSurface (hsurfBitmap);
                    return FALSE;
                }

                /* Now do the bitmap conversion using EngCopyBits(). */

                rclDst.left = 0;
                rclDst.top = 0;
                rclDst.right = sizl.cx;
                rclDst.bottom = sizl.cy;

                ptlSrc.x = 0;
                ptlSrc.y = 0;

                if (!EngCopyBits (psoBitmap, psoColor, NULL, pxlo, &rclDst, &ptlSrc))
                {
                    EngUnlockSurface (psoBitmap);
                    EngDeleteSurface (hsurfBitmap);
                    return FALSE;
                }

            }
            else
            {
                psoBitmap = psoColor;
            }

            /* Create 32 bpp surface for XOR mask */
            hsurf32bpp = (HSURF)EngCreateBitmap (sizl, 0, BMF_32BPP, BMF_TOPDOWN, NULL);

            if (hsurf32bpp != NULL)
            {
                pso32bpp = EngLockSurface (hsurf32bpp);

                if (pso32bpp == NULL)
                {
                    EngDeleteSurface (hsurf32bpp);
                    hsurf32bpp = NULL;
                }
            }

            if (pso32bpp)
            {
                /* Convert psoBitmap bits to pso32bpp bits for known formats */
                if (psoBitmap->iBitmapFormat == BMF_8BPP && ppdev->pPal)
                {
                    PBYTE src = (PBYTE)psoBitmap->pvScan0;
                    PBYTE dst = (PBYTE)pso32bpp->pvScan0;

                    PPALETTEENTRY pPal = ppdev->pPal;
                    ULONG cPalette = 256; /* 256 is hardcoded in the driver in palette.c */

                    for (cy = 0; cy < (ULONG)sizl.cy; cy++)
                    {
                        ULONG cx;

                        PBYTE d = dst;

                        for (cx = 0; cx < (ULONG)sizl.cx; cx++)
                        {
                            BYTE index = src[cx];

                            *d++ = pPal[index].peBlue;  /* B */
                            *d++ = pPal[index].peGreen; /* G */
                            *d++ = pPal[index].peRed;   /* R */
                            *d++ = 0;                   /* destination is 32 bpp */
                        }

                        /* Point to next source and dest scans */
                        src += psoBitmap->lDelta;
                        dst += pso32bpp->lDelta;
                    }

                }
                else if (psoBitmap->iBitmapFormat == BMF_16BPP)
                {
                    PBYTE src = (PBYTE)psoBitmap->pvScan0;
                    PBYTE dst = (PBYTE)pso32bpp->pvScan0;

                    for (cy = 0; cy < (ULONG)sizl.cy; cy++)
                    {
                        ULONG cx;

                        PBYTE d = dst;

                        for (cx = 0; cx < (ULONG)sizl.cx; cx++)
                        {
                            USHORT usSrc = *(USHORT *)&src[cx * 2];

                            *d++ = (BYTE)( usSrc        << 3); /* B */
                            *d++ = (BYTE)((usSrc >> 5)  << 2); /* G */
                            *d++ = (BYTE)((usSrc >> 11) << 3); /* R */
                            *d++ = 0;                          /* destination is 32 bpp */
                        }

                        /* Point to next source and dest scans */
                        src += psoBitmap->lDelta;
                        dst += pso32bpp->lDelta;
                    }

                }
                else if (psoBitmap->iBitmapFormat == BMF_24BPP)
                {
                    PBYTE src = (PBYTE)psoBitmap->pvScan0;
                    PBYTE dst = (PBYTE)pso32bpp->pvScan0;

                    for (cy = 0; cy < (ULONG)sizl.cy; cy++)
                    {
                        ULONG cx;

                        PBYTE s = src;
                        PBYTE d = dst;

                        for (cx = 0; cx < (ULONG)sizl.cx; cx++)
                        {
                            *d++ = *s++; /* B */
                            *d++ = *s++; /* G */
                            *d++ = *s++; /* R */
                            *d++ = 0;    /* destination is 32 bpp */
                        }

                        /* Point to next source and dest scans */
                        src += psoBitmap->lDelta;
                        dst += pso32bpp->lDelta;
                    }

                }
                else if (psoBitmap->iBitmapFormat == BMF_32BPP)
                {
                    RtlCopyMemory (pso32bpp->pvBits, psoBitmap->pvBits, min(pso32bpp->cjBits, psoBitmap->cjBits));
                }
                else
                {
                    EngUnlockSurface (pso32bpp);
                    pso32bpp = NULL;
                    EngDeleteSurface (hsurf32bpp);
                    hsurf32bpp = NULL;
                }
            }

            if (hsurfBitmap)
            {
                EngUnlockSurface (psoBitmap);
                psoBitmap = NULL;
                EngDeleteSurface (hsurfBitmap);
                hsurfBitmap = NULL;
            }
        }
    }

    if (!pso32bpp)
    {
         return (FALSE);
    }

    /*
     * pso is 32 bit BGRX bitmap. Copy it to Pixels
     */

    pjSrcXor = (PBYTE)pso32bpp->pvScan0;

    for (cy = 0; cy < cySrc; cy++)
    {
        /* 32 bit bitmap is being copied */
        RtlCopyMemory (pjDstXor, pjSrcXor, cxSrc * 4);

        /* Point to next source and dest scans */
        pjSrcXor += pso32bpp->lDelta;
        pjDstXor += pPointerAttributes->WidthInBytes;
    }

    if (pso32bpp != psoColor)
    {
        /* Deallocate the temporary 32 bit pso */
        EngUnlockSurface (pso32bpp);
        EngDeleteSurface (hsurf32bpp);
    }

    return (TRUE);
}


/******************************Public*Routine******************************\
* bInitPointer
*
* Initialize the Pointer attributes.
*
\**************************************************************************/

BOOL bInitPointer(PPDEV ppdev, DEVINFO *pdevinfo)
{
    DWORD    returnedDataLength;

    ppdev->pPointerAttributes = NULL;
    ppdev->cjPointerAttributes = 0; // initialized in screen.c

    //
    // Ask the miniport whether it provides pointer support.
    //

    if (EngDeviceIoControl(ppdev->hDriver,
                           IOCTL_VIDEO_QUERY_POINTER_CAPABILITIES,
                           &ppdev->ulMode,
                           sizeof(PVIDEO_MODE),
                           &ppdev->PointerCapabilities,
                           sizeof(ppdev->PointerCapabilities),
                           &returnedDataLength))
    {
         return(FALSE);
    }

    //
    // If neither mono nor color hardware pointer is supported, there's no
    // hardware pointer support and we're done.
    //

    if ((!(ppdev->PointerCapabilities.Flags & VIDEO_MODE_MONO_POINTER)) &&
        (!(ppdev->PointerCapabilities.Flags & VIDEO_MODE_COLOR_POINTER)))
    {
        return(TRUE);
    }

    //
    // Note: The buffer itself is allocated after we set the
    // mode. At that time we know the pixel depth and we can
    // allocate the correct size for the color pointer if supported.
    //

    //
    // Set the asynchronous support status (async means miniport is capable of
    // drawing the Pointer at any time, with no interference with any ongoing
    // drawing operation)
    //

    if (ppdev->PointerCapabilities.Flags & VIDEO_MODE_ASYNC_POINTER)
    {
       pdevinfo->flGraphicsCaps |= GCAPS_ASYNCMOVE;
    }
    else
    {
       pdevinfo->flGraphicsCaps &= ~GCAPS_ASYNCMOVE;
    }

    pdevinfo->flGraphicsCaps2 |= GCAPS2_ALPHACURSOR;

    return(TRUE);
}

