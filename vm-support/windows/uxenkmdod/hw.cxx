/*
 * Copyright 2015, Bromium, Inc.
 * Author: Kris Uchronski <kuchronski@gmail.com>
 * SPDX-License-Identifier: ISC
 */

#include "BDD.hxx"
#include "hw.h"
#include "../../../dm/hw/uxdisp_hw.h" /* XXX */

const ULONG HWPTR_WIDTH_MAX     = 128;
const ULONG HWPTR_HEIGHT_MAX    = 128;

#define HWPTR_FLAG_HIDE         (1 << 0)

static 
ULONG uxdisp_read(_In_ PUXEN_HW_RESOURCES pHw, ULONG reg)
{
    return READ_REGISTER_ULONG((PULONG)(pHw->pMmio + reg));
}

static 
void uxdisp_write(_In_ PUXEN_HW_RESOURCES pHw, ULONG reg, ULONG val)
{
    WRITE_REGISTER_ULONG((PULONG)(pHw->pMmio + reg), val);
}

static
void uxdisp_crtc_write(_In_ PUXEN_HW_RESOURCES pHw, ULONG crtc, ULONG reg, ULONG val)
{
    uxdisp_write(pHw, UXDISP_REG_CRTC(crtc) + reg, val);
}

NTSTATUS hw_init(_Inout_ PUXEN_HW_RESOURCES pHw)
{
    ULONG magic = 0;

    ASSERT(NULL != pHw);

    pHw->pMmio = (PCHAR)MmMapIoSpace(pHw->mmioPhysicalAddress,
                                     (SIZE_T)pHw->mmioLength,
                                     MmNonCached);
    if (pHw->pMmio != NULL) {
        magic = uxdisp_read(pHw, UXDISP_REG_MAGIC);
        if (magic == UXDISP_MAGIC) {
            uxdisp_write(pHw, UXDISP_REG_MODE, UXDISP_MODE_VGA_DISABLED);
            return STATUS_SUCCESS;
        }
    }

    uxen_err("Magic value mismatch! 0x%x != 0x%x", magic, UXDISP_MAGIC);
    return STATUS_UNSUCCESSFUL;
}

void hw_disable_page_tracking(_In_ PUXEN_HW_RESOURCES pHw)
{
    ULONG val = uxdisp_read(pHw, UXDISP_REG_MODE);
    val |= UXDISP_MODE_PAGE_TRACKING_DISABLED;
    uxdisp_write(pHw, UXDISP_REG_MODE, val);
}

void hw_cleanup(_Inout_ PUXEN_HW_RESOURCES pHw)
{
    MmUnmapIoSpace(pHw->pMmio, (SIZE_T)pHw->mmioLength);
}

NTSTATUS hw_set_mode(
    _In_ PUXEN_HW_RESOURCES pHw,
    VIDEO_MODE_INFORMATION *mode)
{
    USHORT width = (USHORT)mode->VisScreenWidth;
    USHORT height = (USHORT)mode->VisScreenHeight;
    USHORT bpp = (USHORT)mode->BitsPerPlane;
    USHORT stride = (USHORT)mode->ScreenStride;
    ULONG fmt;

    perfcnt_inc(hw_set_mode);
#ifdef DBG
    uxen_debug("called: %dx%dx%d", width, height, bpp);
#else
    if (perfcnt_get(hw_set_mode) < 64)
        uxen_msg("called: %dx%dx%d", width, height, bpp);
#endif  /* DBG */

    if (mode->VisScreenWidth > (USHORT)~0 ||
        mode->VisScreenHeight > (USHORT)~0)
        return STATUS_UNSUCCESSFUL;

    switch (bpp) {
    case 32:
        fmt = UXDISP_CRTC_FORMAT_BGRX_8888;
        break;
    case 24:
        fmt = UXDISP_CRTC_FORMAT_BGR_888;
        break;
    case 16:
        fmt = UXDISP_CRTC_FORMAT_BGR_565;
        break;
    case 15:
        fmt = UXDISP_CRTC_FORMAT_BGR_555;
        break;
    default:
        return STATUS_UNSUCCESSFUL;
    }

    uxdisp_crtc_write(pHw, 0, UXDISP_REG_CRTC_ENABLE, 1);
    uxdisp_crtc_write(pHw, 0, UXDISP_REG_CRTC_XRES, width);
    uxdisp_crtc_write(pHw, 0, UXDISP_REG_CRTC_YRES, height);
    uxdisp_crtc_write(pHw, 0, UXDISP_REG_CRTC_STRIDE, stride);
    uxdisp_crtc_write(pHw, 0, UXDISP_REG_CRTC_FORMAT, fmt);

    /* Flush */
    uxdisp_crtc_write(pHw, 0, UXDISP_REG_CRTC_OFFSET, 0);

    return STATUS_SUCCESS;
}

NTSTATUS hw_disable(
    _In_ PUXEN_HW_RESOURCES pHw)
{
    uxdisp_write(pHw, UXDISP_REG_MODE, 0);

    return STATUS_SUCCESS;
}

void hw_query_mouse_pointer_caps(
    _Inout_ DXGK_DRIVERCAPS* pDriverCaps)
{
    ASSERT(NULL != pDriverCaps);

    pDriverCaps->PointerCaps.Color = 1;
    pDriverCaps->PointerCaps.Monochrome = 1;
    pDriverCaps->PointerCaps.MaskedColor = 0;

    pDriverCaps->MaxPointerWidth = HWPTR_WIDTH_MAX;
    pDriverCaps->MaxPointerHeight = HWPTR_HEIGHT_MAX;
}

NTSTATUS hw_pointer_setpos(
    _In_ PUXEN_HW_RESOURCES pHw,
    _In_ CONST DXGKARG_SETPOINTERPOSITION *pSetPointerPosition)
{
    ASSERT(NULL != pHw);
    ASSERT(NULL != pSetPointerPosition);
    ASSERT(pSetPointerPosition->VidPnSourceId < MAX_VIEWS);

    uxdisp_write(pHw, UXDISP_REG_CURSOR_POS_X, pSetPointerPosition->X);
    uxdisp_write(pHw, UXDISP_REG_CURSOR_POS_Y, pSetPointerPosition->Y);

    if (((1 == pSetPointerPosition->Flags.Visible)
         != (0 == (pHw->hwptrFlags & HWPTR_FLAG_HIDE))))
    {
        if (1 == pSetPointerPosition->Flags.Visible) {
            pHw->hwptrFlags &= ~HWPTR_FLAG_HIDE;
            uxdisp_write(pHw, UXDISP_REG_CURSOR_ENABLE, UXDISP_CURSOR_SHOW);
        } else {
            pHw->hwptrFlags |= HWPTR_FLAG_HIDE;
            uxdisp_write(pHw, UXDISP_REG_CURSOR_ENABLE, 0);
        }
    }

    return STATUS_SUCCESS;
}

NTSTATUS hw_pointer_update(
    _In_ PUXEN_HW_RESOURCES pHw,
    _In_ CONST DXGKARG_SETPOINTERSHAPE *pSetPointerShape)
{
    ULONG flags = 0;
    UINT width = 0;
    UINT height = 0;
    size_t bitmap_len;
    ULONG y;
    char *s, *d;

    ASSERT(NULL != pHw);
    ASSERT(NULL != pSetPointerShape);

    width = pSetPointerShape->Width;
    height = pSetPointerShape->Height;

    if (pSetPointerShape->Flags.Color) {
        bitmap_len = 4 * width * height; /* ARGB data */
        bitmap_len += ((width + 7) / 8) * height; /* AND mask */

        if (bitmap_len > (UXDISP_REG_CRTC(0) - UXDISP_REG_CURSOR_DATA))
            return FALSE;

        s = (PCHAR)pSetPointerShape->pPixels;
        d = pHw->pMmio + UXDISP_REG_CURSOR_DATA;
        for (y = 0; y < height; y++) {
            RtlCopyMemory(d, s, (width + 7) / 8);
            d += (width + 7) / 8;
            s += (width + 7) / 8;
        }
        s = (PCHAR)pSetPointerShape->pPixels;
        s += ((((width + 7) / 8) * height) + 3) & ~3;
        for (y = 0; y < height; y++) {
            RtlCopyMemory(d, s, 4 * width);
            d += 4 * width;
            s += pSetPointerShape->Pitch;
        }
    } else {
        bitmap_len = ((width + 7) / 8) * height * 2;
        if (bitmap_len > (UXDISP_REG_CRTC(0) - UXDISP_REG_CURSOR_DATA))
            return FALSE;

        s = (PCHAR)pSetPointerShape->pPixels;
        d = pHw->pMmio + UXDISP_REG_CURSOR_DATA;
        for (y = 0; y < (height * 2); y++) {
            RtlCopyMemory(d, s, (width + 7) / 8);
            d += (width + 7) / 8;
            s += (width + 7) / 8;
        }

        flags |= UXDISP_CURSOR_FLAG_1BPP;
    }

    flags |= UXDISP_CURSOR_FLAG_MASK_PRESENT;

    uxdisp_write(pHw, UXDISP_REG_CURSOR_WIDTH, pSetPointerShape->Width);
    uxdisp_write(pHw, UXDISP_REG_CURSOR_HEIGHT, pSetPointerShape->Height);
    uxdisp_write(pHw, UXDISP_REG_CURSOR_HOT_X, pSetPointerShape->XHot);
    uxdisp_write(pHw, UXDISP_REG_CURSOR_HOT_Y, pSetPointerShape->YHot);
    uxdisp_write(pHw, UXDISP_REG_CURSOR_CRTC, 0);
    uxdisp_write(pHw, UXDISP_REG_CURSOR_FLAGS, flags);
    uxdisp_write(pHw, UXDISP_REG_CURSOR_ENABLE, UXDISP_CURSOR_SHOW);
    pHw->hwptrFlags &= ~HWPTR_FLAG_HIDE;

    return STATUS_SUCCESS;
}
