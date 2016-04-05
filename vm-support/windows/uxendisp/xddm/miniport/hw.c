/*
 * Copyright 2015-2016, Bromium, Inc.
 * Author: Julian Pidancet <julian@pidancet.net>
 * SPDX-License-Identifier: ISC
 */

#include "uxendisp.h"

#include "../../../../../dm/hw/uxdisp_hw.h" /* XXX */

/* A structure describing mode information. Note: The mode numbers
 * usually match VBE, but this should not be relied upon.
 */
typedef struct {
    ULONG     index;          /* Mode number */
    ULONG     xres;           /* Horizontal resolution */
    ULONG     yres;           /* Vertical resolution */
    ULONG     bpp;            /* Color depth */
} BOCHSMode;

static BOCHSMode bochs_modes[] = {
    { 0x12E, 800, 600, 32 },
    { 0x14d, 1024, 700, 32 },
    { 0x138, 1024, 768, 32 },
};

static ULONG uxdisp_read(PDEVICE_EXTENSION dev, ULONG reg)
{
    return READ_REGISTER_ULONG((ULONG *)(dev->mmio_start + reg));
}

static void uxdisp_write(PDEVICE_EXTENSION dev, ULONG reg, ULONG val)
{
    WRITE_REGISTER_ULONG((ULONG *)(dev->mmio_start + reg), val);
}

static ULONG uxdisp_crtc_read(PDEVICE_EXTENSION dev, ULONG crtc, ULONG reg)
{
    uxdisp_read(dev, UXDISP_REG_CRTC(crtc) + reg);
}

static void uxdisp_crtc_write(PDEVICE_EXTENSION dev, ULONG crtc, ULONG reg, ULONG val)
{
    uxdisp_write(dev, UXDISP_REG_CRTC(crtc) + reg, val);
}

static ULONG uxdisp_alloc_read(PDEVICE_EXTENSION dev, ULONG alloc, ULONG reg)
{
    uxdisp_read(dev, UXDISP_REG_ALLOC(alloc) + reg);
}

static void uxdisp_alloc_write(PDEVICE_EXTENSION dev, ULONG alloc, ULONG reg, ULONG val)
{
    uxdisp_write(dev, UXDISP_REG_ALLOC(alloc) + reg, val);
}

VP_STATUS hw_init(PDEVICE_EXTENSION dev)
{
    if (uxdisp_read(dev, UXDISP_REG_MAGIC) != UXDISP_MAGIC)
        return ERROR_DEV_NOT_EXIST;

    uxdisp_write(dev, UXDISP_REG_MODE, UXDISP_MODE_VGA_DISABLED);

    return NO_ERROR;
}

void hw_disable_page_tracking(PDEVICE_EXTENSION dev)
{
    ULONG val = uxdisp_read(dev, UXDISP_REG_MODE);
    val |= UXDISP_MODE_PAGE_TRACKING_DISABLED;
    uxdisp_write(dev, UXDISP_REG_MODE, val);
}

void hw_enable_page_tracking(PDEVICE_EXTENSION dev)
{
    ULONG val = uxdisp_read(dev, UXDISP_REG_MODE);
    val &= ~UXDISP_MODE_PAGE_TRACKING_DISABLED;
    uxdisp_write(dev, UXDISP_REG_MODE, val);
}

ULONG hw_get_nmodes(PDEVICE_EXTENSION dev)
{
    return (sizeof (bochs_modes) / sizeof (bochs_modes[0]));
}

static VP_STATUS mode_info_bpp(ULONG bpp, VIDEO_MODE_INFORMATION *info)
{
    switch (bpp) {
        case 16:
            info->NumberRedBits   = 5;
            info->NumberGreenBits = 6;
            info->NumberBlueBits  = 5;
            info->RedMask         = 0xF800;
            info->GreenMask       = 0x7E0;
            info->BlueMask        = 0x1F;
            break;
        case 24:
        case 32:
            info->NumberRedBits   = 8;
            info->NumberGreenBits = 8;
            info->NumberBlueBits  = 8;
            info->RedMask         = 0xFF0000;
            info->GreenMask       = 0xFF00;
            info->BlueMask        = 0xFF;
            break;
        default:
            return ERROR_INVALID_DATA;
    }

    return NO_ERROR;
}

VP_STATUS hw_is_virt_mode_enabled(PDEVICE_EXTENSION dev)
{
    if (uxdisp_read(dev, UXDISP_REG_VIRTMODE_ENABLED))
        return NO_ERROR;
    return ERROR_DEV_NOT_EXIST;
}

VP_STATUS hw_get_mode_info(PDEVICE_EXTENSION dev, ULONG i,
                              VIDEO_MODE_INFORMATION *info)
{
    VP_STATUS ret;
    BOCHSMode *mode = &bochs_modes[i];

    if (i >= (sizeof (bochs_modes) / sizeof (bochs_modes[0])))
        return ERROR_INVALID_DATA;

    ret = mode_info_bpp(mode->bpp, info);
    if (ret != NO_ERROR)
        return ret;

    info->Length                       = sizeof(VIDEO_MODE_INFORMATION);
    info->ModeIndex                    = mode->index;
    info->VisScreenWidth               = mode->xres;
    info->VisScreenHeight              = mode->yres;
    info->ScreenStride                 = mode->xres * ((mode->bpp + 7) / 8);
    info->NumberOfPlanes               = 1;
    info->BitsPerPlane                 = mode->bpp;
    info->Frequency                    = 60;
    info->XMillimeter                  = 320;
    info->YMillimeter                  = 240;
    info->VideoMemoryBitmapWidth       = mode->xres;
    info->VideoMemoryBitmapHeight      = mode->yres;
    info->DriverSpecificAttributeFlags = 0;
    info->AttributeFlags               = VIDEO_MODE_GRAPHICS | VIDEO_MODE_COLOR;

    return NO_ERROR;
}

VP_STATUS hw_set_mode(PDEVICE_EXTENSION dev, VIDEO_MODE_INFORMATION *mode)
{
    USHORT width = (USHORT)mode->VisScreenWidth;
    USHORT height = (USHORT)mode->VisScreenHeight;
    USHORT bpp = (USHORT)mode->BitsPerPlane;
    USHORT stride = (USHORT)mode->ScreenStride;
    ULONG fmt;

    if (mode->VisScreenWidth > (USHORT)~0 ||
        mode->VisScreenHeight > (USHORT)~0)
        return ERROR_INVALID_PARAMETER;

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
        return ERROR_INVALID_PARAMETER;
    }

    uxdisp_alloc_write(dev, 0, UXDISP_REG_ALLOC_PAGE_START, 0);
    uxdisp_alloc_write(dev, 0, UXDISP_REG_ALLOC_PAGE_COUNT,
                       (height * stride + 4095) >> 12);
    uxdisp_crtc_write(dev, 0, UXDISP_REG_CRTC_ENABLE, 1);
    uxdisp_crtc_write(dev, 0, UXDISP_REG_CRTC_XRES, width);
    uxdisp_crtc_write(dev, 0, UXDISP_REG_CRTC_YRES, height);
    uxdisp_crtc_write(dev, 0, UXDISP_REG_CRTC_STRIDE, stride);
    uxdisp_crtc_write(dev, 0, UXDISP_REG_CRTC_FORMAT, fmt);

    /* Flush */
    uxdisp_crtc_write(dev, 0, UXDISP_REG_CRTC_OFFSET, 0);

    return NO_ERROR;
}

VP_STATUS hw_disable(PDEVICE_EXTENSION dev)
{
    uxdisp_write(dev, UXDISP_REG_MODE, 0);

    return NO_ERROR;
}

ULONG hw_get_vram_size(PDEVICE_EXTENSION dev)
{
    return uxdisp_read(dev, UXDISP_REG_VRAM_SIZE);
}

BOOLEAN hw_pointer_update(PDEVICE_EXTENSION dev, ULONG width, ULONG height,
                          ULONG hot_x, ULONG hot_y,
                          ULONG linesize, PUCHAR pixels,
                          BOOLEAN color)
{
    int flags = 0;
    size_t bitmap_len;
    ULONG y;
    char *s, *d;

    if (color) {
        bitmap_len = 4 * width * height; /* ARGB data */
        bitmap_len += ((width + 7) / 8) * height; /* AND mask */

        if (bitmap_len > (UXDISP_REG_CRTC(0) - UXDISP_REG_CURSOR_DATA))
            return FALSE;



        s = pixels;
        d = dev->mmio_start + UXDISP_REG_CURSOR_DATA;
        for (y = 0; y < height; y++) {
            VideoPortMoveMemory(d, s, (width + 7) / 8);
            d += (width + 7) / 8;
            s += (width + 7) / 8;
        }
        s = pixels;
        s += ((((width + 7) / 8) * height) + 3) & ~3;
        for (y = 0; y < height; y++) {
            VideoPortMoveMemory(d, s, 4 * width);
            d += 4 * width;
            s += linesize;
        }
    } else {
        bitmap_len = ((width + 7) / 8) * height * 2;
        if (bitmap_len > (UXDISP_REG_CRTC(0) - UXDISP_REG_CURSOR_DATA))
            return FALSE;

        s = pixels;
        d = dev->mmio_start + UXDISP_REG_CURSOR_DATA;
        for (y = 0; y < (height * 2); y++) {
            VideoPortMoveMemory(d, s, (width + 7) / 8);
            d += (width + 7) / 8;
            s += (width + 7) / 8;
        }

        flags |= UXDISP_CURSOR_FLAG_1BPP;
    }

    flags |= UXDISP_CURSOR_FLAG_MASK_PRESENT;

    uxdisp_write(dev, UXDISP_REG_CURSOR_WIDTH, width);
    uxdisp_write(dev, UXDISP_REG_CURSOR_HEIGHT, height);
    uxdisp_write(dev, UXDISP_REG_CURSOR_HOT_X, hot_x);
    uxdisp_write(dev, UXDISP_REG_CURSOR_HOT_Y, hot_y);
    uxdisp_write(dev, UXDISP_REG_CURSOR_CRTC, 0);
    uxdisp_write(dev, UXDISP_REG_CURSOR_FLAGS, flags);
    uxdisp_write(dev, UXDISP_REG_CURSOR_ENABLE, UXDISP_CURSOR_SHOW);

    return TRUE;
}

BOOLEAN hw_pointer_setpos(PDEVICE_EXTENSION dev, SHORT x, SHORT y)
{
    uxdisp_write(dev, UXDISP_REG_CURSOR_POS_X, x);
    uxdisp_write(dev, UXDISP_REG_CURSOR_POS_Y, y);

    return TRUE;
}

BOOLEAN hw_pointer_enable(PDEVICE_EXTENSION dev, BOOLEAN en)
{
    uxdisp_write(dev, UXDISP_REG_CURSOR_ENABLE, en ? UXDISP_CURSOR_SHOW : 0);

    return TRUE;
}
