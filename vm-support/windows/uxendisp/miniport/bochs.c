/*
 * Copyright 2012-2015, Bromium, Inc.
 * Author: Julian Pidancet <julian@pidancet.net>
 * SPDX-License-Identifier: ISC
 */

#include "uxendisp.h"

#include "bochs.h"

#include "vga.h"

#define VBE_DISPI_BANK_ADDRESS           0xA0000
#define VBE_DISPI_BANK_SIZE_KB           64

#define VBE_DISPI_MAX_XRES               2560
#define VBE_DISPI_MAX_YRES               1600

#define VBE_DISPI_IOPORT_INDEX           0x01CE
#define VBE_DISPI_IOPORT_DATA            0x01CF

#define VBE_DISPI_INDEX_ID               0x0
#define VBE_DISPI_INDEX_XRES             0x1
#define VBE_DISPI_INDEX_YRES             0x2
#define VBE_DISPI_INDEX_BPP              0x3
#define VBE_DISPI_INDEX_ENABLE           0x4
#define VBE_DISPI_INDEX_BANK             0x5
#define VBE_DISPI_INDEX_VIRT_WIDTH       0x6
#define VBE_DISPI_INDEX_VIRT_HEIGHT      0x7
#define VBE_DISPI_INDEX_X_OFFSET         0x8
#define VBE_DISPI_INDEX_Y_OFFSET         0x9
#define VBE_DISPI_INDEX_VIDEO_MEMORY_64K 0xa
#define VBE_DISPI_INDEX_LFB_ADDRESS_H    0xb
#define VBE_DISPI_INDEX_LFB_ADDRESS_L    0xc

#define VBE_DISPI_ID0                    0xB0C0
#define VBE_DISPI_ID1                    0xB0C1
#define VBE_DISPI_ID2                    0xB0C2
#define VBE_DISPI_ID3                    0xB0C3
#define VBE_DISPI_ID4                    0xB0C4
#define VBE_DISPI_ID5                    0xB0C5

#define VBE_DISPI_DISABLED               0x00
#define VBE_DISPI_ENABLED                0x01
#define VBE_DISPI_GETCAPS                0x02
#define VBE_DISPI_8BIT_DAC               0x20
#define VBE_DISPI_LFB_ENABLED            0x40
#define VBE_DISPI_NOCLEARMEM             0x80

#define VBE_DISPI_LFB_PHYSICAL_ADDRESS   0xF0000000

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

static USHORT dispi_read(PDEVICE_EXTENSION dev, USHORT reg)
{
    VideoPortWritePortUshort(dev->io_index, reg);
    return VideoPortReadPortUshort(dev->io_data);
}
static void dispi_write(PDEVICE_EXTENSION dev, USHORT reg, USHORT val)
{
    VideoPortWritePortUshort(dev->io_index, reg);
    VideoPortWritePortUshort(dev->io_data, val);
}

static UCHAR vga_read(PDEVICE_EXTENSION dev, USHORT reg)
{
    return VideoPortReadPortUchar(dev->io_vga + reg);
}

static void vga_write(PDEVICE_EXTENSION dev, USHORT reg, UCHAR val)
{
    VideoPortWritePortUchar(dev->io_vga + reg, val);
}

static void vga_crtc_write(PDEVICE_EXTENSION dev, UCHAR index, UCHAR val)
{
    VideoPortWritePortUshort((PUSHORT)(dev->io_vga + VGA_CRTC),
                             (val << 8) | index);
}

static void vga_crtc_mask(PDEVICE_EXTENSION dev, UCHAR index,
                          UCHAR off, UCHAR on)
{
    UCHAR v;

    vga_write(dev, VGA_CRTC, index);
    v = vga_read(dev, VGA_CRTC + 1);
    vga_write(dev, VGA_CRTC + 1, (v & ~off) | on);
}

static void vga_set_linelength(PDEVICE_EXTENSION dev, USHORT val)
{
    UCHAR v = (val + 7) / 8;

    vga_crtc_write(dev, 0x13, v);
}

static void vga_grdc_write(PDEVICE_EXTENSION dev, UCHAR index, UCHAR val)
{
    VideoPortWritePortUshort((PUSHORT)(dev->io_vga + VGA_GRAPH_CNTL),
                             (val << 8) | index);
}

static void vga_grdc_mask(PDEVICE_EXTENSION dev, UCHAR index,
                          UCHAR off, UCHAR on)
{
    UCHAR v;

    vga_write(dev, VGA_GRAPH_CNTL, index);
    v = vga_read(dev, VGA_GRAPH_CNTL_DATA);
    vga_write(dev, VGA_GRAPH_CNTL_DATA, (v & ~off) | on);
}

static void vga_sequ_write(PDEVICE_EXTENSION dev, UCHAR index, UCHAR val)
{
    VideoPortWritePortUshort((PUSHORT)(dev->io_vga + VGA_SEQUENCER),
                             (val << 8) | index);
}

static void vga_sequ_mask(PDEVICE_EXTENSION dev, UCHAR index,
                          UCHAR off, UCHAR on)
{
    UCHAR v;

    vga_write(dev, VGA_SEQUENCER, index);
    v = vga_read(dev, VGA_SEQUENCER_DATA);
    vga_write(dev, VGA_SEQUENCER_DATA, (v & ~off) | on);
}

static void vga_attr_mask(PDEVICE_EXTENSION dev, UCHAR index,
                          UCHAR off, UCHAR on)
{
    UCHAR v, orig;

    (void)vga_read(dev, VGA_STAT_ADDR);
    orig = vga_read(dev, VGA_ATTR_W);
    vga_write(dev, VGA_ATTR_W, index);
    v = vga_read(dev, VGA_ATTR_R);
    vga_write(dev, VGA_ATTR_W, (v & ~off) | on);
    vga_write(dev, VGA_ATTR_W, orig);
}

VP_STATUS bochs_init(PDEVICE_EXTENSION dev)
{
    dispi_write(dev, VBE_DISPI_INDEX_ID, VBE_DISPI_ID0);
    if (dispi_read(dev, VBE_DISPI_INDEX_ID) != VBE_DISPI_ID0) {
        return ERROR_DEV_NOT_EXIST;
    }

    dispi_write(dev, VBE_DISPI_INDEX_ID, VBE_DISPI_ID5);

    return NO_ERROR;
}

ULONG bochs_get_nmodes(PDEVICE_EXTENSION dev)
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

VP_STATUS bochs_get_mode_info(PDEVICE_EXTENSION dev, ULONG i,
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

VP_STATUS bochs_set_mode(PDEVICE_EXTENSION dev, VIDEO_MODE_INFORMATION *mode)
{
    USHORT width = (USHORT)mode->VisScreenWidth;
    USHORT height = (USHORT)mode->VisScreenHeight;
    USHORT bpp = (USHORT)mode->BitsPerPlane;
    USHORT stride = (USHORT)mode->ScreenStride;

    if (mode->VisScreenWidth > (USHORT)~0 ||
        mode->VisScreenHeight > (USHORT)~0)
        return ERROR_INVALID_PARAMETER;

    /* Program DISPI */
    dispi_write(dev, VBE_DISPI_INDEX_XRES, width);
    dispi_write(dev, VBE_DISPI_INDEX_YRES, height);
    dispi_write(dev, VBE_DISPI_INDEX_BPP, bpp);
    dispi_write(dev, VBE_DISPI_INDEX_BANK, 0);

    /* Flush */
    dispi_write(dev, VBE_DISPI_INDEX_ENABLE, VBE_DISPI_ENABLED |
                VBE_DISPI_8BIT_DAC | VBE_DISPI_NOCLEARMEM);

    if (dispi_read(dev, VBE_DISPI_INDEX_XRES) != width ||
        dispi_read(dev, VBE_DISPI_INDEX_YRES) != height)
        return ERROR_INVALID_PARAMETER;

    return NO_ERROR;
}

VP_STATUS bochs_disable(PDEVICE_EXTENSION dev)
{
    dispi_write(dev, VBE_DISPI_INDEX_ENABLE, VBE_DISPI_DISABLED);

    return NO_ERROR;
}

ULONG bochs_get_vram_size(PDEVICE_EXTENSION dev)
{
    ULONG vram_size = dispi_read(dev, VBE_DISPI_INDEX_VIDEO_MEMORY_64K);

    return vram_size * (64 * 1024);
}
