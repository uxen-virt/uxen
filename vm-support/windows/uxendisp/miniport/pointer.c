/*
 * Copyright 2012-2015, Bromium, Inc.
 * Author: Julian Pidancet <julian@pidancet.net>
 * SPDX-License-Identifier: ISC
 */

#include "uxendisp.h"

#include "pointer.h"

#define VBE_DISPI_INDEX_HWCURSOR_HI     0xd
#define VBE_DISPI_INDEX_HWCURSOR_LO     0xe
#define VBE_DISPI_INDEX_HWCURSOR_FLUSH  0xf

static void
hwptr_addr_write(PDEVICE_EXTENSION dev, ULONG addr)
{
    VideoPortWritePortUshort(dev->io_index, VBE_DISPI_INDEX_HWCURSOR_HI);
    VideoPortWritePortUshort(dev->io_data, (addr >> 16) & 0xffff);
    VideoPortWritePortUshort(dev->io_index, VBE_DISPI_INDEX_HWCURSOR_LO);
    VideoPortWritePortUshort(dev->io_data, addr & 0xffff);
}

static void
hwptr_flush(PDEVICE_EXTENSION dev)
{
    _WriteBarrier();
    VideoPortWritePortUshort(dev->io_index, VBE_DISPI_INDEX_HWCURSOR_FLUSH);
    VideoPortWritePortUshort(dev->io_data, 0);
}

BOOLEAN
hwptr_update(PDEVICE_EXTENSION dev, ULONG width, ULONG height,
             ULONG hot_x, ULONG hot_y,
             ULONG linesize, PUCHAR pixels,
             BOOLEAN color)
{
    struct hwptr_desc *desc = dev->hwptr_desc_ptr;
    size_t bitmap_len;

    desc->width = width;
    desc->height = height;
    desc->hot_x = hot_x;
    desc->hot_y = hot_y;
    desc->flags &= ~HWPTR_FLAG_HIDE;

    if (color) {
        desc->flags &= ~HWPTR_FLAG_MONOCHROME;
        /* AND Mask (1bpp) */
        bitmap_len = ((width + 7) / 8) * height;
        /* Align on 4-bytes per pixel because ARGB data follows */
        bitmap_len = (bitmap_len + 3) & ~3;
        desc->argb_offset = bitmap_len;
        /* ARGB data (4-bytes per pixel) */
        bitmap_len += linesize * height;
    } else {
        desc->flags |= HWPTR_FLAG_MONOCHROME;
        desc->argb_offset = 0;
        bitmap_len = 2 * ((width + 7) / 8) * height;
    }

    if (bitmap_len >= HWPTR_MEM_MAX)
        return FALSE;

    memcpy(dev->hwptr_bitmap_ptr, pixels, bitmap_len);
    hwptr_flush(dev);

    return TRUE;
}

BOOLEAN
hwptr_enable(PDEVICE_EXTENSION dev, BOOLEAN en)
{
    struct hwptr_desc *desc = dev->hwptr_desc_ptr;

    if (en)
        desc->flags &= ~HWPTR_FLAG_HIDE;
    else
        desc->flags |= HWPTR_FLAG_HIDE;

    hwptr_flush(dev);

    return TRUE;
}

BOOLEAN
hwptr_setpos(PDEVICE_EXTENSION dev, SHORT x, SHORT y)
{
    struct hwptr_desc *desc = dev->hwptr_desc_ptr;

    desc->pos_x = x;
    desc->pos_y = y;

    return TRUE;
}

int
hwptr_init(PDEVICE_EXTENSION dev)
{
    int rc;
    struct hwptr_desc *desc;

    dev->hwptr_desc_ptr = VideoPortAllocateCommonBuffer(
                                                    dev, dev->dma,
                                                    sizeof (struct hwptr_desc),
                                                    &dev->hwptr_desc_addr,
                                                    FALSE, NULL);
    if (!dev->hwptr_desc_ptr)
        return -1;
    VideoPortZeroMemory(dev->hwptr_desc_ptr, sizeof (struct hwptr_desc));

    dev->hwptr_bitmap_ptr = VideoPortAllocateCommonBuffer(
                                                    dev, dev->dma,
                                                    HWPTR_MEM_MAX,
                                                    &dev->hwptr_bitmap_addr,
                                                    FALSE, NULL);
    if (!dev->hwptr_bitmap_ptr) {
        VideoPortReleaseCommonBuffer(dev, dev->dma, sizeof (struct hwptr_desc),
                                     dev->hwptr_desc_addr, dev->hwptr_desc_ptr,
                                     FALSE);
        return -1;
    }
    VideoPortZeroMemory(dev->hwptr_bitmap_ptr, HWPTR_MEM_MAX);

    desc = dev->hwptr_desc_ptr;
    desc->bitmap_addr = dev->hwptr_bitmap_addr.QuadPart;
    desc->bitmap_len = HWPTR_MEM_MAX;

    hwptr_addr_write(dev, (ULONG)dev->hwptr_desc_addr.QuadPart);

    return 0;
}
