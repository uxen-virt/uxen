/*
 * Copyright 2012-2015, Bromium, Inc.
 * Author: Julian Pidancet <julian@pidancet.net>
 * SPDX-License-Identifier: ISC
 */

#ifndef _POINTER_H_
#define _POINTER_H_

#define HWPTR_WIDTH_MAX         128
#define HWPTR_HEIGHT_MAX        128
#define HWPTR_MEM_MAX           (HWPTR_WIDTH_MAX * HWPTR_HEIGHT_MAX * 4)

#define HWPTR_FLAG_HIDE         (1 << 0)
#define HWPTR_FLAG_MONOCHROME   (1 << 1)

struct hwptr_desc {
    UINT32 pos_x, pos_y;
    UINT32 width, height;
    UINT32 hot_x, hot_y;
    UINT64 bitmap_addr;
    UINT64 bitmap_len;
    UINT32 argb_offset;
    UINT32 flags;
};

BOOLEAN hwptr_update(PDEVICE_EXTENSION dev, ULONG width, ULONG height,
                     ULONG hot_x, ULONG hot_y,
                     ULONG linesize, PUCHAR pixels,
                     BOOLEAN color);
BOOLEAN hwptr_setpos(PDEVICE_EXTENSION dev, SHORT x, SHORT y);
BOOLEAN hwptr_enable(PDEVICE_EXTENSION dev, BOOLEAN en);
int hwptr_init(PDEVICE_EXTENSION dev);

#endif /* _POINTER_H_ */
