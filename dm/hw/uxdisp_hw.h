/*
 * Copyright 2015-2016, Bromium, Inc.
 * Author: Julian Pidancet <julian@pidancet.net>
 * SPDX-License-Identifier: ISC
 */

#ifndef UXDISP_HW_H_
#define UXDISP_HW_H_

#define UXDISP_REG_MAGIC                0x00000
#define     UXDISP_MAGIC                            0x7558656e
#define UXDISP_REG_REVISION             0x00004
#define UXDISP_REG_VRAM_SIZE            0x00008
#define UXDISP_REG_ALLOC_COUNT          0x0000C
#define UXDISP_REG_CRTC_COUNT           0x00010
#define UXDISP_REG_STRIDE_ALIGN         0x00014
#define UXDISP_REG_INTERRUPT            0x00018
#define     UXDISP_INTERRUPT_HOTPLUG                0x1
#define     UXDISP_INTERRUPT_VBLANK                 0x2
#define UXDISP_REG_CURSOR_ENABLE        0x0001C
#define     UXDISP_CURSOR_SHOW                      0x1
#define UXDISP_REG_MODE                 0x00020
#define     UXDISP_MODE_VGA_DISABLED                0x1
#define     UXDISP_MODE_PAGE_TRACKING_DISABLED      0x2
#define UXDISP_REG_INTERRUPT_ENABLE     0x00024
#define UXDISP_REG_VIRTMODE_ENABLED     0x00028

#define UXDISP_REG_ALLOC_LEN            0x00008
#define UXDISP_REG_ALLOC(x)             (0x00100 + (x) * UXDISP_REG_ALLOC_LEN)
#define UXDISP_REG_ALLOC_PAGE_START     0x0
#define UXDISP_REG_ALLOC_PAGE_COUNT     0x4

#define UXDISP_REG_CURSOR_POS_X         0x01000
#define UXDISP_REG_CURSOR_POS_Y         0x01004
#define UXDISP_REG_CURSOR_WIDTH         0x01008
#define UXDISP_REG_CURSOR_HEIGHT        0x0100C
#define UXDISP_REG_CURSOR_HOT_X         0x01010
#define UXDISP_REG_CURSOR_HOT_Y         0x01014
#define UXDISP_REG_CURSOR_CRTC          0x01018
#define UXDISP_REG_CURSOR_FLAGS         0x0101C
#define     UXDISP_CURSOR_FLAG_1BPP                 0x1
#define     UXDISP_CURSOR_FLAG_MASK_PRESENT         0x2

#define UXDISP_REG_CURSOR_DATA          0x08000

#define UXDISP_REG_CRTC_LEN             0x02000
#define UXDISP_REG_CRTC(x)              (0x10000 + (x) * UXDISP_REG_CRTC_LEN)
#define UXDISP_REG_CRTC_STATUS          0x0000
#define UXDISP_REG_CRTC_OFFSET          0x0004
#define     UXDISP_REG_CRTC_ALLOC_INDEX_SHIFT        29
#define     UXDISP_REG_CRTC_ALLOC_INDEX_MASK         0x7
#define     UXDISP_REG_CRTC_ALLOC_OFFSET_SHIFT       0
#define     UXDISP_REG_CRTC_ALLOC_OFFSET_MASK        0x1fffffff
#define UXDISP_REG_CRTC_ENABLE          0x1000
#define UXDISP_REG_CRTC_XRES            0x1004
#define UXDISP_REG_CRTC_YRES            0x1008
#define UXDISP_REG_CRTC_STRIDE          0x100C
#define UXDISP_REG_CRTC_FORMAT          0x1010
#define     UXDISP_CRTC_FORMAT_BGRX_8888            0x00000000
#define     UXDISP_CRTC_FORMAT_BGR_888              0x00000001
#define     UXDISP_CRTC_FORMAT_BGR_565              0x00000002
#define     UXDISP_CRTC_FORMAT_BGR_555              0x00000004
#define UXDISP_REG_CRTC_EDID_DATA       0x1100

#if defined(_MSC_VER)
#define INLINE __inline
#else
#define INLINE inline
#endif

static INLINE int uxdisp_fmt_to_bpp(int fmt)
{
    switch (fmt) {
    case UXDISP_CRTC_FORMAT_BGRX_8888:
        return 32;
    case UXDISP_CRTC_FORMAT_BGR_888:
        return 24;
    case UXDISP_CRTC_FORMAT_BGR_565:
        return 16;
    case UXDISP_CRTC_FORMAT_BGR_555:
        return 15;
    }

    return -1;
}

#endif /* UXDISP_HW_H_ */
