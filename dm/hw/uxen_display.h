/*
 * Copyright 2015-2017, Bromium, Inc.
 * Author: Julian Pidancet <julian@pidancet.net>
 * SPDX-License-Identifier: ISC
 */

#ifndef _UXEN_DISPLAY_H_
#define _UXEN_DISPLAY_H_

#define UXENDISP_REVISION_MAJOR 0x1
#define UXENDISP_REVISION_MINOR 0x0

#define UXENDISP_NB_BANKS 1
#define UXENDISP_BANK_ORDER 0x1a /* 64M */

#define UXENDISP_BANK_SIZE (1 << UXENDISP_BANK_ORDER)
#define UXENDISP_VRAM_SIZE (UXENDISP_BANK_SIZE * UXENDISP_NB_BANKS)

#define UXENDISP_NB_CRTCS 1
#define UXENDISP_MMIO_SIZE 0x20000

#define UXENDISP_CURSOR_MAX_WIDTH 64
#define UXENDISP_CURSOR_MAX_HEIGHT 64

struct cursor_regs {
    uint32_t pos_x;
    uint32_t pos_y;
    uint32_t width;
    uint32_t height;
    uint32_t hot_x;
    uint32_t hot_y;
    uint32_t crtc_idx;
    uint32_t flags;
} __attribute__ ((packed));

struct crtc_regs {
    union {
        struct {
            uint32_t enable;
            uint32_t xres;
            uint32_t yres;
            uint32_t stride;
            uint32_t format;
        } p;
        uint8_t padding[256];
    };
    uint8_t edid[256];
} __attribute__ ((packed));

struct uxendisp_state;

void uxendisp_set_interrupt(struct uxendisp_state *s, int irq);

#endif /* _UXEN_DISPLAY_H_ */
