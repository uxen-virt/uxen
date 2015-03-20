/*
 * Copyright 2015, Bromium, Inc.
 * Author: Julian Pidancet <julian@pidancet.net>
 * SPDX-License-Identifier: ISC
 */

#ifndef __UXENVGA_H
#define __UXENVGA_H

#include "types.h" // u8
#include "ioport.h" // outw

#define UXDISP_REG_MAGIC                0x00000
#define     UXDISP_MAGIC                            0x7558656e
#define UXDISP_REG_REVISION             0x00004
#define UXDISP_REG_VRAM_SIZE            0x00008
#define UXDISP_REG_BANK_ORDER           0x0000C
#define UXDISP_REG_CRTC_COUNT           0x00010
#define UXDISP_REG_STRIDE_ALIGN         0x00014
#define UXDISP_REG_INTERRUPT            0x00018
#define     UXDISP_INTERRUPT_HOTPLUG                0x1
#define     UXDISP_INTERRUPT_VBLANK                 0x2
#define UXDISP_REG_CURSOR_ENABLE        0x0001C
#define     UXDISP_CURSOR_SHOW                      0x1
#define UXDISP_REG_MODE                 0x00020
#define     UXDISP_MODE_VGA_DISABLED                0x1

#define UXDISP_REG_BANK_LEN             0x00004
#define UXDISP_REG_BANK(x)              (0x00100 + (x) * UXDISP_REG_BANK_LEN)
#define UXDISP_REG_BANK_POPULATE        0x0

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

struct vgamode_s *uxenvga_find_mode(int mode);
void uxenvga_list_modes(u16 seg, u16 *dest, u16 *last);
int uxenvga_get_window(struct vgamode_s *vmode_g, int window);
int uxenvga_set_window(struct vgamode_s *vmode_g, int window, int val);
int uxenvga_get_linelength(struct vgamode_s *vmode_g);
int uxenvga_set_linelength(struct vgamode_s *vmode_g, int val);
int uxenvga_get_displaystart(struct vgamode_s *vmode_g);
int uxenvga_set_displaystart(struct vgamode_s *vmode_g, int val);
int uxenvga_get_dacformat(struct vgamode_s *vmode_g);
int uxenvga_set_dacformat(struct vgamode_s *vmode_g, int val);
int uxenvga_size_state(int states);
int uxenvga_save_state(u16 seg, void *data, int states);
int uxenvga_restore_state(u16 seg, void *data, int states);
int uxenvga_set_mode(struct vgamode_s *vmode_g, int flags);
int uxenvga_init(void);

static inline u32 uxenvga_read(u16 iobase, u32 addr)
{
    u32 ret;

    outl(addr, iobase + 0);
    ret = inl(iobase + 4);

    return ret;
}

static inline void uxenvga_write(u16 iobase, u32 addr, u32 val)
{
    outl(addr, iobase + 0);
    outl(val, iobase + 4);
}

static inline u32 uxenvga_crtc_read(u16 iobase, u8 crtc, u16 reg)
{
    return uxenvga_read(iobase, UXDISP_REG_CRTC(crtc) + reg);
}

static inline void uxenvga_crtc_write(u16 iobase, u8 crtc, u16 reg, u32 val)
{
    uxenvga_write(iobase, UXDISP_REG_CRTC(crtc) + reg, val);
}

static inline void uxenvga_crtc_flush(u16 iobase, u8 crtc)
{
    u32 offset = uxenvga_crtc_read(iobase, crtc, UXDISP_REG_CRTC_OFFSET);
    uxenvga_crtc_write(iobase, crtc, UXDISP_REG_CRTC_OFFSET, offset);
}

#endif // uxenvga.h
