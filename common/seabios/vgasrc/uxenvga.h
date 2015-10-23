/*
 * Copyright 2015, Bromium, Inc.
 * Author: Julian Pidancet <julian@pidancet.net>
 * SPDX-License-Identifier: ISC
 */

#ifndef __UXENVGA_H
#define __UXENVGA_H

#include "types.h" // u8
#include "ioport.h" // outw

#include "../../../dm/hw/uxdisp_hw.h"

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
int uxenvga_get_ddc_capabilities(u16 unit);
int uxenvga_read_edid(u16 unit, u16 block, u16 seg, void *data);
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
