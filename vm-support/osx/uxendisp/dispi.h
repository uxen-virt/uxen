/*
 * Copyright 2013-2015, Bromium, Inc.
 * Author: Julian Pidancet <julian@pidancet.net>
 * SPDX-License-Identifier: ISC
 */

#ifndef _DISPI_H_
#define _DISPI_H_

#include <architecture/i386/pio.h> // inl, outl

/* VGA I/O port addresses. */
#define VGA_CRTC            0x3D4   /* Color only! */
#define VGA_ATTR_W          0x3C0
#define VGA_ATTR_R          0x3C1
#define VGA_MISC_OUT_W      0x3C2
#define VGA_SEQUENCER       0x3C4
#define VGA_SEQUENCER_DATA  0x3C5
#define VGA_PIXEL_MASK      0x3C6
#define VGA_DAC_W_INDEX     0x3C8
#define VGA_DAC_DATA        0x3C9
#define VGA_MISC_OUT_R      0x3CC
#define VGA_GRAPH_CNTL      0x3CE
#define VGA_GRAPH_CNTL_DATA 0x3CF
#define VGA_STAT_ADDR       0x3DA   /* Color only! */

/* VGA Attribute Controller register indexes. */
#define VGA_AR_MODE         0x10
#define VGA_AR_OVERSCAN     0x11
#define VGA_AR_PLANE_EN     0x12
#define VGA_AR_PIX_PAN      0x13
#define VGA_AR_COLOR_SEL    0x14

/* VGA Graphics Controller register indexes. */
#define VGA_GR_SET_RESET    0x00
#define VGA_GR_DATA_ROTATE  0x03
#define VGA_GR_READ_MAP_SEL 0x04
#define VGA_GR_MODE         0x05
#define VGA_GR_MISC         0x06
#define VGA_GR_BIT_MASK     0x08

/* VGA Sequencer register indexes. */
#define VGA_SR_RESET        0x00
#define VGA_SR_CLK_MODE     0x01
#define VGA_SR_PLANE_MASK   0x02
#define VGA_SR_MEM_MODE     0x04

/* Sequencer constants. */
#define VGA_SR0_NORESET     0x03
#define VGA_SR0_RESET       0x00
#define VGA_SR1_BLANK       0x20

/* VGA CRTC register indexes. */
#define VGA_CR_HORZ_TOTAL   0x00
#define VGA_CR_CUR_START    0x0A
#define VGA_CR_CUR_END      0x0B
#define VGA_CR_START_HI     0x0C
#define VGA_CR_START_LO     0x0D
#define VGA_CR_CUR_POS_HI   0x0E
#define VGA_CR_CUR_POS_LO   0x0F
#define VGA_CR_VSYNC_START  0x10
#define VGA_CR_VSYNC_END    0x11

/* VGA Input Status Register 1 constants. */
#define VGA_STAT_VSYNC      0x08

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

static uint16_t dispi_read(uint16_t reg)
{
    outw(VBE_DISPI_IOPORT_INDEX, reg);
    return inw(VBE_DISPI_IOPORT_DATA);
}
static void dispi_write(uint16_t reg, uint16_t val)
{
    outw(VBE_DISPI_IOPORT_INDEX, reg);
    outw(VBE_DISPI_IOPORT_DATA, val);
}

static uint8_t vga_read(uint16_t reg)
{
    return inb(reg);
}

static void vga_write(uint16_t reg, uint8_t val)
{
    outb(reg, val);
}

static void vga_crtc_write(uint8_t index, uint8_t val)
{
    outw(VGA_CRTC, (val << 8) | index);
}

static void vga_crtc_mask(uint8_t index,
                          uint8_t off, uint8_t on)
{
    uint8_t v;

    vga_write(VGA_CRTC, index);
    v = vga_read(VGA_CRTC + 1);
    vga_write(VGA_CRTC + 1, (v & ~off) | on);
}

static void vga_set_linelength(uint16_t val)
{
    uint8_t v = (val + 7) / 8;

    vga_crtc_write(0x13, v);
}

static void vga_grdc_write(uint8_t index, uint8_t val)
{
    outw(VGA_GRAPH_CNTL, (val << 8) | index);
}

static void vga_grdc_mask(uint8_t index,
                          uint8_t off, uint8_t on)
{
    uint8_t v;

    vga_write(VGA_GRAPH_CNTL, index);
    v = vga_read(VGA_GRAPH_CNTL_DATA);
    vga_write(VGA_GRAPH_CNTL_DATA, (v & ~off) | on);
}

static void vga_sequ_write(uint8_t index, uint8_t val)
{
    outw(VGA_SEQUENCER, (val << 8) | index);
}

static void vga_sequ_mask(uint8_t index,
                          uint8_t off, uint8_t on)
{
    uint8_t v;

    vga_write(VGA_SEQUENCER, index);
    v = vga_read(VGA_SEQUENCER_DATA);
    vga_write(VGA_SEQUENCER_DATA, (v & ~off) | on);
}

static void vga_attr_mask(uint8_t index,
                          uint8_t off, uint8_t on)
{
    uint8_t v, orig;

    (void)vga_read(VGA_STAT_ADDR);
    orig = vga_read(VGA_ATTR_W);
    vga_write(VGA_ATTR_W, index);
    v = vga_read(VGA_ATTR_R);
    vga_write(VGA_ATTR_W, (v & ~off) | on);
    vga_write(VGA_ATTR_W, orig);
}

#endif /* _DISPI_H_ */
