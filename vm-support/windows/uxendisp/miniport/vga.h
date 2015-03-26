/*
 * Copyright 2012-2015, Bromium, Inc.
 * Author: Julian Pidancet <julian@pidancet.net>
 * SPDX-License-Identifier: ISC
 */

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

