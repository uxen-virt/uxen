/*
 * Copyright 2015, Bromium, Inc.
 * Author: Julian Pidancet <julian@pidancet.net>
 * SPDX-License-Identifier: ISC
 */

#include "vgabios.h" // struct vbe_modeinfo
#include "vbe.h" // VBE_CAPABILITY_8BIT_DAC
#include "uxenvga.h" // uxenvga_set_mode
#include "util.h" // dprintf
#include "config.h" // CONFIG_*
#include "biosvar.h" // GET_GLOBAL
#include "stdvga.h" // VGAREG_SEQU_ADDRESS
#include "pci.h" // pci_config_readl
#include "pci_regs.h" // PCI_BASE_ADDRESS_0

struct uxenvga_state {
    u32 mode;
    u32 offset;
    u32 en;
    u32 xres;
    u32 yres;
    u32 stride;
    u32 fmt;
};

static u16 uxenvga_iobase VAR16;

/****************************************************************
 * Mode tables
 ****************************************************************/

static struct uxenvga_mode
{
    u16 mode;
    struct vgamode_s info;
} uxenvga_modes[] VAR16 = {
    /* standard modes */
    { 0x100, { MM_PACKED, 640,  400,  8,  8, 16, SEG_GRAPH } },
    { 0x101, { MM_PACKED, 640,  480,  8,  8, 16, SEG_GRAPH } },
    { 0x102, { MM_PLANAR, 800,  600,  4,  8, 16, SEG_GRAPH } },
    { 0x103, { MM_PACKED, 800,  600,  8,  8, 16, SEG_GRAPH } },
    { 0x104, { MM_PLANAR, 1024, 768,  4,  8, 16, SEG_GRAPH } },
    { 0x105, { MM_PACKED, 1024, 768,  8,  8, 16, SEG_GRAPH } },
    { 0x106, { MM_PLANAR, 1280, 1024, 4,  8, 16, SEG_GRAPH } },
    { 0x107, { MM_PACKED, 1280, 1024, 8,  8, 16, SEG_GRAPH } },
    { 0x10D, { MM_DIRECT, 320,  200,  15, 8, 16, SEG_GRAPH } },
    { 0x10E, { MM_DIRECT, 320,  200,  16, 8, 16, SEG_GRAPH } },
    { 0x10F, { MM_DIRECT, 320,  200,  24, 8, 16, SEG_GRAPH } },
    { 0x110, { MM_DIRECT, 640,  480,  15, 8, 16, SEG_GRAPH } },
    { 0x111, { MM_DIRECT, 640,  480,  16, 8, 16, SEG_GRAPH } },
    { 0x112, { MM_DIRECT, 640,  480,  24, 8, 16, SEG_GRAPH } },
    { 0x113, { MM_DIRECT, 800,  600,  15, 8, 16, SEG_GRAPH } },
    { 0x114, { MM_DIRECT, 800,  600,  16, 8, 16, SEG_GRAPH } },
    { 0x115, { MM_DIRECT, 800,  600,  24, 8, 16, SEG_GRAPH } },
    { 0x116, { MM_DIRECT, 1024, 768,  15, 8, 16, SEG_GRAPH } },
    { 0x117, { MM_DIRECT, 1024, 768,  16, 8, 16, SEG_GRAPH } },
    { 0x118, { MM_DIRECT, 1024, 768,  24, 8, 16, SEG_GRAPH } },
    { 0x119, { MM_DIRECT, 1280, 1024, 15, 8, 16, SEG_GRAPH } },
    { 0x11A, { MM_DIRECT, 1280, 1024, 16, 8, 16, SEG_GRAPH } },
    { 0x11B, { MM_DIRECT, 1280, 1024, 24, 8, 16, SEG_GRAPH } },
    { 0x11C, { MM_PACKED, 1600, 1200, 8,  8, 16, SEG_GRAPH } },
    { 0x11D, { MM_DIRECT, 1600, 1200, 15, 8, 16, SEG_GRAPH } },
    { 0x11E, { MM_DIRECT, 1600, 1200, 16, 8, 16, SEG_GRAPH } },
    { 0x11F, { MM_DIRECT, 1600, 1200, 24, 8, 16, SEG_GRAPH } },
    { 0x140, { MM_DIRECT, 320,  200,  32, 8, 16, SEG_GRAPH } },
    { 0x141, { MM_DIRECT, 640,  400,  32, 8, 16, SEG_GRAPH } },
    { 0x142, { MM_DIRECT, 640,  480,  32, 8, 16, SEG_GRAPH } },
    { 0x143, { MM_DIRECT, 800,  600,  32, 8, 16, SEG_GRAPH } },
    { 0x144, { MM_DIRECT, 1024, 768,  32, 8, 16, SEG_GRAPH } },
    { 0x145, { MM_DIRECT, 1280, 1024, 32, 8, 16, SEG_GRAPH } },
    { 0x146, { MM_PACKED, 320,  200,  8,  8, 16, SEG_GRAPH } },
    { 0x147, { MM_DIRECT, 1600, 1200, 32, 8, 16, SEG_GRAPH } },
    { 0x148, { MM_PACKED, 1152, 864,  8,  8, 16, SEG_GRAPH } },
    { 0x149, { MM_DIRECT, 1152, 864,  15, 8, 16, SEG_GRAPH } },
    { 0x14a, { MM_DIRECT, 1152, 864,  16, 8, 16, SEG_GRAPH } },
    { 0x14b, { MM_DIRECT, 1152, 864,  24, 8, 16, SEG_GRAPH } },
    { 0x14c, { MM_DIRECT, 1152, 864,  32, 8, 16, SEG_GRAPH } },
    { 0x14d, { MM_DIRECT, 1024, 700,  32, 8, 16, SEG_GRAPH } },
    { 0x178, { MM_DIRECT, 1280, 800,  16, 8, 16, SEG_GRAPH } },
    { 0x179, { MM_DIRECT, 1280, 800,  24, 8, 16, SEG_GRAPH } },
    { 0x17a, { MM_DIRECT, 1280, 800,  32, 8, 16, SEG_GRAPH } },
    { 0x17b, { MM_DIRECT, 1280, 960,  16, 8, 16, SEG_GRAPH } },
    { 0x17c, { MM_DIRECT, 1280, 960,  24, 8, 16, SEG_GRAPH } },
    { 0x17d, { MM_DIRECT, 1280, 960,  32, 8, 16, SEG_GRAPH } },
    { 0x17e, { MM_DIRECT, 1440, 900,  16, 8, 16, SEG_GRAPH } },
    { 0x17f, { MM_DIRECT, 1440, 900,  24, 8, 16, SEG_GRAPH } },
    { 0x180, { MM_DIRECT, 1440, 900,  32, 8, 16, SEG_GRAPH } },
    { 0x181, { MM_DIRECT, 1400, 1050, 16, 8, 16, SEG_GRAPH } },
    { 0x182, { MM_DIRECT, 1400, 1050, 24, 8, 16, SEG_GRAPH } },
    { 0x183, { MM_DIRECT, 1400, 1050, 32, 8, 16, SEG_GRAPH } },
    { 0x184, { MM_DIRECT, 1680, 1050, 16, 8, 16, SEG_GRAPH } },
    { 0x185, { MM_DIRECT, 1680, 1050, 24, 8, 16, SEG_GRAPH } },
    { 0x186, { MM_DIRECT, 1680, 1050, 32, 8, 16, SEG_GRAPH } },
    { 0x187, { MM_DIRECT, 1920, 1200, 16, 8, 16, SEG_GRAPH } },
    { 0x188, { MM_DIRECT, 1920, 1200, 24, 8, 16, SEG_GRAPH } },
    { 0x189, { MM_DIRECT, 1920, 1200, 32, 8, 16, SEG_GRAPH } },
    { 0x18a, { MM_DIRECT, 2560, 1600, 16, 8, 16, SEG_GRAPH } },
    { 0x18b, { MM_DIRECT, 2560, 1600, 24, 8, 16, SEG_GRAPH } },
    { 0x18c, { MM_DIRECT, 2560, 1600, 32, 8, 16, SEG_GRAPH } },
};

static int is_uxenvga_mode(struct vgamode_s *vmode_g)
{
    return (vmode_g >= &uxenvga_modes[0].info
            && vmode_g <= &uxenvga_modes[ARRAY_SIZE(uxenvga_modes)-1].info);
}

struct vgamode_s *uxenvga_find_mode(int mode)
{
    struct uxenvga_mode *m = uxenvga_modes;
    for (; m < &uxenvga_modes[ARRAY_SIZE(uxenvga_modes)]; m++)
        if (GET_GLOBAL(m->mode) == mode)
            return &m->info;
    return stdvga_find_mode(mode);
}

void
uxenvga_list_modes(u16 seg, u16 *dest, u16 *last)
{
    struct uxenvga_mode *m = uxenvga_modes;
    for (; m < &uxenvga_modes[ARRAY_SIZE(uxenvga_modes)] && dest<last; m++) {
        u16 mode = GET_GLOBAL(m->mode);
        if (mode == 0xffff)
            continue;
        SET_FARVAR(seg, *dest, mode);
        dest++;
    }
    stdvga_list_modes(seg, dest, last);
}


/****************************************************************
 * Helper functions
 ****************************************************************/

int
uxenvga_get_window(struct vgamode_s *vmode_g, int window)
{
    dprintf(1, "get_window\n");
        return -1;
}

int
uxenvga_set_window(struct vgamode_s *vmode_g, int window, int val)
{
    dprintf(1, "set_window %d %d\n", window, val);
        return -1;
}

int
uxenvga_get_linelength(struct vgamode_s *vmode_g)
{
    u16 iobase = GET_GLOBAL(uxenvga_iobase);
    u32 stride;

    stride = uxenvga_crtc_read(iobase, 0, UXDISP_REG_CRTC_STRIDE);

    return stride;
}

int
uxenvga_set_linelength(struct vgamode_s *vmode_g, int val)
{
    u16 iobase = GET_GLOBAL(uxenvga_iobase);

    uxenvga_crtc_write(iobase, 0, UXDISP_REG_CRTC_STRIDE, val);
    uxenvga_crtc_flush(iobase, 0);

    return 0;
}

int
uxenvga_get_displaystart(struct vgamode_s *vmode_g)
{
    u16 iobase = GET_GLOBAL(uxenvga_iobase);
    u32 offset = uxenvga_crtc_read(iobase, 0, UXDISP_REG_CRTC_OFFSET);

    return offset;
}

int
uxenvga_set_displaystart(struct vgamode_s *vmode_g, int val)
{
    u16 iobase = GET_GLOBAL(uxenvga_iobase);

    uxenvga_crtc_write(iobase, 0, UXDISP_REG_CRTC_OFFSET, val);

    return 0;
}

int
uxenvga_get_dacformat(struct vgamode_s *vmode_g)
{
    return 8;
}

int
uxenvga_set_dacformat(struct vgamode_s *vmode_g, int val)
{
    dprintf(1, "set_dacformat %d\n", val);

    if (val != 8)
        return -1;

    return 0;
}

int
uxenvga_size_state(int states)
{
    int size = stdvga_size_state(states);
    if (size < 0)
        return size;
    if (states & 8)
        size += sizeof (struct uxenvga_state);

    return size;
}

int
uxenvga_save_state(u16 seg, void *data, int states)
{
    u16 iobase = GET_GLOBAL(uxenvga_iobase);

    int ret = stdvga_save_state(seg, data, states);
    if (ret < 0)
        return ret;

    if (!(states & 8))
        return 0;

    struct uxenvga_state *st = (data + stdvga_size_state(states));

    u32 v;
    v = uxenvga_read(iobase, UXDISP_REG_MODE);
    SET_FARVAR(seg, st->mode, v);
    v = uxenvga_crtc_read(iobase, 0, UXDISP_REG_CRTC_OFFSET);
    SET_FARVAR(seg, st->offset, v);
    v = uxenvga_crtc_read(iobase, 0, UXDISP_REG_CRTC_ENABLE);
    SET_FARVAR(seg, st->en, v);
    v = uxenvga_crtc_read(iobase, 0, UXDISP_REG_CRTC_XRES);
    SET_FARVAR(seg, st->xres, v);
    v = uxenvga_crtc_read(iobase, 0, UXDISP_REG_CRTC_YRES);
    SET_FARVAR(seg, st->yres, v);
    v = uxenvga_crtc_read(iobase, 0, UXDISP_REG_CRTC_STRIDE);
    SET_FARVAR(seg, st->stride, v);
    v = uxenvga_crtc_read(iobase, 0, UXDISP_REG_CRTC_FORMAT);
    SET_FARVAR(seg, st->fmt, v);

    return 0;
}

int
uxenvga_restore_state(u16 seg, void *data, int states)
{
    u16 iobase = GET_GLOBAL(uxenvga_iobase);

    int ret = stdvga_restore_state(seg, data, states);
    if (ret < 0)
        return ret;

    if (!(states & 8))
        return 0;

    struct uxenvga_state *st = (data + stdvga_size_state(states));

    u32 v;

    v = GET_FARVAR(seg, st->fmt);
    uxenvga_crtc_write(iobase, 0, UXDISP_REG_CRTC_FORMAT, v);
    v = GET_FARVAR(seg, st->stride);
    uxenvga_crtc_write(iobase, 0, UXDISP_REG_CRTC_STRIDE, v);
    v = GET_FARVAR(seg, st->yres);
    uxenvga_crtc_write(iobase, 0, UXDISP_REG_CRTC_YRES, v);
    v = GET_FARVAR(seg, st->xres);
    uxenvga_crtc_write(iobase, 0, UXDISP_REG_CRTC_XRES, v);
    v = GET_FARVAR(seg, st->en);
    uxenvga_crtc_write(iobase, 0, UXDISP_REG_CRTC_ENABLE, v);
    v = GET_FARVAR(seg, st->offset);
    uxenvga_crtc_write(iobase, 0, UXDISP_REG_CRTC_OFFSET, v);
    v = GET_FARVAR(seg, st->mode);
    uxenvga_write(iobase, UXDISP_REG_MODE, v);

    return 0;
}


/****************************************************************
 * Mode setting
 ****************************************************************/

int
uxenvga_set_mode(struct vgamode_s *vmode_g, int flags)
{
    u16 iobase = GET_GLOBAL(uxenvga_iobase);
    u32 v;

    if (! is_uxenvga_mode(vmode_g)) {
        v = uxenvga_read(iobase, UXDISP_REG_MODE);
        uxenvga_write(iobase, UXDISP_REG_MODE, v & ~UXDISP_MODE_VGA_DISABLED);
        return stdvga_set_mode(vmode_g, flags);
    }

    u8 depth = GET_GLOBAL(vmode_g->depth);
    if (depth == 4)
        stdvga_set_mode(stdvga_find_mode(0x6a), 0);
    if (depth == 8)
        // XXX load_dac_palette(3);
        ;

    uxenvga_crtc_write(iobase, 0, UXDISP_REG_CRTC_ENABLE, 0x1);

    switch (depth) {
    case 32:
        uxenvga_crtc_write(iobase, 0, UXDISP_REG_CRTC_FORMAT,
                           UXDISP_CRTC_FORMAT_BGRX_8888);
        break;
    case 24:
        uxenvga_crtc_write(iobase, 0, UXDISP_REG_CRTC_FORMAT,
                           UXDISP_CRTC_FORMAT_BGR_888);
        break;
    case 16:
        uxenvga_crtc_write(iobase, 0, UXDISP_REG_CRTC_FORMAT,
                           UXDISP_CRTC_FORMAT_BGR_565);
        break;
    case 15:
        uxenvga_crtc_write(iobase, 0, UXDISP_REG_CRTC_FORMAT,
                           UXDISP_CRTC_FORMAT_BGR_555);
        break;
    default:
        return -1;
    }

    u32 width = GET_GLOBAL(vmode_g->width);
    u32 height = GET_GLOBAL(vmode_g->height);
    uxenvga_crtc_write(iobase, 0, UXDISP_REG_CRTC_XRES, width);
    uxenvga_crtc_write(iobase, 0, UXDISP_REG_CRTC_YRES, height);

    u32 linelength = width * ((depth + 7) / 8);
    uxenvga_crtc_write(iobase, 0, UXDISP_REG_CRTC_STRIDE, linelength);

    uxenvga_crtc_write(iobase, 0, UXDISP_REG_CRTC_OFFSET, 0);

    v = uxenvga_read(iobase, UXDISP_REG_MODE);
    uxenvga_write(iobase, UXDISP_REG_MODE, v | UXDISP_MODE_VGA_DISABLED);

    return 0;
}

int uxenvga_get_ddc_capabilities(u16 unit)
{
    u16 iobase = GET_GLOBAL(uxenvga_iobase);
    u32 status;

    status = uxenvga_crtc_read(iobase, unit, UXDISP_REG_CRTC_STATUS);
    if (!status)
        return 0;

    return (1 << 8) | VBE_DDC1_PROTOCOL_SUPPORTED | VBE_DDC2_PROTOCOL_SUPPORTED;
}

int uxenvga_read_edid(u16 unit, u16 block, u16 seg, void *data)
{
    u16 iobase = GET_GLOBAL(uxenvga_iobase);
    u32 status;
    u16 addr;
    u32 v;
    u32 *dest;
    u16 i;

    status = uxenvga_crtc_read(iobase, unit, UXDISP_REG_CRTC_STATUS);
    if (!status)
        return -1;

    dest = data;
    addr = UXDISP_REG_CRTC_EDID_DATA + (block * 128);
    for (i = 0; i < (128 / sizeof (v)); i++) {
        v = uxenvga_crtc_read(iobase, unit, addr);
        SET_FARVAR(seg, *dest, v);
        dest++;
        addr += sizeof (v);
    }

    return 0;
}

/****************************************************************
 * Init
 ****************************************************************/

int
uxenvga_init(void)
{
    u16 iobase;
    int bdf;

    int ret = stdvga_init();
    if (ret)
        return ret;

    bdf = GET_GLOBAL(VgaBDF);
    if (!CONFIG_VGA_PCI || bdf < 0)
        return -1;

    iobase = pci_config_readl(bdf, PCI_BASE_ADDRESS_2)
             & PCI_BASE_ADDRESS_IO_MASK;

    u32 magic = uxenvga_read(iobase, UXDISP_REG_MAGIC);
    if (magic != UXDISP_MAGIC) {
        dprintf(1, "uXenVGA detection failure (iobase=%04x). magic=%08x\n",
                iobase, magic);
        return -1;
    }

    if (GET_GLOBAL(HaveRunInit))
        return 0;

    u32 revision = uxenvga_read(iobase, UXDISP_REG_REVISION);
    u32 totalmem = (1 << uxenvga_read(iobase, UXDISP_REG_BANK_ORDER));

    u32 lfb_addr = pci_config_readl(bdf, PCI_BASE_ADDRESS_0)
                   & PCI_BASE_ADDRESS_MEM_MASK;

    dprintf(1, "uXenVGA %d.%d %02x:%02x.%x iobase=%04x framebuffer=%08x\n",
            revision >> 16, revision & 0xffff,
            pci_bdf_to_bus(bdf), pci_bdf_to_dev(bdf),
            pci_bdf_to_fn(bdf),
            iobase, lfb_addr);

    SET_VGA(VBE_framebuffer, lfb_addr);
    SET_VGA(VBE_total_memory, totalmem);
    SET_VGA(VBE_capabilities, VBE_CAPABILITY_8BIT_DAC);

    SET_VGA(uxenvga_iobase, iobase);

    // Validate modes
    struct uxenvga_mode *m = uxenvga_modes;
    for (; m < &uxenvga_modes[ARRAY_SIZE(uxenvga_modes)]; m++) {
        u16 width = GET_GLOBAL(m->info.width);
        u16 height = GET_GLOBAL(m->info.height);
        u8 depth = GET_GLOBAL(m->info.depth);
        u32 mem = (height * DIV_ROUND_UP(width * vga_bpp(&m->info), 8)
                   * 4 / stdvga_bpp_factor(&m->info));

        if ((depth != 32 && depth != 24 && depth != 16 && depth != 15) ||
            mem > totalmem) {
            dprintf(2, "Removing mode %x\n", GET_GLOBAL(m->mode));
            SET_VGA(m->mode, 0xffff);
        }
    }

    return 0;
}

