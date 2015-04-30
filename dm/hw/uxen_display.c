/*
 * Copyright 2015, Bromium, Inc.
 * Author: Julian Pidancet <julian@pidancet.net>
 * SPDX-License-Identifier: ISC
 */

#include <dm/qemu_glue.h>
#include <dm/bh.h>
#include <dm/dev.h>
#include <dm/dma.h>
#include <dm/console.h>
#include <dm/vga.h>
#include <dm/vmstate.h>
#include <dm/vram.h>
#include <dm/hw/vga.h>
#include "pci.h"
#include "pci-ram.h"

#include "uxen_display.h"
#include "uxdisp_hw.h"

#define DEBUG_UXENDISP

#ifdef DEBUG_UXENDISP
#define DPRINTF(fmt, ...) debug_printf("uxendisp: " fmt, ## __VA_ARGS__)
#else
#define DPRINTF(fmt, ...) do {} while (0)
#endif

struct crtc_state {
    uint32_t offset;
    struct crtc_regs *regs;
    DisplayState *ds;
    int flush_pending;
};

struct uxendisp_state {
    PCIDevice dev;
    VGAState vga;

    MemoryRegion vram; /* BAR 0 */
    MemoryRegion mmio; /* BAR 1 */
    MemoryRegion pio; /* BAR 2 */

    struct cursor_regs *cursor_regs;
    uint8_t *cursor_data;
    struct crtc_state crtcs[UXENDISP_NB_CRTCS];
    struct vram_desc banks[UXENDISP_NB_BANKS];

    uint32_t io_index;
    uint32_t isr;
    uint32_t cursor_en;
    uint32_t mode;
};

/*
 * Drawing and pixel conversion
 */
static void
draw_line_24(uint8_t *d, uint8_t *s, size_t width)
{
    size_t x;

    for (x = 0; x < width; x++) {
        uint8_t *dst = d + (x * 4);
        uint8_t *src = s + (x * 3);

        dst[0] = src[0];
        dst[1] = src[1];
        dst[2] = src[2];
        dst[3] = 0xFF;
    }
}

static void
draw_line_16(uint8_t *d, uint8_t *s, size_t width)
{
    size_t x;

    for (x = 0; x < width; x++) {
        uint8_t *dst = d + (x * 4);
        uint8_t *src = s + (x * 2);

        dst[0] = src[0] << 3;
        dst[1] = (src[1] << 5) | ((src[0] & 0xE0) >> 3);
        dst[2] = src[1] & 0xF8;
        dst[3] = 0xFF;
    }
}

static void
draw_line_15(uint8_t *d, uint8_t *s, size_t width)
{
    size_t x;

    for (x = 0; x < width; x++) {
        uint8_t *dst = d + (x * 4);
        uint8_t *src = s + (x * 2);

        dst[0] = src[0] << 3;
        dst[1] = (src[1] << 6) | ((src[0] & 0xE0) >> 2);
        dst[2] = (src[1] << 1) & 0xF8;
        dst[3] = 0xFF;
    }
}

static void crtc_flush(struct uxendisp_state *s, int crtc_id);

static void
crtc_draw(struct uxendisp_state *s, int crtc_id)
{
    struct crtc_state *crtc = &s->crtcs[crtc_id];
    int bank_id = crtc->offset >> UXENDISP_BANK_ORDER;
    struct vram_desc *bank = &s->banks[bank_id];
    int rc;
    int npages;
    uint8_t *dirty;
    uint8_t *d;
    int linesize;

    int y, y_start;
    uint32_t addr, addr1;
    uint32_t page0, page1, pagei, page_min, page_max;

    if (crtc->flush_pending)
        crtc_flush(s, crtc_id);
    if (!crtc->ds)
        return;

    npages = (crtc->offset + crtc->regs->p.stride * crtc->regs->p.yres +
              TARGET_PAGE_SIZE - 1) >> TARGET_PAGE_BITS;

    if (npages > (UXENDISP_BANK_SIZE >> TARGET_PAGE_BITS))
        return;

    dirty = alloca((npages + 7) / 8);

    rc = xen_hvm_track_dirty_vram(bank->gfn, npages, dirty, 1);
    if (rc) {
        DPRINTF("xen_hvm_track_dirty_vram failed: %d\n", errno);
        return;
    }

    if (ds_surface_lock(crtc->ds, &d, &linesize))
        return;
    addr1 = crtc->offset;
    y_start = -1;
    page_min = (uint32_t)-1;
    page_max = 0;
    for (y = 0; y < crtc->regs->p.yres; y++) {
        int update = 0;

        addr = addr1;
        page0 = addr >> TARGET_PAGE_BITS;
        page1 = (addr + crtc->regs->p.stride - 1) >> TARGET_PAGE_BITS;

        for (pagei = page0; pagei <= page1; pagei++)
            update |= dirty[pagei / 8] & (1 << (pagei % 8));

        if (update) {
            if (y_start < 0)
                y_start = y;
            if (page0 < page_min)
                page_min = page0;
            if (page1 > page_max)
                page_max = page1;
            if (!ds_vram_surface(crtc->ds->surface)) {
                switch (crtc->regs->p.format) {
                case UXDISP_CRTC_FORMAT_BGRX_8888:
                    memcpy(d, bank->view + addr1, crtc->regs->p.xres * 4);
                    break;
                case UXDISP_CRTC_FORMAT_BGR_888:
                    draw_line_24(d, bank->view + addr1, crtc->regs->p.xres);
                    break;
                case UXDISP_CRTC_FORMAT_BGR_565:
                    draw_line_16(d, bank->view + addr1, crtc->regs->p.xres);
                    break;
                case UXDISP_CRTC_FORMAT_BGR_555:
                    draw_line_15(d, bank->view + addr1, crtc->regs->p.xres);
                    break;
                }
            }
        } else if (y_start >= 0) {
            dpy_update(crtc->ds, 0, y_start, crtc->regs->p.xres,
                       y - y_start);
            y_start = -1;
        }
        addr1 += crtc->regs->p.stride;
        d += linesize;
    }
    ds_surface_unlock(crtc->ds);
    if (y_start >= 0) {
        dpy_update(crtc->ds, 0, y_start, crtc->regs->p.xres,
                   y - y_start);
    }
}

/*
 * Console callbacks
 */
static void uxendisp_update(void *opaque)
{
    struct uxendisp_state *s = opaque;

    if (!(s->mode & UXDISP_MODE_VGA_DISABLED)) {
        vga_update_display(&s->vga);
        return;
    }

    crtc_draw(s, 0);
}

static void uxendisp_invalidate(void *opaque)
{
    struct uxendisp_state *s = opaque;

    if (!(s->mode & UXDISP_MODE_VGA_DISABLED)) {
        vga_invalidate_display(&s->vga);
        return;
    }
}

static void uxendisp_text_update(void *opaque, console_ch_t *chardata)
{
    struct uxendisp_state *s = opaque;

    if (!(s->mode & UXDISP_MODE_VGA_DISABLED)) {
        vga_update_text(&s->vga, chardata);
        return;
    }
}

/*
* IO handling
*/

static void
cursor_flush(struct uxendisp_state *s)
{
    uint8_t *mask;
    uint8_t *color;
    struct DisplayState *ds;

    /* XXX crtc 0 only for now */
    if (s->cursor_regs->crtc_idx == 0)
        ds = s->crtcs[0].ds;
    else
        return;

    if (!(s->cursor_en & UXDISP_CURSOR_SHOW)) {
        dpy_cursor_shape(ds, 0, 0, 0, 0, NULL, NULL);
        return;
    }

    if ((s->cursor_regs->width > UXENDISP_CURSOR_MAX_WIDTH) ||
        (s->cursor_regs->height > UXENDISP_CURSOR_MAX_HEIGHT))
        return;

    if (s->cursor_regs->flags & UXDISP_CURSOR_FLAG_1BPP) {
        if (!(s->cursor_regs->flags & UXDISP_CURSOR_FLAG_MASK_PRESENT))
            return;
        color = NULL;
        mask = s->cursor_data;
    } else {
        color = s->cursor_data;
        mask = NULL;
        if (s->cursor_regs->flags & UXDISP_CURSOR_FLAG_MASK_PRESENT) {
            mask = color;
            color += ((s->cursor_regs->width + 7) / 8) *
                     s->cursor_regs->height;
        }
    }

    dpy_cursor_shape(ds, s->cursor_regs->width,
                     s->cursor_regs->height,
                     s->cursor_regs->hot_x,
                     s->cursor_regs->hot_y,
                     mask, color);
}

static void bank_reg_write(struct uxendisp_state *s,
                           int bank_id,
                           target_phys_addr_t addr,
                           uint32_t val);

static void
crtc_flush(struct uxendisp_state *s, int crtc_id)
{
    struct crtc_state *crtc = &s->crtcs[crtc_id];

    /* XXX crtc 0 only for now */
    if (crtc_id == 0 && (s->mode & UXDISP_MODE_VGA_DISABLED)) {
        struct vram_desc *bank;
        size_t sz;

        if (crtc->regs->p.enable) {
            uint32_t offset = crtc->offset & (UXENDISP_BANK_SIZE - 1);
            int bank_id = crtc->offset >> UXENDISP_BANK_ORDER;

            if (bank_id >= UXENDISP_NB_BANKS)
                return;

            bank = &s->banks[bank_id];
            sz = offset + crtc->regs->p.yres * crtc->regs->p.stride;
            if (sz > UXENDISP_BANK_SIZE)
                return;
            if (bank->mapped_len < sz)
                bank_reg_write(s, bank_id, 0, sz);

            console_resize_from(crtc->ds,
                                crtc->regs->p.xres,
                                crtc->regs->p.yres,
                                uxdisp_fmt_to_bpp(crtc->regs->p.format),
                                crtc->regs->p.stride,
                                bank->view, offset);
        } else if (crtc->ds->surface) {
            free_displaysurface(crtc->ds->surface);
            crtc->ds->surface = NULL;
        }

        do_dpy_trigger_refresh(crtc->ds);
    }

    crtc->flush_pending = 0;
}

static void
crtc_write(struct uxendisp_state *s, int crtc_id, target_phys_addr_t addr,
           uint32_t val)
{
    struct crtc_state *crtc = &s->crtcs[crtc_id];

    switch (addr) {
    case UXDISP_REG_CRTC_OFFSET:
        crtc->offset = val;
        crtc_flush(s, crtc_id);
        break;
    case UXDISP_REG_CRTC_ENABLE:
        crtc->regs->p.enable = val;
        return;
    case UXDISP_REG_CRTC_XRES:
        crtc->regs->p.xres = val;
        break;
    case UXDISP_REG_CRTC_YRES:
        crtc->regs->p.yres = val;
        break;
    case UXDISP_REG_CRTC_STRIDE:
        crtc->regs->p.stride = val;
        break;
    case UXDISP_REG_CRTC_FORMAT:
        crtc->regs->p.format = val;
        break;
    default:
        DPRINTF("%s: invalid mmio write for CRTC %d @ %"PRIx64"\n",
                __FUNCTION__, crtc_id, addr);
        return;
    }
}

static uint32_t
crtc_read(struct uxendisp_state *s, int crtc_id, target_phys_addr_t addr)
{
    struct crtc_state *crtc = &s->crtcs[crtc_id];
    uint32_t ret = ~0;

    switch (addr) {
    case UXDISP_REG_CRTC_STATUS:
        ret = 0; /* XXX: No monitor connected */
        break;
    case UXDISP_REG_CRTC_OFFSET:
        ret = crtc->offset;
        break;
    case UXDISP_REG_CRTC_ENABLE:
        ret = crtc->regs->p.enable;
        break;
    case UXDISP_REG_CRTC_XRES:
        ret = crtc->regs->p.xres;
        break;
    case UXDISP_REG_CRTC_YRES:
        ret = crtc->regs->p.yres;
        break;
    case UXDISP_REG_CRTC_STRIDE:
        ret = crtc->regs->p.stride;
        break;
    case UXDISP_REG_CRTC_FORMAT:
        ret = crtc->regs->p.format;
        break;
    default:
        DPRINTF("%s: invalid mmio read for CRTC %d @ %"PRIx64"\n",
                __FUNCTION__, crtc_id, addr);
    }

    return ret;
}

static void
bank_reg_write(struct uxendisp_state *s, int bank_id, target_phys_addr_t addr,
               uint32_t val)
{
    struct vram_desc *bank = &s->banks[bank_id];

    if (addr != 0)
        return;

    val = (val + (TARGET_PAGE_SIZE - 1)) &
          ~(TARGET_PAGE_SIZE - 1);

    if ((bank_id == 0) && val < (vm_vga_mb_mapped << 20))
        val = vm_vga_mb_mapped << 20;

    if (val > UXENDISP_BANK_SIZE)
        val = UXENDISP_BANK_SIZE;

    vram_resize(bank, val);
}

static uint32_t
bank_reg_read(struct uxendisp_state *s, int bank_id, target_phys_addr_t addr)
{
    struct vram_desc *bank = &s->banks[bank_id];

    if (addr != 0)
        return ~0;

    return bank->mapped_len;
}

static void
uxendisp_mmio_write(void *opaque, target_phys_addr_t addr, uint64_t val,
                    unsigned size)
{
    struct uxendisp_state *s = opaque;

    if (size != 4 || addr & 0x3)
        goto invalid;

    if (addr >= UXDISP_REG_CRTC(0) &&
        addr < UXDISP_REG_CRTC(UXENDISP_NB_CRTCS)) {
        int idx = (addr - UXDISP_REG_CRTC(0)) / UXDISP_REG_CRTC_LEN;

        addr &= (UXDISP_REG_CRTC_LEN - 1);

        crtc_write(s, idx, addr, (uint32_t)val);
        return;
    }

    if (addr >= UXDISP_REG_BANK(0) &&
        addr < UXDISP_REG_BANK(UXENDISP_NB_BANKS)) {
        int idx = (addr - UXDISP_REG_BANK(0)) / UXDISP_REG_BANK_LEN;

        addr &= (UXDISP_REG_BANK_LEN - 1);

        bank_reg_write(s, idx, addr, (uint32_t)val);
        return;
    }

    switch (addr) {
    case UXDISP_REG_INTERRUPT:
        s->isr ^= (uint32_t)val;
        if (s->isr == 0)
            qemu_set_irq(s->dev.irq[0], 0);
        return;
    case UXDISP_REG_CURSOR_ENABLE:
        s->cursor_en = val & 0x1;
        cursor_flush(s);
        return;
    case UXDISP_REG_MODE:
        s->mode = val;
        crtc_flush(s, 0);
        uxendisp_invalidate(s);
        return;
    default:
        break;
    }

invalid:
    DPRINTF("%s: invalid mmio write @ %"PRIx64"/%x\n",
            __FUNCTION__, addr, size);
}

static uint64_t
uxendisp_mmio_read(void *opaque, target_phys_addr_t addr, unsigned size)
{
    struct uxendisp_state *s = opaque;

    if (size != 4 || addr & 0x3)
        goto invalid;

    if (addr >= UXDISP_REG_CRTC(0) &&
        addr < UXDISP_REG_CRTC(UXENDISP_NB_CRTCS)) {
        int idx = (addr - UXDISP_REG_CRTC(0)) / UXDISP_REG_CRTC_LEN;

        addr &= (UXDISP_REG_CRTC_LEN - 1);

        return crtc_read(s, idx, addr);
    }

    if (addr >= UXDISP_REG_BANK(0) &&
        addr < UXDISP_REG_BANK(UXENDISP_NB_BANKS)) {
        int idx = (addr - UXDISP_REG_BANK(0)) / UXDISP_REG_BANK_LEN;

        addr &= (UXDISP_REG_BANK_LEN - 1);

        return bank_reg_read(s, idx, addr);
    }

    switch (addr) {
    case UXDISP_REG_MAGIC:
        return UXDISP_MAGIC;
    case UXDISP_REG_REVISION:
        return (UXENDISP_REVISION_MAJOR << 16) | UXENDISP_REVISION_MINOR;
    case UXDISP_REG_VRAM_SIZE:
        return UXENDISP_VRAM_SIZE;
    case UXDISP_REG_BANK_ORDER:
        return UXENDISP_BANK_ORDER;
    case UXDISP_REG_CRTC_COUNT:
        return UXENDISP_NB_CRTCS;
    case UXDISP_REG_STRIDE_ALIGN:
        return 0;
    case UXDISP_REG_INTERRUPT:
        return s->isr;
    case UXDISP_REG_CURSOR_ENABLE:
        return s->cursor_en;
    case UXDISP_REG_MODE:
        return s->mode;
    default:
        break;
    }

invalid:
    DPRINTF("%s: invalid mmio read @ %"PRIx64"/%x\n",
            __FUNCTION__, addr, size);
    return ~0;
}

static const MemoryRegionOps mmio_ops = {
    .read = uxendisp_mmio_read,
    .write = uxendisp_mmio_write
};

static void
uxendisp_pio_write(void *opaque, target_phys_addr_t addr, uint64_t val,
                   unsigned size)
{
    struct uxendisp_state *s = opaque;

    if (size != 4)
        return;

    switch (addr) {
    case 0:
        s->io_index = val;
        break;
    case 4:
        uxendisp_mmio_write(s, s->io_index, val, 4);
        break;
    }
}

static uint64_t
uxendisp_pio_read(void *opaque, target_phys_addr_t addr, unsigned size)
{
    struct uxendisp_state *s = opaque;

    if (size != 4)
        return ~0;

    switch (addr) {
    case 0:
        return s->io_index;
    case 4:
        return uxendisp_mmio_read(s, s->io_index, 4);
    }

    return ~0;
}

static const MemoryRegionOps pio_ops = {
    .read = uxendisp_pio_read,
    .write = uxendisp_pio_write,
    .endianness = DEVICE_LITTLE_ENDIAN,
};

/*
 * RAM pointers
 */
static void
cursor_regs_ptr_update(void *ptr, void *opaque)
{
    struct uxendisp_state *s = opaque;

    s->cursor_regs = ptr;
}

static void
cursor_data_ptr_update(void *ptr, void *opaque)
{
    struct uxendisp_state *s = opaque;

    s->cursor_data = ptr;
}

static void
crtc_data_ptr_update(void *ptr, void *opaque)
{
    struct crtc_state *c = opaque;

    c->regs = ptr;
}

/*
 * BAR 0 moved
 */
static void
bank_mapping_update(void *opaque)
{
    struct uxendisp_state *s = opaque;
    int i;

    for (i = 0; i < UXENDISP_NB_BANKS; i++) {
        struct vram_desc *bank = &s->banks[i];
        uint32_t gfn = (memory_region_absolute_offset(&s->vram) +
                        i * UXENDISP_BANK_SIZE) >> TARGET_PAGE_BITS;

        vram_map(bank, gfn);
    }
}

static void vram_change(struct vram_desc *v, void *opaque)
{
    struct uxendisp_state *s = opaque;
    int crtc_id;

    DPRINTF("%s\n", __FUNCTION__);

    for (crtc_id = 0; crtc_id < UXENDISP_NB_CRTCS; crtc_id++) {
        struct crtc_state *crtc = &s->crtcs[crtc_id];
        int bank_id = crtc->offset >> UXENDISP_BANK_ORDER;
        struct vram_desc *bank = &s->banks[bank_id];

        if (bank == v) {
            DPRINTF("%s: bank_id=%d crtc_id=%d\n",
                    __FUNCTION__, bank_id, crtc_id);
            dpy_vram_change(crtc->ds, bank);
            break;
        }
    }
}

/*
 * Device
 */

static void
uxendisp_pre_save(void *opaque)
{
    struct uxendisp_state *s = opaque;

    pci_ram_pre_save(&s->dev);
}

static int
uxendisp_post_load(void *opaque, int version_id)
{
    struct uxendisp_state *s = opaque;
    int crtc_id;

    pci_ram_post_load(&s->dev, version_id);

    for (crtc_id = 0; crtc_id < UXENDISP_NB_CRTCS; crtc_id++)
        s->crtcs[crtc_id].flush_pending = 1;

    return 0;
}

static const VMStateDescription vmstate_uxendisp_crtc = {
    .name = "uxendisp-crtc",
    .version_id = 6,
    .minimum_version_id = 6,
    .minimum_version_id_old = 6,
    .fields = (VMStateField[]) {
        VMSTATE_UINT32(offset, struct crtc_state),
        VMSTATE_END_OF_LIST(),
    }
};

static const VMStateDescription vmstate_uxendisp = {
    .name = "uxendisp",
    .version_id = 6,
    .minimum_version_id = 6,
    .minimum_version_id_old = 6,
    .pre_save = uxendisp_pre_save,
    .post_load = uxendisp_post_load,
    .fields      = (VMStateField []) {
        VMSTATE_PCI_DEVICE(dev, struct uxendisp_state),
        VMSTATE_STRUCT(vga, struct uxendisp_state, 0,
                       vmstate_vga, VGAState),
        VMSTATE_VRAM_ARRAY(banks, struct uxendisp_state,
                           UXENDISP_NB_BANKS),
        VMSTATE_STRUCT_ARRAY(crtcs, struct uxendisp_state,
                             UXENDISP_NB_CRTCS, 6,
                             vmstate_uxendisp_crtc,
                             struct crtc_state),
        VMSTATE_UINT32(io_index, struct uxendisp_state),
        VMSTATE_UINT32(isr, struct uxendisp_state),
        VMSTATE_UINT32(cursor_en, struct uxendisp_state),
        VMSTATE_UINT32(mode, struct uxendisp_state),
        VMSTATE_END_OF_LIST()
    }
};

static void
uxendisp_reset(void *opaque)
{
    struct uxendisp_state *s = opaque;

    (void)s;
}

static int uxendisp_initfn(PCIDevice *dev)
{
    struct uxendisp_state *s = DO_UPCAST(struct uxendisp_state, dev, dev);
    VGAState *v = &s->vga;
    int i;

    memory_region_init_io(&s->mmio, &mmio_ops, s, "uxendisp.mmio",
                          UXENDISP_MMIO_SIZE);
    memory_region_add_ram_range(&s->mmio, 0x1000, 0x1000,
                                cursor_regs_ptr_update, s);
    memory_region_add_ram_range(&s->mmio, 0x8000, 0x8000,
                                cursor_data_ptr_update, s);
    for (i = 0; i < UXENDISP_NB_CRTCS; i++)
        memory_region_add_ram_range(&s->mmio,
                                    UXDISP_REG_CRTC(i) + 0x1000,
                                    0x1000,
                                    crtc_data_ptr_update, &s->crtcs[i]);
    memory_region_init(&s->vram, "uxendisp.vram", UXENDISP_VRAM_SIZE);
    s->vram.map_cb = bank_mapping_update;
    s->vram.map_opaque = s;

    /* Note: 0x20 appears to be the minumum size of an IO BAR */
    memory_region_init_io(&s->pio, &pio_ops, s, "uxendisp.pio", 0x20);

    for (i = 0; i < UXENDISP_NB_BANKS; i++) {
        struct vram_desc *bank = &s->banks[i];

        vram_init(bank, UXENDISP_BANK_SIZE);
        vram_register_change(bank, vram_change, s);
        vram_alloc(bank, 0x1000); /* FIXME: why do we need this ? */
    }

    pci_register_bar(&s->dev, 0, PCI_BASE_ADDRESS_MEM_PREFETCH, &s->vram);
    pci_register_bar(&s->dev, 1, PCI_BASE_ADDRESS_SPACE_MEMORY, &s->mmio);
    pci_register_bar(&s->dev, 2, PCI_BASE_ADDRESS_SPACE_IO, &s->pio);

    /* XXX: One per CRTC */
    s->crtcs[0].ds = graphic_console_init(uxendisp_update,
                                          uxendisp_invalidate,
                                          uxendisp_text_update, s);
    s->crtcs[0].flush_pending = 0;

    vga_init(v, pci_address_space(dev), pci_address_space_io(dev), s->crtcs[0].ds);

    qemu_register_reset(uxendisp_reset, s);
    uxendisp_reset(s);

    return 0;
}

static int uxendisp_exitfn(PCIDevice *dev)
{
    struct uxendisp_state *s = DO_UPCAST(struct uxendisp_state, dev, dev);
    VGAState *v = &s->vga;

    vga_exit(v);

    return 0;
}

int uxendisp_init(PCIBus *bus)
{
    pci_create_simple(bus, -1, "uxendisp");
    return 0;
}

static PCIDeviceInfo uxendisp_info = {
    .qdev.name    = "uxendisp",
    .qdev.size    = sizeof(struct uxendisp_state),
    .qdev.vmsd    = &vmstate_uxendisp,
    .no_hotplug   = 1,
    .init         = uxendisp_initfn,
    .exit         = uxendisp_exitfn,
    .romfile      = "vgabios-stdvga.bin",

    .vendor_id    = PCI_VENDOR_ID_XEN,
    .device_id    = PCI_DEVICE_ID_UXEN_VGA,
    .class_id     = PCI_CLASS_DISPLAY_VGA,

    .subsystem_vendor_id = PCI_VENDOR_ID_XEN,
    .subsystem_id = PCI_DEVICE_ID_XEN_SUBSYS1,

    .config_write = pci_ram_config_write,
};

static void uxendisp_register(void)
{
    pci_qdev_register(&uxendisp_info);
}

device_init(uxendisp_register);
