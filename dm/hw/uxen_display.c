/*
 * Copyright 2015-2017, Bromium, Inc.
 * Author: Julian Pidancet <julian@pidancet.net>
 * SPDX-License-Identifier: ISC
 */

#include <dm/qemu_glue.h>
#include <dm/bh.h>
#include <dm/dev.h>
#include <dm/dma.h>
#include <dm/console.h>
#include <dm/vmstate.h>
#include <dm/vram.h>
#include <dm/edid.h>
#include <dm/hw/vga.h>
#include <dm/guest-agent.h>
#include "pci.h"
#include "pci-ram.h"

#include "uxen_display.h"
#include "uxdisp_hw.h"
#include "uxendisp-common.h"
#include "pv_vblank.h"

#define DEBUG_UXENDISP

#ifdef DEBUG_UXENDISP
#define DPRINTF(fmt, ...) debug_printf("uxendisp: " fmt, ## __VA_ARGS__)
#else
#define DPRINTF(fmt, ...) do {} while (0)
#endif

#define UXENDISP_XRES_MAX 23170
#define UXENDISP_YRES_MAX 23170
#define UXENDISP_STRIDE_MAX 92683

struct crtc_state {
    int id;

    uint32_t status;
    uint32_t offset;

    /* Validated */
    uint32_t enable;
    uint32_t xres;
    uint32_t yres;
    uint32_t stride;
    uint32_t format;

    volatile struct crtc_regs *regs;
    struct display_state *ds;
    int flush_pending;
    uint8_t edid[256];
};

struct bank_state {
    struct vram_desc vram;
    uint32_t len;
    uint32_t populate_vram_len;
};

struct uxendisp_state {
    PCIDevice dev;
    VGAState vga;

    MemoryRegion vram; /* BAR 0 */
    MemoryRegion mmio; /* BAR 1 */
    MemoryRegion pio; /* BAR 2 */

    volatile struct cursor_regs *cursor_regs;
    volatile uint8_t *cursor_data;
    struct crtc_state crtcs[UXENDISP_NB_CRTCS];
    struct bank_state banks[UXENDISP_NB_BANKS];

    uint32_t io_index;
    uint32_t isr;
    uint32_t interrupt_en;
    uint32_t cursor_en;
    uint32_t mode;
    uint32_t xtra_ctrl;
    int resumed;

    struct vblank_ctx *vblank_ctx;
};

#define crtc_to_state(c) (container_of((c), struct uxendisp_state, crtcs[(c)->id]))

static uint32_t
xtra_caps(void)
{
    uint32_t caps = 0;

    if (disp_pv_vblank != PV_VBLANK_OFF)
        caps |= UXDISP_XTRA_CAPS_PV_VBLANK;
    caps |= UXDISP_XTRA_CAPS_USER_DRAW;

    return caps;
}

/*
 * Interrupts
 */
void
uxendisp_set_interrupt(struct uxendisp_state *s, int irq)
{
    int m;

    m = s->interrupt_en & irq;

    if (m) {
        s->isr |= m;
        qemu_set_irq(s->dev.irq[0], 1);
    }
}

/*
 * EDID
 */
static void
uxendisp_set_display_identification(struct uxendisp_state *s, int crtc_id,
                                    uint8_t *edid, size_t len)
{
    struct crtc_state *crtc = &s->crtcs[crtc_id];

    if (len > sizeof (crtc->edid))
        len = sizeof (crtc->edid);

    if (edid) {
        memcpy(crtc->edid, edid, len);
        if (crtc->regs)
            memcpy((void *)crtc->regs->edid, edid, len);
        crtc->status = 1;
    } else
        crtc->status = 0;

    uxendisp_set_interrupt(s, UXDISP_INTERRUPT_HOTPLUG);
}

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

static void crtc_flush(struct uxendisp_state *s, int crtc_id, uint32_t offset, int force);

static void
crtc_draw(struct uxendisp_state *s, int crtc_id)
{
    struct crtc_state *crtc = &s->crtcs[crtc_id];
    int bank_id = crtc->offset >> UXENDISP_BANK_ORDER;
    uint32_t bank_offset = crtc->offset & (UXENDISP_BANK_SIZE - 1);
    struct bank_state *bank = &s->banks[bank_id];
    int rc;
    int npages;
    uint8_t *dirty;
    uint8_t *d;
    int linesize;

    int y, y_start;
    uint32_t addr, addr1;
    uint32_t page0, page1, pagei, page_min, page_max;

    if (crtc->regs && crtc->flush_pending)
        crtc_flush(s, crtc_id, crtc->offset, 0);
    if (!crtc->ds)
        return;

    npages = bank->len >> TARGET_PAGE_BITS;

    if (npages > (UXENDISP_BANK_SIZE >> TARGET_PAGE_BITS))
        return;

    dirty = alloca((npages + 7) / 8);

    rc = xen_hvm_track_dirty_vram(bank->vram.gfn,
        (s->mode & UXDISP_MODE_PAGE_TRACKING_DISABLED) ? 0 : npages, dirty, 1);
    if (rc) {
        DPRINTF("xen_hvm_track_dirty_vram failed: %d\n", errno);
        return;
    }

    if (ds_surface_lock(crtc->ds, &d, &linesize))
        return;
    addr1 = bank_offset;
    y_start = -1;
    page_min = (uint32_t)-1;
    page_max = 0;
    for (y = 0; y < crtc->yres; y++) {
        int update = 0;

        addr = addr1;
        page0 = addr >> TARGET_PAGE_BITS;
        page1 = (addr + crtc->stride - 1) >> TARGET_PAGE_BITS;

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
                if ((addr1 + crtc->xres * 4) > bank->vram.mapped_len)
                    break;
                switch (crtc->format) {
                case UXDISP_CRTC_FORMAT_BGRX_8888:
                    memcpy(d, bank->vram.view + addr1, crtc->xres * 4);
                    break;
                case UXDISP_CRTC_FORMAT_BGR_888:
                    draw_line_24(d, bank->vram.view + addr1, crtc->xres);
                    break;
                case UXDISP_CRTC_FORMAT_BGR_565:
                    draw_line_16(d, bank->vram.view + addr1, crtc->xres);
                    break;
                case UXDISP_CRTC_FORMAT_BGR_555:
                    draw_line_15(d, bank->vram.view + addr1, crtc->xres);
                    break;
                }
            }
        } else if (y_start >= 0) {
            dpy_update(crtc->ds, 0, y_start, crtc->xres, y - y_start);
            y_start = -1;
        }
        addr1 += crtc->stride;
        d += linesize;
    }
    ds_surface_unlock(crtc->ds);
    if (y_start >= 0) {
        dpy_update(crtc->ds, 0, y_start, crtc->xres, y - y_start);
    }
}

/*
 * Console callbacks
 */
static void uxendisp_update(void *opaque)
{
    struct crtc_state *crtc = opaque;
    struct uxendisp_state *s = crtc_to_state(crtc);

    uxendisp_set_interrupt(s, UXDISP_INTERRUPT_VBLANK);

    if (crtc->id == 0 && !(s->mode & UXDISP_MODE_VGA_DISABLED)) {
        vga_update_display(&s->vga);
        return;
    }

    crtc_draw(s, crtc->id);
}

static void uxendisp_invalidate(void *opaque)
{
    struct crtc_state *crtc = opaque;
    struct uxendisp_state *s = crtc_to_state(crtc);

    if (crtc->id == 0 && !(s->mode & UXDISP_MODE_VGA_DISABLED)) {
        vga_invalidate_display(&s->vga);
        return;
    }
}

static void uxendisp_text_update(void *opaque, console_ch_t *chardata)
{
    struct crtc_state *crtc = opaque;
    struct uxendisp_state *s = crtc_to_state(crtc);

    if (crtc->id == 0 && !(s->mode & UXDISP_MODE_VGA_DISABLED)) {
        vga_update_text(&s->vga, chardata);
        return;
    }
}

void uxendisp_monitor_change(void *opaque, int crtc_id, int w, int h)
{
    struct uxendisp_state *s = opaque;
    uint8_t edid[128];

    if (w == 0 || h == 0) {
        uxendisp_set_display_identification(s, crtc_id, NULL, 0);
        return;
    }

    edid_init_common(edid, w, h);
    uxendisp_set_display_identification(s, crtc_id, edid, sizeof(edid));
}

static struct console_hw_ops uxendisp_hw_ops = {
    .update = uxendisp_update,
    .invalidate = uxendisp_invalidate,
    .text_update = uxendisp_text_update,
};

/*
* IO handling
*/

static void
cursor_flush(struct uxendisp_state *s)
{
    volatile uint8_t *mask;
    volatile uint8_t *color;
    struct display_state *ds;
    unsigned int w, h;

    /* XXX crtc 0 only for now */
    if (s->cursor_regs->crtc_idx == 0)
        ds = s->crtcs[0].ds;
    else
        return;

    if (!(s->cursor_en & UXDISP_CURSOR_SHOW)) {
        dpy_cursor_shape(ds, 0, 0, 0, 0, NULL, NULL);
        return;
    }

    w = s->cursor_regs->width;
    h = s->cursor_regs->height;

    if ((w > UXENDISP_CURSOR_MAX_WIDTH) || (h > UXENDISP_CURSOR_MAX_HEIGHT))
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
            color += ((w + 7) / 8) * h;
        }
    }

    dpy_cursor_shape(ds, w, h,
                     s->cursor_regs->hot_x,
                     s->cursor_regs->hot_y,
                     (uint8_t *)mask,
                     (uint8_t *)color);
}

static void bank_reg_write(struct uxendisp_state *s,
                           int bank_id,
                           target_phys_addr_t addr,
                           uint32_t val);

static int fmt_valid(int fmt)
{
    switch (fmt) {
    case UXDISP_CRTC_FORMAT_BGRX_8888:
    case UXDISP_CRTC_FORMAT_BGR_888:
    case UXDISP_CRTC_FORMAT_BGR_565:
    case UXDISP_CRTC_FORMAT_BGR_555:
        return 1;
    }

    return 0;
}

static void
crtc_flush(struct uxendisp_state *s, int crtc_id, uint32_t offset, int force)
{
    struct crtc_state *crtc = &s->crtcs[crtc_id];
    struct bank_state *bank;
    size_t sz;

    crtc->flush_pending = 0;

    if (crtc_id == 0 && !(s->mode & UXDISP_MODE_VGA_DISABLED))
        return;

    if (crtc->regs->p.enable) {
        uint32_t bank_offset = offset & (UXENDISP_BANK_SIZE - 1);
        int bank_id = offset >> UXENDISP_BANK_ORDER;
        unsigned int w, h, stride, fmt;

        if (!crtc->ds)
            crtc->ds = display_create(&uxendisp_hw_ops, crtc, DCF_START_GUI);

        w = crtc->regs->p.xres;
        h = crtc->regs->p.yres;
        stride = crtc->regs->p.stride;
        fmt = crtc->regs->p.format;

        /* Filter out spurious mode changes */
        if (!force &&
            crtc->xres == w &&
            crtc->yres == h &&
            crtc->stride == stride &&
            crtc->format == fmt &&
            crtc->offset == offset && !s->resumed)
            return;

        if (w > UXENDISP_XRES_MAX || h > UXENDISP_YRES_MAX ||
            stride > UXENDISP_STRIDE_MAX || stride == 0)
            return;

        if (!fmt_valid(fmt))
            return;

        if (bank_id >= UXENDISP_NB_BANKS)
            return;

        bank = &s->banks[bank_id];
        sz = bank_offset + h * stride;
        if (sz > UXENDISP_BANK_SIZE)
            return;

        if (fmt == crtc->format && w < crtc->xres) {
            int src_off = 0;
            int dst_off = 0;
            int max_off = crtc->yres * crtc->stride;
            for (;;) {
                src_off += crtc->stride;
                dst_off += stride;
                if ((src_off > (max_off - stride)) || (dst_off > (max_off - stride)))
                    break;
                if ((bank_offset + dst_off + stride) > bank->vram.mapped_len ||
                    (bank_offset + src_off + stride) > bank->vram.mapped_len)
                    break;
                memmove(bank->vram.view + bank_offset + dst_off,
                        bank->vram.view + bank_offset + src_off, stride);
            }
        }

        if ((bank->len < sz) || (bank->populate_vram_len > 0))
            bank_reg_write(s, bank_id, 0, sz);

        if (fmt == crtc->format && w > crtc->xres) {
            int height = h;
            if (h > crtc->yres)
                height = crtc->yres;
            uint8_t* src = bank->vram.view + bank_offset + height * crtc->stride;
            uint8_t* dst = bank->vram.view + bank_offset + height * stride;
            for (;;) {
                src -= crtc->stride;
                dst -= stride;
                if ((src < (bank->vram.view + bank_offset + stride)) ||
                    (dst < (bank->vram.view + bank_offset + stride)))
                    break;
                if ((src + crtc->stride) <= (bank->vram.view + bank->vram.mapped_len) &&
                    (dst + crtc->stride) <= (bank->vram.view + bank->vram.mapped_len)) {
                    memmove(dst, src, crtc->stride);
                    if (stride > crtc->stride)
                        memset(dst + crtc->stride, 0xff, stride - crtc->stride);
                }
            }
        }

        if ((h > crtc->yres) && (crtc->yres > 0)) {
            uint8_t* dst = bank->vram.view + bank_offset + (crtc->yres * stride);
            int curr_max = crtc->yres * stride;
            int new_max = h * stride;
            if (curr_max < new_max &&
                (bank_offset + new_max) < bank->vram.mapped_len)
                memset(dst, 0xff, new_max - curr_max);
        }

        if (s->mode & UXDISP_MODE_PAGE_TRACKING_DISABLED)
            xen_hvm_track_dirty_vram(0 , 0, NULL, 0);

        display_resize_from(crtc->ds, w, h,
                            uxdisp_fmt_to_bpp(fmt),
                            stride,
                            bank->vram.view,
                            bank_offset);

        crtc->xres = w;
        crtc->yres = h;
        crtc->stride = stride;
        crtc->format = fmt;
        crtc->offset = offset;
        s->resumed = 0;

    } else {
        if (crtc->ds) {
            display_destroy(crtc->ds);
            crtc->ds = NULL;
        }
    }

    crtc->enable = crtc->regs->p.enable;
    do_dpy_trigger_refresh(crtc->ds);
}

static void
crtc_write(struct uxendisp_state *s, int crtc_id, target_phys_addr_t addr,
           uint32_t val)
{
    struct crtc_state *crtc = &s->crtcs[crtc_id];

    switch (addr) {
    case UXDISP_REG_CRTC_OFFSET:
        crtc_flush(s, crtc_id, val, 1);
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

    if (addr >= UXDISP_REG_CRTC_EDID_DATA &&
        addr <= (UXDISP_REG_CRTC_EDID_DATA + sizeof(crtc->regs->edid) - 4))
        return *(uint32_t *)(crtc->regs->edid + addr - UXDISP_REG_CRTC_EDID_DATA);

    switch (addr) {
    case UXDISP_REG_CRTC_STATUS:
        ret = crtc->status;
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
    struct bank_state *bank = &s->banks[bank_id];

    if (addr != 0)
        return;

    val = (val + (TARGET_PAGE_SIZE - 1)) & ~(TARGET_PAGE_SIZE - 1);

    if ((bank_id == 0) && val < (vm_vga_mb_mapped << 20))
        val = vm_vga_mb_mapped << 20;

    if (bank->populate_vram_len > 0)
        val = bank->populate_vram_len;

    if (val > UXENDISP_BANK_SIZE)
        val = UXENDISP_BANK_SIZE;

    bank->len = val;
    vram_resize(&bank->vram, val);
}

static uint32_t
bank_reg_read(struct uxendisp_state *s, int bank_id, target_phys_addr_t addr)
{
    struct bank_state *bank = &s->banks[bank_id];

    if (addr != 0)
        return ~0;

    return bank->len;
}

static void
uxendisp_user_draw_enable(int enable)
{
    debug_printf("%s: user draw enable = %d\n", __FUNCTION__, enable);
    guest_agent_user_draw_enable(enable);
}

static void
xtra_ctrl_write(struct uxendisp_state *s, uint64_t val)
{
    uint32_t new_ctrl = val & xtra_caps();
#ifdef _WIN32
    uint32_t old_ctrl = s->xtra_ctrl;
    uint32_t old_pv_vblank = old_ctrl & UXDISP_XTRA_CTRL_PV_VBLANK_ENABLE;
    uint32_t new_pv_vblank = new_ctrl & UXDISP_XTRA_CTRL_PV_VBLANK_ENABLE;
    uint32_t old_user_draw = old_ctrl & UXDISP_XTRA_CTRL_USER_DRAW_ENABLE;
    uint32_t new_user_draw = new_ctrl & UXDISP_XTRA_CTRL_USER_DRAW_ENABLE;

    if (old_pv_vblank != new_pv_vblank) {
        if (new_pv_vblank)
            pv_vblank_start(s->vblank_ctx);
        else
            pv_vblank_stop(s->vblank_ctx);
    }

    if (old_user_draw != new_user_draw)
        uxendisp_user_draw_enable(!!new_user_draw);
#endif  /* _WIN32 */
    s->xtra_ctrl = new_ctrl;
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
        s->banks[idx].populate_vram_len = val;
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
        if (!vm_vram_dirty_tracking)
            s->mode |= UXDISP_MODE_PAGE_TRACKING_DISABLED;
        crtc_flush(s, 0, s->crtcs[0].offset, 1);
        uxendisp_invalidate(&s->crtcs[0]);
        return;
    case UXDISP_REG_INTERRUPT_ENABLE:
        s->interrupt_en = val;
        return;
    case UXDISP_REG_XTRA_CTRL:
        xtra_ctrl_write(s, val);
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
    case UXDISP_REG_INTERRUPT_ENABLE:
        return s->interrupt_en;
    case UXDISP_REG_VIRTMODE_ENABLED:
        return vm_virt_mode_change;
    case UXDISP_REG_XTRA_CAPS:
        return xtra_caps();
    case UXDISP_REG_XTRA_CTRL:
        return s->xtra_ctrl;
#ifdef _WIN32
    case UXDISP_REG_VSYNC_HZ:
        return pv_vblank_get_reported_vsync_hz();
#endif  /* _WIN32 */
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
    struct crtc_state *crtc = opaque;
    struct crtc_regs *regs = ptr;

    if (regs && !crtc->regs)
        memcpy(regs->edid, crtc->edid, sizeof(regs->edid));

    crtc->regs = regs;
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
        struct bank_state *bank = &s->banks[i];
        uint32_t gfn = (memory_region_absolute_offset(&s->vram) +
                        i * UXENDISP_BANK_SIZE) >> TARGET_PAGE_BITS;

        vram_map(&bank->vram, gfn);
    }
}

static void vram_change(struct vram_desc *v, void *opaque)
{
    struct uxendisp_state *s = opaque;
    int crtc_id;

    for (crtc_id = 0; crtc_id < UXENDISP_NB_CRTCS; crtc_id++) {
        struct crtc_state *crtc = &s->crtcs[crtc_id];
        int bank_id = crtc->offset >> UXENDISP_BANK_ORDER;
        struct bank_state *bank = &s->banks[bank_id];

        if (&bank->vram == v) {
            DPRINTF("%s: bank_id=%d crtc_id=%d\n",
                    __FUNCTION__, bank_id, crtc_id);
            dpy_vram_change(crtc->ds, &bank->vram);
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

#ifdef _WIN32
    if (s->xtra_ctrl & UXDISP_XTRA_CTRL_PV_VBLANK_ENABLE)
        pv_vblank_start(s->vblank_ctx);
#endif  /* _WIN32 */

    return 0;
}

static int
uxendisp_resume(void *opaque, int version_id)
{
    struct uxendisp_state *s = opaque;
    int i;
    int ret;

    ret = uxendisp_post_load(opaque, version_id);
    if (ret)
        return ret;

    for (i = 0; i < UXENDISP_NB_BANKS; i++) {
        struct bank_state *bank = &s->banks[i];
        ret = vram_resume(&bank->vram);
        if (ret)
            return ret;
    }
    s->resumed = 1;
    return 0;
}

static void
uxendisp_post_save(void *opaque)
{
    struct uxendisp_state *s = opaque;
    int i;

    for (i = 0; i < UXENDISP_NB_BANKS; i++) {
        struct bank_state *bank = &s->banks[i];
        vram_suspend(&bank->vram);
    }
    pci_ram_post_save(&s->dev);
#ifdef _WIN32
    pv_vblank_stop(s->vblank_ctx);
#endif  /* _WIN32 */
}

static const VMStateDescription vmstate_uxendisp_crtc = {
    .name = "uxendisp-crtc",
    .version_id = 7,
    .minimum_version_id = 7,
    .minimum_version_id_old = 7,
    .fields = (VMStateField[]) {
        VMSTATE_UINT32(offset, struct crtc_state),
        VMSTATE_UINT32(status, struct crtc_state),
        VMSTATE_BUFFER(edid, struct crtc_state),
        VMSTATE_END_OF_LIST(),
    }
};

static const VMStateDescription vmstate_uxendisp_bank = {
    .name = "uxendisp-bank",
    .version_id = 7,
    .minimum_version_id = 7,
    .minimum_version_id_old = 7,
    .fields = (VMStateField[]) {
        VMSTATE_VRAM(vram, struct bank_state),
        VMSTATE_UINT32(len, struct bank_state),
        VMSTATE_UINT32(populate_vram_len, struct bank_state),
        VMSTATE_END_OF_LIST(),
    }
};

static const VMStateDescription vmstate_uxendisp = {
    .name = "uxendisp",
    .version_id = 7,
    .minimum_version_id = 7,
    .minimum_version_id_old = 7,
    .pre_save = uxendisp_pre_save,
    .post_load = uxendisp_post_load,
    .post_save = uxendisp_post_save,
    .resume = uxendisp_resume,
    .fields      = (VMStateField []) {
        VMSTATE_PCI_DEVICE(dev, struct uxendisp_state),
        VMSTATE_STRUCT(vga, struct uxendisp_state, 0,
                       vmstate_vga, VGAState),
        VMSTATE_STRUCT_ARRAY(banks, struct uxendisp_state,
                             UXENDISP_NB_BANKS, 7,
                             vmstate_uxendisp_bank,
                             struct bank_state),
        VMSTATE_STRUCT_ARRAY(crtcs, struct uxendisp_state,
                             UXENDISP_NB_CRTCS, 6,
                             vmstate_uxendisp_crtc,
                             struct crtc_state),
        VMSTATE_UINT32(io_index, struct uxendisp_state),
        VMSTATE_UINT32(isr, struct uxendisp_state),
        VMSTATE_UINT32(interrupt_en, struct uxendisp_state),
        VMSTATE_UINT32(cursor_en, struct uxendisp_state),
        VMSTATE_UINT32(mode, struct uxendisp_state),
        VMSTATE_UINT32(xtra_ctrl, struct uxendisp_state),
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

#ifdef _WIN32
    s->vblank_ctx = pv_vblank_init(s, disp_pv_vblank);
    if (!s->vblank_ctx) {
        debug_printf("pv vblank init failed\n");
        return -1;
    }
#endif

    dev->config[PCI_INTERRUPT_PIN] = 1;
    memory_region_init_io(&s->mmio, &mmio_ops, s, "uxendisp.mmio",
                          UXENDISP_MMIO_SIZE);
    memory_region_add_ram_range(&s->mmio, 0x1000, 0x1000,
                                cursor_regs_ptr_update, s);
    memory_region_add_ram_range(&s->mmio, 0x8000, 0x8000,
                                cursor_data_ptr_update, s);
    for (i = 0; i < UXENDISP_NB_CRTCS; i++) {
        s->crtcs[i].id = i;
        memory_region_add_ram_range(&s->mmio,
                                    UXDISP_REG_CRTC(i) + 0x1000,
                                    0x1000,
                                    crtc_data_ptr_update, &s->crtcs[i]);
    }
    memory_region_init(&s->vram, "uxendisp.vram", UXENDISP_VRAM_SIZE);
    s->vram.map_cb = bank_mapping_update;
    s->vram.map_opaque = s;

    /* Note: 0x20 appears to be the minumum size of an IO BAR */
    memory_region_init_io(&s->pio, &pio_ops, s, "uxendisp.pio", 0x20);

    pci_register_bar(&s->dev, 0, PCI_BASE_ADDRESS_MEM_PREFETCH, &s->vram);
    pci_register_bar(&s->dev, 1, PCI_BASE_ADDRESS_SPACE_MEMORY, &s->mmio);
    pci_register_bar(&s->dev, 2, PCI_BASE_ADDRESS_SPACE_IO, &s->pio);

    s->crtcs[0].ds = display_create(&uxendisp_hw_ops, &s->crtcs[0], DCF_NONE);
    s->crtcs[0].status = 0x1;
    s->crtcs[0].flush_pending = 0;
    edid_init_common(s->crtcs[0].edid, 1024, 768);

    for (i = 0; i < UXENDISP_NB_BANKS; i++) {
        struct bank_state *bank = &s->banks[i];

        bank->len = 0x1000; /* FIXME: why do we need this ? */
        bank->populate_vram_len = 0;
        vram_init(&bank->vram, UXENDISP_BANK_SIZE);
        vram_register_change(&bank->vram, vram_change, s);
        vram_alloc(&bank->vram, bank->len);
    }

    vga_init(v, pci_address_space(dev), pci_address_space_io(dev), s->crtcs[0].ds);

    if (!vm_vram_dirty_tracking) {
        debug_printf("%s: vram dirty tracking disabled\n", __FUNCTION__);
        s->mode |= UXDISP_MODE_PAGE_TRACKING_DISABLED;
    }

    qemu_register_reset(uxendisp_reset, s);
    uxendisp_reset(s);

    return 0;
}

static int uxendisp_exitfn(PCIDevice *dev)
{
    struct uxendisp_state *s = DO_UPCAST(struct uxendisp_state, dev, dev);
    VGAState *v = &s->vga;

#ifdef _WIN32
    pv_vblank_cleanup(s->vblank_ctx);
#endif

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
