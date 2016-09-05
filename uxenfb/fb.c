/*
 * A framebuffer driver for VBE 2.0+ compliant video cards
 *
 * (c) 2007 Michal Januszewski <spock@gentoo.org>
 *     Loosely based upon the vesafb driver.
 *
 */
/*
 * uXen changes:
 *
 * Copyright 2016, Bromium, Inc.
 * Author: Tomasz Wroblewski <tomasz.wroblewski@gmail.com>
 * SPDX-License-Identifier: ISC
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
 * SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION
 * OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
 * CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include <linux/init.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/skbuff.h>
#include <linux/timer.h>
#include <linux/completion.h>
#include <linux/connector.h>
#include <linux/random.h>
#include <linux/platform_device.h>
#include <linux/limits.h>
#include <linux/fb.h>
#include <linux/io.h>
#include <linux/mutex.h>
#include <linux/mm.h>
#include <linux/pfn.h>
#include <linux/slab.h>
#include <linux/wait.h>
#include <video/edid.h>

#include <uxen/platform_interface.h>
#include <uxen-v4vlib.h>
#include <uxen-platform.h>
#include <uxen-util.h>

#define DEFAULT_XRES 1024
#define DEFAULT_YRES 768
#define MAX_XRES 4096
#define MAX_YRES 2160

#define DEFAULT_FB_ADDR 0xC0000000
#define DEFAULT_FB_SIZEMAX 0x2000000

#define UPDATE_DELAY (HZ/60)

#define V4V_DIRTY_PORT 0xD1580
#define V4V_DIRTY_RING_LEN 4096

#define V4V_CMD_PORT 0xD1581
#define V4V_CMD_RING_LEN 4096

#define UXEN_FB_MSG_SETMODE 1
#define UXEN_FB_MSG_SETMODE_RET 2
#define UXEN_FB_MSG_QUERYCONF 3
#define UXEN_FB_MSG_QUERYCONF_RET 4

struct uxenfb_rect {
    int32_t left;
    int32_t top;
    int32_t right;
    int32_t bottom;
} __attribute__((packed));

struct uxenfb_msg {
    uint8_t type;
    uint16_t xres, yres, stride;
} __attribute__((packed));

struct uxenfb_work {
    struct delayed_work _d;
    struct fb_info *info;
    struct vm_area_struct *vma;
};

struct uxenfb_par {
    u32 xres, yres, bpp, stride;

    int cmap_allocated, registered;
    uxen_v4v_ring_t *cmd_ring, *dirty_ring;
    v4v_addr_t dst_addr;
    v4v_addr_t dst_dirty_addr;
    struct tasklet_struct cmd_tasklet, dirty_tasklet;
    wait_queue_head_t wq;
    struct uxenfb_msg resp;
    int resp_ready, resp_intr;

    atomic_t map_count;

    spinlock_t dirty_lock;
    struct uxenfb_rect dirty_rect;
    struct uxenfb_work dirty_work;
    long dirty_pfn_start, dirty_pfn_end;
};

static struct fb_fix_screeninfo uxenfb_fix = {
    .id	= "uxen fb",
    .type = FB_TYPE_PACKED_PIXELS,
    .accel = FB_ACCEL_NONE,
    .visual = FB_VISUAL_TRUECOLOR,
};

static ulong fb_addr = DEFAULT_FB_ADDR;
static ulong fb_sizemax = DEFAULT_FB_SIZEMAX;
static bool fb_v4vexts = 1;

module_param(fb_addr, ulong, 0444);
module_param(fb_sizemax, ulong, 0444);
module_param(fb_v4vexts, bool, 0444);

static int
send_rect(struct uxenfb_par *par, struct uxenfb_rect *rect)
{
    ssize_t r;

    r = uxen_v4v_send_from_ring(par->dirty_ring, &par->dst_dirty_addr, rect, sizeof(*rect),
                                V4V_PROTO_DGRAM);
    if ( r != sizeof(*rect) )
        return -1;
    return 0;
}

static void
send(struct uxenfb_par *par, struct uxenfb_msg *msg)
{
    ssize_t r;

    r = uxen_v4v_send_from_ring(par->cmd_ring, &par->dst_addr, msg, sizeof(*msg),
                                V4V_PROTO_DGRAM);
    BUG_ON( r != sizeof(*msg) );
}

static void
send_and_wait(struct uxenfb_par *par, struct uxenfb_msg *msg)
{
    par->resp_intr = 0;
    par->resp_ready = 0;
    do {
        send(par, msg);
        wait_event_interruptible(par->wq, par->resp_ready || par->resp_intr);
    } while (par->resp_intr);
}

static void
remote_set_mode(struct uxenfb_par *par, int xres, int yres, int stride)
{
    struct uxenfb_msg msg = { };

    msg.type = UXEN_FB_MSG_SETMODE;
    msg.xres = xres;
    msg.yres = yres;
    msg.stride = stride;

    send_and_wait(par, &msg);
}

static void
remote_query_conf(struct uxenfb_par *par, int *xres, int *yres, int *stride)
{
    struct uxenfb_msg msg = { };

    msg.type = UXEN_FB_MSG_QUERYCONF;

    send_and_wait(par, &msg);

    *xres = par->resp.xres;
    *yres = par->resp.yres;
    *stride = par->resp.stride;
}

static int
uxenfb_setcolreg(unsigned regno, unsigned red, unsigned green,
                 unsigned blue, unsigned transp,
                 struct fb_info *info)
{
    u32 v;

    if (regno > info->cmap.len)
        return 1;

#define CNVT_TOHW(val, width) ((((val)<<(width))+0x7FFF-(val))>>16)
    red = CNVT_TOHW(red, info->var.red.length);
    green = CNVT_TOHW(green, info->var.green.length);
    blue = CNVT_TOHW(blue, info->var.blue.length);
    transp = CNVT_TOHW(transp, info->var.transp.length);
#undef CNVT_TOHW

    v = (red << info->var.red.offset) |
        (green << info->var.green.offset) |
        (blue << info->var.blue.offset);

    switch (info->var.bits_per_pixel) {
    case 16:
    case 24:
    case 32:
        ((u32 *)info->pseudo_palette)[regno] = v;
        break;
    }

    return 0;
}

static int
uxenfb_blank(int blank, struct fb_info *info)
{
    return 0;
}

static void
uxenfb_setup_var(struct fb_var_screeninfo *var,
                 struct fb_info *info,
                 int xres, int yres)
{
    var->xres = xres;
    var->yres = yres;
    var->bits_per_pixel = 32;
    var->xres_virtual = var->xres;
    var->yres_virtual = var->yres;

    /* BGR */
    var->blue.offset = 0;
    var->green.offset = 8;
    var->red.offset = 16;
    var->transp.offset = 24;
    var->blue.length = 8;
    var->green.length = 8;
    var->red.length = 8;
    var->transp.length = 8;
}

static int
uxenfb_check_var(struct fb_var_screeninfo *var,
                 struct fb_info *info)
{
    if (var->xres > MAX_XRES || var->yres > MAX_YRES)
        return -EINVAL;
    if (var->bits_per_pixel != 32)
        return -EINVAL;
    uxenfb_setup_var(var, info, var->xres, var->yres);
    return 0;
}

static void
uxenfb_refresh(struct fb_info *info, int x1, int y1, int w, int h, int console)
{
    struct uxenfb_par *par = info->par;
    struct uxenfb_rect *rc = &par->dirty_rect;
    int l = x1, t = y1, r = x1+w-1, b = y1+h-1;

    if (!fb_v4vexts)
        return;

    if (rc->left == -1 || rc->top == -1) {
        rc->left = l;
        rc->top = t;
        rc->right = r;
        rc->bottom = b;
    } else {
        /* merge */
        if (l < rc->left)
            rc->left = l;
        if (r > rc->right)
            rc->right = r;
        if (t < rc->top)
            rc->top = t;
        if (b > rc->bottom)
            rc->bottom = b;
    }

    if (send_rect(info->par, rc) == 0) {
        /* send ok, clear rect */
        rc->left = -1;
        rc->right = -1;
    }
}

static void
uxenfb_fillrect(struct fb_info *info, const struct fb_fillrect *rect)
{
    sys_fillrect(info, rect);
    uxenfb_refresh(info, rect->dx, rect->dy, rect->width, rect->height, 1);
}

static void
uxenfb_imageblit(struct fb_info *info, const struct fb_image *image)
{
    sys_imageblit(info, image);
    uxenfb_refresh(info, image->dx, image->dy, image->width, image->height, 1);
}

static void
uxenfb_copyarea(struct fb_info *info, const struct fb_copyarea *area)
{
    sys_copyarea(info, area);
    uxenfb_refresh(info, area->dx, area->dy, area->width, area->height, 1);
}

static int
update_pfn_prot(struct vm_area_struct *vma, unsigned long addr,
                unsigned long pfn, pgprot_t prot)
{
    struct mm_struct *mm = vma->vm_mm;
    spinlock_t *ptl;
    pgd_t *pgd;
    pmd_t *pmd;
    pud_t *pud;
    pte_t *ptep;
    pte_t entry;
    int ret;

    ret = -ENOMEM;

    /* pgtable walk */
    pgd = pgd_offset(mm, addr);
    if (pgd_none(*pgd) || unlikely(pgd_bad(*pgd)))
        goto out;

    pud = pud_offset(pgd, addr);
    if (pud_none(*pud) || unlikely(pud_bad(*pud)))
        goto out;

    pmd = pmd_offset(pud, addr);
    if (pmd_none(*pmd) || pmd_bad(*pmd))
        goto out;

    ptep = pte_offset_map_lock(mm, pmd, addr, &ptl);
    if (!ptep)
        goto out;

    /* update pte */
    entry = pte_mkspecial(pfn_pte(pfn, prot));
    set_pte_at(mm, addr, ptep, entry);
    update_mmu_cache(vma, addr, ptep);
    ret = 0;
    pte_unmap_unlock(ptep, ptl);

out:
    return ret;
}

static void
uxenfb_dirty_work(struct work_struct *work)
{
    struct uxenfb_work *w = (struct uxenfb_work*)work;
    struct fb_info *info = w->info;
    struct uxenfb_par *par = info->par;
    struct vm_area_struct *vma = w->vma;
    unsigned long offset, offset_end, size, i, npfns;
    unsigned long vaddr, pfn;
    pgprot_t prot;
    int ret;
    int y0, y1;

    spin_lock(&par->dirty_lock);
    if (par->dirty_pfn_start < 0 || par->dirty_pfn_end < 0) {
        spin_unlock(&par->dirty_lock);
        return;
    }

    offset = (par->dirty_pfn_start << PAGE_SHIFT) - info->fix.smem_start;
    offset_end = (par->dirty_pfn_end << PAGE_SHIFT) - info->fix.smem_start;
    npfns = par->dirty_pfn_end - par->dirty_pfn_start + 1;
    size = npfns << PAGE_SHIFT;
    y0 = offset / info->fix.line_length;
    y1 = offset_end / info->fix.line_length;
    spin_unlock(&par->dirty_lock);

    if (vma->vm_start + offset + size >= vma->vm_end)
        return;

    /* remap dirty range R/O again */
    prot = vma->vm_page_prot;
    pgprot_val(prot) &= ~_PAGE_RW;

    vaddr = vma->vm_start + offset;
    pfn = (info->fix.smem_start + offset) >> PAGE_SHIFT;
    for (i = 0; i < npfns; ++i) {
        ret = update_pfn_prot(vma, vaddr, pfn, prot);
        if (ret)
            break;
        vaddr += PAGE_SIZE;
        pfn++;
    }
    if (ret) {
        printk(KERN_ERR "uxenfb: error %d while updating pte prot\n", ret);
    } else {
        spin_lock(&par->dirty_lock);
        par->dirty_pfn_start = par->dirty_pfn_end = -1;
        spin_unlock(&par->dirty_lock);
        uxenfb_refresh(info, 0, y0, par->xres, y1-y0+1, 0);
    }
}

static int
uxenfb_vm_fault(struct vm_area_struct *vma,
                struct vm_fault *vmf)
{
    struct fb_info *info = vma->vm_private_data;
    pgprot_t prot = vma->vm_page_prot;
    int ret;

    if (vma->vm_end - vma->vm_start > info->fix.smem_len)
        return -EINVAL;

    /* map whole range R/O on first fault */
    prot = vma->vm_page_prot;
    pgprot_val(prot) &= ~_PAGE_RW;
    ret = io_remap_pfn_range(vma, vma->vm_start, info->fix.smem_start >> PAGE_SHIFT,
                             vma->vm_end - vma->vm_start, prot);
    switch (ret) {
    case 0:
    case -ERESTARTSYS:
    case -EINTR:
        return VM_FAULT_NOPAGE;
    case -ENOMEM:
        return VM_FAULT_OOM;
    default:
        return VM_FAULT_SIGBUS;
    }
}

static int
uxenfb_vm_pfn_mkwrite(struct vm_area_struct *vma,
                      struct vm_fault *vmf)
{
    struct fb_info *info = vma->vm_private_data;
    struct uxenfb_par *par = info->par;
    unsigned long offset = vmf->pgoff << PAGE_SHIFT;
    unsigned long phys_address = info->fix.smem_start + offset;
    unsigned long pfn;

    spin_lock(&par->dirty_lock);
    pfn = phys_address >> PAGE_SHIFT;
    if (pfn < par->dirty_pfn_start || par->dirty_pfn_start == -1)
        par->dirty_pfn_start = pfn;
    if (pfn > par->dirty_pfn_end || par->dirty_pfn_end == -1)
        par->dirty_pfn_end = pfn;
    spin_unlock(&par->dirty_lock);

    par->dirty_work.info = info;
    par->dirty_work.vma = vma;
    schedule_delayed_work((struct delayed_work*)&par->dirty_work, UPDATE_DELAY);
    return 0;
}

static void
uxenfb_vm_open(struct vm_area_struct *vma)
{
    struct fb_info *info = vma->vm_private_data;
    struct uxenfb_par *par = info->par;

    atomic_inc(&par->map_count);
}

static void
uxenfb_vm_close(struct vm_area_struct *vma)
{
    struct fb_info *info = vma->vm_private_data;
    struct uxenfb_par *par = info->par;

    if (atomic_dec_and_test(&par->map_count))
        cancel_delayed_work_sync((struct delayed_work*)&par->dirty_work);
}

static const struct vm_operations_struct uxenfb_vm_ops = {
    .open = uxenfb_vm_open,
    .close = uxenfb_vm_close,
    .fault = uxenfb_vm_fault,
    .pfn_mkwrite = uxenfb_vm_pfn_mkwrite,
};

static int
uxenfb_mmap(struct fb_info *info, struct vm_area_struct *vma)
{
    unsigned long offset = vma->vm_pgoff << PAGE_SHIFT;
    unsigned long size = vma->vm_end - vma->vm_start;

    if (offset + size > info->fix.smem_len)
        return -EINVAL;

    vma->vm_flags |= VM_IO | VM_DONTEXPAND | VM_DONTDUMP | VM_PFNMAP;
    vma->vm_ops = &uxenfb_vm_ops;
    vma->vm_private_data = info;
    vma->vm_page_prot = pgprot_writecombine(vma->vm_page_prot);

    uxenfb_vm_open(vma);

    return 0;
}

static int
uxenfb_set_par(struct fb_info *info)
{
    struct uxenfb_par *par = (struct uxenfb_par*)info->par;

    par->xres = info->var.xres;
    par->yres = info->var.yres;
    par->bpp = info->var.bits_per_pixel;
    par->stride = (par->xres * par->bpp) >> 3;
    info->fix.line_length = par->stride;

    if (fb_v4vexts)
        remote_set_mode(par, par->xres, par->yres, par->stride);

    printk("uxenfb: mode change %dx%d, stride=%d\n", par->xres, par->yres,
           par->stride);
    return 0;
}

static struct fb_ops uxenfb_ops = {
    .owner = THIS_MODULE,
    .fb_read = fb_sys_read,
    .fb_write = fb_sys_write,
    .fb_mmap = uxenfb_mmap,
    .fb_setcolreg = uxenfb_setcolreg,
    .fb_blank = uxenfb_blank,
    .fb_fillrect = uxenfb_fillrect,
    .fb_copyarea = uxenfb_copyarea,
    .fb_imageblit = uxenfb_imageblit,
    .fb_check_var = uxenfb_check_var,
    .fb_set_par = uxenfb_set_par,
};

static void
recv_cmd_ring(struct uxenfb_par *par)
{
    ssize_t len;

    len = uxen_v4v_copy_out(par->cmd_ring, NULL, NULL, NULL, 0, 0);
    if (len <= 0)
        return;

    BUG_ON( len != sizeof(par->resp) );

    uxen_v4v_copy_out(par->cmd_ring, NULL, NULL, &par->resp, sizeof(par->resp), 1);
    par->resp_ready = 1;
    wake_up_interruptible(&par->wq);
}

static void
recv_dirty_ring(struct uxenfb_par *par)
{
    u32 dummy;
    ssize_t len;

    for (;;) {
        len = uxen_v4v_copy_out(par->dirty_ring, NULL, NULL, NULL, 0, 0);
        if (len <= 0)
            break;
        if (len > sizeof(dummy))
            len = sizeof(dummy);
        uxen_v4v_copy_out(par->dirty_ring, NULL, NULL, &dummy, len, 1);
    }
}

static void
uxenfb_cmd_tasklet_run(unsigned long opaque)
{
    struct uxenfb_par *par = (void*)opaque;

    if (par->cmd_ring)
        recv_cmd_ring(par);
}

static void
uxenfb_dirty_tasklet_run(unsigned long opaque)
{
    struct uxenfb_par *par = (void*)opaque;

    if (par->dirty_ring)
        recv_dirty_ring(par);
}

static void
uxenfb_cmd_irq(void *opaque)
{
    struct uxenfb_par *par = opaque;

    tasklet_schedule(&par->cmd_tasklet);
}

static void
uxenfb_dirty_irq(void *opaque)
{
    struct uxenfb_par *par = opaque;

    tasklet_schedule(&par->dirty_tasklet);
}

static int
init_v4v_ring(struct uxenfb_par *par)
{
    int err = 0;

    tasklet_init(&par->cmd_tasklet, uxenfb_cmd_tasklet_run, (unsigned long) par);
    tasklet_init(&par->dirty_tasklet, uxenfb_dirty_tasklet_run, (unsigned long) par);

    par->dst_addr.port = V4V_CMD_PORT;
    par->dst_addr.domain = V4V_DOMID_DM;

    par->cmd_ring = uxen_v4v_ring_bind(
        par->dst_addr.port, par->dst_addr.domain,
        V4V_CMD_RING_LEN, uxenfb_cmd_irq, par);
    if (!par->cmd_ring) {
        err = -ENOMEM;
        goto out;
    }
    if (IS_ERR(par->cmd_ring)) {
        err = PTR_ERR(par->cmd_ring);
        par->cmd_ring = NULL;
        goto out;
    }

    par->dst_dirty_addr.port = V4V_DIRTY_PORT;
    par->dst_dirty_addr.domain = V4V_DOMID_DM;

    par->dirty_ring = uxen_v4v_ring_bind(
        par->dst_dirty_addr.port, par->dst_dirty_addr.domain,
        V4V_DIRTY_RING_LEN, uxenfb_dirty_irq, par);
    if (!par->dirty_ring) {
        err = -ENOMEM;
        goto out;
    }
    if (IS_ERR(par->dirty_ring)) {
        err = PTR_ERR(par->dirty_ring);
        par->dirty_ring = NULL;
        goto out;
    }

out:
    if (err) {
        tasklet_kill(&par->cmd_tasklet);
        tasklet_kill(&par->dirty_tasklet);
    }
    return err;
}

static void
cleanup_v4v_ring(struct uxenfb_par *par)
{
    if (par->cmd_ring) {
        uxen_v4v_ring_free(par->cmd_ring);
        tasklet_kill(&par->cmd_tasklet);
        par->cmd_ring = NULL;
    }
    if (par->dirty_ring) {
        uxen_v4v_ring_free(par->dirty_ring);
        tasklet_kill(&par->dirty_tasklet);
        par->dirty_ring = NULL;
    }
}

static int
setup_fb_info(struct fb_info *info)
{
    struct uxenfb_par *par = info->par;
    int err = 0;

    memset(par, 0, sizeof(*par));

    INIT_LIST_HEAD(&info->modelist);

    info->fbops = &uxenfb_ops;
    info->pseudo_palette = (u8*)info->par + sizeof(struct uxenfb_par);
    info->fix = uxenfb_fix;
    info->fix.smem_start = fb_addr;
    info->fix.smem_len = fb_sizemax;
    info->fix.ypanstep = 0;
    info->fix.ywrapstep = 0;

    info->var.activate = FB_ACTIVATE_NOW;
    info->var.vmode = FB_VMODE_NONINTERLACED;
    info->flags = FBINFO_FLAG_DEFAULT | FBINFO_VIRTFB;
    info->fix.line_length = info->var.xres * info->var.bits_per_pixel / 8;

    info->screen_base = ioremap_wc(info->fix.smem_start, info->fix.smem_len);
    if (!info->screen_base) {
        printk(KERN_ERR "uxenfb: failed to map framebuffer area\n");
        err = -EINVAL;
        goto out;
    }

    err = fb_alloc_cmap(&info->cmap, 256, 0);
    if (err) {
        printk(KERN_ERR "uxenfb: failed to alloc cmap\n");
        goto out;
    }
    par->cmap_allocated = 1;

    spin_lock_init(&par->dirty_lock);
    init_waitqueue_head(&par->wq);
    INIT_DELAYED_WORK((struct delayed_work*)&par->dirty_work, uxenfb_dirty_work);
    par->dirty_pfn_start = par->dirty_pfn_end = -1;
    par->dirty_rect.left = par->dirty_rect.top = -1;

    if (fb_v4vexts) {
        err = init_v4v_ring(par);
        if (err) {
            printk(KERN_ERR "uxenfb: failed to init v4v ring\n");
            goto out;
        }
    }

out:
    return err;
}

static void
cleanup_fb_info(struct fb_info *info)
{
    struct uxenfb_par *par;

    if (!info)
        return;

    par = info->par;
    if (par->registered)
        unregister_framebuffer(info);
    if (fb_v4vexts)
        cleanup_v4v_ring(par);
    if (!list_empty(&info->modelist))
        fb_destroy_modelist(&info->modelist);
    fb_destroy_modedb(info->monspecs.modedb);
    if (par->cmap_allocated)
        fb_dealloc_cmap(&info->cmap);
    if (info->screen_base)
        iounmap(info->screen_base);
    framebuffer_release(info);
}

static int
uxenfb_probe(struct uxen_device *dev)
{
    int err = 0;
    struct uxenfb_par *par = 0;
    struct fb_info *info = 0;
    int xres = DEFAULT_XRES, yres = DEFAULT_YRES;

    info = framebuffer_alloc(sizeof(*par) + sizeof(u32) * 256,
                             &dev->dev);
    if (!info) {
        err = -ENOMEM;
        goto out;
    }

    setup_fb_info(info);
    par = info->par;
    if (fb_v4vexts) {
        int r_xres=0, r_yres=0, r_stride=0;

        remote_query_conf(par, &r_xres, &r_yres, &r_stride);
        if (r_xres && r_yres) {
            xres = r_xres;
            yres = r_yres;
        }
    }
    uxenfb_setup_var(&info->var, info, xres, yres);

    printk("uxenfb: registering framebuffer @ %p (mapped @ %p)\n",
           (void*)info->fix.smem_start,
           info->screen_base);
    if (register_framebuffer(info)) {
        printk(KERN_ERR "uxenfb: failed to register framebuffer\n");
        err = -EINVAL;
        goto out;
    }
    dev->priv = info;

out:
    if (err)
        cleanup_fb_info(info);
    return err;
}

static int
uxenfb_remove(struct uxen_device *dev)
{
    struct fb_info *info = dev->priv;

    cleanup_fb_info(info);
    return 0;
}

static int
uxenfb_suspend(struct uxen_device *dev)
{
    return 0;
}

static int
uxenfb_resume(struct uxen_device *dev)
{
    struct fb_info *info = dev->priv;
    struct uxenfb_par *par = info->par;

    /* resend any pending */
    par->resp_intr = 1;
    wake_up_interruptible(&par->wq);

    return 0;
}

static struct uxen_driver uxenfb_driver = {
    .drv = {
        .name = "uxenfb",
        .owner = THIS_MODULE,
    },
    .type = UXENBUS_DEVICE_TYPE_FB,
    .probe = uxenfb_probe,
    .remove = uxenfb_remove,
    .suspend = uxenfb_suspend,
    .resume = uxenfb_resume,
};

static int __init uxenfb_init(void)
{
    return uxen_driver_register(&uxenfb_driver);
}

static void __exit uxenfb_exit(void)
{
    uxen_driver_unregister(&uxenfb_driver);
}

module_init(uxenfb_init);
module_exit(uxenfb_exit);
MODULE_AUTHOR("tomasz.wroblewski@bromium.com");
MODULE_DESCRIPTION("uXen fb driver");
MODULE_LICENSE("GPL");
