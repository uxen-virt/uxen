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
#include <linux/slab.h>
#include <video/edid.h>

#include <uxen/platform_interface.h>
#include <uxen-v4vlib.h>
#include <uxen-platform.h>
#include <uxen-util.h>

#define DEFAULT_XRES 1024
#define DEFAULT_YRES 768
#define DEFAULT_FB_ADDR 0xC0000000
#define DEFAULT_FB_SIZEMAX 0x2000000

struct uxenfb_par {
    u32 xres, yres, bpp, stride;
};

static struct fb_fix_screeninfo uxenfb_fix = {
    .id	= "uxen fb",
    .type = FB_TYPE_PACKED_PIXELS,
    .accel = FB_ACCEL_NONE,
    .visual = FB_VISUAL_TRUECOLOR,
};

static ulong fb_addr = DEFAULT_FB_ADDR;
static ulong fb_sizemax = DEFAULT_FB_SIZEMAX;

module_param(fb_addr, ulong, 0444);
module_param(fb_sizemax, ulong, 0444);

#if 0
static
void process_edid(struct fb_info *info, int *xres, int *yres)
{
    struct uxenfb_par *par = (struct uxenfb_par*) info->par;
    struct fb_var_screeninfo var = { };
    u8 edid[256];
    int i;

    for (i = 0; i < sizeof(edid); ++i)
        edid[i] = ioread8(par->regbase + UXDISP_REG_CRTC(0) +
                          UXDISP_REG_CRTC_EDID_DATA + i);
    fb_parse_edid(edid, &var);
    printk("edid resolution %dx%d\n", var.xres, var.yres);
    *xres = var.xres;
    *yres = var.yres;
}
#endif

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
                 int xres, int yres, int bpp)
{
    var->xres = xres;
    var->yres = yres;
    var->bits_per_pixel = bpp;
    var->xres_virtual = var->xres;
    var->yres_virtual = var->yres;

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
    if (var->xres > 8192 || var->yres > 8192)
        return -EINVAL;
    if (var->xres <= 0 || var->yres <= 0)
        return -EINVAL;
    if (var->bits_per_pixel != 32)
        return -EINVAL;
    uxenfb_setup_var(var, info, var->xres, var->yres, var->bits_per_pixel);
    printk("uxenfb: check_var %d %d %d ok\n", var->xres, var->yres, var->bits_per_pixel);
    return 0;
}

static int
uxenfb_set_par(struct fb_info *info)
{
    struct uxenfb_par *par = (struct uxenfb_par*)info->par;

    par->xres = info->var.xres;
    par->yres = info->var.yres;
    par->bpp = info->var.bits_per_pixel;
    info->fix.line_length = par->xres * par->bpp / 8;
    par->stride = info->fix.line_length;

    printk("uxenfb: mode change %dx%d@%d, stride=%d\n", par->xres, par->yres,
           par->bpp, par->stride);
    return 0;
}

static struct fb_ops uxenfb_ops = {
    .owner = THIS_MODULE,
    .fb_read = fb_sys_read,
    .fb_write = fb_sys_write,
    .fb_setcolreg = uxenfb_setcolreg,
    .fb_blank = uxenfb_blank,
    .fb_fillrect = sys_fillrect,
    .fb_copyarea = sys_copyarea,
    .fb_imageblit = sys_imageblit,
    .fb_check_var = uxenfb_check_var,
    .fb_set_par = uxenfb_set_par,
};

static int
uxenfb_probe(struct uxen_device *dev)
{
    int err = 0;
    uint32_t magic;
    struct uxenfb_par *par = 0;
    struct fb_info *info = 0;
    int have_cmap = 0;
    int xres=0,yres=0;

    info = framebuffer_alloc(sizeof(*par) + sizeof(u32) * 256,
                             &dev->dev);
    if (!info) {
        err = -ENOMEM;
        goto out;
    }
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
    if (err)
        goto out;
    have_cmap = 1;

    par = info->par;

/*  FIXME! resolution setup
    process_edid(info, &xres, &yres);
*/
    xres = DEFAULT_XRES;
    yres = DEFAULT_YRES;
    uxenfb_setup_var(&info->var, info, xres, yres, 32);

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
    if (err) {
        if (info) {
            if (!list_empty(&info->modelist))
		fb_destroy_modelist(&info->modelist);
            fb_destroy_modedb(info->monspecs.modedb);
            if (have_cmap)
                fb_dealloc_cmap(&info->cmap);
            if (info->screen_base)
                iounmap(info->screen_base);
            framebuffer_release(info);
        }
    }
    return err;
}

static void
uxenfb_cleanup(struct fb_info *info)
{
    struct uxenfb_par *par = (struct uxenfb_par*)info->par;

    unregister_framebuffer(info);
    if (!list_empty(&info->modelist))
        fb_destroy_modelist(&info->modelist);
    fb_destroy_modedb(info->monspecs.modedb);
    fb_dealloc_cmap(&info->cmap);
    iounmap(info->screen_base);
    framebuffer_release(info);
}

static void
uxenfb_remove(struct uxen_device *dev)
{
    struct fb_info *info = dev->priv;

    uxenfb_cleanup(info);
}

static struct uxen_driver uxenfb_driver = {
    .drv = {
        .name = "uxenfb",
        .owner = THIS_MODULE,
    },
    .type = UXENBUS_DEVICE_TYPE_FB,
    .probe = uxenfb_probe,
    .remove = uxenfb_remove,
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
