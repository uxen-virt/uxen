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
 * Copyright 2016-2019, Bromium, Inc.
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

#define DEFAULT_FB_ADDR    0x0000000800000000
#define DEFAULT_FB_SIZEMAX          0x2000000

#define UPDATE_DELAY (HZ/60)

#define V4V_CMD_PORT 0xD1581
#define V4V_CMD_RING_LEN 4096

#define UXEN_FB_MSG_SETMODE 1
#define UXEN_FB_MSG_SETMODE_RET 2
#define UXEN_FB_MSG_QUERYCONF 3
#define UXEN_FB_MSG_QUERYCONF_RET 4
#define UXEN_FB_MSG_HEADINIT 5
#define UXEN_FB_MSG_HEADINIT_RET 6

#define UXEN_FB_IO_HEAD_IDENTIFY 0x5000
#define UXEN_FB_IO_HEAD_INIT 0x5001

struct uxenfb_msg {
    uint32_t type;
    uint32_t head;
    uint32_t status;
    uint32_t xres, yres;
    uint32_t stride;
} __attribute__((packed));

struct uxenfb_rect {
    int32_t left;
    int32_t top;
    int32_t right;
    int32_t bottom;
} __attribute__((packed));

struct uxenfb_work {
    struct delayed_work _d;
    struct fb_info *info;
    struct vm_area_struct *vma;
};

struct uxenfb_state;

struct uxenfb_par {
    struct uxenfb_state *state;
    int headid;
    u32 xres, yres, bpp, stride;
    int cmap_allocated, registered;

    atomic_t map_count;
};

struct uxenfb_head {
    int headid;
    struct fb_info *info;
};

struct uxenfb_state {
    struct uxen_device *dev;
    struct uxenfb_head head[FB_MAX];

    struct mutex req_mutex;
    uxen_v4v_ring_t *cmd_ring;
    v4v_addr_t dst_addr;
    struct tasklet_struct cmd_tasklet;
    wait_queue_head_t wq;
    struct uxenfb_msg resp;
    int resp_ready, resp_intr;
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
static bool fb_mmap_only = 1;

module_param(fb_addr, ulong, 0444);
module_param(fb_sizemax, ulong, 0444);
module_param(fb_v4vexts, bool, 0444);
module_param(fb_mmap_only, bool, 0444);

static int uxenfb_head_init(struct uxen_device *dev, int headid);

static void
send(struct uxenfb_state *state, struct uxenfb_msg *msg)
{
    ssize_t r;

    r = uxen_v4v_send_from_ring(state->cmd_ring, &state->dst_addr, msg, sizeof(*msg),
                                V4V_PROTO_DGRAM);
    BUG_ON( r != sizeof(*msg) );
}

static void
send_and_wait(
    struct uxenfb_state *state,
    struct uxenfb_msg *msg,
    struct uxenfb_msg *resp)
{
    mutex_lock(&state->req_mutex);
    state->resp_intr = 0;
    state->resp_ready = 0;
    do {
        send(state, msg);
        wait_event_interruptible(state->wq, state->resp_ready || state->resp_intr);
    } while (state->resp_intr);

    *resp = state->resp;
    mutex_unlock(&state->req_mutex);
}

static void
remote_set_mode(struct uxenfb_par *par, int xres, int yres, int stride)
{
    struct uxenfb_msg msg = { };
    struct uxenfb_msg resp = { };

    msg.type = UXEN_FB_MSG_SETMODE;
    msg.head = par->headid;
    msg.xres = xres;
    msg.yres = yres;
    msg.stride = stride;

    send_and_wait(par->state, &msg, &resp);
}

static void
remote_query_conf(struct uxenfb_par *par, int *xres, int *yres, int *stride)
{
    struct uxenfb_msg msg = { };
    struct uxenfb_msg resp = { };

    msg.type = UXEN_FB_MSG_QUERYCONF;
    msg.head = par->headid;
    
    send_and_wait(par->state, &msg, &resp);

    *xres = resp.xres;
    *yres = resp.yres;
    *stride = resp.stride;
}

static int
remote_head_init(struct uxenfb_par *par)
{
    struct uxenfb_msg msg = { };
    struct uxenfb_msg resp = { };

    msg.type = UXEN_FB_MSG_HEADINIT;
    msg.head = par->headid;

    send_and_wait(par->state, &msg, &resp);

    return resp.status;
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
}

static void
uxenfb_fillrect(struct fb_info *info, const struct fb_fillrect *rect)
{
    if (fb_mmap_only)
        return;
    sys_fillrect(info, rect);
    uxenfb_refresh(info, rect->dx, rect->dy, rect->width, rect->height, 1);
}

static void
uxenfb_imageblit(struct fb_info *info, const struct fb_image *image)
{
    if (fb_mmap_only)
        return;
    sys_imageblit(info, image);
    uxenfb_refresh(info, image->dx, image->dy, image->width, image->height, 1);
}

static void
uxenfb_copyarea(struct fb_info *info, const struct fb_copyarea *area)
{
    if (fb_mmap_only)
        return;
    sys_copyarea(info, area);
    uxenfb_refresh(info, area->dx, area->dy, area->width, area->height, 1);
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

    printk("uxenfb: mode change head %d, %dx%d, stride=%d\n", par->headid, par->xres, par->yres,
           par->stride);

    return 0;
}

static int
uxenfb_ioctl(struct fb_info *info, unsigned int cmd, unsigned long arg)
{
    struct uxenfb_par *par = (struct uxenfb_par*)info->par;
    struct uxen_device *dev = par->state->dev;
    void __user *argp = (void __user*) arg;
    uint32_t head_id;
    int ret = 0;

    switch (cmd) {
    case UXEN_FB_IO_HEAD_IDENTIFY:
        head_id = par->headid;
        ret = copy_to_user(argp, &head_id, sizeof(head_id)) ? -EFAULT : 0;
        break;

    case UXEN_FB_IO_HEAD_INIT:
        if (copy_from_user(&head_id, argp, sizeof(head_id))) {
            ret = -EFAULT;
            goto out;
        }

        ret = uxenfb_head_init(dev, head_id);
        break;

    default:
        ret = -ENOTTY;
        break;
    }

out:
    return ret;
}

static struct fb_ops uxenfb_ops = {
    .owner = THIS_MODULE,
    .fb_read = fb_sys_read,
    .fb_write = fb_sys_write,
    .fb_setcolreg = uxenfb_setcolreg,
    .fb_blank = uxenfb_blank,
    .fb_fillrect = uxenfb_fillrect,
    .fb_copyarea = uxenfb_copyarea,
    .fb_imageblit = uxenfb_imageblit,
    .fb_check_var = uxenfb_check_var,
    .fb_set_par = uxenfb_set_par,
    .fb_ioctl = uxenfb_ioctl,
};

static void
recv_cmd_ring(struct uxenfb_state *state)
{
    ssize_t len;

    len = uxen_v4v_copy_out(state->cmd_ring, NULL, NULL, NULL, 0, 0);
    if (len <= 0)
        return;

    BUG_ON( len != sizeof(state->resp) );

    uxen_v4v_copy_out(state->cmd_ring, NULL, NULL, &state->resp, sizeof(state->resp), 1);
    state->resp_ready = 1;
    wake_up_interruptible(&state->wq);
}

static void
uxenfb_cmd_tasklet_run(unsigned long opaque)
{
    struct uxenfb_state *state = (void*)opaque;

    if (state->cmd_ring)
        recv_cmd_ring(state);
}

static void
uxenfb_cmd_irq(void *opaque)
{
    struct uxenfb_state *state = opaque;

    tasklet_schedule(&state->cmd_tasklet);
}

static int
init_v4v_ring(struct uxen_device *dev)
{
    struct uxenfb_state *state = dev->priv;
    int err = 0;

    tasklet_init(&state->cmd_tasklet, uxenfb_cmd_tasklet_run, (unsigned long) state);

    state->dst_addr.port = V4V_CMD_PORT;
    state->dst_addr.domain = V4V_DOMID_DM;

    state->cmd_ring = uxen_v4v_ring_bind(
        state->dst_addr.port, state->dst_addr.domain,
        V4V_CMD_RING_LEN, uxenfb_cmd_irq, state);
    if (!state->cmd_ring) {
        err = -ENOMEM;
        goto out;
    }
    if (IS_ERR(state->cmd_ring)) {
        err = PTR_ERR(state->cmd_ring);
        state->cmd_ring = NULL;
        goto out;
    }

out:
    if (err) {
        tasklet_kill(&state->cmd_tasklet);
    }
    return err;
}

static void
cleanup_v4v_ring(struct uxen_device *dev)
{
    struct uxenfb_state *state = dev->priv;

    if (state->cmd_ring) {
        uxen_v4v_ring_free(state->cmd_ring);
        tasklet_kill(&state->cmd_tasklet);
        state->cmd_ring = NULL;
    }
}

static int
setup_fb_info(struct fb_info *info, int head)
{
    struct uxenfb_par *par = info->par;
    int err = 0;

    memset(par, 0, sizeof(*par));

    INIT_LIST_HEAD(&info->modelist);

    info->fbops = &uxenfb_ops;
    info->pseudo_palette = (u8*)info->par + sizeof(struct uxenfb_par);
    info->fix = uxenfb_fix;
    info->fix.smem_start = fb_addr + fb_sizemax * head;
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
uxenfb_head_init(struct uxen_device *dev, int headid)
{
    int err = 0;
    struct uxenfb_state *state = dev->priv;
    struct uxenfb_par *par = 0;
    struct fb_info *info = 0;
    int xres = DEFAULT_XRES, yres = DEFAULT_YRES;

    if (!(headid >= 0 && headid < FB_MAX))
        return -EINVAL;

    if (state->head[headid].info)
        return 0; // already initialized

    info = framebuffer_alloc(sizeof(*par) + sizeof(u32) * 256,
                             &dev->dev);
    if (!info) {
        err = -ENOMEM;
        goto out;
    }

    setup_fb_info(info, headid);
    par = info->par;
    par->headid = headid;
    par->state = state;

    if (fb_v4vexts) {
        int r_xres=0, r_yres=0, r_stride=0;

        // send backend head init req
        if (headid > 0) {
            err = remote_head_init(par);
            if (err) {
                printk(KERN_ERR "uxenfb: failed to init head %d\n", par->headid);
                goto out;
            }
            printk("uxenfb: remote head %d initialized\n", headid);
        }

        // query initial resolution
        remote_query_conf(par, &r_xres, &r_yres, &r_stride);
        if (r_xres && r_yres) {
            xres = r_xres;
            yres = r_yres;
        }
    }
    uxenfb_setup_var(&info->var, info, xres, yres);

    printk("uxenfb: registering framebuffer%d @ %p (mapped @ %p) mode %dx%d\n",
           headid,
           (void*)info->fix.smem_start,
           info->screen_base,
           xres, yres);
    if (register_framebuffer(info)) {
        printk(KERN_ERR "uxenfb: failed to register framebuffer\n");
        err = -EINVAL;
        goto out;
    }

    state->head[headid].headid = headid;
    state->head[headid].info = info;

out:
    if (err)
        cleanup_fb_info(info);

    return err;
}

static int
uxenfb_probe(struct uxen_device *dev)
{
    int err = 0;
    int v4v = 0;

    struct uxenfb_state *state;

    state = kzalloc(sizeof(*state), GFP_KERNEL);
    if (!state) {
        err = -ENOMEM;
        goto out;
    }
    state->dev = dev;
    dev->priv = state;

    if (fb_v4vexts) {
        err = init_v4v_ring(dev);
        if (err) {
            printk(KERN_ERR "uxenfb: failed to init v4v ring\n");
            goto out;
        }
        v4v = 1;
    }


    init_waitqueue_head(&state->wq);
    mutex_init(&state->req_mutex);

    // head #0
    err = uxenfb_head_init(dev, 0);
    if (err)
        goto out;

out:
    if (err) {
        if (v4v)
            cleanup_v4v_ring(dev);
        if (state)
            kfree(state);
    }

    return err;
}

static int
uxenfb_remove(struct uxen_device *dev)
{
    struct uxenfb_state *state = dev->priv;
    int i;

    if (fb_v4vexts)
        cleanup_v4v_ring(dev);

    for (i = 0; i < FB_MAX; i++) {
        if (state->head[i].info) {
            cleanup_fb_info(state->head[i].info);
            state->head[i].info = NULL;
        }
    }

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
    struct uxenfb_state *state = dev->priv;

    /* resend any pending */
    state->resp_intr = 1;
    wake_up_interruptible(&state->wq);

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
