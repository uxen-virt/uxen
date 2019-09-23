/*
 * Copyright 2019, Bromium, Inc.
 * Author: Tomasz Wroblewski <tomasz.wroblewski@gmail.com>
 * SPDX-License-Identifier: ISC
 */

#include <dm/qemu_glue.h>
#include <dm/hw.h>
#include <dm/firmware.h>
#include <dm/mr.h>
#include <dm/vram.h>
#include <dm/timer.h>
#include <dm/hw/uxen_v4v.h>
#include <dm/hw/uxen_fb.h>
#include "uxen_platform.h"
#include <uxen/platform_interface.h>

#define FB_ADDR_BASE 0x0000000800000000
#define FB_SIZEMAX   0x0000000002000000

#define FB_ADDR(idx) (FB_ADDR_BASE + (idx)*FB_SIZEMAX)

#define FBLOG(...) debug_printf("uxenfb: " __VA_ARGS__)

#define V4V_PORT 0xD1581
#define V4V_RING_LEN 4096

#define UXEN_FB_MSG_SETMODE 1
#define UXEN_FB_MSG_SETMODE_RET 2
#define UXEN_FB_MSG_QUERYCONF 3
#define UXEN_FB_MSG_QUERYCONF_RET 4
#define UXEN_FB_MSG_HEADINIT 5
#define UXEN_FB_MSG_HEADINIT_RET 6

#define DEFAULT_XRES 1024
#define DEFAULT_YRES 768
#define DEFAULT_STRIDE (DEFAULT_XRES * 4)
#define MAX_XRES 4096
#define MAX_YRES 2160

#define USE_DIRTY_RECTS

int framebuffer_connected = 0;

struct uxenfb;

struct uxenfb_msg {
    uint32_t type;
    uint32_t head;
    uint32_t status;
    uint32_t xres, yres;
    uint32_t stride;
} __attribute__((packed));

struct uxenfb_packet {
    v4v_datagram_t dgram;
    struct uxenfb_msg msg;
} __attribute__((packed));

typedef struct uxenfb_head {
    head_id_t id;
    struct uxenfb *s;
    struct display_state *ds;
    MemoryRegion fbregion;
    struct vram_desc vram;
    int xres, yres, stride;
} uxenfb_head_t;

typedef struct uxenfb {
    UXenPlatformDevice dev;

    int xres, yres, stride;

    struct uxenfb_head *head[FB_HEADMAX];
    Timer *timer;

    struct uxenfb_packet packet;
    v4v_context_t v4v;
    v4v_async_t async;
    uint32_t partner_id;
    ioh_event tx_event;
    ioh_event rx_event;
} uxenfb_t;

static struct uxenfb_head * uxen_fb_head_get (uxenfb_t *s, head_id_t id);
static int uxen_fb_head_init (uxenfb_t *s, head_id_t id);

static void
uxenfb_update(void *opaque)
{
#ifndef USE_DIRTY_RECTS
    struct uxenfb_head *h = opaque;

    if (!h->ds)
        return;

    dpy_update(h->ds, 0, 0, h->xres, h->yres);
#endif
}

static void
uxenfb_invalidate(void *opaque)
{
}

static void
uxenfb_text_update(void *opaque, console_ch_t *chardata)
{
}

static void
fb_mapping_update(void *opaque)
{
    struct uxenfb_head *h = opaque;
    uint32_t gfn;

    gfn = memory_region_absolute_offset(&h->fbregion) >> TARGET_PAGE_BITS;
    FBLOG("mapping update, gfn=0x%x\n", gfn);
    vram_map(&h->vram, gfn);
    // FIXME? s->ds
    display_resize_from(h->ds, h->xres, h->yres,
                        32, h->stride, h->vram.view, 0);
}

static void
vram_change(struct vram_desc *v, void *opaque)
{
    struct uxenfb_head *h = opaque;

    FBLOG("vram change\n");
    dpy_vram_change(h->ds, v);
}

#ifndef USE_DIRTY_RECTS
static void
fb_timer(void *opaque)
{
    uxenfb_t *s = opaque;
    int i;

    for (i = 0; i < FB_HEADMAX; i++) {
        uxenfb_head_t *h = uxen_fb_head_get(s, i);
        if (h)
            do_dpy_trigger_refresh(h->ds);
    }

    qemu_mod_timer(s->timer, get_clock_ms(vm_clock) + 30);
}
#endif

static struct console_hw_ops uxenfb_console_ops = {
    .update = uxenfb_update,
    .invalidate = uxenfb_invalidate,
    .text_update = uxenfb_text_update,
};

static void
respond(uxenfb_t *s, struct uxenfb_packet *resp)
{
    int err;
    size_t bytes;

    resp->dgram.addr.port = V4V_PORT;
    resp->dgram.addr.domain = s->partner_id;
    resp->dgram.flags = 0;

    dm_v4v_async_init(&s->v4v, &s->async, s->tx_event);
    ioh_event_reset(&s->tx_event);
    err = dm_v4v_send(&s->v4v, (v4v_datagram_t*)resp,
        sizeof(*resp), &s->async);
    if (err == 0)
        return;

    if (err != ERROR_IO_PENDING) {
        FBLOG("%s: dm_v4v_send failed with %d\n", __FUNCTION__, err);
        return;
    }

    err = dm_v4v_async_get_result(&s->async, &bytes, true);
    if (err) {
        FBLOG("%s: dm_v4v_async_get_result failed with %d\n",
              __FUNCTION__, err);
        return;
    }
}

static void
fb_recv_msg(uxenfb_t *s, struct uxenfb_msg *msg)
{
    struct uxenfb_packet resp = { };

    resp.msg.status = -1;

    framebuffer_connected = 1;

    switch (msg->type) {
    case UXEN_FB_MSG_SETMODE: {
        if (msg->xres <= MAX_XRES && msg->yres <= MAX_YRES &&
            msg->stride * msg->xres <= FB_SIZEMAX) {

            struct uxenfb_head *h = uxen_fb_head_get(s, msg->head);
            if (h) {
                FBLOG("resizing display%d %dx%d\n", h->id, s->xres, s->yres);
                h->xres = msg->xres;
                h->yres = msg->yres;
                h->stride = msg->stride;
                display_resize_from(h->ds, h->xres, h->yres,
                    32, h->stride, h->vram.view,
                    0);

                resp.msg.type = UXEN_FB_MSG_SETMODE_RET;
                resp.msg.status = 0;
            } else {
                FBLOG("no head: %d\n", msg->head);
                resp.msg.type = UXEN_FB_MSG_SETMODE_RET;
                resp.msg.status = -1;
            }
        } else {
            resp.msg.type = UXEN_FB_MSG_SETMODE_RET;
            resp.msg.status = -1;
            FBLOG("invalid mode set attempt\n");
        }

        break;
    }

    case UXEN_FB_MSG_QUERYCONF: {
        struct uxenfb_head *h = uxen_fb_head_get(s, msg->head);

        if (h) {
            resp.msg.type = UXEN_FB_MSG_QUERYCONF_RET;
            resp.msg.status = 0;
            resp.msg.xres = h->ds->gui->width;
            resp.msg.yres = h->ds->gui->height;
            resp.msg.stride = resp.msg.xres * 4;
        } else {
            resp.msg.type = UXEN_FB_MSG_QUERYCONF_RET;
            resp.msg.status = -1;
        }

        break;
    }

    case UXEN_FB_MSG_HEADINIT: {
        resp.msg.type = UXEN_FB_MSG_HEADINIT_RET;
        resp.msg.status = uxen_fb_head_init(s, msg->head);
        break;
    }
    default:
        FBLOG("unknown message %d\n", msg->type);
        return;
    }

    respond(s, &resp);
}

static int
fb_recv_start(uxenfb_t *s)
{
    int err;

    dm_v4v_async_init(&s->v4v, &s->async, s->rx_event);

    err = dm_v4v_recv(&s->v4v, (v4v_datagram_t*)&s->packet,
        sizeof(s->packet), &s->async);
    if (err && err != ERROR_IO_PENDING) {
        FBLOG("%s: dm_v4v_recv failed with %d\n", __FUNCTION__, err);
        return -1;
    }

    return 0;
}

static void
fb_recv_event(void *opaque)
{
    uxenfb_t *s = opaque;
    size_t bytes;
    int err;

    ioh_event_reset(&s->rx_event);
    err = dm_v4v_async_get_result(&s->async, &bytes, false);
    if (err) {
        switch (err) {
        case ERROR_IO_INCOMPLETE:
            ioh_event_reset(&s->rx_event);
            return;
        }
        FBLOG("%s: dm_v4v_async_get_result failed with %d\n", __FUNCTION__,
              err);
        fb_recv_start(s);
        return;
    }

    fb_recv_msg(s, &s->packet.msg);
    fb_recv_start(s);
}

static int
uxen_fb_init_v4v(uxenfb_t *s)
{
    v4v_bind_values_t bind = { };
    int error;

    error = dm_v4v_open(&s->v4v, V4V_RING_LEN);
    if (error) {
        warnx("%s: v4v_open error %x", __FUNCTION__, error);
        return -1;
    }

    bind.ring_id.addr.port = V4V_PORT;
    bind.ring_id.addr.domain = V4V_DOMID_ANY;
    bind.ring_id.partner = V4V_DOMID_UUID;
    memcpy(&bind.partner, v4v_idtoken, sizeof(bind.partner));

    error = dm_v4v_bind(&s->v4v, &bind);
    if (error) {
        warnx("%s: v4v_bind error %x", __FUNCTION__, error);
        dm_v4v_close(&s->v4v);
        return -1;
    }
    s->partner_id = bind.ring_id.partner;

    ioh_event_init(&s->rx_event);
    ioh_event_init(&s->tx_event);

    ioh_add_wait_object(&s->rx_event, fb_recv_event, s, NULL);

    return fb_recv_start(s);
}

static struct uxenfb_head *
uxen_fb_head_get (uxenfb_t *s, head_id_t id)
{
    if (id >= 0 && id < FB_HEADMAX)
        return s->head[id];

    return NULL;
}

static int
uxen_fb_head_init (uxenfb_t *s, head_id_t id)
{
    struct uxenfb_head *h;

    if (id < 0 || id >= FB_HEADMAX)
        return -EINVAL;

    if (s->head[id])
        return 0;

    h = calloc(1, sizeof(*h));
    h->id = id;
    h->s = s;
    h->xres = DEFAULT_XRES;
    h->yres = DEFAULT_YRES;
    h->stride = DEFAULT_STRIDE;
    h->ds = display_create(&uxenfb_console_ops, h, id, DCF_START_GUI);

    vram_init(&h->vram, FB_SIZEMAX);
    vram_register_change(&h->vram, vram_change, h);
    vram_alloc(&h->vram, FB_SIZEMAX);

    memory_region_init(&h->fbregion, "fb", FB_SIZEMAX);
    h->fbregion.map_cb = fb_mapping_update;
    h->fbregion.map_opaque = h;
    memory_region_add_subregion(system_iomem, FB_ADDR(id), &h->fbregion);
    
    s->head[id] = h;

    return 0;
}

static void
uxen_fb_head_free (struct uxenfb_head *h)
{
    if (h) {
        display_destroy(h->ds);
        vram_release(&h->vram);
        memory_region_del_subregion(system_iomem, &h->fbregion);
        memory_region_destroy(&h->fbregion);
        free(h);
    }
}

static int
uxen_fb_initfn (UXenPlatformDevice *dev)
{
    uxenfb_t *s = DO_UPCAST(uxenfb_t, dev, dev);
    int err;

    uxen_fb_head_init(s, 0);

#ifndef USE_DIRTY_RECTS
    s->timer = new_timer_ms(vm_clock, fb_timer, s);
    qemu_mod_timer(s->timer, get_clock_ms(vm_clock));
#endif

    err = uxen_fb_init_v4v(s);
    if (err)
        errx(1, "uxen_fb v4v initialization failed, err=%d\n", err);

    FBLOG("initialized\n");

    return 0;
}

static int
uxen_fb_exitfn (UXenPlatformDevice *dev)
{
    uxenfb_t *s = DO_UPCAST(uxenfb_t, dev, dev);
    int i;

    dm_v4v_close(&s->v4v);
    ioh_event_close(&s->tx_event);
    ioh_event_close(&s->rx_event);

    for (i = 0; i < FB_HEADMAX; i++) {
        uxen_fb_head_free(s->head[i]);
        s->head[i] = NULL;
    }

    return 0;
}

static UXenPlatformDeviceInfo uxen_fb_info = {
    .qdev.name = "uxenfb",
    .qdev.size = sizeof (uxenfb_t),
    .init = uxen_fb_initfn,
    .exit = uxen_fb_exitfn,
    .devtype = UXENBUS_DEVICE_TYPE_FB,
};

static void
uxen_fb_register_devices (void)
{
    uxenplatform_qdev_register(&uxen_fb_info);
}

device_init (uxen_fb_register_devices);
