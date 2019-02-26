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

#include "uxen_platform.h"
#include <uxen/platform_interface.h>

#define FB_ADDR 0xC0000000
#define FB_SIZEMAX 0x2000000

#define FBLOG(...) debug_printf("uxenfb: " __VA_ARGS__)

#define V4V_PORT 0xD1581
#define V4V_RING_LEN 4096

#define UXEN_FB_MSG_SETMODE 1
#define UXEN_FB_MSG_SETMODE_RET 2
#define UXEN_FB_MSG_QUERYCONF 3
#define UXEN_FB_MSG_QUERYCONF_RET 4

#define DEFAULT_XRES 1024
#define DEFAULT_YRES 768
#define DEFAULT_STRIDE (DEFAULT_XRES * 4)
#define MAX_XRES 4096
#define MAX_YRES 2160

//#define USE_DIRTY_RECTS

int framebuffer_connected = 0;

struct uxenfb_msg {
    uint8_t type;
    uint16_t xres, yres, stride;
} __attribute__((packed));

struct uxenfb_packet {
    v4v_datagram_t dgram;
    struct uxenfb_msg msg;
} __attribute__((packed));

typedef struct {
    UXenPlatformDevice dev;

    int xres, yres, stride;

    MemoryRegion fbregion;
    struct vram_desc vram;
    struct display_state *ds;
    Timer *timer;

    struct uxenfb_packet packet;
    v4v_context_t v4v;
    v4v_async_t async;
    uint32_t partner_id;
    ioh_event tx_event;
    ioh_event rx_event;
} uxen_fb_t;

static void
uxenfb_update(void *opaque)
{
#ifndef USE_DIRTY_RECTS
    uxen_fb_t *s = (uxen_fb_t*)opaque;

    if (!s->ds)
        return;

    dpy_update(s->ds, 0, 0, s->xres, s->yres);
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
    uxen_fb_t *s = opaque;
    uint32_t gfn;

    gfn = memory_region_absolute_offset(&s->fbregion) >> TARGET_PAGE_BITS;
    FBLOG("mapping update, gfn=0x%x\n", gfn);
    vram_map(&s->vram, gfn);
    display_resize_from(s->ds, s->xres, s->yres,
                        32, s->stride, s->vram.view, 0);
}

static void
vram_change(struct vram_desc *v, void *opaque)
{
    uxen_fb_t *s = opaque;

    FBLOG("vram change\n");
    dpy_vram_change(s->ds, v);
}

#ifndef USE_DIRTY_RECTS
static void
fb_timer(void *opaque)
{
    uxen_fb_t *s = opaque;

    do_dpy_trigger_refresh(s->ds);

    qemu_mod_timer(s->timer, get_clock_ms(vm_clock) + 30);
}
#endif

static struct console_hw_ops uxenfb_console_ops = {
    .update = uxenfb_update,
    .invalidate = uxenfb_invalidate,
    .text_update = uxenfb_text_update,
};

static void
respond(uxen_fb_t *s, struct uxenfb_packet *resp)
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
fb_recv_msg(uxen_fb_t *s, struct uxenfb_msg *msg)
{
    struct uxenfb_packet resp = { };

    framebuffer_connected = 1;
    if (msg->type == UXEN_FB_MSG_SETMODE) {
        if (msg->xres <= MAX_XRES && msg->yres <= MAX_YRES &&
            msg->stride * msg->xres <= FB_SIZEMAX) {
            s->xres = msg->xres;
            s->yres = msg->yres;
            s->stride = msg->stride;

            FBLOG("resizing display %dx%d\n", s->xres, s->yres);
            display_resize_from(s->ds, s->xres, s->yres,
                                32, s->stride, s->vram.view,
                                0);

            resp.msg.type = UXEN_FB_MSG_SETMODE_RET;
        } else {
            FBLOG("invalid mode set attempt\n");
            return;
        }
    } else if (msg->type == UXEN_FB_MSG_QUERYCONF) {
        resp.msg.type = UXEN_FB_MSG_QUERYCONF_RET;
        resp.msg.xres = s->ds->gui->width;
        resp.msg.yres = s->ds->gui->height;
        resp.msg.stride = resp.msg.xres * 4;
    } else {
        FBLOG("unknown message %d\n", msg->type);
        return;
    }

    respond(s, &resp);
}

static int
fb_recv_start(uxen_fb_t *s)
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
    uxen_fb_t *s = opaque;
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
uxen_fb_init_v4v(uxen_fb_t *s)
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


static int
uxen_fb_initfn (UXenPlatformDevice *dev)
{
    uxen_fb_t *s = DO_UPCAST(uxen_fb_t, dev, dev);
    int err;

    s->ds = display_create(&uxenfb_console_ops, s, DCF_START_GUI);
    s->xres = DEFAULT_XRES;
    s->yres = DEFAULT_YRES;
    s->stride = DEFAULT_STRIDE;

    vram_init(&s->vram, FB_SIZEMAX);
    vram_register_change(&s->vram, vram_change, s);
    vram_alloc(&s->vram, FB_SIZEMAX);

    memory_region_init(&s->fbregion, "fb", FB_SIZEMAX);
    s->fbregion.map_cb = fb_mapping_update;
    s->fbregion.map_opaque = s;

    memory_region_add_subregion(system_iomem, FB_ADDR, &s->fbregion);

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
    uxen_fb_t *s = DO_UPCAST(uxen_fb_t, dev, dev);

    dm_v4v_close(&s->v4v);
    display_destroy(s->ds);
    ioh_event_close(&s->tx_event);
    ioh_event_close(&s->rx_event);
    vram_release(&s->vram);
    memory_region_del_subregion(system_iomem, &s->fbregion);
    memory_region_destroy(&s->fbregion);

    return 0;
}

static UXenPlatformDeviceInfo uxen_fb_info = {
    .qdev.name = "uxenfb",
    .qdev.size = sizeof (uxen_fb_t),
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
