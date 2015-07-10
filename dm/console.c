/*
 * Copyright 2012-2015, Bromium, Inc.
 * Author: Christian Limpach <Christian.Limpach@gmail.com>
 * SPDX-License-Identifier: ISC
 */

#include "config.h"

#include <err.h>
#include <stdbool.h>
#include <stdint.h>

#include "char.h"
#include "console.h"
#include "ioh.h"
#include "qemu_glue.h"
#include "uxen.h"

static struct display_list displays = TAILQ_HEAD_INITIALIZER(displays);

uint32_t forwarded_keys = 0;

void vga_hw_update(struct display_state *ds)
{
    if (ds->hw_ops->update)
        ds->hw_ops->update(ds->hw);
}

void vga_hw_invalidate(struct display_state *ds)
{
    if (ds->hw_ops->invalidate)
        ds->hw_ops->invalidate(ds->hw);
}


struct display_state *display_create(struct console_hw_ops *ops,
                                     void *opaque)
{
    struct display_state *ds;

    ds = (struct display_state *)calloc(1, sizeof(struct display_state));
    if (!ds)
        errx(1, "%s: alloc struct display_state failed", __FUNCTION__);

    critical_section_init(&ds->resize_lock);
    ds->hw_ops = ops;
    ds->hw = opaque;

    TAILQ_INSERT_TAIL(&displays, ds, link);

    return ds;
}

int console_set_forwarded_keys(yajl_val arg)
{
    yajl_val v;
    unsigned int i;
    char *s;

    /* Reset the state each time. */
    forwarded_keys = 0;

    YAJL_FOREACH_ARRAY_OR_OBJECT(v, arg, i) {
        s = YAJL_GET_STRING(v);
        if (!strcmp(s, "all-control-keys"))
            forwarded_keys |= FORWARD_CONTROL_KEYS;
        else {
            debug_printf("unknown key forward: %s\n", s);
            return -1;
        }
    }
    return 0;
}

void display_resize(struct display_state *ds, int width, int height)
{
    critical_section_enter(&ds->resize_lock);
    ds->surface = resize_displaysurface(ds, ds->surface, width, height);
    critical_section_leave(&ds->resize_lock);
    dpy_resize(ds);
}

void display_resize_from(struct display_state *ds, int width, int height,
                         int depth, int linesize,
                         void *vram_ptr,
                         unsigned int vram_offset)
{
    critical_section_enter(&ds->resize_lock);
    if (ds->surface)
        free_displaysurface(ds, ds->surface);
    ds->surface = create_vram_displaysurface(ds, width, height,
                                             depth, linesize,
                                             vram_ptr,
                                             vram_offset);
    if (ds->surface)
        ds->surface->flags |= DISPLAYSURFACE_VRAM;
    else
        ds->surface = create_displaysurface(ds, width, height);
    critical_section_leave(&ds->resize_lock);

    dpy_resize(ds);
}

PixelFormat default_pixelformat(int bpp)
{
    PixelFormat pf;

    memset(&pf, 0x00, sizeof(PixelFormat));

    pf.bits_per_pixel = bpp;
    pf.bytes_per_pixel = bpp / 8;
    pf.depth = bpp == 32 ? 24 : bpp;

    switch (bpp) {
        case 15:
            pf.bits_per_pixel = 16;
            pf.bytes_per_pixel = 2;
            pf.rmask = 0x00007c00;
            pf.gmask = 0x000003E0;
            pf.bmask = 0x0000001F;
            pf.rmax = 31;
            pf.gmax = 31;
            pf.bmax = 31;
            pf.rshift = 10;
            pf.gshift = 5;
            pf.bshift = 0;
            pf.rbits = 5;
            pf.gbits = 5;
            pf.bbits = 5;
            break;
        case 16:
            pf.rmask = 0x0000F800;
            pf.gmask = 0x000007E0;
            pf.bmask = 0x0000001F;
            pf.rmax = 31;
            pf.gmax = 63;
            pf.bmax = 31;
            pf.rshift = 11;
            pf.gshift = 5;
            pf.bshift = 0;
            pf.rbits = 5;
            pf.gbits = 6;
            pf.bbits = 5;
            break;
        case 24:
            pf.rmask = 0x00FF0000;
            pf.gmask = 0x0000FF00;
            pf.bmask = 0x000000FF;
            pf.rmax = 255;
            pf.gmax = 255;
            pf.bmax = 255;
            pf.rshift = 16;
            pf.gshift = 8;
            pf.bshift = 0;
            pf.rbits = 8;
            pf.gbits = 8;
            pf.bbits = 8;
        case 32:
            pf.rmask = 0x00FF0000;
            pf.gmask = 0x0000FF00;
            pf.bmask = 0x000000FF;
            pf.amax = 255;
            pf.rmax = 255;
            pf.gmax = 255;
            pf.bmax = 255;
            pf.ashift = 24;
            pf.rshift = 16;
            pf.gshift = 8;
            pf.bshift = 0;
            pf.rbits = 8;
            pf.gbits = 8;
            pf.bbits = 8;
            pf.abits = 8;
            break;
        default:
            break;
    }
    return pf;
}

/*
 * Time to wait in ms between vram event and refresh.
 */
#define REFRESH_TIMEOUT_MS 5
static uxen_notification_event vram_event;
static struct Timer *vram_timer = NULL;

static void refresh(void *opaque)
{
    struct display_state *ds;

    TAILQ_FOREACH(ds, &displays, link)
        dpy_refresh(ds);
}

void do_dpy_trigger_refresh(void *opaque)
{
    uint64_t now = get_clock_ms(vm_clock);

    if (vram_timer)
        mod_timer(vram_timer, now + REFRESH_TIMEOUT_MS);
}

void do_dpy_setup_refresh(void)
{
    vram_timer = new_timer_ms(vm_clock, refresh, NULL);
    mod_timer(vram_timer, get_clock_ms(vm_clock) + REFRESH_TIMEOUT_MS);

    uxen_notification_event_init(&vram_event);
    uxen_notification_add_wait_object(&vram_event, do_dpy_trigger_refresh, NULL);
    uxen_ioemu_event(UXEN_IOEMU_EVENT_VRAM, &vram_event);
}

static struct gui_info *gui_info_list = NULL;
static struct gui_info *gui_info = NULL;

void
gui_register_info(struct gui_info *info)
{
    assert(info->size >= sizeof(struct gui_state));
    assert(!info->next);
    info->next = gui_info_list;
    gui_info_list = info;
}

static void
console_state_save(QEMUFile *f, void *opaque)
{
    qemu_put_be32(f, 0);
    qemu_put_be32(f, 0);
}

static int
console_state_load(QEMUFile *f, void *opaque, int version_id)
{
    if (version_id < 3)
        return -EINVAL;

    (void)qemu_get_be32(f);
    (void)qemu_get_be32(f);

    return 0;
}

int
console_init(const char *name)
{
    int ret = 0;
    char *type;
    char *optstr;
    struct display_state *ds;

    type = strdup(name);
    optstr = strchr(type, ',');
    if (optstr) {
        *optstr = '\0';
        optstr++;
    }

    gui_info = gui_info_list;
    while (gui_info) {
        if (!strcmp(type, gui_info->name))
            break;

        gui_info = gui_info->next;
    }

    if (!gui_info) {
        free(type);
        return -1;
    }

    register_savevm(NULL, "console", 0, 3,
                    console_state_save,
                    console_state_load,
                    NULL);

    if (gui_info->init) {
        ret = gui_info->init(optstr);
        if (ret)
            return ret;
    }

    assert(!TAILQ_EMPTY(&displays));
    TAILQ_FOREACH(ds, &displays, link) {
        ds->gui = calloc(1, gui_info->size);
        if (!ds->gui)
            continue;

        if (gui_info->create)
            gui_info->create(ds->gui, ds);
    }

    free(type);

    return ret;
}

void
console_exit(void)
{
    struct display_state *ds;

    TAILQ_FOREACH(ds, &displays, link) {
        if (gui_info->destroy)
            gui_info->destroy(ds->gui);
        free(ds->gui);
        ds->gui = NULL;
    }

    if (gui_info && gui_info->exit)
        gui_info->exit();
}

void
console_start(void)
{
    if (gui_info && gui_info->start) {
        struct display_state *ds;

        TAILQ_FOREACH(ds, &displays, link)
            gui_info->start(ds->gui);
    }

    do_dpy_setup_refresh();
}

struct display_surface *
create_displaysurface(struct display_state *ds, int width, int height)
{
    if (gui_info && gui_info->create_surface)
        return gui_info->create_surface(ds->gui, width, height);
    return NULL;
}

struct display_surface *
create_vram_displaysurface(struct display_state *ds,
                           int width, int height,
                           int depth, int linesize,
                           void *vram_ptr,
                           unsigned int vram_offset)
{
    if (gui_info && gui_info->create_surface)
        return gui_info->create_vram_surface(ds->gui, width, height,
                                             depth, linesize,
                                             vram_ptr, vram_offset);
    return NULL;
}

void
free_displaysurface(struct display_state *ds, struct display_surface *surface)
{
    if (gui_info && gui_info->free_surface)
        gui_info->free_surface(ds->gui, surface);
}

struct display_surface *
resize_displaysurface(struct display_state *ds, struct display_surface *surface,
                      int width, int height)
{
    if (surface)
	free_displaysurface(ds, surface);

    return create_displaysurface(ds, width, height);
}

#ifdef MONITOR
void
mc_resize_screen(Monitor *mon, const dict args)
{
#if 0
    if (gui_info && gui_info->mon_resize_screen)
        gui_info->mon_resize_screen(gui_state, mon, args);
#endif
}
#endif

void
dpy_vram_change(struct display_state *ds, struct vram_desc *v)
{
    if (gui_info && gui_info->vram_change)
        gui_info->vram_change(ds->gui, v);
}

void
dpy_update(struct display_state *ds, int x, int y, int w, int h)
{
    if (gui_info && gui_info->update)
        gui_info->update(ds->gui, x, y, w, h);
}

void
dpy_resize(struct display_state *ds)
{
    int w = ds_get_width(ds);
    int h = ds_get_height(ds);

    if (gui_info && gui_info->resize)
        gui_info->resize(ds->gui, w, h);
}

void
dpy_refresh(struct display_state *ds)
{
    if (gui_info && gui_info->refresh)
        gui_info->refresh(ds->gui);
}

void
dpy_cursor(struct display_state *ds, int x, int y)
{
    if (gui_info && gui_info->cursor)
        gui_info->cursor(ds->gui, x, y);
}

void
dpy_cursor_shape(struct display_state *ds,
                 int w, int h, int hot_x, int hot_y,
                 uint8_t *mask, uint8_t *color)
{
    if (gui_info && gui_info->cursor_shape)
        gui_info->cursor_shape(ds->gui,
                               w, h, hot_x, hot_y, mask, color);
}

