/*
 * Copyright 2012-2018, Bromium, Inc.
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

int desktop_width, desktop_height;

static struct display_list desktop;
static critical_section desktop_lock;
static struct gui_info *gui_info_list = NULL;
static struct gui_info *gui_info = NULL;


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

static void desktop_refresh(void)
{
    struct display_state *ds;
    int max_x = 0;
    int max_y = 0;

    /* desktop_lock is taken */
    TAILQ_FOREACH(ds, &desktop, link) {
        if (!ds->surface)
            continue;
        if (ds->desktop_x + ds->surface->width > max_x)
            max_x = ds->desktop_x + ds->surface->width;
        if (ds->desktop_y + ds->surface->height > max_y)
            max_y = ds->desktop_y + ds->surface->height;
    }
    desktop_width = max_x;
    desktop_height = max_y;

    debug_printf("desktop resize %dx%d\n", max_x, max_y);
}

struct display_state *display_create(struct console_hw_ops *ops, void *opaque,
                                     enum DisplayCreateFlags flags)
{
    struct display_state *ds;

    ds = (struct display_state *)calloc(1, sizeof(struct display_state));
    if (!ds)
        errx(1, "%s: alloc struct display_state failed", __FUNCTION__);


    critical_section_init(&ds->resize_lock);
    ds->hw_ops = ops;
    ds->hw = opaque;

    critical_section_enter(&desktop_lock);
    desktop_refresh();
    ds->desktop_x = desktop_width;
    ds->desktop_y = 0;

    if (gui_info && gui_info->create && !ds->gui) {
        ds->gui = calloc(1, gui_info->size);
        if (ds->gui) {
            gui_info->create(ds->gui, ds);
            if (gui_info->start && (flags & DCF_START_GUI))
                gui_info->start(ds->gui);
        }
    }

    TAILQ_INSERT_TAIL(&desktop, ds, link);
    critical_section_leave(&desktop_lock);

    return ds;
}

void display_destroy(struct display_state *ds)
{
    critical_section_enter(&desktop_lock);
    if (ds->surface) {
        free_displaysurface(ds, ds->surface);
        ds->surface = NULL;
    }
    if (ds->gui && gui_info && gui_info->destroy) {
        gui_info->destroy(ds->gui);
        free(ds->gui);
        ds->gui = NULL;
    }
    TAILQ_REMOVE(&desktop, ds, link);
    desktop_refresh();
    critical_section_leave(&desktop_lock);

    free(ds);
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

void display_move(struct display_state *ds, int desktop_x, int desktop_y)
{
    critical_section_enter(&desktop_lock);
    ds->desktop_x = desktop_x;
    ds->desktop_y = desktop_y;
    desktop_refresh();
    critical_section_leave(&desktop_lock);

}

void display_resize(struct display_state *ds, int width, int height)
{
    critical_section_enter(&desktop_lock);
    critical_section_enter(&ds->resize_lock);
    ds->surface = resize_displaysurface(ds, ds->surface, width, height);
    critical_section_leave(&ds->resize_lock);
    desktop_refresh();
    critical_section_leave(&desktop_lock);
    dpy_resize(ds);
}

void display_resize_from(struct display_state *ds, int width, int height,
                         int depth, int linesize,
                         void *vram_ptr,
                         unsigned int vram_offset)
{
    critical_section_enter(&desktop_lock);
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

    desktop_refresh();
    critical_section_leave(&desktop_lock);
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

/* Time to wait in ms between vram event and refresh. */
uint64_t vm_vram_refresh_delay = 5;
/* Period between refreshes, when vm-dirty-tracking is disabled. */
uint64_t vm_vram_refresh_period = 30;
static int vram_refresh_periodic = 0;
uxen_notification_event vram_event;

static struct Timer *vram_timer = NULL;

static void refresh(void *opaque)
{
    struct display_state *ds;

    if (vram_timer && vram_refresh_periodic)
        mod_timer(vram_timer, get_clock_ms(vm_clock) + vm_vram_refresh_period);

    critical_section_enter(&desktop_lock);
    TAILQ_FOREACH(ds, &desktop, link)
        dpy_refresh(ds);
    critical_section_leave(&desktop_lock);
}

void do_dpy_trigger_refresh(void *opaque)
{
    uint64_t now = get_clock_ms(vm_clock);

    /* do not delay updates infinitely */
    if (vram_timer && !timer_pending(vram_timer))
        mod_timer(vram_timer, now + vm_vram_refresh_delay);
}

void do_dpy_setup_refresh(void)
{
    vram_timer = new_timer_ms(vm_clock, refresh, NULL);
    if (!vm_vram_dirty_tracking) {
        /* setup periodic refresh */
        vram_refresh_periodic = 1;
        mod_timer(vram_timer, get_clock_ms(vm_clock) + vm_vram_refresh_period);
    }

    uxen_notification_event_init(&vram_event);
    uxen_notification_add_wait_object(&vram_event, do_dpy_trigger_refresh, NULL,
                                      NULL);
    uxen_ioemu_event(UXEN_IOEMU_EVENT_VRAM, &vram_event);

    /* initial refresh */
    refresh(NULL);
}

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

    free(type);

    return ret;
}

void
console_exit(void)
{
    struct display_state *ds, *ds_next;

    critical_section_enter(&desktop_lock);
    TAILQ_FOREACH_SAFE(ds, &desktop, link, ds_next) {
        if (ds->surface) {
            free_displaysurface(ds, ds->surface);
            ds->surface = NULL;
        }
        if (ds->gui && gui_info && gui_info->destroy) {
            gui_info->destroy(ds->gui);
            free(ds->gui);
            ds->gui = NULL;
        }
        TAILQ_REMOVE(&desktop, ds, link);
    }
    desktop_refresh();
    critical_section_leave(&desktop_lock);

    if (gui_info && gui_info->exit)
        gui_info->exit();
}

void
console_start(void)
{
    struct display_state *ds;

    critical_section_enter(&desktop_lock);
    assert(!TAILQ_EMPTY(&desktop));
    TAILQ_FOREACH(ds, &desktop, link) {
        if (!ds->gui)
            continue;
        if (gui_info->start)
            gui_info->start(ds->gui);
    }
    critical_section_leave(&desktop_lock);

    do_dpy_setup_refresh();
}

void
console_mask_periodic(int masked)
{
    int enable = !vm_vram_dirty_tracking && !masked;

    vram_refresh_periodic = enable;
    if (vram_timer && !timer_pending(vram_timer))
        mod_timer(vram_timer, get_clock_ms(vm_clock) + 5 /* MS */);
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
dpy_desktop_update(int x, int y, int w, int h)
{
    struct display_state *ds;

    critical_section_enter(&desktop_lock);
    TAILQ_FOREACH(ds, &desktop, link) {
        int x1 = x - ds->desktop_x;
        int y1 = y - ds->desktop_y;
        int x2 = (x + w) - ds->desktop_x;
        int y2 = (y + h) - ds->desktop_y;

        if (!ds->surface)
            continue;

        /* Overlap check */
        if (x1 > ds->surface->width ||
            x2 <= 0 ||
            y1 > ds->surface->height ||
            y2 <= 0)
            continue;

        /* trim to current display size */
        if (x1 < 0)
            x1 = 0;
        if (x2 > ds->surface->width)
            x2 = ds->surface->width;
        if (y1 < 0)
            y1 = 0;
        if (y2 > ds->surface->height)
            y2 = ds->surface->height;

        if (x2 > x1 && y2 > y1)
            dpy_update(ds, x1, y1, x2 - x1, y2 - y1);
    }
    critical_section_leave(&desktop_lock);
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

initcall(desktop_init)
{
    TAILQ_INIT(&desktop);
    desktop_width = desktop_height = 0;
    critical_section_init(&desktop_lock);
}

