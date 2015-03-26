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

DisplayState *display_state;

uint32_t forwarded_keys = 0;

struct Console {
    DisplayState *ds;
    /* Graphic console state.  */
    vga_hw_update_ptr hw_update;
    vga_hw_invalidate_ptr hw_invalidate;
    vga_hw_text_update_ptr hw_text_update;
    void *hw;

    int g_width, g_height;
};

static struct Console *active_console;

void vga_hw_update(void)
{
    if (active_console && active_console->hw_update)
        active_console->hw_update(active_console->hw);
}

void vga_hw_invalidate(void)
{
    if (active_console && active_console->hw_invalidate)
        active_console->hw_invalidate(active_console->hw);
}


DisplayState *graphic_console_init(vga_hw_update_ptr update,
                                   vga_hw_invalidate_ptr invalidate,
                                   vga_hw_text_update_ptr text_update,
                                   void *opaque)
{
    struct Console *s;
    DisplayState *ds;

    ds = (DisplayState *)calloc(1, sizeof(DisplayState));
    if (!ds)
        errx(1, "%s: alloc DisplayState failed", __FUNCTION__);
    critical_section_init(&ds->resize_lock);

    s = (struct Console *)calloc(1, sizeof(struct Console));
    if (!s)
        errx(1, "%s: alloc Console failed", __FUNCTION__);
    active_console = s;
    s->ds = ds;

    s->hw_update = update;
    s->hw_invalidate = invalidate;
    s->hw_text_update = text_update;
    s->hw = opaque;

    display_state = ds;

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

void console_resize(DisplayState *ds, int width, int height)
{
    struct Console *s = active_console;

    if (!s)
        return;

    s->g_width = width;
    s->g_height = height;

    critical_section_enter(&ds->resize_lock);
    ds->surface = resize_displaysurface(ds->surface, width, height);
    critical_section_leave(&ds->resize_lock);
    dpy_resize(ds);
}

void console_resize_from(DisplayState *ds, int width, int height,
                         int depth, int linesize,
                         void *vram_ptr,
                         unsigned int vram_offset)
{
    struct Console *s = active_console;

    if (!s)
        return;

    s->g_width = width;
    s->g_height = height;

    critical_section_enter(&ds->resize_lock);
    if (ds->surface)
        free_displaysurface(ds->surface);
    ds->surface = create_vram_displaysurface(width, height,
                                             depth, linesize,
                                             vram_ptr,
                                             vram_offset);
    if (ds->surface)
        ds->surface->flags |= DISPLAYSURFACE_VRAM;
    else
        ds->surface = create_displaysurface(width, height);
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

static void refresh(void *opaque)
{
    DisplayState *ds = (DisplayState *)opaque;

    dpy_refresh(ds);
}

void do_dpy_trigger_refresh(void *opaque)
{
    DisplayState *ds = (DisplayState *)opaque;
    uint64_t now = get_clock_ms(vm_clock);

    mod_timer(ds->gui_timer, now + REFRESH_TIMEOUT_MS);
}

void do_dpy_setup_refresh(DisplayState *ds)
{
    ds->gui_timer = new_timer_ms(vm_clock, refresh, ds);
    mod_timer(ds->gui_timer, get_clock_ms(vm_clock) + REFRESH_TIMEOUT_MS);

    uxen_notification_event_init(&vram_event);
    uxen_notification_add_wait_object(&vram_event, do_dpy_trigger_refresh, ds);
    uxen_ioemu_event(UXEN_IOEMU_EVENT_VRAM, &vram_event);
}

static struct gui_info *gui_info_list = NULL;
static struct gui_info *gui_info = NULL;
static struct gui_state *gui_state = NULL;

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
    qemu_put_be32(f, gui_state->width);
    qemu_put_be32(f, gui_state->height);
}

static int
console_state_load(QEMUFile *f, void *opaque, int version_id)
{
    if (version_id < 3)
        return -EINVAL;

    gui_state->width = qemu_get_be32(f);
    gui_state->height = qemu_get_be32(f);

    return 0;
}

int
console_display_init(const char *name)
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

    gui_state = calloc(1, gui_info->size);
    if (!gui_state) {
        free(type);
        return -1;
    }

    if (gui_info->init)
        ret = gui_info->init(gui_state, optstr);

    free(type);

    return ret;
}

void
console_display_exit(void)
{
    if (gui_info && gui_info->exit)
        gui_info->exit(gui_state);

    if (gui_state)
        free(gui_state);
}

void
console_display_start(void)
{
    if (gui_info && gui_info->start)
        gui_info->start(gui_state);
    do_dpy_setup_refresh(display_state);
}

DisplaySurface *
create_displaysurface(int width, int height)
{
    if (gui_info && gui_info->create_surface)
        return gui_info->create_surface(gui_state, width, height);
    return NULL;
}

DisplaySurface *
create_vram_displaysurface(int width, int height,
                           int depth, int linesize,
                           void *vram_ptr,
                           unsigned int vram_offset)
{
    if (gui_info && gui_info->create_surface)
        return gui_info->create_vram_surface(gui_state, width, height,
                                             depth, linesize,
                                             vram_ptr, vram_offset);
    return NULL;
}

void
free_displaysurface(DisplaySurface *surface)
{
    if (gui_info && gui_info->free_surface)
        gui_info->free_surface(gui_state, surface);
}

DisplaySurface *
resize_displaysurface(DisplaySurface *surface, int width, int height)
{
    if (surface)
	free_displaysurface(surface);

    return create_displaysurface(width, height);
}

#ifdef MONITOR
void
mc_resize_screen(Monitor *mon, const dict args)
{
    if (gui_info && gui_info->mon_resize_screen)
        gui_info->mon_resize_screen(gui_state, mon, args);
}
#endif

void
dpy_vram_change(struct DisplayState *ds, struct vram_desc *v)
{
    if (gui_info && gui_info->vram_change)
        gui_info->vram_change(gui_state, v);
}

void
dpy_update(struct DisplayState *ds, int x, int y, int w, int h)
{
    if (gui_info && gui_info->display_update)
        gui_info->display_update(gui_state, x, y, w, h);
}

void
dpy_resize(struct DisplayState *ds)
{
    int w = ds_get_width(ds);
    int h = ds_get_height(ds);

    if (gui_info && gui_info->display_resize)
        gui_info->display_resize(gui_state, w, h);
}

void
dpy_refresh(struct DisplayState *s)
{
    if (gui_info && gui_info->display_refresh)
        gui_info->display_refresh(gui_state);
}

void
dpy_cursor(struct DisplayState *s, int x, int y)
{
    if (gui_info && gui_info->display_cursor)
        gui_info->display_cursor(gui_state, x, y);
}

void
dpy_cursor_shape(struct DisplayState *s,
                 int w, int h, int hot_x, int hot_y,
                 uint8_t *mask, uint8_t *color)
{
    if (gui_info && gui_info->display_cursor_shape)
        gui_info->display_cursor_shape(gui_state,
                                       w, h, hot_x, hot_y, mask, color);
}

