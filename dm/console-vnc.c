/*
 * Copyright 2016, Bromium, Inc.
 * Author: Christian Limpach <Christian.Limpach@gmail.com>
 * SPDX-License-Identifier: ISC
 */

#include "config.h"

#include <sys/time.h>

#include "console.h"
#include "dm.h"
#include "vm.h"
#include "base64.h"
#include "uxen.h"
#include "vram.h"
#include "bh.h"
#include "input.h"
#include "vnc-keymap.h"

#include <rfb/rfb.h>

static int vnc_argc = 0;
static char **vnc_argv = NULL;
static rfbScreenInfoPtr vnc_screen = NULL;
static char *vnc_buffer = NULL;
static uxen_thread vnc_thread = NULL;

struct vnc_surface
{
    struct display_surface s; /* Must be first */
    uint8_t *data;
    int linesize;
};

struct vnc_gui_state {
    struct gui_state state; /* Must be first */
    int vram_handle;
    void *vram_view;
    size_t vram_len;
    struct vnc_surface *surface;
    struct display_state *ds;
};

static int
vnc_surface_lock(struct display_surface *s, uint8_t **data, int *linesize)
{
    struct vnc_surface *surface = (struct vnc_surface *)s;

    *data = surface->data;
    *linesize = surface->linesize;

    return 0;
}

static void
vnc_surface_unlock(struct display_surface *s)
{
}

static void
vnc_mangle_server_format(rfbScreenInfoPtr screen)
{
    int red_shift = screen->serverFormat.redShift;

    screen->serverFormat.redShift = screen->serverFormat.blueShift;
    screen->serverFormat.blueShift = red_shift;
}

static void
vnc_inject_key(int scancode, int extended, int up)
{
    struct input_event *input_event;
    BH *bh;

    bh = bh_new_with_data(input_event_cb, sizeof(struct input_event),
                          (void **)&input_event);
    if (!bh)
        return;

    input_event->type = KEYBOARD_INPUT_EVENT;
    input_event->keycode = scancode;
    if (up)
        input_event->keycode |= 0x80;
    input_event->extended = extended;

    bh_schedule_one_shot(bh);
}

static void
vnc_update_key_modifiers(uint32_t change, int up)
{
    static uint32_t modifiers = 0;
    uint32_t updated = modifiers;
    int modkey;

    if (change == MODKEY_shift_on) {
        if (!modifiers &
            (MODKEY_flags(MODKEY_LSHIFT) | MODKEY_flags(MODKEY_RSHIFT)))
            modifiers |= MODKEY_LSHIFT;
    } else if (change == MODKEY_shift_off)
        modifiers &= ~(MODKEY_flags(MODKEY_LSHIFT) |
                       MODKEY_flags(MODKEY_RSHIFT));
    else {
        if (up)
            modifiers &= ~MODKEY_flags(change);
        else
            modifiers |= MODKEY_flags(change);
    }
    updated ^= modifiers;

    for (modkey = MODKEY_LSHIFT; modkey <= MODKEY_last; modkey++) {
        if (updated & MODKEY_flags(modkey))
            vnc_inject_key(modifier_map[modkey].scancode,
                           modifier_map[modkey].extended,
                           !(modifiers & MODKEY_flags(modkey)));
    }
    if (updated & MODKEY_flags(MODKEY_CAPSLOCK)) {
        vnc_inject_key(modifier_map[MODKEY_CAPSLOCK].scancode,
                       modifier_map[MODKEY_CAPSLOCK].extended, 0);
        /* Delay release by 100ms otherwise the HID system in OSX locks up */
        // qemu_mod_timer(capslock_timer, os_get_clock_ms() + 100);
    }
}

static void
vnc_key_event(rfbBool down, rfbKeySym key, rfbClientPtr cl)
{
    int scancode = 0, extended, modifier;

    if (key < vnc_keymap00_len) {
        scancode = vnc_keymap00[key].scancode;
        extended = vnc_keymap00[key].extended;
        modifier = vnc_keymap00[key].modifier;
    }
    if ((key & 0xff00) == 0xff00) {
        scancode = vnc_keymapFF[key & 0xff].scancode;
        extended = vnc_keymapFF[key & 0xff].extended;
        modifier = vnc_keymapFF[key & 0xff].modifier;
    }

    if (modifier == MODKEY_RCTRL || modifier == MODKEY_RALT)
        modifier = MODKEY_LCMD;

    if (modifier)
        vnc_update_key_modifiers(modifier, !down);
    if (scancode)
        vnc_inject_key(scancode, extended, !down);
}

static void
vnc_ptr_event(int buttonMask, int x, int y, rfbClientPtr cl)
{
    struct input_event *input_event;
    BH *bh;
    int buttons = 0;
    static int last_mouse_x = 0;
    static int last_mouse_y = 0;

    if (input_mouse_is_absolute()) {
        last_mouse_x = x;
        last_mouse_y = y;
        x = x * 0x7fff / (cl->screen->width - 1);
        y = y * 0x7fff / (cl->screen->height - 1);
    } else {
        int dx, dy;
        dx = x - last_mouse_x;
        dy = y - last_mouse_y;
        last_mouse_x = x;
        last_mouse_y = y;
        x = dx;
        y = dy;
    }

    if (buttonMask & rfbButton1Mask)
        buttons |= MOUSE_EVENT_LBUTTON;
    if (buttonMask & rfbButton2Mask)
        buttons |= MOUSE_EVENT_MBUTTON;
    if (buttonMask & rfbButton3Mask)
        buttons |= MOUSE_EVENT_RBUTTON;

    bh = bh_new_with_data(input_event_cb, sizeof(struct input_event),
                          (void **)&input_event);
    if (!bh)
        return;

    input_event->type = MOUSE_INPUT_EVENT;
    input_event->x = x;
    input_event->y = y;
    input_event->dz = 0 /* dz */;
    input_event->button_state = buttons;

    bh_schedule_one_shot(bh);
}

#if defined(_WIN32)
static DWORD WINAPI
vnc_run(void *opaque)
#elif defined(__APPLE__)
static void *
vnc_run(void *opaque)
#else
#error "vnc_run: unknown arch"
#endif
{

    setcancel_thread();

    for (;;)
        rfbProcessEvents(vnc_screen, -1);

    return 0;
}

static struct vnc_surface *
vnc_create_surface(struct vnc_gui_state *s,
                   int width, int height, void *data)
{
    struct vnc_surface *surface;
    int ret;

    surface = calloc(1, sizeof(struct vnc_surface));
    if (surface == NULL)
        err(1, "%s: calloc", __FUNCTION__);

    surface->s.width = width;
    surface->s.height = height;

    surface->s.pf = default_pixelformat(32);

    surface->s.lock = vnc_surface_lock;
    surface->s.unlock = vnc_surface_unlock;

    surface->linesize = width * 4;
    surface->data = data;

    s->surface = surface;

    if (!vnc_screen || !vnc_buffer) {
        if (!vnc_screen) {
            vnc_screen = rfbGetScreen(&vnc_argc, vnc_argv,
                                      width, height, 8, 3, 4);
            if (!vnc_screen)
                errx(1, "rfbGetScreen failed");
            vnc_screen->mangleServerFormatHook = vnc_mangle_server_format;
            vnc_mangle_server_format(vnc_screen);
            vnc_screen->kbdAddEvent = vnc_key_event;
            vnc_screen->ptrAddEvent = vnc_ptr_event;
            vnc_screen->desktopName = vm_name;
        }
        vnc_screen->frameBuffer = data;
        rfbInitServer(vnc_screen);
        if (!vnc_thread) {
            ret = create_thread(&vnc_thread, vnc_run, NULL);
            if (ret)
                errx(1, "create_thread(vnc_thread) failed");
        }
    } else {
        rfbNewFramebuffer(vnc_screen, data, width, height, 8, 3, 4);
        free(vnc_buffer);
        vnc_buffer = NULL;
    }

    return surface;
}

static struct display_surface *
create_surface(struct gui_state *state, int width, int height)
{
    struct vnc_gui_state *s = (struct vnc_gui_state *)state;
    void *data;
    struct vnc_surface *surface;

    data = calloc(1, width * height * 4);
    if (!data)
        err(1, "%s: calloc failed", __FUNCTION__);

    surface = vnc_create_surface(s, width, height, data);

    return &surface->s;
}

static struct display_surface *
create_vram_surface(struct gui_state *state,
                    int width, int height,
                    int depth, int linesize,
                    void *vram_ptr,
                    unsigned int vram_offset)
{
    struct vnc_gui_state *s = (struct vnc_gui_state *)state;
    struct vnc_surface *surface;
    uint8_t *data;

    if (vram_ptr != s->vram_view ||
        depth != 32 ||
        linesize != (width * 4))
        return NULL;

    data = (uint8_t *)vram_ptr + vram_offset;
    surface = vnc_create_surface(s, width, height, data);

    return &surface->s;
}

static void
free_surface(struct gui_state *state, struct display_surface *surface)
{
    struct vnc_gui_state *s = (struct vnc_gui_state *)state;
    struct vnc_surface *surf = (struct vnc_surface *)surface;
    int width = s->state.width;
    int height = s->state.height;

    s->surface = NULL;

    if (!vnc_buffer) {
        if (surf->data) {
            vnc_buffer = malloc(height * width * 4);
            if (vnc_buffer) {
                memcpy(vnc_buffer, surf->data, height * width * 4);
                rfbNewFramebuffer(vnc_screen, vnc_buffer, width, height,
                                  8, 3, 4);
            }
        }
        if (!vnc_buffer)
            rfbShutdownServer(vnc_screen, 0);
    }

    if (!(surf->s.flags & DISPLAYSURFACE_VRAM))
        free(surf->data);
    free(surf);
}

static void
vnc_update(struct gui_state *state, int x, int y, int w, int h)
{
    struct vnc_gui_state *s = (struct vnc_gui_state *)state;

    if (vnc_screen && s->surface)
        rfbMarkRectAsModified(vnc_screen, x, y, x + w, y + h);
}

static void
vnc_resize(struct gui_state *state, int w, int h)
{
    struct vnc_gui_state *s = (struct vnc_gui_state *)state;

    rfbNewFramebuffer(vnc_screen, (char *)s->surface->data,
                      w, h, 8, 3, 4);
}

static void
vnc_refresh(struct gui_state *state)
{
    struct vnc_gui_state *s = (struct vnc_gui_state *)state;

    vga_hw_update(s->ds);
}

static rfbCursorPtr
vnc_create_cursor(uint8_t *colour, uint8_t *mask,
                  int w, int h, int hot_x, int hot_y)
{
    rfbCursorPtr cursor = NULL;
    unsigned char *xdata = calloc(w, h);
    unsigned char *data = calloc(w * 4, h);
    int i;
    int j, stride = (w + 7) / 8;

    if (!data)
        return NULL;

    memset(data, ' ', w * h);
    cursor = rfbMakeXCursor(w, h, (char *)data, (char *)data);
    if (!cursor)
        goto out;

    if (colour)
        memcpy(data, colour, w * 4 *h);
    else {
        int set = 0, unset = 0;
        /* the mono cursor is hiding behind ... not a cursor */
        mask += h * stride;
        for (j = 0; j < h; j++)
            for (i = 0; i < w; i++) {
                if (mask[j * stride + i / 8] & (1 << (7 - (i & 7)))) {
                    *(uint32_t *)&data[(j * w + i) * 4] = 0;
                    set++;
                }
                else
                {
                    *(uint32_t *)&data[(j * w + i) * 4] = 0xffffffff;
                    unset++;
                }
            }
    }

    for (i = 0; i < w * h; i++)
        xdata[i] = data[i * 4 + 3];

    cursor->richSource = data;
    cursor->cleanupRichSource = FALSE;
    cursor->alphaSource = xdata;
    xdata = NULL;
    for (j = 0; j < h; j++)
        for (i = 0; i < w; i++) {
            /* colour mask is inverted */
            if ((colour ? ~mask[j * stride + i / 8] :
                 mask[j * stride + i / 8]) & (1 << (7 - (i & 7))))
                cursor->mask[j * stride + i / 8] |= 1 << (7 - (i & 7));
            else
                cursor->mask[j * stride + i / 8] &= ~(1 << (7 - (i & 7)));
        }
    cursor->xhot = hot_x;
    cursor->yhot = hot_y;

  out:
    if (!cursor)
        free(data);
    free(xdata);
    return cursor;
}

static void
vnc_cursor_shape(struct gui_state *state,
                 int w, int h,
                 int hot_x, int hot_y,
                 uint8_t *mask, uint8_t *colour)
{
    rfbCursorPtr cursor = NULL;
    uint8_t hidden_cursor[] = { 0x0 };

    if (w == 0 || h == 0) {
        w = 1;
        h = 1;
        mask = hidden_cursor;
        colour = NULL;
    }

    /* Sanity check */
    if (w > 128 || w < 0 || h > 128 || h < 0 ||
        hot_x >= w || hot_y >= h)
        return;

    cursor = vnc_create_cursor(colour, mask, w, h, hot_x, hot_y);
    if (cursor) {
        rfbCursorPtr old_cursor = vnc_screen->cursor;
        if (old_cursor)
            old_cursor->cleanup = FALSE;
        rfbSetCursor(vnc_screen, cursor);
        if (old_cursor) {
            if (!old_cursor->cleanupRichSource) {
                free(old_cursor->alphaSource);
                old_cursor->alphaSource = NULL;
                free(old_cursor->richSource);
                old_cursor->richSource = NULL;
            }
            rfbFreeCursor(old_cursor);
        }
    }
}

static int
gui_init(char *optstr)
{
    char *c;
    char sep;

    if (!optstr || !optstr[0])
        return 0;

    sep = optstr[0];
    optstr++;

    vnc_argc = 0;
    c = optstr;
    while (*c && (c = strchr(c, sep))) {
        vnc_argc++;
        c++;
    }
    vnc_argc++;

    vnc_argv = calloc(vnc_argc + 1, sizeof(char *));
    if (!vnc_argv)
        err(1, "calloc");

    vnc_argc = 0;
    vnc_argv[vnc_argc++] = "uxendm";
    while (*optstr && (c = strchr(optstr, sep))) {
        *c = 0;
        vnc_argv[vnc_argc++] = strdup(optstr);
        optstr = c + 1;
    }
    if (*optstr)
        vnc_argv[vnc_argc++] = strdup(optstr);

    return 0;
}

static void
gui_exit(void)
{

    if (vnc_thread) {
        cancel_thread(vnc_thread);
        wait_thread(vnc_thread);
        close_thread_handle(vnc_thread);
        vnc_thread = NULL;
    }
    if (vnc_screen) {
        rfbScreenCleanup(vnc_screen);
        vnc_screen = NULL;
        if (vnc_buffer) {
            free(vnc_buffer);
            vnc_buffer = NULL;
        }
    }
}

static int
gui_create(struct gui_state *state, struct display_state *ds)
{
    struct vnc_gui_state *s = (struct vnc_gui_state *)state;

    s->ds = ds;
    s->vram_handle = -1;
    s->vram_view = NULL;
    s->vram_len = 0;
    s->state.width = 640;
    s->state.height = 480;

    return 0;
}

static void
gui_destroy(struct gui_state *state)
{

    gui_exit();
}

static void
gui_start(struct gui_state *state)
{
}

static void
vram_changed(struct gui_state *state, struct vram_desc *v)
{
    struct vnc_gui_state *s = (struct vnc_gui_state *)state;
    int width = s->state.width;
    int height = s->state.height;

    if (vnc_screen && !vnc_buffer) {
        if (s->surface && s->surface->data) {
            vnc_buffer = malloc(height * width * 4);
            if (vnc_buffer) {
                memcpy(vnc_buffer, s->surface->data, height * width * 4);
                rfbNewFramebuffer(vnc_screen, vnc_buffer, width, height,
                                  8, 3, 4);
            }
        }
        if (!vnc_buffer)
            rfbShutdownServer(vnc_screen, 0);
    }

    s->vram_view = v->view;
    s->vram_handle = (int)v->hdl;
    s->vram_len = v->shm_len;

    do_dpy_trigger_refresh(NULL);
}

static struct gui_info vnc_gui_info = {
    .name = "vnc",
    .size = sizeof(struct vnc_gui_state),
    .init = gui_init,
    .start = gui_start,
    .exit = gui_exit,
    .create = gui_create,
    .destroy = gui_destroy,
    .create_surface = create_surface,
    .create_vram_surface = create_vram_surface,
    .free_surface = free_surface,
    .vram_change = vram_changed,
    .update = vnc_update,
    .resize = vnc_resize,
    .refresh = vnc_refresh,
    .cursor_shape = vnc_cursor_shape,
};

console_gui_register(vnc_gui_info)
