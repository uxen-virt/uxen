/*
 * Copyright 2014-2017, Bromium, Inc.
 * Author: Julian Pidancet <julian@pidancet.net>
 * SPDX-License-Identifier: ISC
 */

#include "config.h"

#include "console.h"
#include "dm.h"
#include "vm.h"
#include "uxen.h"
#include "vram.h"
#include "guest-agent.h"

#include "qemu_glue.h"

#ifdef NOTIFY_CLIPBOARD_SERVICE
#include "vbox-drivers/shared-clipboard/notify.h"
#include "vbox-drivers/shared-clipboard/clipboard-interface.h"
#endif

#include <xenctrl.h>

#include <limits.h>
#if defined(__APPLE__)
#include <sys/mman.h> // mmap
#endif

#include "ipc.h"

/* uxenconsolelib */
#include "uxenconsolelib.h"
#include "console-rpc.h"


//#define DEBUG_CONSOLE

#ifdef DEBUG_CONSOLE
#define DPRINTF(fmt, ...) debug_printf(fmt, ## __VA_ARGS__)
#else
#define DPRINTF(fmt, ...) do {} while (0)
#endif

#if defined(_WIN32)
typedef HANDLE file_handle_t;
#elif defined(__APPLE__)
typedef int file_handle_t;
#endif

#define MAX_MSG_LEN 512

struct console_client
{
    struct ipc_client client;
    uint8_t buf[MAX_MSG_LEN];
    size_t msg_len;
};

static struct ipc_service console_svc;

struct remote_surface
{
    struct display_surface s;
    uint8_t *data;
    int linesize;
    file_handle_t segment_handle;
    uint8_t *segment_view;
    size_t len;
};

enum {
    CURSOR_TYPE_HIDDEN = 0,
    CURSOR_TYPE_MONOCHROME = 1,
    CURSOR_TYPE_RGB_MASK = 2,
    CURSOR_TYPE_RGB_ALPHA = 3,
};

struct remote_gui_state {
    struct gui_state state; /* Must be first */
    TAILQ_ENTRY(remote_gui_state) link;
    struct display_state *ds;
    struct remote_surface *surface;
    file_handle_t vram_handle;
    void *vram_view;
    size_t vram_len;
    uint8_t *cursor_view;
    file_handle_t cursor_handle;
    size_t cursor_len;
    size_t cursor_mask_offset;
    int cursor_width;
    int cursor_height;
    int cursor_hot_x;
    int cursor_hot_y;
    int cursor_type;
    int generation_id;
    uint8_t *msgbuf;
    size_t msgbuf_len;
    size_t msg_len;
    int mouse_x, mouse_y;
};
static TAILQ_HEAD(, remote_gui_state) heads;

static void gui_resize(struct gui_state *state, int w, int h);

static void
handle_message(struct uxenconsole_msg_header *hdr)
{
    struct remote_gui_state *s = TAILQ_FIRST(&heads); /* XXX */

    if (!s) {
        warn("%s: State is NULL. Someone is sending us messages before console start.", __FUNCTION__);
        return;
    }

    switch (hdr->type) {
    case UXENCONSOLE_MSG_TYPE_MOUSE_EVENT:
        {
            struct uxenconsole_msg_mouse_event *msg = (void *)hdr;

#ifdef NOTIFY_CLIPBOARD_SERVICE
            /* msg->flags match windows mouse event format */
            input_notify_clipboard_about_click(msg->flags);
#endif

#if !defined(__APPLE__)
            if (guest_agent_mouse_event(msg->x, msg->y, msg->dv, msg->dh,
                                        msg->flags))
#endif /* !__APPLE */
            {
                struct input_event *input_event;
                BH *bh;

                bh = bh_new_with_data(input_event_cb, sizeof(struct input_event),
                                      (void **)&input_event);
                if (!bh)
                    return;

                input_event->type = MOUSE_INPUT_EVENT;
                if (input_mouse_is_absolute()) {
                    input_event->x = (int)msg->x * 0x7fff / (s->state.width - 1);
                    input_event->y = (int)msg->y * 0x7fff / (s->state.height - 1);
                } else {
                    input_event->x = msg->x - s->mouse_x;
                    input_event->y = msg->y - s->mouse_y;
                }
                input_event->dz = (msg->dv < 0) ? 1 : ((msg->dv > 0) ? -1 : 0);
                input_event->button_state = 0;
                if (msg->flags & MOUSE_EVENT_FLAG_LBUTTON_DOWN)
                    input_event->button_state |= MOUSE_EVENT_LBUTTON;
                if (msg->flags & MOUSE_EVENT_FLAG_RBUTTON_DOWN)
                    input_event->button_state |= MOUSE_EVENT_RBUTTON;
                if (msg->flags & MOUSE_EVENT_FLAG_MBUTTON_DOWN)
                    input_event->button_state |= MOUSE_EVENT_MBUTTON;

                s->mouse_x = msg->x;
                s->mouse_y = msg->y;

                bh_schedule_one_shot(bh);
            }
        }
        break;
    case UXENCONSOLE_MSG_TYPE_KEYBOARD_EVENT:
        {
            struct uxenconsole_msg_keyboard_event *msg = (void *)hdr;
            int nchars = msg->charslen;
            int nchars_bare = msg->chars_bare_len;

#ifdef NOTIFY_CLIPBOARD_SERVICE
            input_notify_clipboard_about_keypress(msg->scancode);
#endif

            if (msg->flags & KEYBOARD_EVENT_FLAG_UCS2) {
                nchars /= 2;
                nchars_bare /= 2;
            }

#if !defined(__APPLE__)
            if (guest_agent_kbd_event(msg->keycode, msg->repeat, msg->scancode,
                                      msg->flags & 0xffff, nchars,
                                      (wchar_t *)msg->chars, nchars_bare,
                                      (wchar_t *)msg->chars_bare))
#endif /* !__APPLE */
            {
                struct input_event *input_event;
                BH *bh;

                bh = bh_new_with_data(input_event_cb, sizeof(*input_event),
                                      (void **)&input_event);
                if (!bh)
                    return;

                input_event->type = KEYBOARD_INPUT_EVENT;
                input_event->extended = msg->flags &
                                         KEYBOARD_EVENT_FLAG_EXTENDED;
                input_event->keycode = msg->scancode;

                bh_schedule_one_shot(bh);
            }
        }
        break;
    case UXENCONSOLE_MSG_TYPE_REQUEST_RESIZE:
        {
#if !defined(__APPLE__)
            struct uxenconsole_msg_request_resize *msg = (void *)hdr;

            if (guest_agent_window_event(0, 0x0005 /* WM_SIZE */, msg->flags,
                                         ((msg->height & 0xffff) << 16) |
                                         (msg->width & 0xffff)))
#endif /* !__APPLE */
            {
                /* Cancel request by sending a resize message immediately */
                gui_resize(&s->state, s->state.width, s->state.height);
            }
        }
        break;
    case UXENCONSOLE_MSG_TYPE_CLIPBOARD_PERMIT:
        {
#ifdef NOTIFY_CLIPBOARD_SERVICE
            struct uxenconsole_msg_clipboard_permit *msg = (void *)hdr;

            if (msg->permit_type & CLIPBOARD_PERMIT_COPY)
                uxen_clipboard_allow_copy_access();
            if (msg->permit_type & CLIPBOARD_PERMIT_PASTE)
                uxen_clipboard_allow_paste_access();
#endif
        }
        break;
    case UXENCONSOLE_MSG_TYPE_TOUCH_DEVICE_HOTPLUG:
        {
#if !defined(__APPLE__)
            struct uxenconsole_msg_touch_device_hotplug *msg = (void *)hdr;
            void hotplug_touch_devices(int plug);

            hotplug_touch_devices(msg->plug);
#endif
        }
        break;
    case UXENCONSOLE_MSG_TYPE_SET_SHARED_SURFACE:
        {
#if !defined(__APPLE__)
            struct uxenconsole_msg_set_shared_surface *msg = (void *)hdr;
            struct ipc_client *c;
            TAILQ_FOREACH(c, &console_svc.clients, link)
                ipc_client_send(c, msg, sizeof(*msg));
#endif
        }
        break;
    default:
        break;
    }
}

static void
ledstate_update(struct ipc_client *c, int state)
{
    struct uxenconsole_msg_keyboard_ledstate m;

    m.header.type = UXENCONSOLE_MSG_TYPE_KEYBOARD_LEDSTATE;
    m.header.len = sizeof(m);
    m.state = state;

    ipc_client_send(c, &m, sizeof(m));
}

static int
console_connect(struct ipc_client *c, void *opaque)
{
    struct remote_gui_state *s;
    struct console_client *client = (void *)c;

    DPRINTF("%s connection detected\n", __FUNCTION__);

    client->msg_len = 0;

    TAILQ_FOREACH(s, &heads, link) {
        if (s->surface) {
            struct uxenconsole_msg_resize_surface m;

            m.header.type = UXENCONSOLE_MSG_TYPE_RESIZE_SURFACE;
            m.header.len = sizeof(m);
            m.width = s->state.width;
            m.height = s->state.height;
            m.linesize = s->surface->linesize;
            m.length = s->surface->len;
            m.bpp = 32;
            m.offset = s->surface->data - s->surface->segment_view;
            m.shm_handle = ipc_client_share(c, (uintptr_t)s->surface->segment_handle);

            ipc_client_send(c, &m, sizeof(m));
        }

        if (s->cursor_type) {
            struct uxenconsole_msg_update_cursor m;

            memset(&m, 0, sizeof(m));

            m.header.type = UXENCONSOLE_MSG_TYPE_UPDATE_CURSOR;
            m.header.len = sizeof(m);

            if (s->cursor_width == 0 || s->cursor_height == 0) {
                m.flags = CURSOR_UPDATE_FLAG_HIDE;
                ipc_client_send(c, &m, sizeof(m));
            } else {
                m.w = s->cursor_width;
                m.h = s->cursor_height;
                m.hot_x = s->cursor_hot_x;
                m.hot_y = s->cursor_hot_y;
                if (s->cursor_type != CURSOR_TYPE_RGB_ALPHA)
                    m.mask_offset = s->cursor_mask_offset;
                if (s->cursor_type == CURSOR_TYPE_MONOCHROME)
                    m.flags = CURSOR_UPDATE_FLAG_MONOCHROME;
                m.shm_handle = ipc_client_share(c, (uintptr_t)s->cursor_handle);
                ipc_client_send(c, &m, sizeof(m));
            }
        }
    }

    ledstate_update(c, input_get_kbd_ledstate());

    return 0;
}

static void
console_disconnect(struct ipc_client *c, void *opaque)
{
    ipc_client_close(c);
}

static void
console_data_pending(struct ipc_client *c, void *opaque)
{
    struct console_client *client = (void *)c;
    struct uxenconsole_msg_header *hdr = (void *)client->buf;
    const size_t hdrlen = sizeof(*hdr);
    int rc;

    if (client->msg_len < hdrlen) {
        rc = ipc_client_recv(c, client->buf + client->msg_len,
                             hdrlen - client->msg_len);
        if (rc > 0)
            client->msg_len += rc;
    } else {
        if (hdr->len < hdrlen || hdr->len > sizeof (client->buf)) {
            ipc_client_close(c);
            return;
        }
        rc = ipc_client_recv(c, client->buf + client->msg_len, hdr->len - client->msg_len);
        if (rc > 0)
            client->msg_len += rc;

        if (client->msg_len >= hdrlen && client->msg_len == hdr->len) {
            handle_message(hdr);
            client->msg_len = 0;
        }
    }
}

static struct ipc_service_ops svc_ops = {
    .connect = console_connect,
    .disconnect = console_disconnect,
    .data_pending = console_data_pending,
};

static void *
create_shm_segment(size_t len, file_handle_t *out_hdl)
{
    file_handle_t hdl;
    void *view;

#if defined(_WIN32)
    hdl = CreateFileMapping(INVALID_HANDLE_VALUE, NULL,
                            PAGE_READWRITE | SEC_COMMIT, 0,
                            len, NULL);
    if (!hdl) {
        Wwarn("CreateFileMapping");
        return NULL;
    }

    view = MapViewOfFile(hdl, FILE_MAP_WRITE, 0, 0, len);
    if (!view) {
        Wwarn("MapViewOfFile");
        CloseHandle(hdl);
        return NULL;
    }
#elif defined (__APPLE__)
    int ret;
    uint32_t id;
    char name[32];

    generate_random_bytes(&id, sizeof(id));
    snprintf(name, 32, "shm-%08x%08x", getpid(), id);

    hdl = shm_open(name, O_RDWR | O_CREAT | O_EXCL, 0600);
    if (hdl == -1) {
        warn("shm_open");
        return NULL;
    }
    shm_unlink(name);

    ret = ftruncate(hdl, len);
    if (ret) {
        warn("ftruncate");
        close(hdl);
        return NULL;
    }

    view = mmap(NULL, len, PROT_READ | PROT_WRITE, MAP_FILE | MAP_SHARED,
                hdl, 0);
    if (view == MAP_FAILED) {
        warn("mmap");
        close(hdl);
        return NULL;
    }
#endif

    *out_hdl = hdl;
    return view;
}

static void
destroy_shm_segment(file_handle_t hdl, void *view, size_t len)
{
#if defined(_WIN32)
    UnmapViewOfFile(view);
    CloseHandle(hdl);
#elif defined (__APPLE__)
    munmap(view, len);
    close(hdl);
#endif
}

static int
surface_lock(struct display_surface *surface, uint8_t **data, int *linesize)
{
    struct remote_surface *s = (void *)surface;

    *data = s->data;
    *linesize = s->linesize;

    return 0;
}

static void
surface_unlock(struct display_surface *surface)
{

}

static struct remote_surface *
alloc_surface(struct remote_gui_state *s, int width, int height, int linesize)
{
    struct remote_surface *surface;

    surface = calloc(1, sizeof(struct remote_surface));
    if (!surface)
        err(1, "%s: calloc failed", __FUNCTION__);

    surface->s.width = width;
    surface->s.height = height;
    surface->s.pf = default_pixelformat(32);
    surface->s.lock = surface_lock;
    surface->s.unlock = surface_unlock;
    surface->linesize = linesize;

    s->surface = surface;

    return surface;
}

static struct display_surface *
create_surface(struct gui_state *state, int width, int height)
{
    struct remote_gui_state *s = (void *)state;
    struct remote_surface *surf;

    DPRINTF("%s %d %d\n", __FUNCTION__, width, height);

    surf = alloc_surface(s, width, height, width * 4);

    surf->len = width * height * 4;
    surf->segment_view = create_shm_segment(surf->len, &surf->segment_handle);
    if (!surf->segment_view) {
        free(surf);
        return NULL;
    }
    surf->data = surf->segment_view;

    return &surf->s;
}

static struct display_surface *
create_vram_surface(struct gui_state *state,
                    int width, int height,
                    int depth, int linesize,
                    void *vram_ptr,
                    unsigned int vram_offset)
{
    struct remote_gui_state *s = (void *)state;
    struct remote_surface *surf;

    DPRINTF("%s %d %d\n", __FUNCTION__, width, height);

    if (vram_ptr != s->vram_view || depth != 32)
        return NULL;

    surf = alloc_surface(s, width, height, linesize);
#if 0
    memcpy(surf->name, s->vram_name, sizeof(surf->name));
#endif
    surf->segment_handle = s->vram_handle;
    surf->segment_view = s->vram_view;
    surf->data = surf->segment_view + vram_offset;
    surf->len = s->vram_len;

    return &surf->s;
}

static void
free_surface(struct gui_state *state, struct display_surface *surface)
{
    struct remote_gui_state *s = (void *)state;
    struct remote_surface *surf = (void *)surface;

    DPRINTF("%s\n", __FUNCTION__);

    s->surface = NULL;
    if (!(surf->s.flags & DISPLAYSURFACE_VRAM)) {
#if defined(_WIN32)
        VirtualFree(surf->segment_view, surf->len, MEM_DECOMMIT);
#endif
        destroy_shm_segment(surf->segment_handle, surf->segment_view,
                            surf->len);
    }
    free(surf);
}

static void
gui_update(struct gui_state *state, int x, int y, int w, int h)
{
    struct uxenconsole_msg_invalidate_rect m;
    struct ipc_client *c;

    m.header.type = UXENCONSOLE_MSG_TYPE_INVALIDATE_RECT;
    m.header.len = sizeof(m);
    m.x = x;
    m.y = y;
    m.w = w;
    m.h = h;

    TAILQ_FOREACH(c, &console_svc.clients, link)
        ipc_client_send(c, &m, sizeof(m));
}

static void
gui_resize(struct gui_state *state, int w, int h)
{
    struct remote_gui_state *s = (void *)state;
    struct uxenconsole_msg_resize_surface m;
    struct ipc_client *c;

    if (!s || !s->surface) {
        warn("%s: state(0x%p) or state->surface is NULL.", __FUNCTION__, s);
        return;
    }

    m.header.type = UXENCONSOLE_MSG_TYPE_RESIZE_SURFACE;
    m.header.len = sizeof(m);
    m.width = w;
    m.height = h;
    m.linesize = s->surface->linesize;
    m.length = s->surface->len;
    m.bpp = 32;
    m.offset = s->surface->data - s->surface->segment_view;

    TAILQ_FOREACH(c, &console_svc.clients, link) {
        m.shm_handle = ipc_client_share(c, (uintptr_t)s->surface->segment_handle);
        ipc_client_send(c, &m, sizeof(m));
    }

    s->state.width = w;
    s->state.height = h;
}

static void
gui_refresh(struct gui_state *state)
{
    struct remote_gui_state *s = (void *)state;

    vga_hw_update(s->ds);
}

static void
gui_cursor_shape(struct gui_state *state,
                 int w, int h,
                 int hot_x, int hot_y,
                 uint8_t *mask, uint8_t *color)
{
    struct remote_gui_state *s = (void *)state;
    struct uxenconsole_msg_update_cursor m;
    struct ipc_client *c;


    /* Sanity checks */
    if (w > 128 || w < 0 || h > 128 || h < 0)
        return;

    if (w != 0 && h != 0) {
        size_t colorlen = 0;
        size_t masklen;

        if (hot_x >= w || hot_y >= h)
            return;

        if (color) {
            colorlen = w * h * 4;
            memcpy(s->cursor_view, color, colorlen);
        }

        if (mask) {
            masklen = ((w + 7) / 8) * h;
            if (!color)
                masklen *= 2;
            memcpy(s->cursor_view + s->cursor_mask_offset, mask, masklen);
        }
    }

    s->cursor_width = w;
    s->cursor_height = h;
    s->cursor_hot_x = hot_x;
    s->cursor_hot_y = hot_y;

    if (color && mask)
        s->cursor_type = CURSOR_TYPE_RGB_MASK;
    else if (mask)
        s->cursor_type = CURSOR_TYPE_MONOCHROME;
    else if (color)
        s->cursor_type = CURSOR_TYPE_RGB_ALPHA;
    else
        s->cursor_type = CURSOR_TYPE_HIDDEN;

    memset(&m, 0, sizeof(m));
    m.header.type = UXENCONSOLE_MSG_TYPE_UPDATE_CURSOR;
    m.header.len = sizeof(m);

    if (s->cursor_width == 0 || s->cursor_height == 0) {
        m.flags = CURSOR_UPDATE_FLAG_HIDE;
        TAILQ_FOREACH(c, &console_svc.clients, link)
            ipc_client_send(c, &m, sizeof(m));
    } else {
        m.w = s->cursor_width;
        m.h = s->cursor_height;
        m.hot_x = s->cursor_hot_x;
        m.hot_y = s->cursor_hot_y;
        if (s->cursor_type != CURSOR_TYPE_RGB_ALPHA)
            m.mask_offset = s->cursor_mask_offset;
        if (s->cursor_type == CURSOR_TYPE_MONOCHROME)
            m.flags = CURSOR_UPDATE_FLAG_MONOCHROME;
        TAILQ_FOREACH(c, &console_svc.clients, link) {
            m.shm_handle = ipc_client_share(c, (uintptr_t)s->cursor_handle);
            ipc_client_send(c, &m, sizeof(m));
        }
    }
}

static void
console_ledstate_notify(int state, void *opaque)
{
    struct ipc_client *c;

    TAILQ_FOREACH(c, &console_svc.clients, link)
        ledstate_update(c, state);
}

static int
gui_init(char *optstr)
{
    TAILQ_INIT(&heads);

    if (optstr) {
        int rc;

        rc = ipc_service_init(&console_svc, optstr, &svc_ops, sizeof(struct console_client), NULL);

        if (rc) {
            debug_printf("ipc_service_init failed: \"%s\"\n", optstr);
            return -1;
        }
    }

#if !defined(__APPLE__)
    guest_agent_init();
#endif

    input_kbd_ledstate_register(console_ledstate_notify, NULL);

    return 0;
}

static int
gui_create(struct gui_state *state, struct display_state *ds)
{
    struct remote_gui_state *s = (void *)state;

    s->state.width = 640;
    s->state.height = 480;

    s->ds = ds;
    s->cursor_mask_offset = 128 * 128 * 4;
    s->cursor_len = s->cursor_mask_offset + 128 * 128 * 2 / 8;
    s->cursor_view = create_shm_segment(s->cursor_len, &s->cursor_handle);
    if (!s->cursor_view) {
        return -1;
    }
    TAILQ_INSERT_TAIL(&heads, s, link);

    return 0;
}

static void
gui_start(struct gui_state *state)
{
    DPRINTF("%s\n", __FUNCTION__);
}

static void
gui_exit(void)
{
    ipc_service_cleanup(&console_svc);
}

static void
gui_destroy(struct gui_state *state)
{
    struct remote_gui_state *s = (void *)state;

    TAILQ_REMOVE(&heads, s, link);
    destroy_shm_segment(s->cursor_handle, s->cursor_view,
                        s->cursor_len);
}

void do_dpy_trigger_refresh(void *opaque);

static void
vram_changed(struct gui_state *state, struct vram_desc *v)
{
    struct remote_gui_state *s = (void *)state;

    s->vram_view = v->view;
    s->vram_handle = (file_handle_t)v->hdl;
    s->vram_len = v->shm_len;

    do_dpy_trigger_refresh(NULL);
}

static struct gui_info remote_gui_info = {
    .name = "remote",
    .size = sizeof(struct remote_gui_state),
    .init = gui_init,
    .start = gui_start,
    .exit = gui_exit,
    .create = gui_create,
    .destroy = gui_destroy,
    .create_surface = create_surface,
    .create_vram_surface = create_vram_surface,
    .free_surface = free_surface,
    .vram_change = vram_changed,
    .update = gui_update,
    .resize = gui_resize,
    .refresh = gui_refresh,
    .cursor_shape = gui_cursor_shape,
};

console_gui_register(remote_gui_info)

