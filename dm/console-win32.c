/*
 * Copyright 2012-2018, Bromium, Inc.
 * Author: Jacob Gorm Hansen <jacobgorm@gmail.com>
 * SPDX-License-Identifier: ISC
 */

#include <windowsx.h>

#include "config.h"

#include "console.h"
#include "dm.h"
#include "vm.h"
#include "uxen.h"
#include "hw/uxen_platform.h"
#include "vram.h"
#include "guest-agent.h"

#include "qemu_glue.h"

#include <fcntl.h>
#ifdef NOTIFY_CLIPBOARD_SERVICE
#include "vbox-drivers/shared-clipboard/notify.h"
#endif

// #define EVENT_DEBUG 1

#include "libnickel.h"

#include <uuid/uuid.h>

#include <xenctrl.h>

#include "win32-touch.h"
#include <uxenhid-common.h>
#include "hw/uxen_hid.h"
#include "console-dr.h"

#define WM_UXEN_SETCURSOR (WM_USER + 1)
#define WM_UXEN_EXIT (WM_USER + 2)

static UINT wm_print_surface = 0;
static console_dr_context_t dr_context;
static uint64_t current_rect;

struct win_surface
{
    struct display_surface s; /* Must be first */

    HDC dc;
    HBITMAP bitmap;

    uint8_t *data;
    int linesize;
};

struct win32_gui_state {
    struct gui_state state; /* Must be first */
    HWND window;
    HANDLE event_loop_thread;
    HANDLE ready_event;
    HANDLE start_event;
    HANDLE stop_event;
    HCURSOR cursor;
    int requested_w;
    int requested_h;
    int resizing;
    HANDLE vram_handle;
    void *vram_view;
    uint32_t vram_size;
    struct win_surface *surface;
    CRITICAL_SECTION surface_lock;
    struct display_state *ds;
};

static int
win_surface_lock(struct display_surface *s, uint8_t **data, int *linesize)
{
    struct win_surface *surface = (void *)s;

    *data = surface->data;
    *linesize = surface->linesize;

    return 0;
}

static void
win_surface_unlock(struct display_surface *s)
{

}

static struct win_surface *
win_create_surface(struct win32_gui_state *s,
                   int width, int height, int linesize, HANDLE vram_hdl, int vram_offset)
{
    struct win_surface *surface;
    HDC hdc;
    BITMAPINFO bmi;

    if (width == 0)
        width = s->state.width;
    if (height == 0)
        height = s->state.height;

    surface = calloc(1, sizeof(struct win_surface));
    if (!surface)
        err(1, "%s: calloc failed", __FUNCTION__);

    surface->s.width = s->state.width = width;
    surface->s.height = s->state.height = height;

    surface->s.pf = default_pixelformat(32);

    surface->s.lock = win_surface_lock;
    surface->s.unlock = win_surface_unlock;

    hdc = GetDC(s->window);
    surface->dc = CreateCompatibleDC(hdc);
    ReleaseDC(s->window, hdc);
    if (!surface->dc)
        return NULL;

    /* Setup bitmap info struct. */
    bmi.bmiHeader.biSize = sizeof(BITMAPINFOHEADER);
    bmi.bmiHeader.biWidth = linesize >> 2;
    bmi.bmiHeader.biHeight = -height;
    bmi.bmiHeader.biPlanes = 1;
    bmi.bmiHeader.biBitCount = 32; // four 8-bit components
    bmi.bmiHeader.biCompression = BI_RGB;
    bmi.bmiHeader.biSizeImage = linesize * height;

    surface->bitmap = CreateDIBSection(surface->dc, &bmi,
                                       DIB_RGB_COLORS,
                                       (void **)&surface->data,
                                       vram_hdl, vram_offset);

    if (!surface->bitmap) {
        DeleteDC(surface->dc);
        return NULL;
    }
    SelectObject(surface->dc, surface->bitmap);

    surface->linesize = linesize;

    s->surface = surface;
    LeaveCriticalSection(&s->surface_lock);

    return surface;
}

static struct display_surface *
create_surface(struct gui_state *state, int width, int height)
{
    struct win32_gui_state *s = (void *)state;
    struct win_surface *surface;
    int linesize = width * 4;

    surface = win_create_surface(s, width, height, linesize, NULL, 0);
    if (!surface)
        return NULL;

    return &surface->s;
}

static struct display_surface *
create_vram_surface(struct gui_state *state,
                    int width, int height,
                    int depth, int linesize,
                    void *vram_ptr,
                    unsigned int vram_offset)
{
    struct win32_gui_state *s = (void *)state;
    struct win_surface *surface;

    if (vram_ptr != s->vram_view || depth != 32)
        return NULL;

    surface = win_create_surface(s, width, height, linesize, s->vram_handle, vram_offset);
    if (!surface)
        return NULL;

    return &surface->s;
}

static void
free_surface(struct gui_state *state, struct display_surface *surface)
{
    struct win32_gui_state *s = (void *)state;
    struct win_surface *surf = (struct win_surface *)surface;

    EnterCriticalSection(&s->surface_lock);
    s->surface = NULL;
    DeleteObject(surf->bitmap);
    DeleteDC(surf->dc);
    free(surf);
}

/* Update a region of the screen. */
static void
gui_update(struct gui_state *state, int x, int y, int w, int h)
{
    struct win32_gui_state *s = (void *)state;
    RECT r = { x, y, x + w, y + h };

    InvalidateRect(s->window, &r, FALSE);
}


/* Resize the screen. */
static void
gui_resize(struct gui_state *state, int w, int h)
{
    struct win32_gui_state *s = (void *)state;
    int width = s->requested_w ? : w;
    int height = s->requested_h ? : h;
    int borderX, borderY;
    RECT inner, outer;

    if (w == s->requested_w)
        s->requested_w = 0;
    if (h == s->requested_h)
        s->requested_h = 0;

    if (s->surface == NULL)
        create_displaysurface(s->ds, width, height);

    /* If we have a border around the window, we need to take its dimensions
     * into account before asking for a Window resize. */

    GetClientRect(s->window, &inner);
    GetWindowRect(s->window, &outer);

    borderX = (outer.right - outer.left) - (inner.right - inner.left);
    borderY = (outer.bottom - outer.top) - (inner.bottom - inner.top);

    SetWindowPos(s->window, HWND_NOTOPMOST, CW_USEDEFAULT, CW_USEDEFAULT,
                 width + borderX, height + borderY, SWP_NOMOVE);
}

/* Request to refresh the screen. */
static void
gui_refresh(struct gui_state *state)
{
    struct win32_gui_state *s = (void *)state;

    vga_hw_update(s->ds);
}

static void
gui_cursor_shape(struct gui_state *state,
                 int w, int h,
                 int hot_x, int hot_y,
                 uint8_t *mask, uint8_t *color)
{
    struct win32_gui_state *s = (void *)state;
    HCURSOR hcursor;
    ICONINFO icon;
    HBITMAP maskbm = NULL;
    HBITMAP colorbm = NULL;
    uint8_t hidden_cursor[8] = { 0xff, 0xff, 0x00, 0x00 };

    if (w == 0 || h == 0) {
        color = NULL;
        mask = hidden_cursor;
        w = 1;
        h = 1;
        hot_x = 0;
        hot_y = 0;
    }

    /* Sanity check */
    if (w > 128 || w < 0 || h > 128 || h < 0 ||
        hot_x >= w || hot_y >= h)
        return;

    if (color) {
        maskbm = CreateBitmap(w, h, 1, 1, mask);
        colorbm = CreateBitmap(w, h, 1, 32, color);
        if (!colorbm || !maskbm)
            goto out;
    } else {
        maskbm = CreateBitmap(w, h * 2, 1, 1, mask);
        colorbm = NULL;
        if (!maskbm)
            goto out;
    }

    icon.fIcon = FALSE; /* This is a cursor */
    icon.xHotspot = hot_x;
    icon.yHotspot = hot_y;
    icon.hbmMask = maskbm;
    icon.hbmColor = colorbm;

    hcursor = CreateIconIndirect(&icon);
    if (hcursor)
        SendMessage(s->window, WM_UXEN_SETCURSOR, (WPARAM)hcursor, 0);

out:
    if (colorbm)
        DeleteObject(colorbm);
    if (maskbm)
        DeleteObject(maskbm);
}

static void
start_command_prompt(void)
{
    guest_agent_cmd_prompt();
}

static void
create_app_dump(void)
{
    if (app_dump_command)
        guest_agent_execute(app_dump_command);
}

static void
start_perf_data_collection(void)
{
    guest_agent_perf_collection(0xFULL, 1000, 60);
}

static void
key_event_send(int force_ps2,
               uint8_t keycode, uint16_t repeat, uint8_t scancode,
               uint8_t flags, int16_t nchars, wchar_t *chars,
               int16_t nchars_bare, wchar_t *chars_bare)
{
    if (force_ps2 ||
        guest_agent_kbd_event(keycode, repeat, scancode, flags, nchars,
                              chars, nchars_bare, chars_bare)) {
        struct input_event *input_event;
        BH *bh;

        bh = bh_new_with_data(input_event_cb, sizeof(struct input_event),
                              (void **)&input_event);
        if (bh) {
            input_event->type = KEYBOARD_INPUT_EVENT;
            input_event->extended = flags & 0x1;
            input_event->keycode = scancode;
            bh_schedule_one_shot(bh);
        }
    }
}

static int
handle_resizing(struct win32_gui_state *s, int w, int h)
{
    RECT inner, outer;

    GetClientRect(s->window, &inner);
    GetWindowRect(s->window, &outer);

    /*
     * Window has no current size, probably because it is hidden,
     * do not force size.
     */
    if (!inner.right && !inner.left && !inner.bottom && !inner.top)
        return 0;

    w += (inner.right - inner.left) - (outer.right - outer.left);
    h += (inner.bottom - inner.top) - (outer.bottom - outer.top);

    if (w == s->requested_w && h == s->requested_h)
        return 0;

    if (w == ds_get_width(s->ds) &&
        h == ds_get_height(s->ds))
        return 0;

    if (w <= 0 || h <= 0) {
        debug_printf("%s: invalid size requested %dx%d (border:%ldx%ld)\n",
                     __FUNCTION__, w, h,
                     (outer.right - outer.left) - (inner.right - inner.left),
                     (outer.bottom - outer.top) - (inner.bottom - inner.top));
        return -1;
    }

    if (guest_agent_window_event(0, WM_SIZE, SIZE_RESTORED,
                                 ((h & 0xffff) << 16) | (w & 0xffff)))
        return -1;

    s->requested_w = w;
    s->requested_h = h;

    return 0;
}

static int last_mouse_x = 0;
static int last_mouse_y = 0;

static void
handle_mouse_event(struct win32_gui_state *s, int x, int y, int dz, int wParam)
{
    struct input_event *input_event;
    BH *bh;
    int buttons = 0;

    if (input_mouse_is_absolute()) {
        last_mouse_x = x;
        last_mouse_y = y;
        x = x * 0x7fff / (desktop_width - 1);
        y = y * 0x7fff / (desktop_height - 1);
    } else {
        int dx, dy;
        dx = x - last_mouse_x;
        dy = y - last_mouse_y;
        last_mouse_x = x;
        last_mouse_y = y;
        x = dx;
        y = dy;
    }

    if (wParam & MK_LBUTTON)
        buttons |= MOUSE_EVENT_LBUTTON;
    if (wParam & MK_RBUTTON)
        buttons |= MOUSE_EVENT_RBUTTON;
    if (wParam & MK_MBUTTON)
        buttons |= MOUSE_EVENT_MBUTTON;

    bh = bh_new_with_data(input_event_cb, sizeof(struct input_event),
                          (void **)&input_event);
    if (!bh)
        return;

    input_event->type = MOUSE_INPUT_EVENT;
    input_event->x = x;
    input_event->y = y;
    input_event->dz = dz;
    input_event->button_state = buttons;
    bh_schedule_one_shot(bh);
}

static void
triple_finger_salute(void)
{
    struct input_event *ev;
    int i;
    BH *bh;
    int sc[6] = { 0x1D,     /* left ctrl down   */
                  0x38,     /* left alt down    */
                  0x53,     /* delete down      */
                  0xD3,     /* delete up        */
                  0xB8,     /* left alt up      */
                  0x9D };   /* left ctrl up     */


    for (i = 0; i < 6; i++) {
        bh = bh_new_with_data(input_event_cb, sizeof(struct input_event),
                              (void **)&ev);
        if (bh) {
            ev->type = KEYBOARD_INPUT_EVENT;
            ev->extended = 0;
            ev->keycode = sc[i];
            bh_schedule_one_shot(bh);
        }
    }
}

struct menu_timer
{
    HMENU m;
    int lines[7];
    UINT_PTR timer;
};

static void CALLBACK
menu_timer_cb(HWND window, UINT msg, UINT_PTR ev, DWORD time)
{
    struct menu_timer *mt = (void *)ev;
    int ret;
    xc_dominfo_t info;
    char buf[128];
    int balloon_cur, balloon_min, balloon_max;
    int priv_mb, lowmem_mb, highmem_mb;
    int pod_mb, tmpl_mb, zero_mb;
    float cpu, cpu_u, cpu_k;
    unsigned int tcp_nb_conn = 0, tcp_nb_total = 0, net_last = 0, net_rx_rate = 0, net_tx_rate = 0,
        net_nav_tx_rate = 0, net_nav_rx_rate = 0;
    int vm_nb, running_vm_nb;
    int used_lowmem_mb, used_highmem_mb, remaining_highmem_mb;
    uint64_t blk_io_reads = 0, blk_io_writes = 0;
    static uint64_t blk_io_prevreads = 0, blk_io_prevwrites = 0;

    ret = xc_domain_getinfo(xc_handle, vm_id, 1, &info);
    if (ret != 1 || info.domid != vm_id) {
        warn("xc_domain_getinfo failed");
        return;
    }
#if defined(CONFIG_NICKEL)
    ni_stats(&tcp_nb_conn, &tcp_nb_total, &net_last,
            &net_rx_rate, &net_tx_rate, &net_nav_rx_rate, &net_nav_tx_rate);
#endif
    balloon_cur = balloon_min = balloon_max;
    uxen_platform_get_balloon_size(&balloon_cur, &balloon_min, &balloon_max);
    snprintf(buf, sizeof(buf), "M: %d, B: %d (%d, %d)",
             vm_mem_mb, balloon_cur, balloon_min, balloon_max);
    ModifyMenuA(mt->m, mt->lines[0], MF_BYCOMMAND | MF_STRING | MF_GRAYED,
                mt->lines[0], buf);

    priv_mb = info.nr_pages * UXEN_PAGE_SIZE / (1024 * 1024);
    highmem_mb = info.nr_hidden_pages * UXEN_PAGE_SIZE / (1024 * 1024);
    lowmem_mb = priv_mb - highmem_mb;
    snprintf(buf, sizeof(buf), "P: %d, L: %d H: %d",
             priv_mb, lowmem_mb, highmem_mb);
    ModifyMenuA(mt->m, mt->lines[1], MF_BYCOMMAND | MF_STRING | MF_GRAYED,
                mt->lines[1], buf);

    pod_mb = info.nr_pod_pages * UXEN_PAGE_SIZE / (1024 * 1024);
    tmpl_mb = info.nr_tmpl_shared_pages * UXEN_PAGE_SIZE / (1024 * 1024);
    zero_mb = info.nr_zero_shared_pages * UXEN_PAGE_SIZE / (1024 * 1024);
    snprintf(buf, sizeof(buf), "D: %d, T: %d, Z: %d, B: %d",
             pod_mb, tmpl_mb, zero_mb - balloon_cur, balloon_cur);
    ModifyMenuA(mt->m, mt->lines[2], MF_BYCOMMAND | MF_STRING | MF_GRAYED,
                mt->lines[2], buf);

    cpu_u = 0.0f;
    cpu_k = 0.0f;
    cpu_usage(&cpu_u, &cpu_k, NULL, NULL);
    cpu = cpu_u + cpu_k;
#ifdef CONFIG_DUMP_BLOCK_STAT
    blockstats_getabs(&blk_io_reads, NULL, &blk_io_writes, NULL);
#endif  /* CONFIG_DUMP_BLOCK_STAT */
    snprintf(buf, sizeof(buf), "C: %.1f (%.1f, %.1f), R: %d, W: %d",
             cpu * 100.0f, cpu_u * 100.0f, cpu_k * 100.0f,
             (blk_io_reads  - blk_io_prevreads) >> 20,
             (blk_io_writes - blk_io_prevwrites) >> 20);
    blk_io_prevreads = blk_io_reads;
    blk_io_prevwrites = blk_io_writes;
    ModifyMenuA(mt->m, mt->lines[3], MF_BYCOMMAND | MF_STRING | MF_GRAYED,
                mt->lines[3], buf);

    snprintf(buf, sizeof(buf),
             "N: %u/%u, t: %.3fs, Tx: %.3f/%.3f Mbps, Rx: %.3f/%.3f Mbps",
             tcp_nb_conn, tcp_nb_total, (float)net_last * 1e-3,
             (float)net_nav_tx_rate * 8e-6,
             (float)net_tx_rate * 8e-6,
             (float)net_nav_rx_rate * 8e-6,
             (float)net_rx_rate * 8e-6);
    ModifyMenuA(mt->m, mt->lines[4], MF_BYCOMMAND | MF_STRING | MF_GRAYED,
                mt->lines[4], buf);

    vm_nb = 0; /* XXX */
    running_vm_nb = 0; /* XXX */
    snprintf(buf, sizeof(buf), "V: %d, r: %d",
             vm_nb, running_vm_nb);
    ModifyMenuA(mt->m, mt->lines[5], MF_BYCOMMAND | MF_STRING | MF_GRAYED,
                mt->lines[5], buf);

    used_lowmem_mb = 0; /* XXX */
    used_highmem_mb = 0; /* XXX */
    remaining_highmem_mb = 0; /* XXX */
    snprintf(buf, sizeof(buf), "L: %d, H: %d, h: %d",
             used_lowmem_mb, used_highmem_mb, remaining_highmem_mb);
    ModifyMenuA(mt->m, mt->lines[6], MF_BYCOMMAND | MF_STRING | MF_GRAYED,
                mt->lines[6], buf);

    mt->timer = SetTimer(window, ev, 1000, menu_timer_cb);
}

static void
show_context_menu(HWND hwnd)
{
    const struct {
        char *caption;
        void (*handler)(void);
        int min_level;
    } menu[] = {
        {"&Start Command Prompt", &start_command_prompt, 1},
        {"Create &App Dump File", &create_app_dump, 1},
        {"&Inject CTRL+ALT+DEL", &triple_finger_salute, 2},
        {"Collect &Performance Data", &start_perf_data_collection, 1},
        {"Create uVM Dump File", &vm_inject_nmi, 1},
    };
    HMENU hPopupMenu;
    int i, n;
    RECT rect;
    struct menu_timer mt;
    char buf[128];

    if (debugkey_level <= 0)
        return;

    /* Create context menu */
    GetWindowRect(hwnd, &rect);
    hPopupMenu = CreatePopupMenu();
    if (!hPopupMenu) {
        Wwarn("failed to create diagnostic menu");
        goto out;
    }
    n = 0;
    for (i = 0; i < ARRAY_SIZE(menu); i++)
        if (menu[i].min_level <= debugkey_level) {
            if (!InsertMenuA(hPopupMenu, -1, MF_BYPOSITION | MF_STRING, i + 1,
                             menu[i].caption))
            {
                Wwarn("failed to add item to diagnostic menu");
                goto out;
            }
            n++;
        }

    InsertMenuA(hPopupMenu, -1, MF_BYPOSITION | MF_MENUBREAK,
                i + 2, NULL);
    snprintf(buf, sizeof(buf), "U: %s, d: %d", vm_name, vm_id);
    InsertMenuA(hPopupMenu, -1, MF_BYPOSITION | MF_STRING | MF_GRAYED,
                i + 3, buf);
    InsertMenuA(hPopupMenu, -1, MF_BYPOSITION | MF_MENUBREAK,
                i + 4, NULL);
    InsertMenuA(hPopupMenu, -1, MF_BYPOSITION | MF_STRING | MF_GRAYED,
                i + 5, "");
    InsertMenuA(hPopupMenu, -1, MF_BYPOSITION | MF_STRING | MF_GRAYED,
                i + 6, "");
    InsertMenuA(hPopupMenu, -1, MF_BYPOSITION | MF_STRING | MF_GRAYED,
                i + 7, "");
    InsertMenuA(hPopupMenu, -1, MF_BYPOSITION | MF_STRING | MF_GRAYED,
                i + 8, "");
    InsertMenuA(hPopupMenu, -1, MF_BYPOSITION | MF_STRING | MF_GRAYED,
                i + 9, "");
    InsertMenuA(hPopupMenu, -1, MF_BYPOSITION | MF_MENUBREAK,
                i + 10, NULL);
    InsertMenuA(hPopupMenu, -1, MF_BYPOSITION | MF_STRING | MF_GRAYED,
                i + 11, "");
    InsertMenuA(hPopupMenu, -1, MF_BYPOSITION | MF_STRING | MF_GRAYED,
                i + 12, "");

    mt.m = hPopupMenu;
    mt.lines[0] = i + 5;
    mt.lines[1] = i + 6;
    mt.lines[2] = i + 7;
    mt.lines[3] = i + 8;
    mt.lines[4] = i + 9;
    mt.lines[5] = i + 11;
    mt.lines[6] = i + 12;
    mt.timer = 0;
    menu_timer_cb(hwnd, WM_TIMER, (UINT_PTR)&mt, 0);

    /* Display menu and execute choosen command */
    SetForegroundWindow(hwnd);
    i = TrackPopupMenu(hPopupMenu,
                       TPM_TOPALIGN | TPM_LEFTALIGN |
                       TPM_RETURNCMD | TPM_NONOTIFY,
                       rect.left + 10, rect.top + 10,
                       0, hwnd, NULL);
    if (0 != i) {
        i--;
        menu[i].handler();
    }
    PostMessage(hwnd, WM_NULL, 0, 0);
    KillTimer(hwnd, mt.timer);

  out:
    if (hPopupMenu)
        DestroyMenu(hPopupMenu);
}

static int comp(const void *a, const void *b) { return *(int *)a - *(int *)b; }

static enum {
    KBD_STATE_NORMAL = 0,
    KBD_STATE_DEADKEY_PRESSED,
    KBD_STATE_DEADKEY_RELEASED,
    KBD_STATE_COMPKEY_PRESSED,
    KBD_STATE_UNICODE,
} kbd_state = 0;
static uint8_t kbd_dead_key = 0;
static uint8_t kbd_comp_key = 0;
static uint8_t kbd_last_key = 0;
static uint8_t kbd_unicode_key = 0;

static int
is_numpad_key(int keycode)
{
    return (keycode >= VK_NUMPAD0) && (keycode <= VK_NUMPAD9);
}

static int
hid_mouse_event(struct win32_gui_state *s,
                int x, int y, int wheel, int hwheel, int wParam)
{
    uint8_t buttons = 0;
    int ret;
    int scaled_x, scaled_y;

    if (wParam & MK_LBUTTON)
        buttons |= UXENHID_MOUSE_BUTTON_1;
    if (wParam & MK_RBUTTON)
        buttons |= UXENHID_MOUSE_BUTTON_2;
    if (wParam & MK_MBUTTON)
        buttons |= UXENHID_MOUSE_BUTTON_3;
    if (wParam & MK_XBUTTON1)
        buttons |= UXENHID_MOUSE_BUTTON_4;
    if (wParam & MK_XBUTTON2)
        buttons |= UXENHID_MOUSE_BUTTON_5;

    scaled_x = ((x + s->ds->desktop_x) * UXENHID_XY_MAX) / (desktop_width - 1);
    scaled_y = ((y + s->ds->desktop_y) * UXENHID_XY_MAX) / (desktop_height - 1);

    ret = uxenhid_send_mouse_report(buttons, scaled_x, scaled_y,
                                    wheel / 30, hwheel / 30);
    if (!ret) {
        last_mouse_x = x;
        last_mouse_y = y;
    }

    return ret;
}

static int
hid_touch_event(struct win32_gui_state *s,
                POINTER_TOUCH_INFO *info, UINT32 count)
{
    UINT32 i;
    POINT pos = {0, 0};
    RECT client;

    ClientToScreen(s->window, &pos);
    GetClientRect(s->window, &client);


    for (i = 0; i < count; i++) {
        if ((info[i].pointerInfo.ptPixelLocation.x < pos.x) ||
            (info[i].pointerInfo.ptPixelLocation.x >= (pos.x + client.right)) ||
            (info[i].pointerInfo.ptPixelLocation.y < pos.y) ||
            (info[i].pointerInfo.ptPixelLocation.y >= (pos.y + client.bottom)))
            return -1;
    }

    for (i = 0; i < count; i++) {
        int rc;
        int x, y;
        int width, height;
        uint8_t flags = 0;
        uint16_t pointer_id;

        /* hash 32bit pointer id into 16bit value */
        pointer_id = info[i].pointerInfo.pointerId & 0xffff;
        pointer_id ^= info[i].pointerInfo.pointerId >> 16;

#define SCALE_X(v) \
        ((((v) + s->ds->desktop_x) * UXENHID_XY_MAX) / (desktop_width - 1))
#define SCALE_Y(v) \
        ((((v) + s->ds->desktop_y) * UXENHID_XY_MAX) / (desktop_height - 1))

        x = SCALE_X(info[i].pointerInfo.ptPixelLocation.x - pos.x);
        y = SCALE_Y(info[i].pointerInfo.ptPixelLocation.y - pos.y);
        width = SCALE_X(info[i].rcContact.right - info[i].rcContact.left);
        height = SCALE_Y(info[i].rcContact.bottom - info[i].rcContact.top);

        if (info[i].pointerInfo.pointerFlags & POINTER_FLAG_INRANGE)
            flags |= UXENHID_FLAG_IN_RANGE;
        if (info[i].pointerInfo.pointerFlags & POINTER_FLAG_INCONTACT)
            flags |= UXENHID_FLAG_TIP_SWITCH;

        /*
         * The first touch report of a frame gets the number of contact
         * points in the frame. Contact count is zero in the following
         * reports.
         */
        rc = uxenhid_send_touch_report(i == 0 ? count : 0,
                                       pointer_id,
                                       x, y, width, height,
                                       flags);
        if (rc == -1) {
            debug_printf("%s: failed to send touch report\n", __FUNCTION__);
            return -1;
        }
    }

    return 0;
}

static int
hid_pen_event(struct win32_gui_state *s, POINTER_PEN_INFO *info, UINT32 count)
{
    UINT32 i;
    POINT pos = {0, 0};

    ClientToScreen(s->window, &pos);

    for (i = 0; i < count; i++) {
        int rc;
        int x, y;
        uint8_t flags = 0;
        uint16_t pressure = 0;

        x = SCALE_X(info[i].pointerInfo.ptPixelLocation.x - pos.x);
        y = SCALE_Y(info[i].pointerInfo.ptPixelLocation.y - pos.y);

        if (info[i].pointerInfo.pointerFlags & POINTER_FLAG_INRANGE)
            flags |= UXENHID_FLAG_IN_RANGE;
        if (info[i].pointerInfo.pointerFlags & POINTER_FLAG_INCONTACT)
            flags |= UXENHID_FLAG_TIP_SWITCH;

        if (info[i].penFlags & PEN_FLAG_BARREL)
            flags |= UXENHID_PEN_FLAG_BARREL_SWITCH;
        if (info[i].penFlags & PEN_FLAG_INVERTED)
            flags |= UXENHID_PEN_FLAG_INVERT;
        if (info[i].penFlags & PEN_FLAG_ERASER)
            flags |= UXENHID_PEN_FLAG_ERASER;

        if (info[i].penMask & PEN_MASK_PRESSURE)
            pressure = info[i].pressure;

        rc = uxenhid_send_pen_report(x, y, flags, pressure);
        if (rc == -1) {
            debug_printf("%s: failed to send pen report\n", __FUNCTION__);
            return -1;
        }
    }

    return 0;
}

static void
handle_key_event(HWND hwnd, int message, int wParam, int lParam)
{
    int up = (message == WM_KEYUP) || (message == WM_SYSKEYUP);
    uint32_t scancode = (lParam >> 16) & 0x7f;
    int rmenu, rwin, lctrl, rctrl;
    HWND parent_window;

    /* check if key has been blocked by configuration */
    if (bsearch(&wParam, disabled_keys, disabled_keys_len, sizeof(int),
                comp))
        return;

    scancode |= up ? 0x80 : 0;

    rmenu = !!(GetKeyState(VK_RMENU) & 0x8000);
    rwin = !!(GetKeyState(VK_RWIN) & 0x8000);
    lctrl = !!(GetKeyState(VK_LCONTROL) & 0x8000);
    rctrl = !!(GetKeyState(VK_RCONTROL) & 0x8000);

#ifdef NOTIFY_CLIPBOARD_SERVICE
    input_notify_clipboard_about_keypress(scancode);
#endif

    /*
     * Hinder sending ctrl-alt-delete to a VM in case Alt-Gr is pressed
     * on a european layout.
     */
    if (wParam == VK_DELETE && rmenu && lctrl) {
        return;
    }

    /*
     * Check for CTRL special keys that must go via parent Window.
     *
     * If Right-Menu key is pressed at the same time as Left-Ctrl, it possibly
     * means that Alt-Gr was pressed on a european keyboard layout. In this
     * case, don't filter anything.
     */
    if (((lctrl && !rmenu) || rctrl) && (forwarded_keys & FORWARD_CONTROL_KEYS)
        && wParam != VK_CONTROL) {
        parent_window = GetParent(hwnd);
        if (IsWindow(parent_window) && SendMessage(parent_window,
                    message, wParam, lParam)) return;
    }

    /*
     * Discard PrintScreen key events as Windows never sends any key down
     * events for it, and we don't particularly need this key to reach the
     * guest.
     */
    if (wParam == VK_SNAPSHOT)
        return;

    if (debugkey_level && wParam == VK_DELETE && (rwin || rctrl)) {
        /* Only send this on key release */
        if (up) {
            /* Avoid sending a spurious event */
            if (rctrl)
                handle_key_event(hwnd, WM_KEYUP, VK_CONTROL,
                                 MapVirtualKeyW(VK_RCONTROL, 0) << 16 |
                                  0xc1000001);
            else /* if (rwin) */
                handle_key_event(hwnd, WM_KEYUP, VK_RWIN,
                                 MapVirtualKeyW(VK_RWIN, 0) << 16 |
                                  0xc1000001);

            show_context_menu(hwnd);
        }

        return; /* Inhibit key event (down or up) */
    }

    if (is_numpad_key(wParam))
        key_event_send(1, wParam, lParam & 0xffff, scancode,
                       lParam >> 24, 0, NULL, 0, NULL);
    else {
        unsigned char state[256];
        wchar_t chars[4];
        int nchars;
        wchar_t chars_bare[4] = {0};
        int nchars_bare = 0;
        HKL layout;

        layout = GetKeyboardLayout(0);
        GetKeyboardState(state);

        if (!up)
            kbd_last_key = wParam;

        nchars = ToUnicodeEx(wParam, scancode, state, chars,
                             sizeof(chars) / sizeof (wchar_t),
                             0, layout);
        if (nchars > 0) {
            nchars = ToUnicodeEx(wParam, scancode, state, chars,
                                 sizeof(chars) / sizeof (wchar_t),
                                 0, layout);

            state[VK_CONTROL] = state[VK_LCONTROL] = state[VK_RCONTROL] = 0;
            state[VK_MENU] = state[VK_LMENU] = state[VK_RMENU] = 0;
            nchars_bare = ToUnicodeEx(wParam, scancode, state, chars_bare,
                                 sizeof(chars_bare) / sizeof (wchar_t),
                                 0, layout);
        }


        /*
         * I see dead keys...
         */
        switch (kbd_state) {
        case KBD_STATE_UNICODE:
            if (up && (wParam == kbd_unicode_key ||
                       wParam == VK_PROCESSKEY))
                kbd_state = KBD_STATE_NORMAL;
            break;
        case KBD_STATE_COMPKEY_PRESSED:
            if (up && (kbd_comp_key == wParam))
                kbd_state = KBD_STATE_NORMAL;
            if (up && (kbd_dead_key == wParam))
                kbd_dead_key = 0;
            break;
        case KBD_STATE_DEADKEY_RELEASED:
            if (!up) {
                kbd_comp_key = wParam;
                kbd_state = KBD_STATE_COMPKEY_PRESSED;
            } else
                goto sendkey;
            break;
        case KBD_STATE_DEADKEY_PRESSED:
            if (up) {
                if (kbd_dead_key == wParam) {
                    kbd_state = KBD_STATE_DEADKEY_RELEASED;
                    kbd_dead_key = 0;
                } else
                    goto sendkey;
            } else { /* down */
                kbd_comp_key = wParam;
                kbd_state = KBD_STATE_COMPKEY_PRESSED;
            }
            break;
        case KBD_STATE_NORMAL:
            if (!up) {
                if (wParam == VK_PROCESSKEY) {
                    kbd_state = KBD_STATE_UNICODE;
                    kbd_unicode_key = MapVirtualKeyW(scancode,
                                                     MAPVK_VSC_TO_VK_EX);
                    break;
                } else if (wParam == VK_PACKET) {
                    kbd_state = KBD_STATE_UNICODE;
                    kbd_unicode_key = wParam;
                    break;
                } else if (nchars == -1) {
                    kbd_state = KBD_STATE_DEADKEY_PRESSED;
                    kbd_dead_key = wParam;
                    break;
                }
            }
sendkey:
            if (wParam == kbd_dead_key)
                kbd_dead_key = 0;
            else
                key_event_send(0, wParam, lParam & 0xffff, scancode,
                               lParam >> 24, nchars, chars,
                               nchars_bare, chars_bare);
            break;
        default:
            assert(0);
        }
    }
}

static void
reset_key_modifiers(HWND hwnd, int focus)
{
    /*
     * Emulate release of modifier keys when loosing the focus,
     * or emulate press of modifier keys when getting the focus back
     */

#define FIXKEYPRESS(key, vk)						\
    if (GetKeyState(key) & 0x8000) {					\
        int wParam = vk;						\
        int lParam = MapVirtualKeyW(key, 0) << 16 | 0x1;		\
        lParam |= focus ? 0 : (0x3 << 30);				\
        handle_key_event(hwnd, focus ? WM_KEYDOWN : WM_KEYUP, wParam,   \
                         lParam);                                       \
    }									\
    /* Variant for extended keys */
#define FIXKEYPRESS_EXT(key, vk)					\
    if (GetKeyState(key) & 0x8000) {					\
        int wParam = vk;						\
        int lParam = MapVirtualKeyW(key, 0) << 16 | 0x1;		\
        lParam |= focus ? 0 : (0x3 << 30);				\
        lParam |= (0x1 << 24);						\
        handle_key_event(hwnd, focus ? WM_KEYDOWN : WM_KEYUP, wParam,   \
                         lParam);                                       \
    }									\

    FIXKEYPRESS(VK_LSHIFT, VK_SHIFT);
    FIXKEYPRESS(VK_RSHIFT, VK_SHIFT);
    FIXKEYPRESS(VK_LCONTROL, VK_CONTROL);
    FIXKEYPRESS_EXT(VK_RCONTROL, VK_CONTROL);
    FIXKEYPRESS_EXT(VK_LWIN, VK_LWIN);
    FIXKEYPRESS_EXT(VK_RWIN, VK_RWIN);

    /*
     * When gaining the focus following an Alt-Tab or similar combination,
     * windows will report the Alt key as pressed but will never transmit
     * a SYSKEYUP event following release of the key.
     *
     * If Alt is pressed when gaining the focus back for another reason than
     * using the alt-tab combination, we will most likely get repeat events.
     *
     * Hence we can assume safe here not sending alt to the guest on focus.
     */
    if (!focus) {
        FIXKEYPRESS(VK_LMENU, VK_MENU);
        FIXKEYPRESS_EXT(VK_RMENU, VK_MENU);
    }

    /*
     * When gaining the focus, detect if the VM toggle key state matches the
     * host's state by reading out the keyboard LED state from the PS/2
     * controller. If the VM state is inconsistant with the host state,
     * simulate a toggle event.
     */

    if (focus) {
        int ledstate = input_get_kbd_ledstate();

        if ((GetKeyState(VK_SCROLL) & 0x1) != (ledstate & 0x1)) {
            handle_key_event(hwnd, WM_KEYDOWN, VK_SCROLL,
                             MapVirtualKeyW(VK_SCROLL, 0) << 16 | 0x1);
            handle_key_event(hwnd, WM_KEYUP, VK_SCROLL,
                             MapVirtualKeyW(VK_SCROLL, 0) << 16 | 0xC0000001);
        }
        if ((GetKeyState(VK_NUMLOCK) & 0x1) != ((ledstate >> 1) & 0x1)) {
            handle_key_event(hwnd, WM_KEYDOWN, VK_NUMLOCK,
                             MapVirtualKeyW(VK_NUMLOCK, 0) << 16 | 0x1);
            handle_key_event(hwnd, WM_KEYUP, VK_NUMLOCK,
                             MapVirtualKeyW(VK_NUMLOCK, 0) << 16 | 0xC0000001);
        }
        if ((GetKeyState(VK_CAPITAL) & 0x1) != ((ledstate >> 2) & 0x1)) {
            handle_key_event(hwnd, WM_KEYDOWN, VK_CAPITAL,
                             MapVirtualKeyW(VK_CAPITAL, 0) << 16 | 0x1);
            handle_key_event(hwnd, WM_KEYUP, VK_CAPITAL,
                             MapVirtualKeyW(VK_CAPITAL, 0) << 16 | 0xC0000001);
        }
    }
}

static void
sync_keyboard_state(void)
{
    BOOL rc;
    uint8_t state[256];
    int key;

    rc = GetKeyboardState(state);
    if (!rc) {
        debug_printf("%s: GetKeyboardState failed (%d)\n",
                     __FUNCTION__, (int)GetLastError());
        return;
    }

    for (key = 0; key < 256; key++) {
        uint16_t s = GetAsyncKeyState(key);
        uint8_t fix = (state[key] & 0x7F) | ((s >> 8) & 0x80);

#ifdef EVENT_DEBUG
        if (state[key] != fix) {
            debug_printf("%s: Incoherent state for key %x: %x, should be %x\n",
                         __FUNCTION__, key, state[key], fix);
        }
#endif

        state[key] = fix;
    }

    rc = SetKeyboardState(state);
    if (!rc) {
        debug_printf("%s: SetKeyboardState failed (%d)\n",
                     __FUNCTION__, (int)GetLastError());
        return;
    }
}

#ifndef WM_MOUSEHWHEEL
#define WM_MOUSEHWHEEL 0x020E
#endif

static int mouse_left = 0;
static int mouse_captured = 0;

static void
reset_mouse_tracking(HWND hwnd)
{
    TRACKMOUSEEVENT mousetrack;

    mousetrack.cbSize = sizeof (mousetrack);
    mousetrack.dwFlags = 0x2; /* TIME_LEAVE */
    mousetrack.hwndTrack = hwnd;
    mousetrack.dwHoverTime = 0;

    TrackMouseEvent(&mousetrack);
}

static int
print_surface(HANDLE shm, struct win_surface *surface)
{
    BITMAPINFO *bmi;
    int width, height, h;
    uint8_t *pixels, *p, *s;
    int mapping_len;

    width = surface->s.width;
    height = surface->s.height;
    mapping_len = UXEN_PAGE_SIZE +
                  ((width * height * 4 + (UXEN_PAGE_SIZE - 1)) &
                   ~(UXEN_PAGE_SIZE - 1));

    bmi = MapViewOfFile(shm, FILE_MAP_WRITE, 0, 0, mapping_len);
    if (!bmi) {
        Wwarn("%s: MapViewOfFile failed");
        return -1;
    }
    VirtualAlloc(bmi, mapping_len, MEM_COMMIT, PAGE_READWRITE);

    pixels = (uint8_t *)bmi + UXEN_PAGE_SIZE;

    bmi->bmiHeader.biSize = sizeof(BITMAPINFOHEADER);
    bmi->bmiHeader.biWidth = width;
    bmi->bmiHeader.biHeight = -height;
    bmi->bmiHeader.biPlanes = 1;
    bmi->bmiHeader.biBitCount = 32; // four 8-bit components
    bmi->bmiHeader.biCompression = BI_RGB;
    bmi->bmiHeader.biSizeImage = width * height * 4;

    for (h = 0, p = pixels, s = surface->data;
         h < height;
         h++, p += width * 4, s += surface->linesize)
        memcpy(p, s, width * 4);

    UnmapViewOfFile(bmi);
    CloseHandle(shm);

    return 1;
}

static void
count_fps(void)
{
    static int fps;
    static uint64_t fps_t0, fps_t1;

    fps++;
    fps_t1 = os_get_clock_ms();
    if (fps_t1 - fps_t0 >= 1000) {
        debug_printf("display fps: %d\n", fps);
        fps = 0;
        fps_t0 = fps_t1;
    }
}

/* Callback for Window events. */
LRESULT CALLBACK
win_window_proc(HWND hwnd, UINT message, WPARAM wParam, LPARAM lParam)
{
    struct win32_gui_state *s = (void *)GetWindowLongPtr(hwnd, GWLP_USERDATA);
    PAINTSTRUCT ps ;
    int ret = 0;
    int x, y, w, h;
    RECT *r;
    POINT pos = { 0, 0 };

#ifdef EVENT_DEBUG
    switch (message) {
    case WM_PAINT:
        break;
    default:
        debug_printf("%s: message %x wparam %"PRIx64" lparam %"PRIx64"\n",
                     __FUNCTION__, message, wParam, lParam);
        break;
    }
#endif

    if (message == wm_print_surface) {
        ret = -1;
        if (TryEnterCriticalSection(&s->surface_lock)) {
            ret = print_surface((HANDLE)wParam, s->surface);
            LeaveCriticalSection(&s->surface_lock);
        }
        return ret;
    }

    /* The actual input processing switch. */
    switch (message) {
    case WM_UXEN_SETCURSOR:
        SetClassLongPtr(hwnd, GCLP_HCURSOR, (LONG_PTR)wParam);
        SetCursor((HCURSOR)wParam);
        if (s->cursor)
            DestroyIcon(s->cursor);
        s->cursor = (HCURSOR)wParam;
        return 0;

    case WM_SETFOCUS:
        sync_keyboard_state();
        reset_key_modifiers(hwnd, 1);
        guest_agent_window_event(0, message, wParam, lParam);
        return 0;

    case WM_KEYDOWN:
    case WM_KEYUP:
    case WM_SYSKEYDOWN:
    case WM_SYSKEYUP:
        handle_key_event(hwnd, message, wParam, lParam);
        return 0;

    case WM_CHAR:
    case WM_SYSCHAR:
        if (kbd_state == KBD_STATE_COMPKEY_PRESSED ||
            kbd_state == KBD_STATE_UNICODE) {
            wchar_t ch = wParam;
            uint8_t scancode = (lParam >> 16) & 0x7f;

            key_event_send(0, kbd_last_key, lParam & 0xffff, scancode,
                           lParam >> 24, 1, &ch, 0, NULL);
            key_event_send(0, kbd_last_key, lParam & 0xffff, scancode | 0x80,
                           lParam >> 24, 1, &ch, 0, NULL);

            return 0;
        }
        break;

    case WM_KILLFOCUS:
        guest_agent_window_event(0, message, wParam, lParam);
        reset_key_modifiers(hwnd, 0);
        return 0;

    case WM_LBUTTONDOWN:
    case WM_RBUTTONDOWN:
    case WM_MBUTTONDOWN:
    case WM_LBUTTONUP:
    case WM_RBUTTONUP:
    case WM_MBUTTONUP:
    case WM_MOUSEMOVE:
        if (mouse_left) {
            reset_mouse_tracking(hwnd);
            mouse_left = 0;
        }

        if (!mouse_captured && (message == WM_LBUTTONDOWN ||
                                message == WM_RBUTTONDOWN ||
                                message == WM_MBUTTONDOWN)) {
            mouse_captured = message;
            SetCapture(hwnd);
        } else if (message == (mouse_captured + 1)) {
            ReleaseCapture();
            mouse_captured = 0;
        }
#ifdef NOTIFY_CLIPBOARD_SERVICE
        /* wParam == button state */
        input_notify_clipboard_about_click(wParam);
#endif
        x = GET_X_LPARAM(lParam);
        y = GET_Y_LPARAM(lParam);

        /*
         * Since we use SetCapture, we need to make sure we're not trying to
         * transmit negative or coordinates larger than the desktop size.
         */
        if ((x < 0) || (x >= desktop_width) ||
            (y < 0) || (y >= desktop_height)) {
            x = last_mouse_x;
            y = last_mouse_y;
        }
        if (hid_mouse_event(s, x, y, 0, 0, wParam) &&
            (!event_service_mouse_moves ||
             guest_agent_window_event(0, message, wParam, lParam)))
            handle_mouse_event(s, x, y, 0, wParam);
        return 0;

    case WM_XBUTTONDOWN:
    case WM_XBUTTONUP:
        /* Special non-PS2 buttons */
        x = GET_X_LPARAM(lParam);
        y = GET_Y_LPARAM(lParam);
        if (!hid_mouse_event(s, x, y, 0, 0, wParam) ||
            !guest_agent_window_event(0, message, wParam, lParam))
            return TRUE;
        break;
    case WM_MOUSEWHEEL:
        ClientToScreen(hwnd, &pos);
        x = GET_X_LPARAM(lParam) - pos.x;
        y = GET_Y_LPARAM(lParam) - pos.y;
        if (hid_mouse_event(s, x, y, GET_WHEEL_DELTA_WPARAM(wParam), 0,
                            wParam) &&
            guest_agent_window_event(0, message, wParam, lParam)) {
            handle_mouse_event(s, x, y,
                               GET_WHEEL_DELTA_WPARAM(wParam) < 0 ? 1 : -1,
                               GET_KEYSTATE_WPARAM(wParam));
        }
        return 0;
    case WM_MOUSEHWHEEL:
        ClientToScreen(hwnd, &pos);
        x = GET_X_LPARAM(lParam) - pos.x;
        y = GET_Y_LPARAM(lParam) - pos.y;
        if (hid_mouse_event(s, x, y, 0, GET_WHEEL_DELTA_WPARAM(wParam),
                            wParam))
            guest_agent_window_event(0, message, wParam, lParam);
        break;
    case WM_MOUSELEAVE:
        mouse_left = 1;
        guest_agent_window_event(0, message, wParam, lParam);
        return 0;

    case WM_CREATE:
        return 0;

    case WM_CLOSE:
        vm_set_run_mode(DESTROY_VM);
        return 0;

    case WM_UXEN_EXIT:
        SetEvent(s->stop_event);
        DestroyWindow(hwnd);
        return 0;

    case WM_DESTROY:
        PostQuitMessage(0);
        return 0;

    case WM_SIZE:
#ifdef EVENT_DEBUG
        debug_printf("%s: resize %"PRId64"x%"PRId64"\n", __FUNCTION__,
                     lParam & 0xffff, (lParam >> 16) & 0xffff);
#endif
        return 0;

    case WM_PAINT:
        if (TryEnterCriticalSection(&s->surface_lock)) {
            HDC hdcClient;

            hdcClient = BeginPaint (hwnd, &ps) ;

            x = ps.rcPaint.left;
            y = ps.rcPaint.top;
            w = ps.rcPaint.right - ps.rcPaint.left;
            h = ps.rcPaint.bottom - ps.rcPaint.top;

            if (!BitBlt(hdcClient, x, y, w, h,
                        s->surface->dc, x, y, SRCCOPY)) {
                Wwarn("BitBlt failed");
                ret = -1;
            }

            EndPaint (hwnd, &ps);
            LeaveCriticalSection(&s->surface_lock);

            if (disp_fps_counter)
                count_fps();

            if (dr_context)
                console_dr_ack_rect(dr_context, current_rect);
        }
        return ret;

    case WM_SIZING:
        r = (RECT *)lParam;

        if (handle_resizing(s, r->right - r->left, r->bottom - r->top)) {
            /* force current size */
            GetWindowRect(hwnd, r);

            return TRUE;
        }
        break;

    case WM_MOVING:
        {
            RECT src;
            RECT *dst = (RECT *)lParam;

            GetWindowRect(hwnd, &src);
            dst->right = dst->left + (src.right - src.left);
            dst->bottom = dst->top + (src.bottom - src.top);

            return TRUE;
        }

    case WM_WINDOWPOSCHANGING:
        {
            WINDOWPOS *p = (WINDOWPOS *)lParam;

#ifdef EVENT_DEBUG
            debug_printf("%s: pos changing %x %dx%d %dx%d\n", __FUNCTION__,
                         p->flags, p->x, p->y, p->cx, p->cy);
#endif

            if (p->flags & SWP_NOSIZE || p->flags & SWP_DRAWFRAME)
                break;

            if (handle_resizing(s, p->cx, p->cy)) {
                RECT rect;

                GetWindowRect(hwnd, &rect);
                p->cx = rect.right - rect.left;
                p->cy = rect.bottom - rect.top;
                return 0;
            }
        }
        break;

    case WM_ACTIVATE:
        if (wParam == WA_INACTIVE) {
            /* release mouse buttons with previous coordinates */
            handle_mouse_event(s, last_mouse_x, last_mouse_y, 0, 0);
        }

        break;

    case WM_ERASEBKGND:
        return 1;

    case WM_DROPFILES:
        {
            HWND parent_window = GetParent(hwnd);
            if (IsWindow(parent_window)) {
                PostMessage(parent_window, message, wParam, lParam);
            }
        }
        return 0;
    case WM_POINTERENTER:
    case WM_POINTERUP:
    case WM_POINTERDOWN:
    case WM_POINTERLEAVE:
    case WM_POINTERUPDATE:
        {
            UINT32 id = GET_POINTERID_WPARAM(wParam);
            POINTER_PEN_INFO pen_info[32];
            POINTER_TOUCH_INFO touch_info[32];
            UINT32 count;

            count = 32;
            if (FN_GetPointerFrameTouchInfo(id, &count, touch_info) &&
                !hid_touch_event(s, touch_info, count)) {
                FN_SkipPointerFrameMessages(id);
                return 0;
            }

            count = 32;
            if (FN_GetPointerFramePenInfo(id, &count, pen_info) &&
                !hid_pen_event(s, pen_info, count)) {
                FN_SkipPointerFrameMessages(id);
                return 0;
            }
        }
        break;

    default:
        break;
    }

    return DefWindowProcW(hwnd, message, wParam, lParam);
}

static void
vram_changed(struct gui_state *state, struct vram_desc *v)
{
    struct win32_gui_state *s = (void *)state;

    s->vram_view = v->view;
    s->vram_handle = (HANDLE)v->hdl;
    s->vram_size = v->shm_len;

    do_dpy_trigger_refresh(NULL);
}

static wchar_t window_class_name[] = L"uXenWindow";
static wchar_t window_caption[] = L"uXen VM";

static int
win_register_class(void)
{
    WNDCLASSEXW wndclass;

    /* Register a Window class. */
    wndclass.cbSize         = sizeof(wndclass);
    wndclass.style          = 0; //CS_HREDRAW | CS_VREDRAW;
    wndclass.lpfnWndProc    = win_window_proc;
    wndclass.cbClsExtra     = 0;
    wndclass.cbWndExtra     = 0;
    wndclass.hInstance      = g_instance;
    wndclass.hIcon          = LoadIcon(NULL, IDI_APPLICATION);
    wndclass.hIconSm        = LoadIcon(NULL, IDI_APPLICATION);
    wndclass.hCursor        = LoadCursor(NULL, IDC_ARROW);
    wndclass.hbrBackground  = (HBRUSH)GetStockObject(WHITE_BRUSH);
    wndclass.lpszClassName  = window_class_name;
    wndclass.lpszMenuName   = NULL;
    if (!RegisterClassExW(&wndclass)) {
        Werr(1, "RegisterClassEx failed");
        return -1;
    }

    return 0;
}

static DWORD WINAPI
win_event_loop(PVOID opaque)
{
    struct win32_gui_state *s = opaque;
    MSG msg;
    DWORD ret;

    ret = WaitForSingleObject(s->start_event, INFINITE);
    if (ret == WAIT_FAILED)
        Wwarn("%s: WaitForSingleObject failed", __FUNCTION__);
    CloseHandle(s->start_event);
    s->start_event = NULL;

    /* Create Window. */
    s->window = CreateWindowExW(
        vm_window_parent ?      // extended window style
            WS_EX_NOACTIVATE :
            WS_EX_CLIENTEDGE,
        window_class_name,           // window class name
        window_caption,                   // window caption

        vm_window_parent ?      // if parent is set we want no border
            (WS_CHILD | WS_CLIPCHILDREN |WS_CLIPSIBLINGS) :
            (WS_OVERLAPPEDWINDOW & ~(WS_MAXIMIZEBOX)),

        vm_window_parent ? 0 : CW_USEDEFAULT, // initial x position
        vm_window_parent ? 0 : CW_USEDEFAULT, // initial y position
        s->state.width,                        // initial x size
        s->state.height,                        // initial y size
        vm_window_parent,                 // parent window handle
        NULL,                             // window menu handle
        NULL,                             // program instance handle
        NULL);                            // creation parameters

    if (s->window == NULL)
        Werr(1, "CreateWindowEx failed");
    if (!IsWindowUnicode(s->window))
        errx(1, "Window is not unicode");

    debug_printf("uxen window %p\n", s->window);

    vm_window = s->window;
    SetWindowLongPtr(s->window, GWLP_USERDATA, (LONG_PTR)s);

    ShowWindow(s->window, g_showwindow);
    UpdateWindow(s->window);

    reset_mouse_tracking(s->window);

    wm_print_surface = RegisterWindowMessageA("uxen-print-surface");

    debug_printf("%s: starting\n", __FUNCTION__);
    SetEvent(s->ready_event);

    /* Runs until DestroyWindow is called. */
    while (WaitForSingleObject(s->stop_event, 0) != WAIT_OBJECT_0) {
        ret = MsgWaitForMultipleObjectsEx(
            1, &s->stop_event, INFINITE, QS_ALLINPUT, MWMO_ALERTABLE);
        if (ret == WAIT_OBJECT_0 + 1) {
            while (PeekMessageW(&msg, NULL, 0, 0, PM_REMOVE)) {
                TranslateMessage(&msg);
                DispatchMessageW(&msg);
            }
        }
    }
    CloseHandle(s->stop_event);

    debug_printf("%s: exiting\n", __FUNCTION__);
    ExitThread(0);
}

#ifdef MONITOR
static void
mon_resize_screen(struct gui_state *s, Monitor *mon, const dict args)
{
    int w, h;


    w = dict_get_integer(args, "w");
    h = dict_get_integer(args, "h");

    if (guest_agent_window_event(0, WM_SIZE, SIZE_RESTORED,
                                ((h & 0xffff) << 16) | (w & 0xffff)))
        debug_printf("screen not resizable\n");
}
#endif  /* MONITOR */

static void
disp_inv_rect(void *priv, int x, int y, int w, int h, uint64_t rect_id)
{
    current_rect = rect_id;
    dpy_desktop_update(x, y, w, h);
}

static int
gui_init(char *optstr)
{
    win_register_class();
    guest_agent_init();

    dr_context = console_dr_init(-1, v4v_idtoken, NULL, disp_inv_rect, 0);
    if (!dr_context)
        Wwarn("%s: console_dr_init failed", __FUNCTION__);

    return 0;
}

static void
gui_exit(void)
{
    console_dr_cleanup(dr_context);
    dr_context = NULL;
    guest_agent_cleanup();
}

static int
gui_create(struct gui_state *state, struct display_state *ds)
{
    struct win32_gui_state *s = (void *)state;

    s->ds = ds;
    InitializeCriticalSection(&s->surface_lock);
    EnterCriticalSection(&s->surface_lock);
    s->state.width = 640;
    s->state.height = 480;

    s->start_event = CreateEvent(NULL, FALSE, FALSE, NULL);
    if (!s->start_event)
        Werr(1, "CreateEvent failed");
    s->ready_event = CreateEvent(NULL, FALSE, FALSE, NULL);
    if (!s->ready_event)
        Werr(1, "CreateEvent failed");
    s->stop_event = CreateEvent(NULL, FALSE, FALSE, NULL);
    if (!s->stop_event)
        Werr(1, "CreateEvent failed");

    s->event_loop_thread = CreateThread(NULL, 0, win_event_loop, s,
                                        0, NULL);
    if (!s->event_loop_thread)
        Werr(1, "CreateThread(win_event_loop) failed");

    return 0;
}

static void
gui_start(struct gui_state *state)
{
    struct win32_gui_state *s = (void *)state;
    DWORD ret;

    SetEvent(s->start_event);

    ret = WaitForSingleObject(s->ready_event, INFINITE);
    if (ret == WAIT_FAILED)
        Wwarn("%s: WaitForSingleObject failed", __FUNCTION__);
    CloseHandle(s->ready_event);
    s->ready_event = NULL;
}

static void
gui_destroy(struct gui_state *state)
{
    struct win32_gui_state *s = (void *)state;
    DWORD ret;

    if (s->event_loop_thread) {
        /* Ask window thread to close window and quit. */
        SendMessage(s->window, WM_UXEN_EXIT, 0, 0);

        /* Wait for window thread finishing. */
        ret = WaitForSingleObject(s->event_loop_thread, INFINITE);
        if (ret == WAIT_FAILED)
            Wwarn("%s: WaitForSingleObject failed", __FUNCTION__);
        CloseHandle(s->event_loop_thread);
        s->event_loop_thread = NULL;

        DeleteCriticalSection(&s->surface_lock);
    }
}

static struct gui_info win_gui_info = {
    .name = "win32",
    .size = sizeof(struct win32_gui_state),
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
#if MONITOR
    .mon_resize_screen = mon_resize_screen,
#endif
};

console_gui_register(win_gui_info)
