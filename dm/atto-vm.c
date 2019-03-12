/*
 * Copyright 2019, Bromium, Inc.
 * Author: Tomasz Wroblewski <tomasz.wroblewski@gmail.com>
 * SPDX-License-Identifier: ISC
 */

#include "config.h"
#include "dm.h"
#include "console.h"
#include "ioh.h"
#include "atto-agent.h"
#include "queue2.h"
#include "vm.h"
#include <err.h>
#include <stdbool.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <libvhd.h>
#include <xenctrl.h>
#include <xenguest.h>
#include <xc_attovm.h>
#include "timer.h"

#define MAX_DIRPATH_LEN (4 * MAX_PATH)
#define ATTOVM_IMAGE_EXT ".attovm"

typedef struct win_cursor {
    LIST_ENTRY(win_cursor) entry;
    int x11_type;
    uint64_t x11_ptr;
    int w;
    int h;
    int hot_x;
    int hot_y;
    uint8_t *mask;
    uint8_t *color;
} win_cursor;

static LIST_HEAD(, win_cursor) win_cursor_list =
       LIST_HEAD_INITIALIZER(&win_cursor_list);

static win_cursor *current_cursor = NULL;
static int vm_has_keyboard_focus = 0;
static int host_offer_focus = 0;

void attovm_set_keyboard_focus(int offer_focus)
{
    host_offer_focus = !!offer_focus;
}

void attovm_check_keyboard_focus(void)
{
    int rc;

    if (vm_get_run_mode() == DESTROY_VM)
        return;

    if (vm_has_keyboard_focus == host_offer_focus)
        return;

    rc = xc_attovm_change_focus(xc_handle, vm_id, host_offer_focus);

    if (host_offer_focus) {
       if (rc == 0)
           vm_has_keyboard_focus = 1;
       return;
    }

    // host wants focus
    if (rc == 0)
        vm_has_keyboard_focus = 0;
}

static LPCTSTR
map_x11_to_win_cursor(int x11_cursor)
{
    switch (x11_cursor) {
    case 52: /* XC_fleur */
        return IDC_SIZEALL;
    case 68: /* XC_left_ptr */
        return IDC_ARROW;
    case 34: /* XC_crosshair */
        return IDC_CROSS;
    case 58: /* XC_hand1 */
    case 60: /* XC_hand2 */
        return IDC_HAND;
    case 152: /* XC_xterm */
        return IDC_IBEAM;
    case 150: /* XC_watch */
        return IDC_WAIT;
    case 92: /* XC_question_arrow */
        return IDC_HELP;
    case 96: /* XC_right_side */
        return IDC_SIZEWE;
    case 138: /* XC_top_side */
        return IDC_SIZENS;
    case 136: /* XC_top_right_corner */
        return IDC_SIZENESW;
    case 134: /* XC_top_left_corner */
        return IDC_SIZENWSE;
    case 16: /* XC_bottom_side */
        return IDC_SIZENS;
    case 14: /* XC_bottom_right_corner */
        return IDC_SIZENWSE;
    case 12: /* XC_bottom_left_corner */
        return IDC_SIZENESW;
    case 70: /* XC_left_side */
        return IDC_SIZEWE;
    case 116: /* XC_sb_v_double_arrow */
        return IDC_SIZENS;
    case 108: /* XC_sb_h_double_arrow */
        return IDC_SIZEWE;
    default:
        return IDC_ARROW;
    }

    return IDC_ARROW;
}

static void
delete_cursor(win_cursor *wc)
{
    free(wc->mask);
    free(wc->color);
    free(wc);
}

static win_cursor *
x11_get_cursor(uint64_t x11_ptr)
{
    win_cursor *wc = NULL;
    LIST_FOREACH(wc, &win_cursor_list, entry) {
        if (wc->x11_ptr != x11_ptr)
            continue;
        return wc;
    }
    return NULL;
}

static void
x11_make_standard_cursor(win_cursor *wc)
{
    ICONINFO info;
    BITMAP mask_info;
    BITMAP color_info = {0};
    LONG count;
    BOOL ok;
    HCURSOR cursor;

    /* Windows will lie to you about the cursor metrics unless you pretend to be
       DPI aware. Even if you call LoadImage instead and explicitly request the
       larger size*/
    DPI_AWARENESS_CONTEXT old_dpi = Win32_SetThreadDpiAwarenessContext(
        DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE);
    cursor = LoadCursor(NULL, map_x11_to_win_cursor(wc->x11_type));

    ok = GetIconInfo(cursor, &info);
    if (!ok) {
        debug_printf("Failed to get cursor info err=%d for type %d\n",
            (int)GetLastError(), wc->x11_type);
        goto out;
    }
    GetObject(info.hbmMask, sizeof(BITMAP), &mask_info);
    wc->w = mask_info.bmWidth;
    wc->hot_x = info.xHotspot;
    wc->hot_y = info.yHotspot;
    count = mask_info.bmWidthBytes * mask_info.bmHeight;
    wc->mask = malloc(count);
    GetBitmapBits(info.hbmMask, count, wc->mask);
    if (info.hbmColor) {
        GetObject(info.hbmColor, sizeof(BITMAP), &color_info);
        count = color_info.bmWidthBytes * color_info.bmHeight;
        wc->color = malloc(count);
        GetBitmapBits(info.hbmColor, count, wc->color);
        wc->h = color_info.bmHeight;
    } else {
        /* B&W bitmaps stash the xor mask in there too, doubling the height */
        wc->h = mask_info.bmHeight / 2;
    }
    DeleteObject(info.hbmMask);
    DeleteObject(info.hbmColor);
out:
    Win32_SetThreadDpiAwarenessContext(old_dpi);
}

static void
x11_get_or_create_standard_cursor(int x11_type, uint64_t x11_ptr)
{
    win_cursor *wc = NULL, *wc_next;
    LIST_FOREACH_SAFE(wc, &win_cursor_list, entry, wc_next) {
        if (wc->x11_ptr != x11_ptr)
            continue;
        if (wc->x11_type == x11_type)
            return; /* Already setup */
        LIST_REMOVE(wc, entry);
        delete_cursor(wc);
        wc = NULL;
        break;
    }

    if (!x11_type)
        x11_type = 68 /* XC_left_ptr */;

    wc = calloc(1, sizeof(*wc));
    if (!wc) {
        warn("%s: malloc error\n", __FUNCTION__);
        return;
    }
    wc->x11_type = x11_type;
    wc->x11_ptr = x11_ptr;
    x11_make_standard_cursor(wc);
    LIST_INSERT_HEAD(&win_cursor_list, wc, entry);
}

void
attovm_unmap_x11_cursor(uint64_t x11_ptr)
{
    struct win_cursor *wc = NULL, *wc_next;

    LIST_FOREACH_SAFE(wc, &win_cursor_list, entry, wc_next) {
        if (wc->x11_ptr != x11_ptr)
            continue;
        LIST_REMOVE(wc, entry);
        delete_cursor(wc);
        break;
    }
}

static void
report_cursor_change(struct display_state* ds, win_cursor *wc)
{
    if (!wc) {
        // No cursor yet, probably shouldn't happen...
        return;
    }
    dpy_cursor_shape(ds, wc->w, wc->h, wc->hot_x, wc->hot_y,
                     wc->mask, wc->color);
}

void
attovm_set_x11_cursor(struct display_state* ds, uint64_t x11_ptr)
{
    current_cursor = x11_get_cursor(x11_ptr);
    report_cursor_change(ds, current_cursor);
}

void
attovm_set_current_cursor(struct display_state* ds)
{
    report_cursor_change(ds, current_cursor);
}

void
attovm_map_x11_cursor(int x11_type, uint64_t x11_ptr)
{
    assert(x11_type != -1);
    x11_get_or_create_standard_cursor(x11_type, x11_ptr);
}

void
attovm_create_custom_cursor(uint64_t x11_ptr, int xhot, int yhot,
                            int x11_nx, int x11_ny,
                            int nbytes, uint8_t *data)
{
    /* Old behaviour was to do nothing if x11_ptr matched anything */
    win_cursor *wc = NULL;
    LIST_FOREACH(wc, &win_cursor_list, entry) {
        if (wc->x11_ptr == x11_ptr) {
            return;
        }
    }

    wc = calloc(1, sizeof(*wc));
    if (!wc) {
        warn("%s: malloc error\n", __FUNCTION__);
        return;
    }
    wc->x11_type = -1; /* custom */
    wc->x11_ptr = x11_ptr;
    wc->hot_x = xhot;
    wc->hot_y = yhot;
    wc->w = x11_nx;
    wc->h = x11_ny;
    /* It appears that these must always be monochrome */
    wc->mask = malloc(nbytes);
    memcpy(wc->mask, data, nbytes);
    wc->color = NULL;
    LIST_INSERT_HEAD(&win_cursor_list, wc, entry);
}

int
is_attovm_image(const char *file)
{
    const char *ext = NULL;

    while (file && *file) {
        file = strchr(file, '.');
        if (file) {
            ext = file;
            file++;
        }
    }

    return ext && (strcasecmp(ext, ATTOVM_IMAGE_EXT) == 0);
}

char *
attovm_load_appdef(const char *file, uint32_t *out_size)
{
    uint32_t sz = 0;
    uint32_t left;
    void *buf;
    void *def = NULL;
    FILE *f;

    f = fopen(file, "rb");
    if (!f)
        goto out;
    fseek(f, 0, SEEK_END);
    sz = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (!sz)
        goto out;
    def = malloc(sz);
    if (!def)
        goto out;

    left = sz;
    buf = def;
    while (left) {
        uint32_t chunk_read = 0;
        uint32_t chunk = left;

        if (chunk > 0x10000)
            chunk = 0x10000;
        chunk_read = fread(buf, 1, chunk, f);
        if (chunk_read != chunk) {
            free(def);
            def = NULL;
            goto out;
        }
        buf  += chunk;
        left -= chunk;
    }

out:
    if (f)
        fclose(f);
    *out_size = sz;

    return def;
}
