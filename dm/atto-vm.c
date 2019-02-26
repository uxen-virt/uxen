/*
 * Copyright 2019, Bromium, Inc.
 * Author: Tomasz Wroblewski <tomasz.wroblewski@gmail.com>
 * SPDX-License-Identifier: ISC
 */

#include "config.h"
#include "dm.h"
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

struct win_cursor {
    LIST_ENTRY(win_cursor) entry;
    uint64_t x11_ptr;
    HCURSOR cursor;
    int custom;
};

static LIST_HEAD(, win_cursor) win_cursor_list =
       LIST_HEAD_INITIALIZER(&win_cursor_list);

static HCURSOR current_cursor = NULL;
static unsigned current_kbd_layout = 0;
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

static HCURSOR
x11_get_cursor(int x11_type, uint64_t x11_ptr, HCURSOR cursor)
{
    struct win_cursor *wc = NULL, *wc_next;
    LIST_FOREACH_SAFE(wc, &win_cursor_list, entry, wc_next) {
        if (wc->x11_ptr != x11_ptr)
            continue;
        if (!x11_type)
            return wc->cursor;
        LIST_REMOVE(wc, entry);
        if (wc->custom && wc->cursor)
            DestroyCursor(wc->cursor);
        free(wc);
        wc = NULL;
        break;
    }

    if (!x11_type)
        x11_type = 68 /* XC_left_ptr */;

    wc = calloc(1, sizeof(*wc));
    if (!wc) {
        warn("%s: malloc error\n", __FUNCTION__);
        return NULL;
    }
    wc->x11_ptr = x11_ptr;
    if (cursor) {
        wc->cursor = cursor;
        wc->custom = 1;
    } else {
        wc->cursor = LoadCursor(NULL, map_x11_to_win_cursor(x11_type));
    }
    LIST_INSERT_HEAD(&win_cursor_list, wc, entry);
    return wc->cursor;
}

void
attovm_check_kbd_layout_change(void)
{
    char layout[KL_NAMELENGTH + 1];

    if (!atto_agent_window_ready())
        return;

    memset(layout, 0, sizeof(layout));
    if (GetKeyboardLayoutName((LPSTR)layout)) {
        unsigned nlayout = 0;

        nlayout = strtoul(layout, NULL, 16);
        if (current_kbd_layout != nlayout) {
            atto_agent_change_kbd_layout(nlayout);
            current_kbd_layout = nlayout;
        }
    }
}

void
attovm_unmap_x11_cursor(uint64_t x11_ptr)
{
    struct win_cursor *wc = NULL, *wc_next;

    LIST_FOREACH_SAFE(wc, &win_cursor_list, entry, wc_next) {
        if (wc->x11_ptr != x11_ptr)
            continue;
        LIST_REMOVE(wc, entry);
        if (wc->custom && wc->cursor)
            DestroyCursor(wc->cursor);
        free(wc);
        break;
    }
}

void
attovm_set_x11_cursor(uint64_t x11_ptr)
{
    current_cursor = x11_get_cursor(0, x11_ptr, NULL);
    SetCursor(current_cursor);
}

void
attovm_set_current_cursor(void)
{
    SetCursor(current_cursor);
}

void
attovm_map_x11_cursor(int x11_type, uint64_t x11_ptr)
{
    x11_get_cursor(x11_type, x11_ptr, NULL);
}

void
attovm_create_custom_cursor(uint64_t x11_ptr, int xhot, int yhot,
                            int x11_nx, int x11_ny,
                            int nbytes, uint8_t *x11_and, uint8_t *x11_xor)
{
    HCURSOR cursor = NULL;
    struct win_cursor *wc = NULL, *wc_next;

    LIST_FOREACH_SAFE(wc, &win_cursor_list, entry, wc_next) {
        if (wc->x11_ptr == x11_ptr) {
            cursor = wc->cursor;
            break;
        }
    }

    if (!cursor) {
        cursor = CreateCursor(NULL, xhot, yhot, x11_nx, x11_ny,
                              x11_and, x11_xor);
        if (!cursor) {
            debug_printf("%s: CreateCursor failed, err %d\n", __FUNCTION__,
                         (int) GetLastError());
            return;
        }

        x11_get_cursor(-1, x11_ptr, cursor);
    }

    current_cursor = cursor;
    SetCursor(current_cursor);
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
