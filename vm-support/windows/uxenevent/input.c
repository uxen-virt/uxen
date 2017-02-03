/*
 * Copyright 2013-2017, Bromium, Inc.
 * Author: Julian Pidancet <julian@pidancet.net>
 * SPDX-License-Identifier: ISC
 */

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <windowsx.h>
#include <tchar.h>
#include <wchar.h>

#define ERR_WINDOWS
#include <err.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

#include <guest-agent-proto.h>

#include "input.h"
#include "uxenevent.h"

//#define DEBUG_INPUT

static unsigned int keycnt = 0;

#ifdef DEBUG_INPUT
#define DPRINTF(fmt, ...) uxen_msg("%08x:" fmt, keycnt, ## __VA_ARGS__)
#define DPRINT_KBD_STATE(state) print_kbd_state(__FUNCTION__, state)
#else
#define DPRINTF(fmt, ...) do {} while (0)
#define DPRINT_KBD_STATE(state) do {} while (0)
#endif

static struct kbd_state {
    int lshift_down, rshift_down;
    int lctrl_down, rctrl_down;
    int lalt_down, ralt_down;
    int capslock_down, capslock_toggled;
} current_state = {
    0, 0,
    0, 0,
    0, 0,
    0, 0,
};

#ifdef DEBUG_INPUT
static void
print_kbd_state(const char *func, struct kbd_state *st)
{
    uxen_msg("%08x %s: lshift=%d rshift=%d lctrl=%d rctrl=%d lalt=%d ralt=%d"
              " capslock=%d cs_toggled=%d",
            keycnt, func,
            current_state.lshift_down,
            current_state.rshift_down,
            current_state.lctrl_down,
            current_state.rctrl_down,
            current_state.lalt_down,
            current_state.ralt_down,
            current_state.capslock_down,
            current_state.capslock_toggled);
}
#endif

static void
update_kbd_state(int keycode, int up, int extended)
{

    switch (keycode) {
    case VK_LSHIFT:
        current_state.lshift_down = !up;
        break;
    case VK_RSHIFT:
        current_state.rshift_down = !up;
        break;
    case VK_LCONTROL:
        current_state.lctrl_down = !up;
        break;
    case VK_RCONTROL:
        current_state.rctrl_down = !up;
        break;
    case VK_LMENU:
        current_state.lalt_down = !up;
        break;
    case VK_RMENU:
        current_state.ralt_down = !up;
        break;
    case VK_CAPITAL:
        if (!current_state.capslock_down && !up)
            current_state.capslock_toggled = !current_state.capslock_toggled;
        current_state.capslock_down = !up;
        break;
    default:
        return;
    }

    DPRINT_KBD_STATE(&current_state);
}

static int
inject_key(int keycode, int up, int extended)
{
    INPUT i = {0};
    int rc;

    DPRINTF("keycode=0x%08x up=%d ext=%d", keycode, !!up, extended);
    if ((keycode < 0x30) || ((keycode > 0x5A) && (keycode < VK_NUMPAD0)) || (keycode > VK_NUMPAD9)) {
        //uxen_msg("keycode=0x%08x up=%d ext=%d", keycode, !!up, extended);
    }

    switch (keycode) {
    case VK_SHIFT:
        if (extended)
            keycode = VK_RSHIFT;
        else
            keycode = VK_LSHIFT;
        break;
    case VK_CONTROL:
        if (extended)
            keycode = VK_RCONTROL;
        else
            keycode = VK_LCONTROL;
        break;
    case VK_MENU:
        if (extended)
            keycode = VK_RMENU;
        else
            keycode = VK_LMENU;
        break;
    default:
        break;
    }

    update_kbd_state(keycode, up, extended);

    i.type = INPUT_KEYBOARD;
    i.ki.wVk = keycode;
    i.ki.wScan = MapVirtualKey(keycode, MAPVK_VK_TO_VSC);
    if (extended)
        i.ki.dwFlags |= KEYEVENTF_EXTENDEDKEY;
    if (up)
        i.ki.dwFlags |= KEYEVENTF_KEYUP;

    rc = SendInput(1, &i, sizeof (i));
    if (!rc)
        return -1;

    return 0;
}

static void
get_kbd_state(struct kbd_state *state)
{
    *state = current_state;
}

static int
set_kbd_state(struct kbd_state *state)
{
    int ret = 0;

    if (current_state.lshift_down ^ state->lshift_down)
        ret |= inject_key(VK_LSHIFT, current_state.lshift_down, 0);
    if (current_state.rshift_down ^ state->rshift_down)
        ret |= inject_key(VK_RSHIFT, current_state.rshift_down, 1);
    if (current_state.lctrl_down ^ state->lctrl_down)
        ret |= inject_key(VK_LCONTROL, current_state.lctrl_down, 0);
    if (current_state.rctrl_down ^ state->rctrl_down)
        ret |= inject_key(VK_RCONTROL, current_state.rctrl_down, 1);
    if (current_state.lalt_down ^ state->lalt_down)
        ret |= inject_key(VK_LMENU, current_state.lalt_down, 0);
    if (current_state.ralt_down ^ state->ralt_down)
        ret |= inject_key(VK_RMENU, current_state.ralt_down, 1);
    if (current_state.capslock_toggled != state->capslock_toggled) {
        ret |= inject_key(VK_CAPITAL, 0, 0);
        ret |= inject_key(VK_CAPITAL, 1, 0);
    }

    DPRINT_KBD_STATE(&current_state);

    return ret;
}

static wchar_t
keycode_to_char(uint8_t scancode, uint8_t keycode)
{
    uint8_t state[256];
    wchar_t buf[2];
    int n;

    memset(state, 0, 256);
    if (current_state.lshift_down)
        state[VK_SHIFT] = state[VK_LSHIFT] = 0x80;
    if (current_state.rshift_down)
        state[VK_SHIFT] = state[VK_RSHIFT] = 0x80;
    if (current_state.lctrl_down)
        state[VK_CONTROL] = state[VK_LCONTROL] = 0x80;
    if (current_state.rctrl_down)
        state[VK_CONTROL] = state[VK_RCONTROL] = 0x80;
    if (current_state.lalt_down)
        state[VK_MENU] = state[VK_LMENU] = 0x80;
    if (current_state.ralt_down)
        state[VK_MENU] = state[VK_RMENU] = 0x80;
    if (current_state.capslock_toggled)
        state[VK_CAPITAL] = 0x01;

    state[keycode] = 0x80;
    n = ToUnicode(keycode, scancode, state, buf, 2, 0);
    if (n != 1) {
        DPRINTF("ToUnicode=%d", n);
        return 0;
    }

    DPRINTF("scancode=%08x keycode=%08x char=%04x",
            scancode, keycode, buf[0]);

    return buf[0];
}

static int
handle_ctrl_shortcuts(wchar_t ch, uint8_t keycode, wchar_t ch_bare, int up)
{
    struct kbd_state s1, s2;
    int alt_up;
    int ctrl_down;

    get_kbd_state(&s1);
    s2 = s1;
    alt_up = !s1.lalt_down && !s1.ralt_down;
    ctrl_down = s1.lctrl_down || s1.rctrl_down;

    if (!up && alt_up && ctrl_down && (ch != ch_bare) && (keycode >= VK_OEM_1)) {
        UINT mapped_ch = MapVirtualKey(keycode, MAPVK_VK_TO_CHAR) & 0xff;
        DPRINTF("mapped_ch=%04x keycode=%04x ch_bare=%04x wctob=%04x",
                mapped_ch, keycode, ch_bare, wctob(ch_bare));
        if ((mapped_ch > 0) && (mapped_ch != wctob(ch_bare))) {
            s1.lshift_down = 1;
        } else {
            s1.lshift_down = 0;
        }
        set_kbd_state(&s1);
        inject_key(keycode, up, 0);
        set_kbd_state(&s2);
        return 1;
    }
    return 0;
}

static int
inject_char(wchar_t ch, uint8_t keycode, wchar_t ch_bare, int up)
{
    uint16_t scan;
    int ret = 0;

    ret = handle_ctrl_shortcuts(ch, keycode, ch_bare, up);
    if (ret)
        return 0;

    scan = VkKeyScanW(ch);
    DPRINTF("ch=%04x up=%d scan=%04x", ch, up, scan);
    if (scan != 0xffff) {
        struct kbd_state s1, s2;
        int shift_needed = !!((scan >> 8) & 0x1);
        int ctrl_needed = !!((scan >> 8) & 0x2);
        int alt_needed = !!((scan >> 8) & 0x4);

        get_kbd_state(&s1);
        get_kbd_state(&s2);

        if (!shift_needed)
            s1.lshift_down = s1.rshift_down = s1.capslock_toggled = 0;
        else {
            s1.capslock_toggled = 0;
            if (!s1.rshift_down)
                s1.lshift_down = 1;
        }

        if (!ctrl_needed)
            s1.lctrl_down = s1.rctrl_down = 0;
        else if (!s1.rctrl_down)
            s1.lctrl_down = 1;

        if (!alt_needed)
            s1.lalt_down = s1.ralt_down = 0;
        else if (!s1.ralt_down)
            s1.lalt_down = 1;

        ret |= set_kbd_state(&s1);
        ret |= inject_key(scan & 0xff, up, 0);
        ret |= set_kbd_state(&s2);
    } else {
        int rc;
        INPUT i = {0};

        i.type = INPUT_KEYBOARD;
        i.ki.wVk = 0;
        i.ki.wScan = ch;
        i.ki.dwFlags = KEYEVENTF_UNICODE;

        if (up)
            i.ki.dwFlags |= KEYEVENTF_KEYUP;

        rc = SendInput(1, &i, sizeof (i));
        if (!rc)
            return -1;
    }

    return ret;
}

int
input_key_event(uint8_t keycode, uint16_t repeat, uint8_t scancode,
                uint8_t flags, int nchars, wchar_t *chars,
                int nchars_bare, wchar_t *chars_bare)
{
    int ret = 0;
    int up = scancode & 0x80;
    int extended = flags & 0x1;
    int i;

    DPRINTF("keycode=0x%02x up=%d ext=%d nchars=%d", keycode, !!up, extended, nchars);
    if ((keycode < 0x30) || ((keycode > 0x5A) && (keycode < VK_NUMPAD0)) || (keycode > VK_NUMPAD9)) {
        //uxen_msg("keycode=0x%02x up=%d ext=%d nchars=%d", keycode, !!up, extended, nchars);
    }

    if (nchars == 0) {
        ret = inject_key(keycode, up, extended);
    } else if (nchars > 0) {
        if (nchars == 1 &&
            (keycode_to_char(scancode, keycode) == chars[0]))
            ret = inject_key(keycode, up, extended);
        else {
            for (i = 0; i < nchars; i++) {
                wchar_t ch_bare = 0;
                if (i < nchars_bare)
                    ch_bare = chars_bare[i];
                ret |= inject_char(chars[i], keycode, ch_bare, up);
            }
        }
    }

    keycnt++;

    return ret;
}

int
input_mouse_event(uint32_t x, uint32_t y, int32_t dv, int32_t dh,
                  uint32_t flags)
{
    INPUT i;
    int rc;
    static uint32_t lastflags = 0;
    uint32_t fl;

    memset(&i, 0, sizeof (i));
    i.type = INPUT_MOUSE;

    i.mi.dwFlags |= MOUSEEVENTF_MOVE | MOUSEEVENTF_ABSOLUTE |
                    MOUSEEVENTF_VIRTUALDESK;
    i.mi.dx = x;
    i.mi.dy = y;
    i.mi.dx = i.mi.dx * 0xffff / (GetSystemMetrics(SM_CXVIRTUALSCREEN) - 1);
    i.mi.dy = i.mi.dy * 0xffff / (GetSystemMetrics(SM_CYVIRTUALSCREEN) - 1);

    fl = lastflags ^ flags;
    if (fl & MK_LBUTTON) {
        if (flags & MK_LBUTTON)
            i.mi.dwFlags |= MOUSEEVENTF_LEFTDOWN;
        else
            i.mi.dwFlags |= MOUSEEVENTF_LEFTUP;
    }
    if (fl & MK_RBUTTON) {
        if (flags & MK_RBUTTON)
            i.mi.dwFlags |= MOUSEEVENTF_RIGHTDOWN;
        else
            i.mi.dwFlags |= MOUSEEVENTF_RIGHTUP;
    }
    if (fl & MK_MBUTTON) {
        if (flags & MK_MBUTTON)
            i.mi.dwFlags |= MOUSEEVENTF_MIDDLEDOWN;
        else
            i.mi.dwFlags |= MOUSEEVENTF_MIDDLEUP;
    }

    /*
     * These conditions are all exclusive as they all use mouseData for
     * a different purpose.
     */
    if (fl & MK_XBUTTON1) {
        if (flags & MK_XBUTTON1)
            i.mi.dwFlags |= MOUSEEVENTF_XDOWN;
        else
            i.mi.dwFlags |= MOUSEEVENTF_XUP;
        i.mi.mouseData = XBUTTON1;
    } else if (fl & MK_XBUTTON2) {
        if (flags & MK_XBUTTON2)
            i.mi.dwFlags |= MOUSEEVENTF_XDOWN;
        else
            i.mi.dwFlags |= MOUSEEVENTF_XUP;
        i.mi.mouseData = XBUTTON2;
    } else if (dv) {
        i.mi.dwFlags |= MOUSEEVENTF_WHEEL;
        i.mi.mouseData = dv;
    } else if (dh) {
        i.mi.dwFlags |= MOUSEEVENTF_HWHEEL;
        i.mi.mouseData = dh;
    }
    i.mi.time = 0;

    lastflags = flags;

    rc = SendInput(1, &i, sizeof (i));
    if (!rc) {
        uxen_err("SendInput failed");
        return -1;
    }

    return 0;
}

int
input_wm_mouse_event(UINT message, WPARAM wParam, LPARAM lParam)
{
    INPUT i;
    int rc;

    memset(&i, 0, sizeof (i));
    i.type = INPUT_MOUSE;

    switch (message) {
    case WM_LBUTTONDOWN:
    case WM_RBUTTONDOWN:
    case WM_MBUTTONDOWN:
    case WM_XBUTTONDOWN:
    case WM_LBUTTONUP:
    case WM_RBUTTONUP:
    case WM_MBUTTONUP:
    case WM_XBUTTONUP:
    case WM_MOUSEMOVE:
        i.mi.dwFlags |= MOUSEEVENTF_MOVE | MOUSEEVENTF_ABSOLUTE;
        i.mi.dx = GET_X_LPARAM(lParam);
        i.mi.dy = GET_Y_LPARAM(lParam);
        i.mi.dx = i.mi.dx * 0xffff / (GetSystemMetrics(SM_CXVIRTUALSCREEN) - 1);
        i.mi.dy = i.mi.dy * 0xffff / (GetSystemMetrics(SM_CYVIRTUALSCREEN) - 1);

        if (message == WM_LBUTTONDOWN) {
            i.mi.dwFlags |= MOUSEEVENTF_LEFTDOWN;
        } else if (message == WM_RBUTTONDOWN) {
            i.mi.dwFlags |= MOUSEEVENTF_RIGHTDOWN;
        } else if (message == WM_MBUTTONDOWN) {
            i.mi.dwFlags |= MOUSEEVENTF_MIDDLEDOWN;
        } else if (message == WM_XBUTTONDOWN) {
            i.mi.dwFlags |= MOUSEEVENTF_XDOWN;
        } else if (message == WM_LBUTTONUP) {
            i.mi.dwFlags |= MOUSEEVENTF_LEFTUP;
        } else if (message == WM_RBUTTONUP) {
            i.mi.dwFlags |= MOUSEEVENTF_RIGHTUP;
        } else if (message == WM_MBUTTONUP) {
            i.mi.dwFlags |= MOUSEEVENTF_MIDDLEUP;
        } else if (message == WM_XBUTTONUP) {
            i.mi.dwFlags |= MOUSEEVENTF_XUP;
        }

        if (i.mi.dwFlags & (MOUSEEVENTF_XUP | MOUSEEVENTF_XDOWN)) {
            i.mi.mouseData = (short)(wParam >> 16);
        }

        break;
    case WM_MOUSEWHEEL:
        i.mi.dwFlags |= MOUSEEVENTF_WHEEL;
        i.mi.mouseData = (short)(wParam >> 16);
        break;
    case WM_MOUSEHWHEEL:
        i.mi.dwFlags |= MOUSEEVENTF_HWHEEL;
        i.mi.mouseData = (short)(wParam >> 16);
        break;
    case WM_MOUSELEAVE:
        /*
         * Move the pointer to "nowhere".
         */
        return 0;
    default:
        return -1;
    }

    i.mi.time = 0;

    rc = SendInput(1, &i, sizeof (i));
    if (!rc) {
        uxen_err("SendInput failed");
        return -1;
    }

    return 0;
}

#include "touch-defs.h"

static int input_touch_enabled = 0;

int input_touch_init(void)
{
    BOOL rc;

    rc = InitializeTouchInjection(256, TOUCH_FEEDBACK_NONE);
    if (!rc) {
        uxen_err("InitializeTouchInjection failed: %d", GetLastError());
        return -1;
    }

    input_touch_enabled = 1;
    return 0;
}

int input_touch_event(int count, struct ns_event_touch_contact *contacts)
{
    POINTER_TOUCH_INFO *touch_info;
    int i;
    BOOL rc;

    if (!input_touch_enabled)
        return -1;

    if (count > MAX_TOUCH_CONTACTS) {
        uxen_err("Too many contact points %d (max:%d)",
                  count, MAX_TOUCH_CONTACTS);
        return -1;
    }

    touch_info = calloc(count, sizeof (*touch_info));
    if (!touch_info)
        return -1;

    for (i = 0; i < count; i++) {
        touch_info[i].pointerInfo.pointerType = PT_TOUCH;

        touch_info[i].pointerInfo.pointerId = contacts[i].id;
        touch_info[i].pointerInfo.ptPixelLocation.x = contacts[i].x;
        touch_info[i].pointerInfo.ptPixelLocation.y = contacts[i].y;

        if (contacts[i].mask & NS_EVENT_TOUCH_MASK_CONTACTAREA) {
            touch_info[i].rcContact.left = contacts[i].left;
            touch_info[i].rcContact.right = contacts[i].right;
            touch_info[i].rcContact.top = contacts[i].top;
            touch_info[i].rcContact.bottom = contacts[i].bottom;
            touch_info[i].touchMask |= TOUCH_MASK_CONTACTAREA;
        }

        if (contacts[i].mask & NS_EVENT_TOUCH_MASK_ORIENTATION) {
            touch_info[i].orientation = contacts[i].orientation;
            touch_info[i].touchMask |= TOUCH_MASK_ORIENTATION;
        }

        if (contacts[i].mask & NS_EVENT_TOUCH_MASK_PRESSURE) {
            touch_info[i].pressure = contacts[i].pressure;
            touch_info[i].touchMask |= TOUCH_MASK_PRESSURE;
        }

        if (contacts[i].flags & NS_EVENT_TOUCH_FLAG_PRIMARY)
            touch_info[i].pointerInfo.pointerFlags |= POINTER_FLAG_PRIMARY;
        if (contacts[i].flags & NS_EVENT_TOUCH_FLAG_INRANGE)
            touch_info[i].pointerInfo.pointerFlags |= POINTER_FLAG_INRANGE;
        if (contacts[i].flags & NS_EVENT_TOUCH_FLAG_INCONTACT)
            touch_info[i].pointerInfo.pointerFlags |= POINTER_FLAG_INCONTACT;

        if (contacts[i].flags & NS_EVENT_TOUCH_FLAG_DOWN)
            touch_info[i].pointerInfo.pointerFlags |= POINTER_FLAG_DOWN;
        else if (contacts[i].flags & NS_EVENT_TOUCH_FLAG_UP)
            touch_info[i].pointerInfo.pointerFlags |= POINTER_FLAG_UP;
        else
            touch_info[i].pointerInfo.pointerFlags |= POINTER_FLAG_UPDATE;
    }

    rc = InjectTouchInput(i, touch_info);
    if (!rc)
        uxen_err("InjectTouchInput failed: %d", GetLastError());

    free(touch_info);

    return rc ? 0 : -1;
}
