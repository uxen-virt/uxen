/*
 * Copyright 2014-2016, Bromium, Inc.
 * Author: Julian Pidancet <julian@pidancet.net>
 * SPDX-License-Identifier: ISC
 */

#define _WIN32_WINNT 0x0601
#include <windows.h>
#include <windowsx.h>
#define ERR_WINDOWS
#define ERR_AUTO_CONSOLE
#include <err.h>
#include <getopt.h>
#define UUID _UUID
#include <uuid/uuid.h>

#include "uxenconsolelib.h"
#include "uxenhid-common.h"

#include "../../dm/win32-touch.h"

WINBASEAPI ULONGLONG WINAPI GetTickCount64(void);

DECLARE_PROGNAME;

#define BUF_SZ 1024
struct console {
    uxenconsole_context_t ctx;
    hid_context_t hid;
    disp_context_t disp;
    HANDLE channel_event;
    HWND window;
    HINSTANCE instance;
    int show;
    HDC dc;
    HANDLE surface_handle;
    HBITMAP surface;
    int width;
    int height;
    int mouse_left;
    int mouse_captured;
    int last_mouse_x;
    int last_mouse_y;
    int kbd_state;
    int kbd_dead_key;
    int kbd_comp_key;
    int kbd_last_key;
    int kbd_unicode_key;
    unsigned char tx_buf[BUF_SZ];
    unsigned int tx_len;
    HCURSOR cursor;
    int requested_width;
    int requested_height;
    int resize_pending;
    int stop;
    int kbd_ledstate;
    void *surface_bits;
};

enum {
    KBD_STATE_NORMAL = 0,
    KBD_STATE_DEADKEY_PRESSED,
    KBD_STATE_DEADKEY_RELEASED,
    KBD_STATE_COMPKEY_PRESSED,
    KBD_STATE_UNICODE,
};

static int screenshot_idx = 0;
static const wchar_t *screenshot_path = L"";
/* Times are in ms */
static uint64_t screenshot_interval = 0;

#define SCALE_X(v) \
        (((v) * UXENHID_XY_MAX) / (cons->width - 1))
#define SCALE_Y(v) \
        (((v) * UXENHID_XY_MAX) / (cons->height - 1))


#if 0
static int
hid_mouse_event(struct console *cons, int x, int y, int wheel, int hwheel, int wParam)
{
    int buttons = 0;
    int ret;
    int scaled_x, scaled_y;

    if (!cons->hid)
        return -1;

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

    scaled_x = SCALE_X(x);
    scaled_y = SCALE_Y(y);

    ret = uxenconsole_hid_mouse_report(cons->hid, buttons, scaled_x, scaled_y,
                                       wheel / 30, hwheel / 30);
    if (!ret) {
        cons->last_mouse_x = x;
        cons->last_mouse_y = y;
    }

    return ret;
}
#endif

static int
hid_touch_event(struct console *cons, POINTER_TOUCH_INFO *info, UINT32 count)
{
    UINT32 i;
    POINT pos = {0, 0};
    RECT client;

    if (!cons->hid)
        return -1;

    ClientToScreen(cons->window, &pos);
    GetClientRect(cons->window, &client);

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
        rc = uxenconsole_hid_touch_report(cons->hid,
                                          i == 0 ? count : 0,
                                          pointer_id,
                                          x, y, width, height,
                                          flags);
        if (rc == -1)
            return -1;
    }

    return 0;
}

static int
hid_pen_event(struct console *cons, POINTER_PEN_INFO *info, UINT32 count)
{
    UINT32 i;
    POINT pos = {0, 0};

    if (!cons->hid)
        return -1;

    ClientToScreen(cons->window, &pos);

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

        rc = uxenconsole_hid_pen_report(cons->hid, x, y, flags, pressure);
        if (rc == -1)
            return -1;
   }

    return 0;
}

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
resize_window(struct console *cons, int w, int h)
{
    RECT inner, outer;

    GetClientRect(cons->window, &inner);
    GetWindowRect(cons->window, &outer);

    /*
     * Window has no current size, probably because it is hidden,
     * do not force size.
     */
    if (!inner.right && !inner.left && !inner.bottom && !inner.top)
        return 0;

    w += (inner.right - inner.left) - (outer.right - outer.left);
    h += (inner.bottom - inner.top) - (outer.bottom - outer.top);

    cons->requested_width = w;
    cons->requested_height = h;

    return 0;
}

#ifndef WM_MOUSEHWHEEL
#define WM_MOUSEHWHEEL 0x020E
#endif

LRESULT CALLBACK
window_proc(HWND hwnd, UINT message, WPARAM wParam, LPARAM lParam)
{
    struct console *cons = (void *)GetWindowLongPtr(hwnd, GWLP_USERDATA);

    switch (message) {
    case WM_PAINT:
        {
            HDC hdc;
            PAINTSTRUCT ps;
            int x, y, w, h;

            hdc = BeginPaint(hwnd, &ps);
            x = ps.rcPaint.left;
            y = ps.rcPaint.top;
            w = ps.rcPaint.right - x;
            h = ps.rcPaint.bottom - y;
            BitBlt(hdc, x, y, w, h, cons->dc, x, y, SRCCOPY);
            EndPaint(hwnd, &ps);
        }
        return 0;
    case WM_LBUTTONDOWN:
    case WM_RBUTTONDOWN:
    case WM_MBUTTONDOWN:
    case WM_LBUTTONUP:
    case WM_RBUTTONUP:
    case WM_MBUTTONUP:
    case WM_MOUSEMOVE:
    case WM_XBUTTONDOWN:
    case WM_XBUTTONUP:
    case WM_MOUSEWHEEL:
    case WM_MOUSEHWHEEL:
        {
            POINT cursor;
            int dv = 0;
            int dh = 0;

            if (cons->mouse_left) {
                reset_mouse_tracking(hwnd);
                cons->mouse_left = 0;
            }

            if (!cons->mouse_captured && (message == WM_LBUTTONDOWN ||
                                          message == WM_RBUTTONDOWN ||
                                          message == WM_MBUTTONDOWN)) {
                cons->mouse_captured = message;
                SetCapture(hwnd);
            } else if (message == (cons->mouse_captured + 1)) {
                ReleaseCapture();
                cons->mouse_captured = 0;
            }

            cursor.x = GET_X_LPARAM(lParam);
            cursor.y = GET_Y_LPARAM(lParam);

            if (message == WM_MOUSEWHEEL) {
                ScreenToClient(hwnd, &cursor);
                dv = GET_WHEEL_DELTA_WPARAM(wParam);
            } else if (message == WM_MOUSEHWHEEL) {
                ScreenToClient(hwnd, &cursor);
                dh = GET_WHEEL_DELTA_WPARAM(wParam);
            }

            /*
             * Since we use SetCapture, we need to make sure we're not trying to
             * transmit negative or coordinates larger than the desktop size.
             */
            if ((cursor.x < 0) || (cursor.x >= cons->width) ||
                (cursor.y < 0) || (cursor.y >= cons->height)) {
                cursor.x = cons->last_mouse_x;
                cursor.y = cons->last_mouse_y;
            } else {
                cons->last_mouse_x = cursor.x;
                cons->last_mouse_y = cursor.y;
            }

            /* wParam maps to the flags parameter  */
            uxenconsole_mouse_event(cons->ctx, cursor.x, cursor.y, dv, dh,
                                    GET_KEYSTATE_WPARAM(wParam));
        }
        return 0;
    case WM_MOUSELEAVE:
        {
            cons->mouse_left = 1;
        }
        return 0;
    case WM_KEYDOWN:
    case WM_KEYUP:
    case WM_SYSKEYDOWN:
    case WM_SYSKEYUP:
        {
            unsigned char state[256];
            wchar_t chars[4];
            int nchars;
            wchar_t chars_bare[4] = {0};
            int nchars_bare = 0;
            HKL layout;
            int up = (message == WM_KEYUP) || (message == WM_SYSKEYUP);
            unsigned int scancode = (lParam >> 16) & 0x7f;

            layout = GetKeyboardLayout(0);
            GetKeyboardState(state);

            if (!up)
                cons->kbd_last_key = wParam;

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
            switch (cons->kbd_state) {
            case KBD_STATE_UNICODE:
                if (up && (wParam == cons->kbd_unicode_key ||
                           wParam == VK_PROCESSKEY))
                    cons->kbd_state = KBD_STATE_NORMAL;
                break;
            case KBD_STATE_COMPKEY_PRESSED:
                if (up && (cons->kbd_comp_key == wParam))
                    cons->kbd_state = KBD_STATE_NORMAL;
                if (up && (cons->kbd_dead_key == wParam))
                    cons->kbd_dead_key = 0;
                break;
            case KBD_STATE_DEADKEY_RELEASED:
                if (!up) {
                    cons->kbd_comp_key = wParam;
                    cons->kbd_state = KBD_STATE_COMPKEY_PRESSED;
                } else
                    goto sendkey;
                break;
            case KBD_STATE_DEADKEY_PRESSED:
                if (up) {
                    if (cons->kbd_dead_key == wParam) {
                        cons->kbd_state = KBD_STATE_DEADKEY_RELEASED;
                        cons->kbd_dead_key = 0;
                    } else
                        goto sendkey;
                } else { /* down */
                    cons->kbd_comp_key = wParam;
                    cons->kbd_state = KBD_STATE_COMPKEY_PRESSED;
                }
                break;
            case KBD_STATE_NORMAL:
                if (!up) {
                    if (wParam == VK_PROCESSKEY) {
                        cons->kbd_state = KBD_STATE_UNICODE;
                        cons->kbd_unicode_key = MapVirtualKeyW(scancode,
                                                         MAPVK_VSC_TO_VK_EX);
                        break;
                    } else if (wParam == VK_PACKET) {
                        cons->kbd_state = KBD_STATE_UNICODE;
                        cons->kbd_unicode_key = wParam;
                        break;
                    } else if (nchars == -1) {
                        cons->kbd_state = KBD_STATE_DEADKEY_PRESSED;
                        cons->kbd_dead_key = wParam;
                        break;
                    }
                }
sendkey:
                if (wParam == cons->kbd_dead_key)
                    cons->kbd_dead_key = 0;
                else
                    uxenconsole_keyboard_event(
                            cons->ctx,
                            wParam,
                            lParam & 0xffff,
                            scancode | (up ? 0x80 : 0x0),
                            (lParam >> 24) | KEYBOARD_EVENT_FLAG_UCS2,
                            chars, nchars, chars_bare, nchars_bare);
                break;
            default:
                /* assert */
                break;
            }
        }
        return 0;
    case WM_CHAR:
    case WM_SYSCHAR:
        if (cons->kbd_state == KBD_STATE_COMPKEY_PRESSED ||
            cons->kbd_state == KBD_STATE_UNICODE) {
            wchar_t ch = wParam;
            unsigned char scancode = (lParam >> 16) & 0x7f;

            uxenconsole_keyboard_event(
                    cons->ctx,
                    cons->kbd_last_key,
                    lParam & 0xffff,
                    scancode,
                    (lParam >> 24) | KEYBOARD_EVENT_FLAG_UCS2,
                    &ch, 1, NULL, 0);
            uxenconsole_keyboard_event(
                    cons->ctx,
                    cons->kbd_last_key,
                    lParam & 0xffff,
                    scancode | 0x80,
                    (lParam >> 24) | KEYBOARD_EVENT_FLAG_UCS2,
                    &ch, 1, NULL, 0);
            return 0;
        }
        break;
    case WM_MOVING:
        {
            RECT src;
            RECT *dst = (RECT *)lParam;

            GetWindowRect(hwnd, &src);
            dst->right = dst->left + (src.right - src.left);
            dst->bottom = dst->top + (src.bottom - src.top);
        }
        return TRUE;
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
                !hid_touch_event(cons, touch_info, count)) {
                FN_SkipPointerFrameMessages(id);
                return 0;
            }

            count = 32;
            if (FN_GetPointerFramePenInfo(id, &count, pen_info) &&
                !hid_pen_event(cons, pen_info, count)) {
                FN_SkipPointerFrameMessages(id);
                return 0;
            }
        }
        break;
    case WM_WINDOWPOSCHANGING:
        {
            WINDOWPOS *p = (WINDOWPOS *)lParam;
            if (p->flags & (SWP_NOSIZE | SWP_DRAWFRAME))
                break;
            if (resize_window(cons, p->cx, p->cy)) {
                RECT r;
                GetWindowRect(hwnd, &r);
                p->cx = r.right - r.left;
                p->cy = r.bottom - r.top;
                return 0;
            }
        }
        break;
    case WM_CLOSE:
        cons->stop = 1;
        return 0;
    default:
        break;
    }

    return DefWindowProcW(hwnd, message, wParam, lParam);
}

static int
create_window(struct console *cons)
{
    WNDCLASSEXW wndclass;

    wndclass.cbSize         = sizeof(wndclass);
    wndclass.style          = 0;
    wndclass.lpfnWndProc    = window_proc;
    wndclass.cbClsExtra     = 0;
    wndclass.cbWndExtra     = 0;
    wndclass.hInstance      = cons->instance;
    wndclass.hIcon          = LoadIcon(NULL, IDI_APPLICATION);
    wndclass.hIconSm        = LoadIcon(NULL, IDI_APPLICATION);
    wndclass.hCursor        = LoadCursor(NULL, IDC_ARROW);
    wndclass.hbrBackground  = (HBRUSH)GetStockObject(WHITE_BRUSH);
    wndclass.lpszClassName  = L"uXenConsole";
    wndclass.lpszMenuName   = NULL;
    if (!RegisterClassExW(&wndclass))
        Werr(1, "RegisterClassEx failed");

    cons->window = CreateWindowExW(WS_EX_CLIENTEDGE,
                                   L"uXenConsole",
                                   L"uXen console",
                                   (WS_OVERLAPPEDWINDOW & ~(WS_MAXIMIZEBOX)),
                                   CW_USEDEFAULT,
                                   CW_USEDEFAULT,
                                   CW_USEDEFAULT,
                                   CW_USEDEFAULT,
                                   NULL,
                                   NULL,
                                   NULL,
                                   NULL);

    if (cons->window == NULL)
        Werr(1, "CreateWindowEx failed");
    if (!IsWindowUnicode(cons->window))
        errx(1, "Window is not unicode");

    printf("created window %p\n", cons->window);

    SetWindowLongPtr(cons->window, GWLP_USERDATA, (LONG_PTR)cons);

    reset_mouse_tracking(cons->window);

    return 0;
}

static int
release_surface(struct console *cons)
{
    if (cons->surface) {
        DeleteObject(cons->surface);
        cons->surface = NULL;
    }
    if (cons->dc) {
        DeleteDC(cons->dc);
        cons->dc = NULL;
    }
    if (cons->surface_handle) {
        CloseHandle(cons->surface_handle);
        cons->surface_handle = NULL;
    }

    return 0;
}

static int
alloc_surface(struct console *cons,
              unsigned int width,
              unsigned int height,
              unsigned int linesize,
              unsigned int length,
              unsigned int bpp,
              unsigned int offset,
              HANDLE shm_handle)
{
    HDC hdc;
    BITMAPINFO bmi;

    if (linesize != (width * 4) || bpp != 32) {
        warnx("Invalid surface format");
        return -1;
    }

    cons->surface_handle = shm_handle;

    hdc = GetDC(cons->window);
    cons->dc = CreateCompatibleDC(hdc);
    if (!cons->dc) {
        Wwarn("CreateCompatibleDC");
        ReleaseDC(cons->window, hdc);
        CloseHandle(cons->surface_handle); cons->surface_handle = NULL;
        return -1;
    }
    ReleaseDC(cons->window, hdc);

    bmi.bmiHeader.biSize = sizeof(BITMAPINFOHEADER);
    bmi.bmiHeader.biWidth = width;
    bmi.bmiHeader.biHeight = -height;
    bmi.bmiHeader.biPlanes = 1;
    bmi.bmiHeader.biBitCount = 32;
    bmi.bmiHeader.biCompression = BI_RGB;
    bmi.bmiHeader.biSizeImage = width * height * 4;

    cons->surface = CreateDIBSection(cons->dc, &bmi,
                                     DIB_RGB_COLORS,
                                     &cons->surface_bits,
                                     cons->surface_handle, offset);
    if (!cons->surface) {
        Wwarn("CreateDIBSection");
        DeleteDC(cons->dc); cons->dc = NULL;
        CloseHandle(cons->surface_handle); cons->surface_handle = NULL;
        return -1;
    }
    SelectObject(cons->dc, cons->surface);

    return 0;
}

static void
console_resize_surface(void *priv,
                       unsigned int width,
                       unsigned int height,
                       unsigned int linesize,
                       unsigned int length,
                       unsigned int bpp,
                       unsigned int offset,
                       HANDLE shm_handle)
{
    struct console *cons = priv;
    int ret;
    RECT inner, outer;
    int borderX, borderY;

    release_surface(cons);

    if (!cons->window)
        create_window(cons);

    GetClientRect(cons->window, &inner);
    GetWindowRect(cons->window, &outer);

    borderX = (outer.right - outer.left) - (inner.right - inner.left);
    borderY = (outer.bottom - outer.top) - (inner.bottom - inner.top);

    SetWindowPos(cons->window, HWND_NOTOPMOST,
                 CW_USEDEFAULT, CW_USEDEFAULT,
                 width + borderX, height + borderY,
                 SWP_NOMOVE);

    cons->width = width;
    cons->height = height;

    ret = alloc_surface(cons, width, height, linesize, length, bpp, offset, shm_handle);
    if (ret)
        errx(1, "alloc_surface failed");

    ShowWindow(cons->window, cons->show);
    UpdateWindow(cons->window);

    cons->resize_pending = 0;
}

static void
console_invalidate_rect(void *priv,
                        int x,
                        int y,
                        int w,
                        int h)
{
    struct console *cons = priv;
    RECT r = { x, y, x + w, y + h };

    InvalidateRect(cons->window, &r, FALSE);
    UpdateWindow(cons->window);
}

static void
console_update_cursor(void *priv,
                      unsigned int width,
                      unsigned int height,
                      unsigned int hot_x,
                      unsigned int hot_y,
                      unsigned int mask_offset,
                      unsigned int flags,
                      HANDLE shm_handle)
{
    struct console *cons = priv;
    unsigned char hidden_cursor[8] = { 0xff, 0xff, 0x00, 0x00 };
    HCURSOR hcursor;
    ICONINFO icon;

    icon.fIcon = FALSE; /* This is a cursor */
    icon.xHotspot = hot_x;
    icon.yHotspot = hot_y;
    icon.hbmColor = NULL;

    if (flags & CURSOR_UPDATE_FLAG_HIDE) {
        icon.hbmMask = CreateBitmap(1, 1 * 2, 1, 1, hidden_cursor);
    } else {
        size_t mask_len = (width * height + 7) / 8;
        size_t shm_len = (mask_offset) ? mask_len + mask_offset : width * 4 * height;
        char *p = (char *)MapViewOfFile(shm_handle, FILE_MAP_ALL_ACCESS, 0, 0,
                                  shm_len);
        if (!p) {
            Wwarn("MapViewOfFile");
            CloseHandle(shm_handle);
            return;
        }

        if (flags & CURSOR_UPDATE_FLAG_MONOCHROME) {
            icon.hbmMask = CreateBitmap(width, height * 2, 1, 1, p + mask_offset);
        } else if (mask_offset != 0) {
            icon.hbmMask = CreateBitmap(width, height, 1, 1, p + mask_offset);
            icon.hbmColor = CreateBitmap(width, height, 1, 32, p);
        } else {
            icon.hbmMask = CreateBitmap(width, height, 1, 1, NULL);
            icon.hbmColor = CreateBitmap(width, height, 1, 32, p);
        }

        UnmapViewOfFile(p);
    }

    hcursor = CreateIconIndirect(&icon);
    if (hcursor) {
        SetClassLongPtr(cons->window, GCLP_HCURSOR, (LONG_PTR)hcursor);
        SetCursor(hcursor);
        if (cons->cursor)
            DestroyIcon(cons->cursor);
        cons->cursor = hcursor;
    }

    DeleteObject(icon.hbmMask);
    if (icon.hbmColor)
        DeleteObject(icon.hbmColor);
}

static void
console_keyboard_ledstate(void *priv, int state)
{
    struct console *cons = priv;

    printf("Keyboard LED=%x\n", state);
    cons->kbd_ledstate = state;
}

static void
console_disconnected(void *priv)
{
    struct console *cons = priv;

    printf("disconnected\n");
    cons->stop = 1;
}

static int save_screenshot(struct console *cons)
{
    BITMAPFILEHEADER bmfh;
    BITMAPINFOHEADER bmih;
    HANDLE f = INVALID_HANDLE_VALUE;
    DWORD written = 0;
    wchar_t filename[256];
    BOOL ok = FALSE;

    swprintf(filename, L"%s%04d.bmp", screenshot_path, screenshot_idx++);

    if (!cons->surface_handle) {
        Wwarn("save_screenshot");
        return -1;
    }
    f = CreateFileW(filename, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL, NULL);
    if (f == INVALID_HANDLE_VALUE) {
        Wwarn("save_screenshot CreateFileW");
        return -1;
    }

    bmfh.bfType = 0x4d42; /* Magic number for .bmp files */
    bmfh.bfReserved1 = bmfh.bfReserved2 = 0;
    bmih.biSize = sizeof(BITMAPINFOHEADER);
    bmih.biWidth = cons->width;
    bmih.biHeight = -cons->height;
    bmih.biPlanes = 1;
    bmih.biBitCount = 32;
    bmih.biCompression = BI_RGB;
    bmih.biSizeImage = cons->width * cons->height * 4;

    ok = WriteFile(f, &bmfh, sizeof(BITMAPFILEHEADER), &written, NULL);
    if (!ok) goto out;
    ok = WriteFile(f, &bmih, sizeof(BITMAPINFOHEADER), &written, NULL);
    if (!ok) goto out;
    bmfh.bfOffBits = SetFilePointer(f, 0, NULL, FILE_CURRENT);
    ok = WriteFile(f, cons->surface_bits, bmih.biSizeImage, &written, NULL);
    if (!ok) goto out;
    bmfh.bfSize = SetFilePointer(f, 0, NULL, FILE_CURRENT);
    SetFilePointer(f, 0, 0, FILE_BEGIN);
    ok = WriteFile(f, &bmfh, sizeof(BITMAPFILEHEADER), &written, NULL);

out:
    if (!ok) {
        FILE_DISPOSITION_INFO info;
        info.DeleteFile = TRUE;
        Wwarn("save_screenshot WriteFile");
        SetFileInformationByHandle(f, FileDispositionInfo, &info, sizeof(info));
    }
    CloseHandle(f);
    return ok ? 0 : -1;
}

static ConsoleOps console_ops = {
    .resize_surface = console_resize_surface,
    .invalidate_rect = console_invalidate_rect,
    .update_cursor = console_update_cursor,
    .keyboard_ledstate = console_keyboard_ledstate,

    .disconnected = console_disconnected,
};

static int
main_loop(struct console *cons)
{
    HANDLE events[1];
    DWORD w;
    int ret = 0;
    int64_t next_screenshot = 0;
    int64_t t;
    DWORD wait;

    if (screenshot_interval) {
        next_screenshot = GetTickCount64();
    }

    events[0] = cons->channel_event;

    while (!cons->stop) {
        wait = INFINITE;
        if (next_screenshot) {
            t = GetTickCount64();
            if (t >= next_screenshot && cons->surface_handle) {
                save_screenshot(cons);
                next_screenshot = t + screenshot_interval;
            }
            wait = (t >= next_screenshot) ? INFINITE : (DWORD)(next_screenshot - t);
        }

        w = MsgWaitForMultipleObjectsEx(1, events, wait, QS_ALLINPUT, MWMO_ALERTABLE);
        switch (w) {
        case WAIT_IO_COMPLETION:
            break;
        case WAIT_OBJECT_0:
            {
                uxenconsole_channel_event(cons->ctx, cons->channel_event, 0);
            }
            break;
        case WAIT_OBJECT_0 + 1:
            if (cons->window) {
                MSG msg;

                while (PeekMessageW(&msg, NULL, 0, 0, PM_REMOVE)) {
                    TranslateMessage(&msg);
                    DispatchMessageW(&msg);
                }

                if (!cons->resize_pending &&
                    (cons->width != cons->requested_width ||
                     cons->height != cons->requested_height)) {
                    cons->resize_pending = 1;
                    uxenconsole_request_resize(cons->ctx,
                                               cons->requested_width,
                                               cons->requested_height,
                                               0,
                                               CONSOLE_RESIZE_FLAG_NONE);
                    cons->requested_width = 0;
                    cons->requested_height = 0;
                }
            }
            break;
        case WAIT_TIMEOUT:
            /* Go round loop again to take screenshot */
            break;
        default:
            Wwarn("MsgWaitForMultipleObjects");
            ret = -1;
            goto out;
        }

    }
out:
    if (cons->window) {
        DestroyWindow(cons->window);
        cons->window = NULL;
    }
    return ret;
}

/* Convert a wide string to CP_ACP. */
static char *
cp_acp(const wchar_t *ws)
{
    int sz;
    char *s;

    /* First figure out buffer size needed and malloc it. */
    sz = WideCharToMultiByte(CP_ACP, 0, ws, -1, NULL, 0, NULL, 0);
    if (!sz)
        return NULL;

    s = (char *)malloc(sz + sizeof(char));
    if (s == NULL)
        return NULL;
    s[sz] = 0;

    /* Now perform the actual conversion. */
    sz = WideCharToMultiByte(CP_ACP, 0, ws, -1, s, sz, NULL, 0);
    if (!sz) {
        free(s);
        s = NULL;
    }

    return s;
}

/* Convert a CP_ACP narrow string to a wide string. */
static wchar_t *
wide(const char *s)
{
    /* First figure out buffer size needed and malloc it. */
    int sz;
    wchar_t *ws;

    sz = MultiByteToWideChar(CP_ACP, 0, s, -1, NULL, 0);
    if (!sz)
        return NULL;

    ws = (wchar_t *)malloc(sizeof(wchar_t) * (sz + 1));
    if (!ws)
        return NULL;
    ws[sz] = 0;

    /* Now perform the actual conversion. */
    sz = MultiByteToWideChar(CP_ACP, 0, s, -1, ws, sz);
    if (!sz) {
        free(ws);
        ws = NULL;
    }
    return ws;
}

/*
 * Syntax: uxenconsole.exe [options] <pipe> [<domid>]
 * Options: -s|--screenshotprefix <screenshot_prefix>
 *          -i|--interval <screenshot_interval>
 */

int WINAPI
WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance,
        LPSTR lpCmdLine, int iCmdShow)
{
    struct console cons;
    int ret;
    int argc, i;
    wchar_t **argv_w;
    char **argv;
    char *pipename;
    int interval;
    STARTUPINFO si;
    int domid = 0;
    unsigned char idtoken[16] = { };
    int have_id = 0;

    memset(&cons, 0, sizeof (cons));
    cons.instance = hInstance;
    cons.show = iCmdShow;
    if (iCmdShow == SW_SHOWDEFAULT) {
        GetStartupInfo(&si);
        if (si.dwFlags & STARTF_USESHOWWINDOW) {
            cons.show = si.wShowWindow;
        }
    }

    argv_w = CommandLineToArgvW(GetCommandLineW(), &argc);

    /* Create non-wide-char argv */
    argv = (char **)malloc(sizeof(char *) * argc);
    if (argv == NULL)
        err(1, "malloc");

    for (i = 0; i < argc; i++) {
        argv[i] = cp_acp(argv_w[i]);
        if (!argv[i])
            errx(1, "cp_acp(arg %d)", i);
    }

    setprogname(argv[0]);

    static const struct option long_options[] = {
        {"interval",         required_argument, NULL, 'i'},
        {"screenshotprefix", required_argument, NULL, 's'},
        {NULL,               0,                 NULL, 0}
    };

    while (1) {
        int c = getopt_long(argc, argv, "i:s:", long_options, NULL);
        if (c == -1)
            break;
        switch (c) {
            case 's':
                /* getopt permutes the argument order so there is no easy way
                 * to recover the original wide string pointer from argv_w */
                screenshot_path = wide(optarg);
                if (!screenshot_path) {
                    errx(1, "Error converting %s", optarg);
                }
                break;
            case 'i':
                if (sscanf(optarg, "%d", &interval) == 1) {
                    /* screenshot_interval is in ms */
                    screenshot_interval = interval * 1000;
                }
                break;
            default:
                break;
        }
    }
    /* At this point optind points to the first non-option argument */

    if (optind >= argc)
        errx(1, "usage: %s [options] pipename [idtoken]", argv[0]);

    pipename = argv[optind];
    optind++;

    if (optind < argc) {
        have_id = 1;
        if (!uuid_parse(argv[optind], idtoken))
            domid = -1;
        else if (sscanf(argv[optind], "%d", &domid) != 1)
            have_id = 0;
        optind++;
    }

    cons.ctx = uxenconsole_init(&console_ops, &cons, pipename);
    if (!cons.ctx)
        Werr(1, "uxenconsole_init");

    if (have_id) {
        cons.disp = uxenconsole_disp_init(domid, idtoken, &cons,
                                          console_invalidate_rect);
        if (!cons.disp)
            Werr(1, "uxenconsole_disp_init");
        cons.hid = uxenconsole_hid_init(domid, idtoken);
    } else {
        cons.disp = NULL;
        cons.hid = NULL;
    }

    printf("Connecting to %s\n", pipename);
    cons.channel_event = uxenconsole_connect(cons.ctx);
    if (!cons.channel_event)
        Werr(1, "uxenconsole_connect");
    printf("Connected\n");
    ret = main_loop(&cons);

    if (cons.disp)
        uxenconsole_disp_cleanup(cons.disp);
    uxenconsole_cleanup(cons.ctx);

    return ret;
}
