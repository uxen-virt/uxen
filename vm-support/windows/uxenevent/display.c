/*
 * Copyright 2013-2015, Bromium, Inc.
 * Author: Julian Pidancet <julian@pidancet.net>
 * SPDX-License-Identifier: ISC
 */

#include <windows.h>
#include <tchar.h>

#include <err.h>
#include <stdio.h>
#include <stdlib.h>

#include <uxendisp_esc.h>

#include "uxenevent.h"
#include "d3dkmthk_x.h"

static HDC hdc;
static D3DKMT_HANDLE disp_adapter = 0;
static DISPLAY_DEVICE dispDevice;
static HWND blank_window;
static HANDLE blank_thread;
static int blanking = 0;
static int current_w = 0;
static int current_h = 0;

int
display_get_size(int *w, int *h)
{
    if (w) *w = current_w;
    if (h) *h = current_h;
    return 0;
}

static int
display_escape(int escape_code, void *in_buf, int in_buf_size)
{
    D3DKMT_ESCAPE escape;
    NTSTATUS status;
    int ret;

    if (disp_adapter) {
        /* for now assume there is only one kind of escape call for wddm */
        escape.hAdapter = disp_adapter;
        escape.hDevice = 0;
        escape.Type = D3DKMT_ESCAPE_DRIVERPRIVATE;
        escape.Flags.Value = 0;
        escape.Flags.HardwareAccess = 1;
        escape.pPrivateDriverData = in_buf;
        escape.PrivateDriverDataSize = in_buf_size;
        escape.hContext = 0;
        ret = !NT_SUCCESS(status = D3DKMTEscape(&escape));
        if (ret)
            warnx("D3DKMTEscape() failed: 0x%x", (unsigned int)status);
    } else {
        ret = ExtEscape(hdc, escape_code, in_buf_size, in_buf, 0, NULL);
        if (ret <= 0)
            warnx("ExtEscape() failed: %d", ret);
        ret = ret <= 0;
    }

    return ret;
}

int
display_resize(int w, int h)
{
    UXENDISPCustomMode cm;
    DWORD mode = 0;
    DEVMODE devMode;
    LONG status;
    BOOL rc;

    cm.width = w;
    cm.height = h;
    if (display_escape(UXENDISP_ESCAPE_SET_CUSTOM_MODE, &cm, sizeof(cm))) {
        warnx("failed to inject custom mode [%dx%d]", w, h);
        return -1;
    }

    FillMemory(&devMode, sizeof(DEVMODE), 0);
    devMode.dmSize = sizeof(DEVMODE);
    while ((rc = EnumDisplaySettings(dispDevice.DeviceName, mode, &devMode))) {

        if (devMode.dmPelsWidth == w && devMode.dmPelsHeight == h)
            break;

        mode++;
    }

    if (!disp_adapter && !rc) {
        warnx("couldn't find desired mode %dx%d", w, h);
        return -1;
    }

    devMode.dmFields = DM_BITSPERPEL | DM_PELSWIDTH | DM_PELSHEIGHT;

    status = ChangeDisplaySettingsEx(dispDevice.DeviceName,
                                     &devMode,
                                     NULL,
                                     0,
                                     NULL);
    if (status != DISP_CHANGE_SUCCESSFUL) {
        warnx("couldn't change display settings");
        return -1;
    }

    current_w = w;
    current_h = h;

    if (blanking)
        SetWindowPos(blank_window, HWND_TOPMOST,
                     0, 0,
                     current_w, current_h,
                     SWP_SHOWWINDOW);

    return 0;
}

void
display_blank(int blank)
{
    debug_log("%s blank=%d", __FUNCTION__, blank);

    if (blank)
        SetWindowPos(blank_window, HWND_TOPMOST,
                     0, 0,
                     current_w, current_h,
                     SWP_SHOWWINDOW);
    else
        ShowWindow(blank_window, SW_HIDE);

    blanking = blank;
}

static DWORD WINAPI
blank_loop(void *opaque)
{
    WNDCLASSEX wndclass;
    MSG msg;
    BOOL rc;

    wndclass.cbSize         = sizeof(wndclass);
    wndclass.style          = 0;
    wndclass.lpfnWndProc    = DefWindowProc;
    wndclass.cbClsExtra     = 0;
    wndclass.cbWndExtra     = 0;
    wndclass.hInstance      = (HINSTANCE)GetModuleHandle(NULL);
    wndclass.hIcon          = LoadIcon(NULL, IDI_APPLICATION);
    wndclass.hIconSm        = LoadIcon(NULL, IDI_APPLICATION);
    wndclass.hCursor        = LoadCursor(NULL, IDC_ARROW);
    wndclass.hbrBackground  = (HBRUSH)GetStockObject(BLACK_BRUSH);
    wndclass.lpszClassName  = "BlankWindow";
    wndclass.lpszMenuName   = NULL;
    RegisterClassEx(&wndclass);

    blank_window = CreateWindowEx(0,
                                  "BlankWindow",
                                  "Blank Window",
                                  WS_POPUP,
                                  0, 0,
                                  current_w, current_h,
                                  NULL, NULL,
                                  (HINSTANCE)GetModuleHandle(NULL),
                                  NULL);
    if (!blank_window) {
        warnx("failed to create blank window");
        return -1;
    }

    ShowWindow(blank_window, SW_HIDE);

    rc = GetMessage(&msg, NULL, 0, 0);
    while (rc > 0) {
        DispatchMessage(&msg);
        rc = GetMessage(&msg, NULL, 0, 0);
    }

    return 0;
}

int
display_init(void)
{
    BOOL rc;
    INT devNum = 0;
    DEVMODE devMode;
    NTSTATUS status;
    D3DKMT_OPENADAPTERFROMHDC open_adapter_info;

    /* Sanity check here */
    FillMemory(&dispDevice, sizeof(DISPLAY_DEVICE), 0);
    dispDevice.cb = sizeof(DISPLAY_DEVICE);
    while ((rc = EnumDisplayDevices(NULL, devNum, &dispDevice, 0))) {
        if (!_tcsncmp(dispDevice.DeviceString, _T("uXen Display"),
                      sizeof (dispDevice.DeviceString)))
            break;

        ++devNum;
    }

    if (!rc) {
        warnx("failed to find uXen Display");
        return -1;
    }

    FillMemory(&devMode, sizeof(DEVMODE), 0);
    devMode.dmSize = sizeof(DEVMODE);
    rc = EnumDisplaySettings(dispDevice.DeviceName, ENUM_CURRENT_SETTINGS, &devMode);

    if (!rc) {
        warnx("failed to retrieve current settings for uXen Display");
        return -1;
    }

    current_w = devMode.dmPelsWidth;
    current_h = devMode.dmPelsHeight;

    hdc = CreateDC(dispDevice.DeviceName, dispDevice.DeviceName, NULL, NULL);
    if (!hdc) {
        warnx("failed to create device context: %d", (int)GetLastError());
        return -1;
    }

    /* open WDDM interface if possible */
    memset(&open_adapter_info, 0, sizeof (open_adapter_info));
    open_adapter_info.hDc = hdc;
    status = D3DKMTOpenAdapterFromHdc(&open_adapter_info);
    if (NT_SUCCESS(status))
        disp_adapter = open_adapter_info.hAdapter;

    blank_thread = CreateThread(NULL, 0, blank_loop, NULL, 0, NULL);
    if (!blank_thread) {
        warnx("failed to create blanking thread");
        return -1;
    }

    return 0;
}
