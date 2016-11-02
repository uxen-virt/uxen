/*
 * Copyright 2013-2016, Bromium, Inc.
 * Author: Julian Pidancet <julian@pidancet.net>
 * SPDX-License-Identifier: ISC
 */

#include <windows.h>
#include <Windowsx.h>
#include <Sddl.h>
#include <tchar.h>
#define __CRT_STRSAFE_IMPL
#include <Strsafe.h>
#include <Setupapi.h>

#include <uxendisp_esc.h>

#include "uxenevent.h"
#include "d3dkmthk_x.h"
#include "hid_interface.h"
#include "uxenconsolelib.h"

static HDC hdc;
static D3DKMT_HANDLE disp_adapter = 0;
static DISPLAY_DEVICE dispDevice;
static HWND blank_window;
static HWND right_window;
static HWND bottom_window;
static HANDLE blank_thread;
static int blanking = 0;
static int virtual_w = 0;
static int virtual_h = 0;
static int current_w = 0;
static int current_h = 0;
static int virtual_mode_change = 0;

void display_border_windows_on_top()
{
    if (right_window) {
        SetWindowPos(right_window, HWND_TOPMOST, 0, 0, 0, 0,
                         SWP_NOMOVE | SWP_NOSIZE);
    }

    if (bottom_window) {
        SetWindowPos(bottom_window, HWND_TOPMOST, 0, 0, 0, 0,
                         SWP_NOMOVE | SWP_NOSIZE);
    }
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
            debug_log("D3DKMTEscape() failed: 0x%x", (unsigned int)status);
    } else {
        ret = ExtEscape(hdc, escape_code, in_buf_size, in_buf, 0, NULL);
        if (ret <= 0)
            debug_log("ExtEscape() failed: %d", ret);
        ret = ret <= 0;
    }

    return ret;
}

static VOID
SendResolutionToHidDriver()
{
    SP_DEVICE_INTERFACE_DATA did = {sizeof did};
    HDEVINFO hdev;
    BOOL res;
    BYTE buffer[1024];
    DWORD size;
    PSP_DEVICE_INTERFACE_DETAIL_DATA pdidd = (PSP_DEVICE_INTERFACE_DETAIL_DATA)buffer;
    HANDLE devhdl = INVALID_HANDLE_VALUE;
    struct virt_mode mode = {virtual_w, virtual_h, current_w, current_h};
    DWORD last_error;
    DWORD dev_idx = 0;

    hdev = SetupDiGetClassDevs(&UXENHID_IFACE_GUID, 0, 0, DIGCF_PRESENT | DIGCF_DEVICEINTERFACE);
    if (INVALID_HANDLE_VALUE == hdev) {
        debug_log("SetupDiGetClassDevs failed");
        goto exit;
    }

    for (;;) {
        res = SetupDiEnumDeviceInterfaces(hdev, 0, &UXENHID_IFACE_GUID, dev_idx, &did);
        last_error = GetLastError();
        if (!res && (last_error != ERROR_NO_MORE_ITEMS)) {
            debug_log("SetupDiEnumDeviceInterfaces failed");
            goto exit;
        }

        if (last_error == ERROR_NO_MORE_ITEMS)
            break;

        pdidd->cbSize = sizeof *pdidd;
        size = sizeof buffer;
        res = SetupDiGetDeviceInterfaceDetail(hdev, &did, pdidd, size, &size, 0);
        if (!res) {
            debug_log("SetupDiGetDeviceInterfaceDetail failed");
            goto exit;
        }

        devhdl = CreateFile(pdidd->DevicePath, GENERIC_READ | GENERIC_WRITE,
                            FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING,
                            FILE_ATTRIBUTE_NORMAL, NULL);
        if (INVALID_HANDLE_VALUE == devhdl) {
            debug_log("CreateFile failed");
            goto exit;
        }

        res = DeviceIoControl(devhdl, IOCTL_UXENHID_SET_VIRTUAL_MODE,
                              &mode, sizeof mode, NULL, 0, &size, NULL);
        if (!res) {
            debug_log("DeviceIoControl failed");
            goto exit;
        }

        CloseHandle(devhdl);
        devhdl = INVALID_HANDLE_VALUE;
        dev_idx++;
    }

exit:
    if (devhdl != INVALID_HANDLE_VALUE)
        CloseHandle(devhdl);

    if (hdev != INVALID_HANDLE_VALUE)
        SetupDiDestroyDeviceInfoList(hdev);
}

int
display_resize(int w, int h, unsigned int flags)
{
    UXENDISPCustomMode cm;
    BOOL set_mode = (current_w < w) || (current_h < h);
    BOOL force_change = (flags & CONSOLE_RESIZE_FLAG_FORCE) != 0;

    if (set_mode || !virtual_mode_change || force_change) {
        DWORD mode = 0;
        DEVMODE devMode;
        LONG status;
        BOOL rc;

        if (virtual_mode_change && !force_change) {
            w = max(w, current_w);
            h = max(h, current_h);
        }

        cm.esc_code = UXENDISP_ESCAPE_SET_CUSTOM_MODE;
        cm.width = w;
        cm.height = h;
        if (display_escape(UXENDISP_ESCAPE_SET_CUSTOM_MODE, &cm, sizeof(cm))) {
            debug_log("failed to inject custom mode [%dx%d]", w, h);
            return -1;
        }

        if (!disp_adapter) {
            FillMemory(&devMode, sizeof(DEVMODE), 0);
            devMode.dmSize = sizeof(DEVMODE);
            while ((rc = EnumDisplaySettings(dispDevice.DeviceName, mode, &devMode))) {
                if (devMode.dmPelsWidth == w && devMode.dmPelsHeight == h)
                    break;
                mode++;
            }

            if (!rc) {
                debug_log("couldn't find desired mode %dx%d", w, h);
                return -1;
            }

            devMode.dmFields = DM_BITSPERPEL | DM_PELSWIDTH | DM_PELSHEIGHT;

            status = ChangeDisplaySettingsEx(dispDevice.DeviceName,
                                             &devMode,
                                             NULL,
                                             CDS_RESET,
                                             NULL);
            if (status != DISP_CHANGE_SUCCESSFUL) {
                debug_log("couldn't change display settings");
                return -1;
            }
        }

        current_w = w;
        current_h = h;
    }

    virtual_w = w;
    virtual_h = h;

    if (blanking)
        SetWindowPos(blank_window, HWND_TOPMOST, 0, 0, w, h, SWP_SHOWWINDOW);

    if (!virtual_mode_change)
        return 0;

    if (!set_mode && !force_change) {
        cm.esc_code = UXENDISP_ESCAPE_SET_VIRTUAL_MODE;
        cm.width = w;
        cm.height = h;
        if (display_escape(UXENDISP_ESCAPE_SET_VIRTUAL_MODE, &cm, sizeof(cm))) {
            debug_log("failed to inject virtual mode [%dx%d]", w, h);
            return -1;
        }
    }

    SendResolutionToHidDriver();

    if (virtual_w != current_w)
        SetWindowPos(right_window, HWND_TOPMOST, virtual_w, 0, current_w, current_h, SWP_SHOWWINDOW);
    else
        ShowWindow(right_window, SW_HIDE);

    if (virtual_h != current_h)
        SetWindowPos(bottom_window, HWND_TOPMOST, 0, virtual_h, current_w, current_h, SWP_SHOWWINDOW);
    else
        ShowWindow(bottom_window, SW_HIDE);

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
    DWORD ret = 0;

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

    blank_window = CreateWindowEx(0, "BlankWindow", "Blank Window", WS_POPUP,
                                  0, 0, current_w, current_h,
                                  NULL, NULL, NULL, NULL);
    if (!blank_window) {
        debug_log("failed to create blank window");
        ret = -1;
        goto exit;
    }
    ShowWindow(blank_window, SW_HIDE);

    right_window = CreateWindowEx(WS_EX_TOPMOST | WS_EX_TOOLWINDOW, "BlankWindow", "Right Window",
                                  WS_POPUP, virtual_w, 0, virtual_w + 1, virtual_h,
                                  NULL, NULL, NULL, NULL);
    if (!right_window) {
        debug_log("failed to create right window");
        ret = -1;
        goto exit;
    }
    ShowWindow(right_window, SW_HIDE);

    bottom_window = CreateWindowEx(WS_EX_TOPMOST | WS_EX_TOOLWINDOW, "BlankWindow", "Bottom Window",
                                   WS_POPUP, 0, virtual_h, virtual_w, virtual_h + 1,
                                   NULL, NULL, NULL, NULL);
    if (!bottom_window) {
        debug_log("failed to create bottom window");
        ret = -1;
        goto exit;
    }
    ShowWindow(bottom_window, SW_HIDE);

    rc = GetMessage(&msg, NULL, 0, 0);
    while (rc > 0) {
        DispatchMessage(&msg);
        rc = GetMessage(&msg, NULL, 0, 0);
    }

exit:
    if (bottom_window)
        DestroyWindow(bottom_window);
    if (right_window)
        DestroyWindow(right_window);
    if (blank_window)
        DestroyWindow(blank_window);
    return ret;
}

int
display_init(void)
{
    BOOL rc;
    INT devNum = 0;
    DEVMODE devMode;
    NTSTATUS status;
    D3DKMT_OPENADAPTERFROMHDC open_adapter_info;
    UXENDISPCustomMode cm;

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
        debug_log("failed to find uXen Display");
        return -1;
    }

    FillMemory(&devMode, sizeof(DEVMODE), 0);
    devMode.dmSize = sizeof(DEVMODE);
    rc = EnumDisplaySettings(dispDevice.DeviceName, ENUM_CURRENT_SETTINGS, &devMode);

    if (!rc) {
        debug_log("failed to retrieve current settings for uXen Display");
        return -1;
    }

    current_w = devMode.dmPelsWidth;
    current_h = devMode.dmPelsHeight;
    virtual_w = current_w;
    virtual_h = current_h;

    hdc = CreateDC(dispDevice.DeviceName, dispDevice.DeviceName, NULL, NULL);
    if (!hdc) {
        debug_log("failed to create device context: %d", (int)GetLastError());
        return -1;
    }

    /* open WDDM interface if possible */
    memset(&open_adapter_info, 0, sizeof (open_adapter_info));
    open_adapter_info.hDc = hdc;
    status = D3DKMTOpenAdapterFromHdc(&open_adapter_info);
    if (NT_SUCCESS(status))
        disp_adapter = open_adapter_info.hAdapter;

    cm.esc_code = UXENDISP_ESCAPE_IS_VIRT_MODE_ENABLED;
    if (display_escape(UXENDISP_ESCAPE_IS_VIRT_MODE_ENABLED, &cm, sizeof(cm))) {
        debug_log("Virtual Mode Change is DISABLED.");
    } else {
        virtual_mode_change = 1;
    }

    blank_thread = CreateThread(NULL, 0, blank_loop, NULL, 0, NULL);
    if (!blank_thread) {
        debug_log("failed to create blanking thread");
        return -1;
    }

    return 0;
}
