/** @file
 * Shared Clipboard: Win32 host.
 */

/*
 * Copyright (C) 2006-2007 Oracle Corporation
 *
 * This file is part of VirtualBox Open Source Edition (OSE), as
 * available from http://www.virtualbox.org. This file is free software;
 * you can redistribute it and/or modify it under the terms of the GNU
 * General Public License (GPL) as published by the Free Software
 * Foundation, in version 2 as it comes in the "COPYING" file of the
 * VirtualBox OSE distribution. VirtualBox OSE is distributed in the
 * hope that it will be useful, but WITHOUT ANY WARRANTY of any kind.
 */
/*
 * uXen changes:
 *
 * Copyright 2012-2015, Bromium, Inc.
 * SPDX-License-Identifier: ISC
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
 * SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION
 * OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
 * CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#define BROMIUM_CHANGES 1
#include "os.h"
#include <windows.h>

#include "VBoxClipboardSvc.h"

#include <iprt/alloc.h>
#include <iprt/string.h>
#include <iprt/assert.h>
#include <process.h>

#include "VBoxClipboard.h"
#include "clipboardformats.h"
#include "clipboard-interface.h"
#include "uxen_bmp_convert.h"
#include "vm.h"
#include "dm.h"
#include "control.h"
#include "bh.h"

#undef dprintf
#define dprintf Log

static char gachWindowClassName[] = "VBoxSharedClipboardClass";

#define VSENTRY_UNSUPPORTED_FORMAT_MSG L"This object originated from an untrusted document and could not be copied into the clipboard."
#define MAGIC_LPARAM_UNSUPPORTED_FORMAT 0xdeadcde

enum { CBCHAIN_TIMEOUT = 5000 /* ms */ };

struct _VBOXCLIPBOARDCONTEXT
{
    HWND    hwnd;
    HWND    hwndNextInChain;

    UINT     timerRefresh;

    bool     fCBChainPingInProcess;

    RTTHREAD thread;
    bool volatile fTerminate;

    HANDLE hRenderEvent;
    HANDLE hRenderAllEvent;

    VBOXCLIPBOARDCLIENTDATA *pClient;
    int owner;
};

#define CLIPBOARD_TIMEOUT (20 * 1000)

/* Only one client is supported. There seems to be no need for more clients. */
static VBOXCLIPBOARDCONTEXT g_ctx;

#if 0
/* Dumping clipboard data to log files is way beyond the line. */
void vboxClipboardDump(const void *pv, size_t cb, uint32_t u32Format)
{
    if (u32Format & VBOX_SHARED_CLIPBOARD_FMT_UNICODETEXT)
    {
        Log(("DUMP: VBOX_SHARED_CLIPBOARD_FMT_UNICODETEXT:\n"));
        if (pv && cb)
        {
            Log(("%ls\n", pv));
        }
        else
        {
            Log(("%p %d\n", pv, cb));
        }
    }
    else if (u32Format & VBOX_SHARED_CLIPBOARD_FMT_BITMAP)
    {
        dprintf(("DUMP: VBOX_SHARED_CLIPBOARD_FMT_BITMAP\n"));
    }
    else if (u32Format & VBOX_SHARED_CLIPBOARD_FMT_HTML)
    {
        Log(("DUMP: VBOX_SHARED_CLIPBOARD_FMT_HTML:\n"));
        if (pv && cb)
        {
            Log(("%s\n", pv));
        }
        else
        {
            Log(("%p %d\n", pv, cb));
        }
    }
    else
    {
        dprintf(("DUMP: invalid format %02X\n", u32Format));
    }
}
#else
#define vboxClipboardDump(__pv, __cb, __format) do { NOREF(__pv); NOREF(__cb); NOREF(__format); } while (0)
#endif /* LOG_ENABLED */

static void vboxClipboardGetData (uint32_t u32Format, const void *pvSrc, uint32_t cbSrc,
                                  void *pvDst, uint32_t cbDst, uint32_t *pcbActualDst)
{
    dprintf (("vboxClipboardGetData.\n"));

    *pcbActualDst = cbSrc;

    LogFlow(("vboxClipboardGetData cbSrc = %d, cbDst = %d\n", cbSrc, cbDst));

    if (cbSrc > cbDst)
    {
        /* Do not copy data. The dst buffer is not enough. */
        return;
    }

    memcpy (pvDst, pvSrc, cbSrc);

    vboxClipboardDump(pvDst, cbSrc, u32Format);

    return;
}

static int vboxClipboardReadDataFromClient (VBOXCLIPBOARDCONTEXT *pCtx, uint32_t u32Format)
{
    int ret;
    Assert(pCtx->pClient);
    Assert(pCtx->pClient->data.pv == NULL && pCtx->pClient->data.cb == 0 && pCtx->pClient->data.u32Format == 0);

    LogFlow(("vboxClipboardReadDataFromClient u32Format = %02X\n", u32Format));

    ResetEvent (pCtx->hRenderEvent);

    vboxSvcClipboardRequestFormat(u32Format);

    ret = WaitForSingleObject(pCtx->hRenderEvent, CLIPBOARD_TIMEOUT);

    LogFlow(("vboxClipboardReadDataFromClient wait completed, ret 0x%x\n", ret));

    return (ret == WAIT_OBJECT_0) ? VINF_SUCCESS : VERR_TIMEOUT;
}

static void vboxClipboardChanged (VBOXCLIPBOARDCONTEXT *pCtx)
{
    char buf[16384];
    int len = uxenclipboard_prepare_format_announce(buf, sizeof(buf));
    if (len < 0)
        Log(("vboxClipboardChanged:prepare_format_announce %d\n", len));
    else
        vboxSvcClipboardAnnounceFormats(buf, len);
}


#define MAX_OPENCLIPBOARD_RETRIES 10
BOOL OpenClipboardWithRetry(HWND hwnd)
{
    int count = 0;
    while (!OpenClipboard(hwnd) && count < MAX_OPENCLIPBOARD_RETRIES) {
        /* Add PID so that other processes sleep different */
        Sleep((GetCurrentProcessId() & 0x7f) + 100);
        count++;
    }
    return count < MAX_OPENCLIPBOARD_RETRIES;
}

#ifndef WM_CLIPBOARDUPDATE
/* Seriously, its year 2013 here */
#define WM_CLIPBOARDUPDATE 0x031D
#endif

static void render_format_(UINT format, int *status_ptr)
{
    /* Insert the requested clipboard format data into the clipboard. */
    VBOXCLIPBOARDCONTEXT *pCtx = &g_ctx;
    int is_warning_request = (status_ptr && *status_ptr == MAGIC_LPARAM_UNSUPPORTED_FORMAT);

    uint32_t u32Format;
    if (is_warning_request)
        u32Format = format;
    else
        u32Format = uxenclipboard_translate_announced_format(format);
    if (!u32Format) {
        LogRel(("translate_announced_format for 0x%x failed\n", format));
        return;
    }

    LogRel(("render clipboard format 0x%x (remote 0x%x)\n", format, u32Format));

    if (u32Format == 0 || pCtx->pClient == NULL)
    {
        /* Unsupported clipboard format is requested. */
        Log(("WM_RENDERFORMAT unsupported format requested or client is not active.\n"));
        EmptyClipboard ();
    }
    else
    {
        int vboxrc = 0;
        if (is_warning_request)
            vboxClipboardWriteData(pCtx->pClient,
                                   VSENTRY_UNSUPPORTED_FORMAT_MSG,
                                   sizeof(VSENTRY_UNSUPPORTED_FORMAT_MSG),
                                   u32Format);
        else
            vboxrc = vboxClipboardReadDataFromClient(pCtx, u32Format);

        dprintf(("vboxClipboardReadDataFromClient vboxrc = %d\n", vboxrc));
        /* Workaround for broken applications like PowerPoint that
           announce CF_BITMAP as available, but return 0 bytes of data.
        */
        if (RT_SUCCESS (vboxrc) && pCtx->pClient->data.cb == 0 &&
            pCtx->pClient->data.u32Format == 0) {
            dprintf(("vboxClipboard: pClient->data.u32Format == 0\n"));
            return;
        }

        if (   RT_SUCCESS (vboxrc)
               && pCtx->pClient->data.pv != NULL
               && pCtx->pClient->data.cb > 0
               && pCtx->pClient->data.u32Format == u32Format)
        {
            HANDLE hMem = GlobalAlloc (GMEM_DDESHARE | GMEM_MOVEABLE, pCtx->pClient->data.cb);

            dprintf(("hMem %p\n", hMem));

            if (hMem)
            {
                void *pMem = GlobalLock (hMem);

                dprintf(("pMem %p, GlobalSize %d\n", pMem, GlobalSize (hMem)));

                if (pMem)
                {
                    int err;
                    Log(("WM_RENDERFORMAT setting data\n"));

                    if (pCtx->pClient->data.pv)
                    {
                        memcpy (pMem, pCtx->pClient->data.pv, pCtx->pClient->data.cb);

                        RTMemFree (pCtx->pClient->data.pv);
                        pCtx->pClient->data.pv        = NULL;
                    }

                    pCtx->pClient->data.cb        = 0;
                    pCtx->pClient->data.u32Format = 0;

                    /* The memory must be unlocked before inserting to the Clipboard. */
                    GlobalUnlock (hMem);

                    /* 'hMem' contains the host clipboard data.
                     * size is 'cb' and format is 'format'.
                     */
                    HANDLE hClip = SetClipboardData (format, hMem);
                    err = GetLastError();
                    dprintf(("SetClipboardData hClip %p for 0x%x error dec %d\n", hClip, format, err));

                    if (hClip)
                    {
                        /* The hMem ownership has gone to the system. Nothing to do. */
                        if (status_ptr)
                            *status_ptr = 1;
                        return;
                    }
                }

                GlobalFree (hMem);
            }
        }

        RTMemFree (pCtx->pClient->data.pv);
        pCtx->pClient->data.pv        = NULL;
        pCtx->pClient->data.cb        = 0;
        pCtx->pClient->data.u32Format = 0;

        /* Something went wrong. */
        /* EmptyClipboard (); */
    }
}

static void render_format(UINT format, int *status_ptr, int lock)
{
    int pause;

    if (lock)
        critical_section_enter(&vm_pause_lock);
    pause = vm_is_paused() && deferred_clipboard;
    if (pause) {
        LogRel(("clipboard render: unpause/re-pause cycle necessary\n"));
        vm_unpause();
    }
    render_format_(format, status_ptr);
    if (pause)
        vm_pause();
    if (lock)
        critical_section_leave(&vm_pause_lock);
}

static void clipboard_ownership_cb(void *opaque)
{
    int owner = opaque != NULL;
    control_send_status("clipboard-ownership", owner ? "on" : "off", NULL);
}

int render_all_formats(HWND hwnd)
{
    UINT fmt = 0;
    int r = -1;
    critical_section_enter(&vm_pause_lock);
    if (GetClipboardOwner() != hwnd) {
        LogRel(("not clipboard owner, skip render\n"));
        goto out;
    }
    LogRel(("clipboard: render all formats\n"));
    if (OpenClipboardWithRetry(hwnd)) {
        while ((fmt = EnumClipboardFormats(fmt)) != 0) {
            int status;
            render_format(fmt, &status, FALSE);
        }

        CloseClipboard();
    } else {
        LogRel(("failed to open clipboard\n"));
        goto out;
    }
    r = 0;
out:
    critical_section_leave(&vm_pause_lock);
    SetEvent(g_ctx.hRenderAllEvent);
    return r;
}

int vm_renderclipboard(int wait)
{
    if (g_ctx.hwnd && deferred_clipboard) {
        uxen_clipboard_allow_copy_access();
        ResetEvent(g_ctx.hRenderAllEvent);
        PostMessage(g_ctx.hwnd, WM_USER+1, 0, 0);
        if (wait) {
            WaitForSingleObject(g_ctx.hRenderAllEvent, CLIPBOARD_TIMEOUT);
            LogRel(("clipboard: finished wait for rendering formats\n"));
        }
    }
    return 0;
}

static LRESULT CALLBACK vboxClipboardWndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
    LRESULT rc = 0;

    VBOXCLIPBOARDCONTEXT *pCtx = &g_ctx;

    switch (msg)
    {
        case WM_CLIPBOARDUPDATE:
        {
            int owner = GetClipboardOwner() == hwnd;

            Log(("WM_CLIPBOARDUPDATE next %p\n", pCtx->hwndNextInChain));
            if (!owner) {
                /* Clipboard was updated by another application. */
                vboxClipboardChanged (pCtx);
            }
            if (owner != pCtx->owner) {
                BH *bh;
                pCtx->owner = owner;
                bh = bh_new(clipboard_ownership_cb, owner ? (void*)1 : NULL);
                bh_schedule_one_shot(bh);
            }
        } break;

        case WM_CLOSE:
        {
            /* Do nothing. Ignore the message. */
        } break;

        case WM_RENDERFORMAT:
        {
            UINT format = (UINT)wParam;
            int *status_ptr = (int*)lParam;
            render_format(format, status_ptr, TRUE);
        } break;

        case WM_RENDERALLFORMATS:
        {
            /* Do nothing. The clipboard formats will be unavailable now, because the
             * windows is to be destroyed and therefore the guest side becomes inactive.
             */

#ifndef BROMIUM_CHANGES
            /* Do we really want to empty clipboard on shutdown? Not really.*/
            if (OpenClipboardWithRetry (hwnd))
            {
                EmptyClipboard();

                CloseClipboard();
            }
#endif
        } break;

        case WM_USER:
        {
            if (pCtx->pClient == NULL || pCtx->pClient->fMsgFormats)
            {
                /* Host has pending formats message. Ignore the guest announcement,
                 * because host clipboard has more priority.
                 */
                break;
            }

            /* Announce available formats. Do not insert data, they will be inserted in WM_RENDER*. */
            uint32_t u32Formats = (uint32_t)lParam;

            Log(("WM_USER u32Formats = %02X\n", u32Formats));

            if (OpenClipboardWithRetry (hwnd))
            {
                int i = 0;
                unsigned int local, remote, status, status_cumulative = 0;

                EmptyClipboard();
                Log(("WM_USER emptied clipboard\n"));

                while (!uxenclipboard_get_announced_format(i, &local, &remote)) {
                    if (deferred_clipboard) {
                        status = 1;
                        SetClipboardData(local, NULL);
                    } else {
                        status = 0;
                        vboxClipboardWndProc(hwnd, WM_RENDERFORMAT, local, 
                                             (LPARAM)&status);
                    }
                    status_cumulative |= status;
                    i++;
                }

                if (!status_cumulative) {
                    int write_warning = MAGIC_LPARAM_UNSUPPORTED_FORMAT;
                    vboxClipboardWndProc(hwnd, WM_RENDERFORMAT, CF_UNICODETEXT,
                        (LPARAM)&write_warning);
                }
                CloseClipboard();

                dprintf(("window proc WM_USER: processed %d formats\n",
                    i));
            }
            else
            {
                dprintf(("window proc WM_USER: failed to open clipboard\n"));
            }
        } break;

        case WM_USER+1:
            render_all_formats(hwnd);
            break;
        default:
        {
            Log(("WM_ %p\n", msg));
            rc = DefWindowProc (hwnd, msg, wParam, lParam);
        }
    }

    /*Log(("WM_ rc %d\n", rc));*/
    return rc;
}
static DWORD WINAPI VBoxClipboardThread(LPVOID pInstance)
{
    /* Create a window and make it a clipboard viewer. */
    int rc = VINF_SUCCESS;

    LogFlow(("VBoxClipboardThread\n"));

    VBOXCLIPBOARDCONTEXT *pCtx = &g_ctx;

    HINSTANCE hInstance = (HINSTANCE)GetModuleHandle (NULL);

    /* Register the Window Class. */
    WNDCLASS wc;

    wc.style         = CS_NOCLOSE;
    wc.lpfnWndProc   = vboxClipboardWndProc;
    wc.cbClsExtra    = 0;
    wc.cbWndExtra    = 0;
    wc.hInstance     = hInstance;
    wc.hIcon         = NULL;
    wc.hCursor       = NULL;
    wc.hbrBackground = (HBRUSH)(COLOR_BACKGROUND + 1);
    wc.lpszMenuName  = NULL;
    wc.lpszClassName = gachWindowClassName;

    ATOM atomWindowClass = RegisterClass (&wc);

    if (atomWindowClass == 0)
    {
        Log(("Failed to register window class\n"));
        rc = VERR_NOT_SUPPORTED;
    }
    else
    {
        /* Create the window. */
        pCtx->hwnd = CreateWindowEx (WS_EX_TOOLWINDOW | WS_EX_TRANSPARENT | WS_EX_TOPMOST,
                                     gachWindowClassName, gachWindowClassName,
                                     WS_POPUPWINDOW,
                                     -200, -200, 100, 100, NULL, NULL, hInstance, NULL);
        if (pCtx->hwnd == NULL)
        {
            Log(("Failed to create window\n"));
            rc = VERR_NOT_SUPPORTED;
        }
        else
        {
            SetWindowPos(pCtx->hwnd, HWND_TOPMOST, -200, -200, 0, 0,
                         SWP_NOACTIVATE | SWP_HIDEWINDOW | SWP_NOCOPYBITS | SWP_NOREDRAW | SWP_NOSIZE);

            if (!mingw_AddClipboardFormatListener(pCtx->hwnd)) {
                int err = GetLastError();
                LogRel(("AddClipboardFormatListener error %d\n", err));
            }

            MSG msg;
            while (GetMessage(&msg, NULL, 0, 0) && !pCtx->fTerminate)
            {
                TranslateMessage(&msg);
                DispatchMessage(&msg);
            }
        }
    }

    if (pCtx->hwnd)
    {
        DestroyWindow (pCtx->hwnd);
        pCtx->hwnd = NULL;
    }

    if (atomWindowClass != 0)
    {
        UnregisterClass (gachWindowClassName, hInstance);
        atomWindowClass = 0;
    }

    return rc;
}

/*
 * Public platform dependent functions.
 */
int vboxClipboardInit (void)
{
    int rc = VINF_SUCCESS;

    g_ctx.owner = 0;
    g_ctx.hRenderEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
    g_ctx.hRenderAllEvent = CreateEvent(NULL, TRUE, FALSE, NULL);

    g_ctx.thread = CreateThread(NULL, 0x10000, VBoxClipboardThread,
        NULL, 0, NULL);
    if (!g_ctx.thread) {
        CloseHandle (g_ctx.hRenderEvent);
        return VERR_NO_MEMORY;
    }

    return rc;
}

void vboxClipboardDestroy (void)
{
    Log(("vboxClipboardDestroy\n"));

    /* Set the termination flag and ping the window thread. */
    // ASMAtomicWriteBool (&g_ctx.fTerminate, true);
    // I see no reason why we have to use atomic write here...
    g_ctx.fTerminate = true;


    if (g_ctx.hwnd)
    {
        PostMessage (g_ctx.hwnd, WM_CLOSE, 0, 0);
    }

    CloseHandle (g_ctx.hRenderEvent);
    CloseHandle (g_ctx.hRenderAllEvent);

    /* Wait for the window thread to terminate. */
    WaitForSingleObject(g_ctx.thread, INFINITE);

    g_ctx.thread = NULL;
}

int vboxClipboardConnect (VBOXCLIPBOARDCLIENTDATA *pClient, bool unused)
{
    Log(("vboxClipboardConnect\n"));

    if (g_ctx.pClient != NULL)
    {
        /* One client only. */
        return VERR_NOT_SUPPORTED;
    }

    pClient->pCtx = &g_ctx;

    pClient->pCtx->pClient = pClient;

    /* Sync the host clipboard content with the client. */
    vboxClipboardSync (pClient);

    return VINF_SUCCESS;
}

int vboxClipboardSync (VBOXCLIPBOARDCLIENTDATA *pClient)
{
    /* Sync the host clipboard content with the client. */
    vboxClipboardChanged (pClient->pCtx);

    return VINF_SUCCESS;
}

void vboxClipboardDisconnect (VBOXCLIPBOARDCLIENTDATA *pClient)
{
    Log(("vboxClipboardDisconnect\n"));

    g_ctx.pClient = NULL;
}

void vboxClipboardFormatAnnounce (VBOXCLIPBOARDCLIENTDATA *pClient, uint32_t u32Formats)
{
    /*
     * The guest announces formats. Forward to the window thread.
     */
    PostMessage (pClient->pCtx->hwnd, WM_USER, 0, u32Formats);
}

int vboxClipboardReadData (VBOXCLIPBOARDCLIENTDATA *pClient, uint32_t u32Format, void *pv, uint32_t cb, uint32_t *pcbActual)
{
    LogFlow(("vboxClipboardReadData: u32Format = %02X\n", u32Format));

    int ret = -1;
    int err;
    char* data;
    unsigned int data_size;
    
    /*
     * The guest wants to read data in the given format.
     */
    if (OpenClipboardWithRetry (pClient->pCtx->hwnd))
    {
        dprintf(("Clipboard opened.\n"));

        ret = uxenclipboard_getdata(u32Format, &data, &data_size);
        if (!ret) {
            vboxClipboardGetData (u32Format, data, data_size,
                                          pv, cb, pcbActual);
            free(data);
        } else {
            err = GetLastError();
            dprintf(("vboxClipboardReadData: GetClipboardData ret 0x%x lasterror %d\n", ret, err));
        }
      
        CloseClipboard ();
    }
    else
    {
        dprintf(("vboxClipboardReadData: failed to open clipboard\n"));
    }

    if (ret)
    {
        /* Reply with empty data. */
        vboxClipboardGetData (0, NULL, 0,
                              pv, cb, pcbActual);
    }

    return VINF_SUCCESS;
}

void vboxClipboardWriteData (VBOXCLIPBOARDCLIENTDATA *pClient, void *pv, uint32_t cb, uint32_t u32Format)
{
    LogFlow(("vboxClipboardWriteData\n"));

    /*
     * The guest returns data that was requested in the WM_RENDERFORMAT handler.
     */
    Assert(pClient->data.pv == NULL && pClient->data.cb == 0 && pClient->data.u32Format == 0);

    vboxClipboardDump(pv, cb, u32Format);

    if (cb > 0)
    {
        pClient->data.pv = RTMemAlloc (cb);

        if (pClient->data.pv)
        {
            memcpy (pClient->data.pv, pv, cb);
            pClient->data.cb = cb;
            pClient->data.u32Format = u32Format;
        }
    }

    SetEvent(pClient->pCtx->hRenderEvent);
}
