/* $Id: service.cpp 37472 2011-06-15 16:15:34Z vboxsync $ */
/** @file
 * Shared Clipboard: Host service entry points.
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
 * Copyright 2012-2019, Bromium, Inc.
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

/** @page pg_hostclip       The Shared Clipboard Host Service
 *
 * The shared clipboard host service provides a proxy between the host's
 * clipboard and a similar proxy running on a guest.  The service is split
 * into a platform-independent core and platform-specific backends.  The
 * service defines two communication protocols - one to communicate with the
 * clipboard service running on the guest, and one to communicate with the
 * backend.  These will be described in a very skeletal fashion here.
 *
 * @section sec_hostclip_guest_proto  The guest communication protocol
 *
 * The guest clipboard service communicates with the host service via HGCM
 * (the host service runs as an HGCM service).  The guest clipboard must
 * connect to the host service before all else (Windows hosts currently only
 * support one simultaneous connection).  Once it has connected, it can send
 * HGCM messages to the host services, some of which will receive replies from
 * the host.  The host can only reply to a guest message, it cannot initiate
 * any communication.  The guest can in theory send any number of messages in
 * parallel (see the descriptions of the messages for the practice), and the
 * host will receive these in sequence, and may reply to them at once
 * (releasing the caller in the guest) or defer the reply until later.
 *
 * There are currently four messages defined.  The first is
 * VBOX_SHARED_CLIPBOARD_FN_GET_HOST_MSG, which waits for a message from the
 * host.  Host messages currently defined are
 * VBOX_SHARED_CLIPBOARD_HOST_MSG_QUIT (unused),
 * VBOX_SHARED_CLIPBOARD_HOST_MSG_READ_DATA (request that the guest send the
 * contents of its clipboard to the host) and
 * VBOX_SHARED_CLIPBOARD_HOST_MSG_FORMATS (to notify the guest that new
 * clipboard data is available).  If a host message is sent while the guest is
 * not waiting, it will be queued until the guest requests it.  At most one
 * host message of each type will be kept in the queue.  The host code only
 * supports a single simultaneous VBOX_SHARED_CLIPBOARD_FN_GET_HOST_MSG call
 * from the guest.
 *
 * The second guest message is VBOX_SHARED_CLIPBOARD_FN_FORMATS, which tells
 * the host that the guest has new clipboard data available.  The third is
 * VBOX_SHARED_CLIPBOARD_FN_READ_DATA, which asks the host to send its
 * clipboard data and waits until it arrives.  The host supports at most one
 * simultaneous VBOX_SHARED_CLIPBOARD_FN_READ_DATA call from the guest - if a
 * second call is made before the first has returned, the first will be
 * aborted.
 *
 * The last guest message is VBOX_SHARED_CLIPBOARD_FN_WRITE_DATA, which is
 * used to send the contents of the guest clipboard to the host.  This call
 * should be used after the host has requested data from the guest.
 *
 * @section sec_hostclip_backend_proto  The communication protocol with the
 *                                      platform-specific backend
 *
 * This section may be written in the future :)
 */
#include <dm/config.h>
#include <dm/os.h>
#include <dm/vbox-drivers/heap.h>
#include <dm/hw/uxen_hid.h>
#include "VBoxClipboardSvc.h"
#include "VBoxClipboardExt.h"
#include "clipboardformats.h"

#include <iprt/alloc.h>
#include <iprt/string.h>
#include <iprt/assert.h>

#include "VBoxClipboard.h"
#include "clipboard-interface.h"

#define METADATA_FORMAT_NAME "Bromium vSentry Metadata"

static void VBoxHGCMParmUInt32Set (VBOXHGCMSVCPARM *pParm, uint32_t u32)
{
    pParm->type = VBOX_HGCM_SVC_PARM_32BIT;
    pParm->u.uint32 = u32;
}

static int VBoxHGCMParmUInt32Get (VBOXHGCMSVCPARM *pParm, uint32_t *pu32)
{
    if (pParm->type == VBOX_HGCM_SVC_PARM_32BIT)
    {
        *pu32 = pParm->u.uint32;
        return VINF_SUCCESS;
    }

    return VERR_INVALID_PARAMETER;
}

#if 0
static void VBoxHGCMParmPtrSet (VBOXHGCMSVCPARM *pParm, void *pv, uint32_t cb)
{
    pParm->type             = VBOX_HGCM_SVC_PARM_PTR;
    pParm->u.pointer.size   = cb;
    pParm->u.pointer.addr   = pv;
}
#endif

static int VBoxHGCMParmPtrGet (VBOXHGCMSVCPARM *pParm, void **ppv, uint32_t *pcb)
{
    if (pParm->type == VBOX_HGCM_SVC_PARM_PTR)
    {
        *ppv = pParm->u.pointer.addr;
        *pcb = pParm->u.pointer.size;
        return VINF_SUCCESS;
    }

    return VERR_INVALID_PARAMETER;
}

static PVBOXHGCMSVCHELPERS g_pHelpers;

static CRITICAL_SECTION critsect;
static uint32_t g_u32Mode = VBOX_SHARED_CLIPBOARD_MODE_BIDIRECTIONAL;

static PFNHGCMSVCEXT g_pfnExtension;
static void *g_pvExtension;

static VBOXCLIPBOARDCLIENTDATA *g_pClient;

#if 0
/* Serialization of data reading and format announcements from the RDP client. */
static bool g_fReadingData = false;
static bool g_fDelayedAnnouncement = false;
static uint32_t g_u32DelayedFormats = 0;
#endif

/** Is the clipboard running in headless mode? */
static bool g_fHeadless = false;

static uint32_t vboxSvcClipboardMode (void)
{
    return g_u32Mode;
}

#ifdef UNIT_TEST
/** Testing interface, getter for clipboard mode */
uint32_t TestClipSvcGetMode(void)
{
    return vboxSvcClipboardMode();
}
#endif

/** Getter for headless setting */
bool vboxSvcClipboardGetHeadless(void)
{
    return g_fHeadless;
}

static void vboxSvcClipboardModeSet (uint32_t u32Mode)
{
    switch (u32Mode)
    {
        case VBOX_SHARED_CLIPBOARD_MODE_OFF:
        case VBOX_SHARED_CLIPBOARD_MODE_HOST_TO_GUEST:
        case VBOX_SHARED_CLIPBOARD_MODE_GUEST_TO_HOST:
        case VBOX_SHARED_CLIPBOARD_MODE_BIDIRECTIONAL:
            g_u32Mode = u32Mode;
            break;

        default:
            g_u32Mode = VBOX_SHARED_CLIPBOARD_MODE_OFF;
    }
}

bool vboxSvcClipboardLock (void)
{
    EnterCriticalSection (&critsect);
    return true;
}

void vboxSvcClipboardUnlock (void)
{
    LeaveCriticalSection (&critsect);
}

#define EXTRA_LOGGING 1
#include <windows.h>

static bool have_policy = true;
static bool clipboard_policy = true;
static bool is_relaxed_policy = false;

static bool isClipboardfixedPolicy(bool *ret)
{
    *ret = clipboard_policy;
    return have_policy;
}

void uxen_clipboard_set_policy(const char *policy)
{
    Log(("Clipboard: set policy to %s\n", policy));
    if (!strcmp(policy, "allow")) {
        have_policy = true;
        clipboard_policy = true;
    }
    else if (!strcmp(policy, "deny")) {
        have_policy = true;
        clipboard_policy = false;
    } else
        have_policy = false;
    if (!strcmp(policy, "relaxed"))
        is_relaxed_policy = true;
}

static uint64_t RTTimeSystemMilliTS()
{
    uint64_t u64; /* manual say larger integer, should be safe to 
                    assume it's the same. */
    GetSystemTimeAsFileTime((LPFILETIME)&u64);
    return u64 / 10000;
}

static bool click_seen, last_input_event_is_right_click;
static int clicks_seen;
static int remote_render_blocked;

static uint64_t copy_allowed_timestamp, paste_allowed_timestamp;
static uint64_t click_timestamp;
#define CLIPBOARD_GRACE_PERIOD 5000 //2s - yes, Adobe Reader sometimes is this slow
/* Plus, in relaxed policy case, we have to give some time for a human to
  complete Rclick-Down-Up-Down-Enter sequence */

static uint64_t copy_allowed_timestamp_delta()
{
    if (is_relaxed_policy)
        /* This is a rather nonstraightforward way to always allow copy;
        but the simplest. */
        return 0;
    return RTTimeSystemMilliTS()-copy_allowed_timestamp;
}

static uint64_t paste_allowed_timestamp_delta()
{
    return RTTimeSystemMilliTS()-paste_allowed_timestamp;
}

void uxen_clipboard_allow_copy_access()
{
    copy_allowed_timestamp = RTTimeSystemMilliTS();
}

void uxen_clipboard_allow_paste_access()
{
    paste_allowed_timestamp = RTTimeSystemMilliTS();
}

int uxen_clipboard_remote_render_blocked(void)
{
    return remote_render_blocked;
}

void uxen_clipboard_block_remote_render(int block)
{
    remote_render_blocked = block;
}

enum {
    COPY_KEY_PRESSED,
    PASTE_KEY_PRESSED,
    LEFT_BUTTON_PRESSED,
    RIGHT_BUTTON_PRESSED
};

static void InputNotify(int inputtype)
{
#ifdef EXTRA_LOGGING
    LogRelFlow(("Clipboard: KeypressNotify: %d\n", inputtype));
#endif
    switch (inputtype) {
        case COPY_KEY_PRESSED:
            uxen_clipboard_allow_copy_access();
            break;
        case PASTE_KEY_PRESSED:
            uxen_clipboard_allow_paste_access();
            break;
        case LEFT_BUTTON_PRESSED:
            click_seen = true;
            ++clicks_seen;
            click_timestamp = RTTimeSystemMilliTS();
            copy_allowed_timestamp = RTTimeSystemMilliTS();
            if (is_relaxed_policy)
                paste_allowed_timestamp = RTTimeSystemMilliTS();
            break;
        case RIGHT_BUTTON_PRESSED:
            click_seen = true;
            ++clicks_seen;
            click_timestamp = RTTimeSystemMilliTS();
            last_input_event_is_right_click = true;
            copy_allowed_timestamp = RTTimeSystemMilliTS();
            paste_allowed_timestamp = RTTimeSystemMilliTS();
            break;
        default:
            LogRel(("Clipboard: InputNotify: received %d ?\n", inputtype));
    }
}

static void relaxed_policy_tweaks()
{
    if (is_relaxed_policy && last_input_event_is_right_click)
        paste_allowed_timestamp = RTTimeSystemMilliTS();
}

static bool is_ctrl_pressed()
{
    short int ctrl = GetKeyState(VK_CONTROL);
    return (ctrl < 0);
}
static bool is_shift_pressed()
{
    short int ctrl = GetKeyState(VK_SHIFT);
    return (ctrl < 0);
}

void input_notify_clipboard_about_keypress(int keycode)
{
    UINT vk;

    relaxed_policy_tweaks();
    last_input_event_is_right_click = false;
    if (keycode & 0x80) /* KEYUP */
        return;
    vk = MapVirtualKey(keycode, MAPVK_VSC_TO_VK);
    if ((vk == 'C' || vk == 'X' || vk == 'Z' || vk == VK_INSERT) &&
        is_ctrl_pressed())
        InputNotify(COPY_KEY_PRESSED);
    if (vk == VK_DELETE && is_shift_pressed())
        InputNotify(COPY_KEY_PRESSED);
    if (vk == 'V' && is_ctrl_pressed())
        InputNotify(PASTE_KEY_PRESSED);
    if (vk == VK_INSERT && is_shift_pressed())
        InputNotify(PASTE_KEY_PRESSED);
}

void input_notify_clipboard_about_click(int button_state)
{
    relaxed_policy_tweaks();
    last_input_event_is_right_click = false;
    if (button_state == 1)
        InputNotify(LEFT_BUTTON_PRESSED);
    if (button_state == 2)
        InputNotify(RIGHT_BUTTON_PRESSED);
}

int BrPolicyGetClipboardAccessDecision(int *retval, int is_copy);
bool GetClipboardAccessDecision(int is_copy)
{
    static uint64_t last_failed_timestamp;
    uint64_t timestamp;
    HRESULT hr;
    int retval;

    timestamp = RTTimeSystemMilliTS();
    // Do not let guest flood desktop with security prompts
    // 30s should be enough to kill offending guest if necessary
    if (timestamp-last_failed_timestamp < 30*1000)
        return false;
    last_failed_timestamp = timestamp;

    hr = BrPolicyGetClipboardAccessDecision(&retval, is_copy);
    if (hr == E_NOTIMPL) // we are template, or not vbox vm
        retval = true;
    else if (!SUCCEEDED(hr)) {
        LogRel(("clipboard: GetClipboardAccessDecision hr=0x%x\n", hr));
        retval = false;
    }
    // if human acknowledges, reset the timestamp back to mesozoic era
    if (retval)
        last_failed_timestamp = 0;
    return retval;
}

bool isClipboardFormatAnnounceAllowed(void)
{
    bool ret;
#ifdef EXTRA_LOGGING
    LogRel(("isClipboardFormatAnnounceAllowed, copy_allowed_timestamp_delta=%llx\n",
        copy_allowed_timestamp_delta()));
#endif
    if (isClipboardfixedPolicy(&ret))
        return ret;
    if (copy_allowed_timestamp_delta() < CLIPBOARD_GRACE_PERIOD)
        return true;
    if (!click_seen)
        return false;
    if (GetClipboardAccessDecision(true)) { // true == copy access requested
        copy_allowed_timestamp = RTTimeSystemMilliTS(); // checked in isClipboardWriteDataAllowed
        return true;
    } else
        return false;
}

bool isClipboardWriteDataAllowed(uint32_t remotefmt)
{
    bool ret;
#ifdef EXTRA_LOGGING
    LogRel(("isClipboardWriteDataAllowed, copy_allowed_timestamp_delta=%llx\n", copy_allowed_timestamp_delta()));
#endif
    if (isClipboardfixedPolicy(&ret))
        return ret;
    if (copy_allowed_timestamp_delta() < CLIPBOARD_GRACE_PERIOD) {
        return true;
    } else {
        int wr;

        if (uxenclipboard_test_format_written(remotefmt, &wr))
            return false; /* error, wasn't announced */
        /* allow write if this is first attempt after announce */
        if (!wr)
            return true;
    }
    if (GetClipboardAccessDecision(true)) { // true == copy access requested
        copy_allowed_timestamp = RTTimeSystemMilliTS(); // checked in isClipboardWriteDataAllowed
        return true;
    } else
        return false;
}

static bool
is_metadata(int fmt)
{
    char name[256] = { 0 };

    uxenclipboard_get_format_name(fmt, name, sizeof(name));

    return !strncmp(name, METADATA_FORMAT_NAME, sizeof(name));
}

bool isClipboardReadDataAllowed(int fmt)
{
    bool ret;
#ifdef EXTRA_LOGGING
    LogRel(("isClipboardReadDataAllowed, paste_allowed_timestamp_delta=%llx\n", paste_allowed_timestamp_delta()));
#endif
    if (isClipboardfixedPolicy(&ret))
        return ret;
    if (paste_allowed_timestamp_delta() < CLIPBOARD_GRACE_PERIOD) {
        return true;
    }
    /* metadata format can be read from guest/host hooks inside EnumClipboardFormats. Always
     * allow that w/o prompt since we don't prompt for EnumClipboardFormats either */
    if (is_metadata(fmt))
        return true;
    /* uxendm is unable to police this when touch device is used as it doesn't see touch
     * events, assume OK */
    if (uxenhid_is_touch_ready())
        return true;

    /* If we haven't seen a mouse click, deny. Apparently Office2007
       likes to get clipboard on startup. */
    if (!click_seen)
        return false;
    /* If we're just few seconds from first click, automatically deny. Office likes
       to read clipboard on windows activation / first click */
    if (clicks_seen <= 1 &&
        (RTTimeSystemMilliTS() - click_timestamp <= 2000))
        return false;

    if (GetClipboardAccessDecision(false)) { // false == paste access requested
        paste_allowed_timestamp = RTTimeSystemMilliTS();
        return true;
    }
    else
        return false;
}

void ClipboardPolicyUnsetPasteAllowed(void)
{
#ifdef EXTRA_LOGGING
    LogRel(("ClipboardPolicyUnsetPasteAllowed\n"));
#endif
    paste_allowed_timestamp = 0;
}

void vboxSvcClipboardAnnounceFormats(char *data, uint32_t len)
{
    bool ret;

    if (isClipboardfixedPolicy(&ret) && !ret)
        return;
    vboxSvcClipboardLock();
    uxen_clipboard_notify_guest(VBOX_SHARED_CLIPBOARD_HOST_MSG_FORMATS,
        data, len);
    vboxSvcClipboardUnlock();
}

void vboxSvcClipboardRequestFormat(uint32_t format)
{
    vboxSvcClipboardLock();
    uxen_clipboard_notify_guest(VBOX_SHARED_CLIPBOARD_HOST_MSG_READ_DATA,
        (char*)&format, sizeof(format));
    vboxSvcClipboardUnlock();
}

static void vboxSvcClipboardPostQuit()
{
    vboxSvcClipboardLock();
    uxen_clipboard_notify_guest(VBOX_SHARED_CLIPBOARD_HOST_MSG_QUIT,
        NULL, 0);
    vboxSvcClipboardUnlock();
}

static int svcInit (void)
{
    int rc = VINF_SUCCESS;

    remote_render_blocked = 0;
    clicks_seen = 0;
    click_seen = false;
    last_input_event_is_right_click = false;
    copy_allowed_timestamp = 0;
    paste_allowed_timestamp = 0;
    click_timestamp = 0;

    InitializeCriticalSection (&critsect);

    if (RT_SUCCESS (rc))
    {
        vboxSvcClipboardModeSet (VBOX_SHARED_CLIPBOARD_MODE_BIDIRECTIONAL);

        rc = vboxClipboardInit ();

        /* Clean up on failure, because 'svnUnload' will not be called
         * if the 'svcInit' returns an error.
         */
        if (RT_FAILURE (rc))
        {
            DeleteCriticalSection (&critsect);
        }
    }

    return rc;
}

static DECLCALLBACK(int) svcUnload (void *unused)
{
    vboxClipboardDestroy ();
    DeleteCriticalSection (&critsect);
    return VINF_SUCCESS;
}

/**
 * Disconnect the host side of the shared clipboard and send a "host disconnected" message
 * to the guest side.
 */
static DECLCALLBACK(int) svcDisconnect (void *unused, uint32_t u32ClientID, void *pvClient)
{
    VBOXCLIPBOARDCLIENTDATA *pClient = (VBOXCLIPBOARDCLIENTDATA *)pvClient;

    vboxSvcClipboardPostQuit();

    vboxClipboardDisconnect (pClient);

    memset (pClient, 0, sizeof (*pClient));

    g_pClient = NULL;

    return VINF_SUCCESS;
}

static DECLCALLBACK(int) svcConnect (void *unused, uint32_t u32ClientID, void *pvClient)
{
    VBOXCLIPBOARDCLIENTDATA *pClient = (VBOXCLIPBOARDCLIENTDATA *)pvClient;

    int rc = VINF_SUCCESS;

    /* If there is already a client connected then we want to release it first. */
    if (g_pClient != NULL)
    {
        uint32_t u32OldClientID = g_pClient->u32ClientID;

        svcDisconnect(NULL, u32OldClientID, g_pClient);
        /* And free the resources in the hgcm subsystem. */
        g_pHelpers->pfnDisconnectClient(g_pHelpers->pvInstance, u32OldClientID);
    }

    /* Register the client. */
    memset (pClient, 0, sizeof (*pClient));

    /* we no longer use GETHOSTMSG, so we must alloc room for response here */
    pClient->async.paParms = hgcm_malloc(2 * sizeof(VBOXHGCMSVCPARM));

    pClient->u32ClientID = u32ClientID;

    rc = vboxClipboardConnect (pClient, vboxSvcClipboardGetHeadless());

    if (RT_SUCCESS (rc))
    {
        g_pClient = pClient;
    }

    LogRel2(("vboxClipboardConnect: rc = %d\n", rc));

    return rc;
}

static DECLCALLBACK(void) svcCall (void *unused,
                                   VBOXHGCMCALLHANDLE callHandle,
                                   uint32_t u32ClientID,
                                   void *pvClient,
                                   uint32_t u32Function,
                                   uint32_t cParms,
                                   VBOXHGCMSVCPARM paParms[])
{
    int rc = VINF_SUCCESS;

    LogRel2(("svcCall: u32ClientID = %d, fn = %d, cParms = %d, pparms = %d\n",
             u32ClientID, u32Function, cParms, paParms));

    VBOXCLIPBOARDCLIENTDATA *pClient = (VBOXCLIPBOARDCLIENTDATA *)pvClient;

    bool fAsynchronousProcessing = false;

#ifdef DEBUG
    uint32_t i;

    for (i = 0; i < cParms; i++)
    {
        /** @todo parameters other than 32 bit */
        LogRel2(("    pparms[%d]: type %d value %d\n", i, paParms[i].type, paParms[i].u.uint32));
    }
#endif

    switch (u32Function)
    {
        case VBOX_SHARED_CLIPBOARD_FN_GET_HOST_MSG:
        {
            rc = VERR_NOT_SUPPORTED;
#if 0            
            /* The quest requests a host message. */
            LogRel2(("svcCall: VBOX_SHARED_CLIPBOARD_FN_GET_HOST_MSG\n"));

            if (cParms != VBOX_SHARED_CLIPBOARD_CPARMS_GET_HOST_MSG)
            {
                rc = VERR_INVALID_PARAMETER;
            }
            else if (   paParms[0].type != VBOX_HGCM_SVC_PARM_32BIT   /* msg */
                     || paParms[1].type != VBOX_HGCM_SVC_PARM_32BIT   /* formats */
                    )
            {
                rc = VERR_INVALID_PARAMETER;
            }
            else
            {
                /* Atomically verify the client's state. */
                if (vboxSvcClipboardLock ())
                {
                    bool fMessageReturned = vboxSvcClipboardReturnMsg (pClient, paParms);

                    if (fMessageReturned)
                    {
                        /* Just return to the caller. */
                        pClient->fAsync = false;
                    }
                    else
                    {
                        /* No event available at the time. Process asynchronously. */
                        fAsynchronousProcessing = true;

                        pClient->fAsync           = true;
                        pClient->async.callHandle = callHandle;
                        pClient->async.paParms    = paParms;

                        LogRel2(("svcCall: async.\n"));
                    }

                    vboxSvcClipboardUnlock ();
                }
                else
                {
                    rc = VERR_NOT_SUPPORTED;
                }
            }
#endif            
        } break;

        case VBOX_SHARED_CLIPBOARD_FN_FORMATS:
        {
            rc = VERR_NOT_SUPPORTED;
#if 0            
            /* The guest reports that some formats are available. */
            LogRel2(("svcCall: VBOX_SHARED_CLIPBOARD_FN_FORMATS\n"));

            if (cParms != VBOX_SHARED_CLIPBOARD_CPARMS_FORMATS)
            {
                rc = VERR_INVALID_PARAMETER;
            }
            else if (   paParms[0].type != VBOX_HGCM_SVC_PARM_32BIT   /* formats */
                    )
            {
                rc = VERR_INVALID_PARAMETER;
            }
            else
            {
                uint32_t u32Formats;

                rc = VBoxHGCMParmUInt32Get (&paParms[0], &u32Formats);

                if (RT_SUCCESS (rc))
                {
                    if (   vboxSvcClipboardMode () != VBOX_SHARED_CLIPBOARD_MODE_GUEST_TO_HOST
                        && vboxSvcClipboardMode () != VBOX_SHARED_CLIPBOARD_MODE_BIDIRECTIONAL)
                    {
                        rc = VERR_NOT_SUPPORTED;
                        break;
                    }

                    /* Ignore message when no formats specified.
                    Such spurious messages are sometimes generated at
                    application shutdown, probably to clean clipboard,
                    and we do not want prompts in such case. */
                    if (!u32Formats)
                        break;
                    if (!isClipboardFormatAnnounceAllowed())
                        break;

                    if (g_pfnExtension)
                    {
                        VBOXCLIPBOARDEXTPARMS parms;

                        parms.u32Format = u32Formats;

                        g_pfnExtension (g_pvExtension, VBOX_CLIPBOARD_EXT_FN_FORMAT_ANNOUNCE, &parms, sizeof (parms));
                    }
                    else
                    {
                        vboxClipboardFormatAnnounce (pClient, u32Formats);
                    }
                }
            }
#endif            
        } break;

        case VBOX_SHARED_CLIPBOARD_FN_FORMATS_V2:
        {
            void     *pv;
            uint32_t cb;
            int ret;

            /* Format change announce, new style. */
            LogRel(("svcCall: VBOX_SHARED_CLIPBOARD_FN_FORMATS_V2\n"));

            if (cParms != VBOX_SHARED_CLIPBOARD_CPARMS_FORMATS_V2)
            {
                rc = VERR_INVALID_PARAMETER;
            }
            else if (paParms[0].type != VBOX_HGCM_SVC_PARM_PTR)     /* ptr */
            {
                rc = VERR_INVALID_PARAMETER;
            }
            else
            {
                rc = VBoxHGCMParmPtrGet (&paParms[0], &pv, &cb);
            }

            if (!RT_SUCCESS (rc))
                break;

            /* Ignore message when no formats specified.
               Such spurious messages are sometimes generated at
               application shutdown, probably to clean clipboard,
               and we do not want prompts in such case. */
            if (!cb)
                break;

            if (!isClipboardFormatAnnounceAllowed())
                break;

            LogRel(("VBOX_SHARED_CLIPBOARD_FN_FORMATS_V2 len 0x%x data 0x%x\n",
                cb, *(unsigned int*)pv));
            ret = uxenclipboard_parse_remote_format_announce(pv, cb);
            if (ret < 0) {
                LogRel(("uxenclipboard_parse_remote_format_announce %d\n",
                    ret));
                rc = VERR_INVALID_PARAMETER;
                break;
            }
            {
                int i = 0;
                unsigned int local, remote;
                while (!uxenclipboard_get_announced_format(i, &local, &remote)) {
                    char name[256] = { 0 };

                    uxenclipboard_get_format_name(local, name, sizeof(name));
                    LogRel(("got local fmt 0x%x remote 0x%x: %s\n",
                            local, remote, name));
                    uxenclipboard_mark_format_written(remote, 0);
                    i++;
                }
            }
            if (cb > 0)
                vboxClipboardFormatAnnounce (pClient, 0);

        } break;

        case VBOX_SHARED_CLIPBOARD_FN_READ_DATA:
        {
            /* The guest wants to read data in the given format. */
            LogRel2(("svcCall: VBOX_SHARED_CLIPBOARD_FN_READ_DATA\n"));

            if (cParms != VBOX_SHARED_CLIPBOARD_CPARMS_READ_DATA)
            {
                rc = VERR_INVALID_PARAMETER;
            }
            else if (   paParms[0].type != VBOX_HGCM_SVC_PARM_32BIT   /* format */
                     || paParms[1].type != VBOX_HGCM_SVC_PARM_PTR     /* ptr */
                     || paParms[2].type != VBOX_HGCM_SVC_PARM_32BIT   /* size */
                    )
            {
                rc = VERR_INVALID_PARAMETER;
            }
            else
            {
                uint32_t u32Format;
                void     *pv;
                uint32_t cb;

                rc = VBoxHGCMParmUInt32Get (&paParms[0], &u32Format);

                if (RT_SUCCESS (rc))
                {
                    rc = VBoxHGCMParmPtrGet (&paParms[1], &pv, &cb);

                    if (RT_SUCCESS (rc))
                    {
                        uint32_t cbActual = 0;

                        if (   vboxSvcClipboardMode () != VBOX_SHARED_CLIPBOARD_MODE_HOST_TO_GUEST
                            && vboxSvcClipboardMode () != VBOX_SHARED_CLIPBOARD_MODE_BIDIRECTIONAL)
                        {
                            paParms[1].u.pointer.size = 0;
                            rc = VERR_NOT_SUPPORTED;
                            break;
                        }

                        if (!isClipboardReadDataAllowed(u32Format)) {
                            paParms[1].u.pointer.size = 0;
                            break;
                        }

                        rc = vboxClipboardReadData (pClient, u32Format, pv, cb, &cbActual);

                        /* Remember our read request until it is completed.
                         * See the protocol description above for more
                         * information. */
                        if (0) /* vboxClipboardReadData never fails */
//                        if (rc == VINF_HGCM_ASYNC_EXECUTE)
                        {
                            if (vboxSvcClipboardLock())
                            {
                                pClient->asyncRead.callHandle = callHandle;
                                pClient->asyncRead.paParms    = paParms;
                                pClient->fReadPending         = true;
                                fAsynchronousProcessing = true;
                                vboxSvcClipboardUnlock();
                            }
                            else
                                rc = VERR_NOT_SUPPORTED;
                        }
                        else if (RT_SUCCESS (rc))
                        {
                            VBoxHGCMParmUInt32Set (&paParms[2], cbActual);
                            /* Transfer just the relevant buffer region */
                            if (paParms[1].u.pointer.size >= cbActual)
                                paParms[1].u.pointer.size = cbActual;
                            else 
                                /* Guest must observe paParms[2] > size,
                                ignore the buffer and retry with new size */
                                paParms[1].u.pointer.size = 0;
                        }
                    }
                }
            }
        } break;

        case VBOX_SHARED_CLIPBOARD_FN_WRITE_DATA:
        {
            /* The guest writes the requested data. */
            LogRel2(("svcCall: VBOX_SHARED_CLIPBOARD_FN_WRITE_DATA\n"));

            if (cParms != VBOX_SHARED_CLIPBOARD_CPARMS_WRITE_DATA)
            {
                rc = VERR_INVALID_PARAMETER;
            }
            else if (   paParms[0].type != VBOX_HGCM_SVC_PARM_32BIT   /* format */
                     || paParms[1].type != VBOX_HGCM_SVC_PARM_PTR     /* ptr */
                    )
            {
                rc = VERR_INVALID_PARAMETER;
            }
            else
            {
                void *pv;
                uint32_t cb;
                uint32_t u32Format;

                rc = VBoxHGCMParmUInt32Get (&paParms[0], &u32Format);

                if (RT_SUCCESS (rc))
                {
                    rc = VBoxHGCMParmPtrGet (&paParms[1], &pv, &cb);

                    if (RT_SUCCESS (rc))
                    {
                        if (   vboxSvcClipboardMode () != VBOX_SHARED_CLIPBOARD_MODE_GUEST_TO_HOST
                            && vboxSvcClipboardMode () != VBOX_SHARED_CLIPBOARD_MODE_BIDIRECTIONAL)
                        {
                            rc = VERR_NOT_SUPPORTED;
                            break;
                        }

                        if (!isClipboardWriteDataAllowed(u32Format))
                            break;

                        if (g_pfnExtension)
                        {
                            VBOXCLIPBOARDEXTPARMS parms;

                            parms.u32Format = u32Format;
                            parms.u.pvData = pv;
                            parms.cbData = cb;

                            g_pfnExtension (g_pvExtension, VBOX_CLIPBOARD_EXT_FN_DATA_WRITE, &parms, sizeof (parms));
                        }
                        else
                        {
                            vboxClipboardWriteData (pClient, pv, cb, u32Format);
                            uxenclipboard_mark_format_written(u32Format, 1);
                        }
                    }
                }
            }
        } break;

        default:
        {
            rc = VERR_NOT_IMPLEMENTED;
        }
    }

    LogRelFlow(("svcCall: rc = %d\n", rc));

    if (!fAsynchronousProcessing)
    {
        g_pHelpers->pfnCallComplete (callHandle, rc);
    }
}

/** If the client in the guest is waiting for a read operation to complete
 * then complete it, otherwise return.  See the protocol description in the
 * shared clipboard module description. */
void vboxSvcClipboardCompleteReadData(VBOXCLIPBOARDCLIENTDATA *pClient, int rc, uint32_t cbActual)
{
    VBOXHGCMCALLHANDLE callHandle = NULL;
    VBOXHGCMSVCPARM *paParms = NULL;
    bool fReadPending = false;
    if (vboxSvcClipboardLock())  /* if not can we do anything useful? */
    {
        callHandle   = pClient->asyncRead.callHandle;
        paParms      = pClient->asyncRead.paParms;
        fReadPending = pClient->fReadPending;
        pClient->fReadPending = false;
        vboxSvcClipboardUnlock();
    }
    if (fReadPending)
    {
        VBoxHGCMParmUInt32Set (&paParms[2], cbActual);
        g_pHelpers->pfnCallComplete (callHandle, rc);
    }
}

/*
 * We differentiate between a function handler for the guest and one for the host.
 */
static DECLCALLBACK(int) svcHostCall (void *unused,
                                      uint32_t u32Function,
                                      uint32_t cParms,
                                      VBOXHGCMSVCPARM paParms[])
{
    int rc = VINF_SUCCESS;

    LogRel2(("svcHostCall: fn = %d, cParms = %d, pparms = %d\n",
         u32Function, cParms, paParms));
    switch (u32Function)
    {
        case VBOX_SHARED_CLIPBOARD_HOST_FN_SET_MODE:
        {
            LogRel2(("svcCall: VBOX_SHARED_CLIPBOARD_HOST_FN_SET_MODE\n"));

            if (cParms != 1)
            {
                rc = VERR_INVALID_PARAMETER;
            }
            else if (   paParms[0].type != VBOX_HGCM_SVC_PARM_32BIT   /* mode */
                    )
            {
                rc = VERR_INVALID_PARAMETER;
            }
            else
            {
                uint32_t u32Mode = VBOX_SHARED_CLIPBOARD_MODE_OFF;

                rc = VBoxHGCMParmUInt32Get (&paParms[0], &u32Mode);

                /* The setter takes care of invalid values. */
                vboxSvcClipboardModeSet (u32Mode);
            }
        } break;

        case VBOX_SHARED_CLIPBOARD_HOST_FN_SET_HEADLESS:
        {
            uint32_t u32Headless = g_fHeadless;

            rc = VERR_INVALID_PARAMETER;
            if (cParms != 1)
                break;
            rc = VBoxHGCMParmUInt32Get (&paParms[0], &u32Headless);
            if (RT_SUCCESS(rc))
                LogRelFlow(("svcCall: VBOX_SHARED_CLIPBOARD_HOST_FN_SET_HEADLESS, u32Headless=%u\n",
                            (unsigned) u32Headless));
            g_fHeadless = RT_BOOL(u32Headless);
        } break;

        default:
            break;
    }

    LogRelFlow(("svcHostCall: rc = %d\n", rc));
    return rc;
}

void uxen_clipboard_resume(void)
{
    remote_render_blocked = 0;
}

int uxen_clipboard_VBoxHGCMSvcLoad (VBOXHGCMSVCFNTABLE *ptable)
{
    int rc = VINF_SUCCESS;

    LogRelFlowFunc(("ptable = %p\n", ptable));

    if (!ptable)
    {
        rc = VERR_INVALID_PARAMETER;
    }
    else
    {
        uxenclipboard_init_formats_critical_section();
        LogRel2(("VBoxHGCMSvcLoad: ptable->cbSize = %d, ptable->u32Version = 0x%08X\n", ptable->cbSize, ptable->u32Version));

        if (   ptable->cbSize != sizeof (VBOXHGCMSVCFNTABLE)
            || ptable->u32Version != VBOX_HGCM_SVC_VERSION)
        {
            rc = VERR_INVALID_PARAMETER;
        }
        else
        {
            g_pHelpers = ptable->pHelpers;

            ptable->cbClient = sizeof (VBOXCLIPBOARDCLIENTDATA);

            ptable->pfnUnload     = svcUnload;
            ptable->pfnConnect    = svcConnect;
            ptable->pfnDisconnect = svcDisconnect;
            ptable->pfnCall       = svcCall;
            ptable->pfnHostCall   = svcHostCall;
            ptable->pfnSaveState  = NULL;
            ptable->pfnLoadState  = NULL;
            ptable->pfnRegisterExtension  = NULL;
            ptable->pvService     = NULL;

            /* Service specific initialization. */
            rc = svcInit ();
        }
    }
    return rc;
}
