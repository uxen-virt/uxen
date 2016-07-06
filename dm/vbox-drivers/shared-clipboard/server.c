/** @file
 * Shared Folders: Host service entry points.
 */

/*
 * Copyright (C) 2006-2010 Oracle Corporation
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
 * Copyright 2012-2016, Bromium, Inc.
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

#include <dm/config.h>
#include <iprt/alloc.h>
#include <iprt/string.h>
#include <iprt/assert.h>
#include <windows.h>
#include "VBoxClipboard.h"
#include "clipboard-interface.h"
#include <generic-server.h>

VBOXCLIPBOARDCLIENTDATA clientData;

static int g_HelperRc;
static void tcpCallComplete(VBOXHGCMCALLHANDLE callHandle, int32_t rc)
{
    g_HelperRc = rc;
}
static VBOXHGCMSVCFNTABLE svcTable;
static VBOXHGCMSVCHELPERS helpers;

int uxen_clipboard_process_request(uint8_t *req, int reqsize, 
    uint8_t** respbuf, int* respsize)
{
    /* Normally svcTable.pfnCall is initialized early, during service
    connect or vm restore. But a malicious guest can omit/close 
    clipboard-hostmsg connection, preventing correct init. So, check that
    we are actually initialized. */
    if (!svcTable.pfnCall)
        return -1;
    return generic_server_process_request((char*)req, reqsize, 
        (char**)respbuf, respsize, FALSE,
        svcTable.pfnCall, &clientData, &g_HelperRc);
}

static VBOXHGCMSVCFNTABLE svcTable;
static VBOXHGCMSVCHELPERS helpers;
int uxen_clipboard_VBoxHGCMSvcLoad (VBOXHGCMSVCFNTABLE *ptable);
int uxen_clipboard_init()
{
    int rc;

    svcTable.cbSize = sizeof (VBOXHGCMSVCFNTABLE);
    svcTable.u32Version = VBOX_HGCM_SVC_VERSION;
    helpers.pfnCallComplete = tcpCallComplete;
    svcTable.pHelpers = &helpers;
    rc = uxen_clipboard_VBoxHGCMSvcLoad(&svcTable);
    if (rc) {
        LogRel(("VBoxHGCMSvcLoad error 0x%x\n", rc));
        return rc;
    }
    return rc;
}

void uxen_clipboard_connect()
{
    svcTable.pfnConnect(NULL, 0, &clientData);
}


