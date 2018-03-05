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
 * Copyright 2012-2018, Bromium, Inc.
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
#include <dm/dm.h>
#include <VBox/shflsvc.h>


#include <iprt/alloc.h>
#include <iprt/string.h>
#include <iprt/assert.h>
#include <windows.h>
#include "shfl.h"
#include "vbsf.h"
#include "mappings.h"
#include <generic-server.h>
#include <dm/vbox-drivers/heap.h>
#include <inttypes.h>

SHFLCLIENTDATA clientData;

static int g_HelperRc;
static void tcpCallComplete(VBOXHGCMCALLHANDLE callHandle, int32_t rc)
{
    g_HelperRc = rc;
}
static VBOXHGCMSVCFNTABLE svcTable;
static VBOXHGCMSVCHELPERS helpers;

/* see generic_server_process_request for parameters explanation */
int sf_server_process_request(char *req, int reqsize, char* respbuf, int* respsize)
{
    return generic_server_process_request(req, reqsize, &respbuf, respsize, TRUE,
        svcTable.pfnCall, (void*)&clientData, &g_HelperRc);
}

void sf_quit(void)
{
    vbsfDisconnect(&clientData);
}

void *
makeSHFLString(wchar_t *str)
{
    int len = 2*wcslen(str) + 2;
    PSHFLSTRING shfl = (PSHFLSTRING)hgcm_malloc(sizeof(SHFLSTRING) + len);
    shfl->u16Size = len;
    shfl->u16Length = len - 2;
    wcscpy(shfl->String.ucs2, str);
    return shfl;
}

void *
makeSHFLStringUTF8(char *str)
{
    void *ret;
    wchar_t *buf;
    int size = MultiByteToWideChar(CP_UTF8, 0, str, -1, NULL, 0);
    if (!size)
        return NULL;
    buf = hgcm_malloc(2 * size);
    if (!buf)
        return NULL;
    MultiByteToWideChar(CP_UTF8, 0, str, -1, buf, size);
    ret = makeSHFLString(buf);
    hgcm_free(buf);
    return ret;
}

int sf_VBoxHGCMSvcLoad (VBOXHGCMSVCFNTABLE *ptable);
int sf_init()
{
    int rc;

    svcTable.cbSize = sizeof (VBOXHGCMSVCFNTABLE);
    svcTable.u32Version = VBOX_HGCM_SVC_VERSION;
    helpers.pfnCallComplete = tcpCallComplete;
    svcTable.pHelpers = &helpers;
    rc = sf_VBoxHGCMSvcLoad(&svcTable);
    if (rc) {
        LogRel(("VBoxHGCMSvcLoad error 0x%x\n", rc));
        return rc;
    }
    return rc;
}

int
sf_add_mapping(char *folder, char *name, int writable,
               uint64_t opts, uint64_t quota)
{
    SHFLSTRING *folder_sstr, *name_sstr;
    int rc;

    folder_sstr = makeSHFLStringUTF8(folder);
    if (!folder_sstr)
        return VERR_NO_MEMORY;

    name_sstr = makeSHFLStringUTF8(name);
    if (!name_sstr)
        return VERR_NO_MEMORY;

    if (!hide_log_sensitive_data)
        LogRel(("shared-folders: Host path '%ls', map name '%ls', %s, opts=0x%" PRIx64
                ", quota=%" PRId64 "\n",
                folder_sstr->String.ucs2,
                name_sstr->String.ucs2,
                writable ? "writable" : "read-only",
                opts,
                quota));

    /* Execute the function. */
    rc = vbsfMappingsAdd(folder_sstr, name_sstr,
                         writable, 0, 0, opts, quota);

    hgcm_free(folder_sstr);
    hgcm_free(name_sstr);

    return rc;
}

