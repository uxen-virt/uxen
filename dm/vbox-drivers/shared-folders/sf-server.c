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

#include <VBox/shflsvc.h>


#include <iprt/alloc.h>
#include <iprt/string.h>
#include <iprt/assert.h>
#include <windows.h>
#include "shfl.h"
#include "vbsf.h"
#include <generic-server.h>
#include <dm/vbox-drivers/heap.h>

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

static void *makeSHFLString(wchar_t *str)
{
    int len = 2*wcslen(str) + 2;
    PSHFLSTRING shfl = (PSHFLSTRING)hgcm_malloc(sizeof(SHFLSTRING) + len);
    shfl->u16Size = len;
    shfl->u16Length = len - 2;
    wcscpy(shfl->String.ucs2, str);
    return shfl;
}

static void *makeSHFLStringUTF8(char *str)
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

static int addMappingInternal(VBOXHGCMSVCFNTABLE *svcTable, char *folder, 
                              char *name, int writable, int crypt)
{
    VBOXHGCMSVCPARM addMappingParams[SHFL_CPARMS_ADD_MAPPING];
    void * shflString;
    int rc;

    addMappingParams[0].type = VBOX_HGCM_SVC_PARM_PTR;
    shflString = makeSHFLStringUTF8(folder);
    if (!shflString)
        return VERR_NO_MEMORY;
    addMappingParams[0].u.pointer.addr = shflString;
    addMappingParams[0].u.pointer.size = ShflStringSizeOfBuffer(shflString);

    addMappingParams[1].type = VBOX_HGCM_SVC_PARM_PTR;
    shflString = makeSHFLStringUTF8(name);
    if (!shflString)
        return VERR_NO_MEMORY;
    addMappingParams[1].u.pointer.addr = shflString;
    addMappingParams[1].u.pointer.size = ShflStringSizeOfBuffer(shflString);
    addMappingParams[2].type = VBOX_HGCM_SVC_PARM_32BIT;

    addMappingParams[2].u.uint32 = writable | (crypt << 3);

    rc = svcTable->pfnHostCall(NULL, SHFL_FN_ADD_MAPPING, SHFL_CPARMS_ADD_MAPPING, addMappingParams);

    hgcm_free(addMappingParams[0].u.pointer.addr);
    hgcm_free(addMappingParams[1].u.pointer.addr);

    return rc;
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

int sf_add_mapping(char *folder, char *name, int writable, int crypt)
{
    return addMappingInternal(&svcTable, folder, name, writable, crypt);
}

