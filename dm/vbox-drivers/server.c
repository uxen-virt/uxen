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
#include <iprt/log.h>
#include <windows.h>
#include <hgcm-limits.h>
#include <hgcm-simple.h>
#include "generic-server.h"

/* This is effectively unused - we assume a single client.
   Retained to maintain svcCall prototype. */
static int g_u32ClientID = 0x01020304;

void convert_HGCMFunctionParameter_to_VBOXHGCMSVCPARM(HGCMFunctionParameter*f,
VBOXHGCMSVCPARM*p, int count)
{
    int i;
    for (i = 0; i < count; i++) {
        switch (f[i].type) {
            case VMMDevHGCMParmType_32bit:
                p[i].type = VBOX_HGCM_SVC_PARM_32BIT;
                p[i].u.uint32 = f[i].u.value32;
                break;
            case VMMDevHGCMParmType_64bit:
                p[i].type = VBOX_HGCM_SVC_PARM_64BIT;
                p[i].u.uint64 = f[i].u.value64;
                break;
            case VMMDevHGCMParmType_LinAddr:
            case VMMDevHGCMParmType_LinAddr_In:
            case VMMDevHGCMParmType_LinAddr_Out:
                p[i].type = VBOX_HGCM_SVC_PARM_PTR;
                p[i].u.pointer.size = f[i].u.Pointer.size;
                p[i].u.pointer.addr = (void*)(uintptr_t)f[i].u.Pointer.u.linearAddr;
            break;
            default:
                LogRel(("unknown HGCMFunctionParameter type 0x%x\n", f[i].type));
        }
    }
}

void convert_VBOXHGCMSVCPARM_to_HGCMFunctionParameter(HGCMFunctionParameter*f,
VBOXHGCMSVCPARM*p, int count)
{
    int i;
    for (i = 0; i < count; i++) {
        switch (f[i].type) {
            case VMMDevHGCMParmType_32bit:
                f[i].u.value32 = p[i].u.uint32;
                break;
            case VMMDevHGCMParmType_64bit:
                f[i].u.value64 = p[i].u.uint64;
                break;
            case VMMDevHGCMParmType_LinAddr:
            case VMMDevHGCMParmType_LinAddr_In:
            case VMMDevHGCMParmType_LinAddr_Out:
                f[i].u.Pointer.size = p[i].u.pointer.size;
            break;
            default:
                LogRel(("unknown HGCMFunctionParameter type 0x%x\n", f[i].type));
        }
    }
}

/* main generic server routine
   1) check whether the whole request has been received in req/reqsize.
      If not, return 0.
   2) If !respbuf, return 1, indicating there is a whole request available
   3) process request, and pass the response in respbuf/respsize
*/
int generic_server_process_request(char *req, int reqsize, char** respbuf, 
    int* respsize, int preallocated,
    svcCall_t svcCall, void *clientdata, int *g_HelperRc)
{
    TcpMarshallHeader *header, *respheader;
    uint32_t marshall_size;
    int rc;
    unsigned int i;
    char *tmpbuf;
    VBOXHGCMSVCPARM svcparms[MAX_HGCM_PARAMS];
    struct {
        VBoxGuestHGCMCallInfo callInfo;
        HGCMFunctionParameter parms[MAX_HGCM_PARAMS];
    } clientRequest;

    if (reqsize < sizeof(*header))
        return 0;
    header = (TcpMarshallHeader *) req;
    if (header->size > MAX_HGCM_PACKET_SIZE || header->u.cParms > MAX_HGCM_PARAMS) {
        LogRel(("generic_server header: magix=0x%x size=0x%x cParams=0x%x\n",
            header->magic, header->size, header->u.cParms));
        return VERR_BUFFER_OVERFLOW;
    }
    if (reqsize < sizeof(*header) + header->size)
        return 0;

    if (!respbuf)
        return 1;

    rc = VbglHGCMCall_tcp_unmarshall(&clientRequest.callInfo, req + sizeof(*header), 
        header->u.cParms, false, header->size);
    if (rc) {
        unsigned int i;
        LogRel(("generic_server unmarshall 0x%x ", rc));
        for (i = 0; i < header->size/4 && i < 256; i++)
            LogRel(("0x%x ", *(unsigned int*)(req + sizeof(*header) +4*i)));
        LogRel(("\n"));
        return VERR_INVALID_PARAMETER;
    }

    clientRequest.callInfo.cParms = header->u.cParms;
        
    convert_HGCMFunctionParameter_to_VBOXHGCMSVCPARM(clientRequest.parms,
        svcparms, header->u.cParms);
    svcCall(NULL, NULL, g_u32ClientID, clientdata,
        header->u32Function, header->u.cParms, svcparms);
    convert_VBOXHGCMSVCPARM_to_HGCMFunctionParameter(clientRequest.parms,
        svcparms, header->u.cParms);

    rc = VbglHGCMCall_tcp_marshall(&clientRequest.callInfo, false, false, &marshall_size, NULL);
    if (rc || marshall_size > MAX_HGCM_PACKET_SIZE) {
        LogRel(("generic_server: rc=0x%x marshall_size=0x%x?\n",
            rc, marshall_size));
        return VERR_BUFFER_OVERFLOW;
    }

    if (preallocated) {
        if (marshall_size + sizeof(*respheader) > *respsize)
            return VERR_BUFFER_OVERFLOW;
        tmpbuf = *respbuf;
    } else {
        /* TODO: get rid of this allocation (used in clipboard only?) */
        tmpbuf = malloc(marshall_size + sizeof(*respheader));
        if (!tmpbuf) {
            LogRel(("generic_server: malloc for 0x%x failed\n", marshall_size + sizeof(*respheader)));
            return VERR_NO_MEMORY;
        }
    }

    respheader = (TcpMarshallHeader *)(tmpbuf);
    VbglHGCMCall_tcp_marshall(&clientRequest.callInfo, true, false, &respheader->size,
        tmpbuf + sizeof(*respheader));
    respheader->u.status = *g_HelperRc;
    respheader->magic = HGCMMagicSimple;
    Log(("generic_server resp.size=0x%x\n", respheader->size));
    *respbuf = tmpbuf;
    *respsize = marshall_size + sizeof(*respheader);
    
    for (i = 0;i < header->u.cParms; i++) {
        switch (clientRequest.parms[i].type) {
            case VMMDevHGCMParmType_LinAddr:
            case VMMDevHGCMParmType_LinAddr_In:
            case VMMDevHGCMParmType_LinAddr_Out:
                RTMemFree((void*)(uintptr_t)clientRequest.parms[i].u.Pointer.u.linearAddr);
                break;
            default:;
        }
    }

    return 1;
}

