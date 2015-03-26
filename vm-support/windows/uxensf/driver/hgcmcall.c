/* $Revision: 37672 $ */
/** @file
 * VBoxGuestR0LibSharedFolders - Ring 0 Shared Folders calls.
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
 *
 * The contents of this file may alternatively be used under the terms
 * of the Common Development and Distribution License Version 1.0
 * (CDDL) only, as it comes in the "COPYING.CDDL" file of the
 * VirtualBox OSE distribution, in which case the provisions of the
 * CDDL are applicable instead of those of the GPL.
 *
 * You may elect to license modified versions of this file under the
 * terms and conditions of either the GPL or the CDDL or both.
 */
/*
 * uXen changes:
 *
 * Copyright 2013-2015, Bromium, Inc.
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

/* Entire file is ifdef'ed with !VBGL_VBOXGUEST */
#ifndef VBGL_VBOXGUEST

#ifdef RT_OS_LINUX
# include "VBoxGuestR0LibSharedFolders.h"
# define DbgPrint RTAssertMsg2Weak
#else
# include "VBoxGuestR0LibSharedFolders.h"
#endif
#include <iprt/time.h>
#include <iprt/mem.h>
#include <iprt/path.h>
#include <iprt/string.h>

#include "hgcm-simple.h"
#include "hgcm-limits.h"
#include "channel.h"
#define MEMTAG_MARSHALL_HEADER ((ULONG)'30rb')

/* Try to use static buffer in a common case, instead of ExAllocatePoolWithTag */
static char hgcmBuf[RING_SIZE];
#define BUFFER_OVERHEAD 4096

/* This is the equivalent of the Vbox VbglHGCMCall, that transfers data
over tcp (well, ChannelSend/Recv), instead of real vbox hgcm.
*/
int VbglHGCMCall_worker (VBGLHGCMHANDLE handle, VBoxGuestHGCMCallInfo* info, 
uint32_t size)
{
    int rc, sz;
    TcpMarshallHeader header, *resp_hdr=0;
    char *resp_body=0;

    header.magic = HGCMMagicSimple;
    header.u32Function = info->u32Function;
    header.u.cParms = info->cParms;
    rc = VbglHGCMCall_tcp_marshall(info, false, true, &header.size, NULL);
    if (rc)
        return STATUS_NOT_IMPLEMENTED;

    if ( header.size + sizeof(header) + BUFFER_OVERHEAD > RING_SIZE )
        return STATUS_BUFFER_OVERFLOW;

    VbglHGCMCall_tcp_marshall(info, true, true, &header.size, 
        hgcmBuf + sizeof(header));

    *((TcpMarshallHeader*)hgcmBuf) = header;

    ChannelPrepareReq();
    rc = ChannelSend(hgcmBuf, sizeof(header) + header.size);

    if (!NT_SUCCESS(rc)) {
        Log(("VBOXSF: send error 0x%x\n", rc));
        return rc;
    }

    rc = ChannelRecv(hgcmBuf, sizeof(hgcmBuf), &sz);
    if (!NT_SUCCESS(rc)) {
        Log(("VBOXSF: recv error 0x%x\n", rc));
        return rc;
    }

    resp_hdr = (TcpMarshallHeader*)hgcmBuf;
    resp_body = hgcmBuf + sizeof(TcpMarshallHeader);

    if (resp_hdr->magic != HGCMMagicSimple)
        return STATUS_INFO_LENGTH_MISMATCH;

    rc = VbglHGCMCall_tcp_unmarshall(info, resp_body, info->cParms, true, resp_hdr->size);
    if (!NT_SUCCESS(rc))
        return rc;

    info->result = resp_hdr->u.status;

    return rc;
}

KMUTEX g_Mutex;
static int init_done;
int VBOXCALL VbglHGCMCall (VBGLHGCMHANDLE handle, VBoxGuestHGCMCallInfo* info, uint32_t size)
{
    NTSTATUS status, rc;
    if (!init_done) {
        init_done = 1;
        KeInitializeMutex(&g_Mutex, 0);
    }
    status = KeWaitForMutexObject(&g_Mutex,
                                  UserRequest,
                                  KernelMode,
                                  FALSE,
                                  NULL);
    if (status) {
        Log(("BRHVSF: sfdebug: KeWaitForMutexObject error 0x%x\n", status));
        return status;
    }

    rc = VbglHGCMCall_worker(handle, info, size);
    KeReleaseMutex(&g_Mutex, FALSE);
    return rc;
}


#endif /* !VBGL_VBOXGUEST */
