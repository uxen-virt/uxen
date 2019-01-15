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
 * Copyright 2013-2019, Bromium, Inc.
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
#define MEMTAG_HGCMBUF ((ULONG)'30hg')

/* Try to use static buffer in a common case, instead of ExAllocatePoolWithTag */
static NPAGED_LOOKASIDE_LIST lookaside_hgcmbuf;

#define HGCMBUF_SIZE RING_SIZE
#define BUFFER_OVERHEAD 4096

#include "dbghlp.h"

void *hgcmbuf_get(void)
{
    return ExAllocateFromNPagedLookasideList(&lookaside_hgcmbuf);
}

void hgcmbuf_put(void *p)
{
    ExFreeToNPagedLookasideList(&lookaside_hgcmbuf, p);
}

/* This is the equivalent of the Vbox VbglHGCMCall, that transfers data
over tcp (well, ChannelSend/Recv), instead of real vbox hgcm.
*/
int VbglHGCMCall_worker (VBGLHGCMHANDLE handle, VBoxGuestHGCMCallInfo* info, 
uint32_t size)
{
    int rc, sz;
    TcpMarshallHeader header, *resp_hdr=0;
    char *resp_body=0;
    struct channel_req req;
    char *hgcmBuf = NULL;

    verify_on_stack(info);

    header.magic = HGCMMagicSimple;
    header.u32Function = info->u32Function;
    header.u.cParms = info->cParms;
    rc = VbglHGCMCall_tcp_marshall(info, false, true, &header.size, NULL);
    if (rc) {
        rc = STATUS_NOT_IMPLEMENTED;
        goto out;
    }

    if ( header.size + sizeof(header) + BUFFER_OVERHEAD > RING_SIZE ) {
        rc = STATUS_BUFFER_OVERFLOW;
        goto out;
    }

    hgcmBuf = hgcmbuf_get();
    if (!hgcmBuf) {
        uxen_err("VBOXSF: out of memory while getting hgcm buffer\n");
        rc = STATUS_NO_MEMORY;
        goto out;
    }

    VbglHGCMCall_tcp_marshall(info, true, true, &header.size, 
        hgcmBuf + sizeof(header));

    *((TcpMarshallHeader*)hgcmBuf) = header;

    ChannelPrepareReq(&req, hgcmBuf, HGCMBUF_SIZE, sizeof(header) + header.size);
    rc = ChannelSendReq(&req);

    if (!NT_SUCCESS(rc)) {
        ChannelReleaseReq(&req);
        uxen_err("VBOXSF: send error 0x%x\n", rc);
        goto out;
    }

    rc = ChannelRecvResp(&req, &sz);
    if (!NT_SUCCESS(rc)) {
        ChannelReleaseReq(&req);
        uxen_err("VBOXSF: recv error 0x%x\n", rc);
        goto out;
    }

    ChannelReleaseReq(&req);

    resp_hdr = (TcpMarshallHeader*)hgcmBuf;
    resp_body = hgcmBuf + sizeof(TcpMarshallHeader);

    if (resp_hdr->magic != HGCMMagicSimple) {
        rc = STATUS_INFO_LENGTH_MISMATCH;
        goto out;
    }

    verify_on_stack(info);

    rc = VbglHGCMCall_tcp_unmarshall(info, resp_body, info->cParms, true, resp_hdr->size);
    if (!NT_SUCCESS(rc))
        goto out;

    info->result = resp_hdr->u.status;

out:
    if (hgcmBuf)
        hgcmbuf_put(hgcmBuf);

    return rc;
}

void
hgcmcall_init(void)
{
    ExInitializeNPagedLookasideList(&lookaside_hgcmbuf,
        NULL, NULL, 0,
        HGCMBUF_SIZE, MEMTAG_HGCMBUF, 0);
    if (!NT_SUCCESS(ChannelConnect()))
        uxen_err("failed to connect v4v channel\n");
}

void
hgcmcall_cleanup(void)
{
    ChannelDisconnect();
    ExDeleteNPagedLookasideList(&lookaside_hgcmbuf);
}

int VBOXCALL VbglHGCMCall (VBGLHGCMHANDLE handle, VBoxGuestHGCMCallInfo* info, uint32_t size)
{
    NTSTATUS status, rc;

    verify_on_stack(info);

    rc = VbglHGCMCall_worker(handle, info, size);

    return rc;
}


#endif /* !VBGL_VBOXGUEST */
