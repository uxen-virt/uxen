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
 * Copyright 2013-2017, Bromium, Inc.
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

#include <iprt/time.h>
#include <iprt/mem.h>
#include <iprt/path.h>
#include <iprt/string.h>
#include <iprt/log.h>
#include <malloc.h>
#include <VBox/VMMDev.h>
#include <VBox/VBoxGuest2.h>
#include "hgcm-simple.h"
#include "../uxensf/driver/hgcm-limits.h"
#include "channel.h"
#include <VBox/VBoxGuestLib.h>
#include "../common/debug-user.h"

#define STATUS_NOT_IMPLEMENTED VERR_INVALID_PARAMETER
#define STATUS_INFO_LENGTH_MISMATCH VINF_BUFFER_OVERFLOW
//#define STATUS_NO_MEMORY VERR_NO_MEMORY

/* This is the equivalent of the Vbox VbglHGCMCall, that transfers data
over tcp, instead of real vbox hgcm.
*/
int VbglHGCMCall(VBGLHGCMHANDLE handle, VBoxGuestHGCMCallInfo* info, 
    uint32_t size)
{
    int rc;
    char *tmpbuf;
    TcpMarshallHeader header;
    TcpMarshallHeader *resp_hdr = NULL;
    int resp_len;

    header.magic = HGCMMagicSimple;
    header.u32Function = info->u32Function;
    header.u.cParms = info->cParms;
    rc = VbglHGCMCall_tcp_marshall(info, false, true, &header.size, NULL);
    if (rc)
        return STATUS_NOT_IMPLEMENTED;

    if (header.size > MAX_HGCM_PACKET_SIZE)
        return VINF_BUFFER_OVERFLOW;

    tmpbuf = (char*)malloc(header.size + sizeof(header));
    if (!tmpbuf)
        return VERR_NO_MEMORY;
    VbglHGCMCall_tcp_marshall(info, true, true, &header.size, 
        tmpbuf + sizeof(header));
    *(TcpMarshallHeader*)tmpbuf = header;

    rc = ChannelSend(tmpbuf, sizeof(header) + header.size);
    uxen_debug("BRHVSF: sent %d bytes rc=%d\n", sizeof(header)+header.size, rc);
    free(tmpbuf);
    tmpbuf = NULL;

    if (!rc)
        rc = ChannelRecv((void**)&tmpbuf, &resp_len);
    uxen_debug("BRHVSF: received %d bytes\n", resp_len);
    resp_hdr = (TcpMarshallHeader*)tmpbuf;
    if (!rc && resp_len < sizeof(TcpMarshallHeader)) {
        free(tmpbuf);
        return STATUS_INFO_LENGTH_MISMATCH;
    }
    if (!rc && resp_hdr->magic != HGCMMagicSimple)
        return STATUS_INFO_LENGTH_MISMATCH;
    uxen_debug("BRHVSF: sfdebug: channelrecv2 rc=0x%x\n", rc);
    if (!rc)
        rc = VbglHGCMCall_tcp_unmarshall(info, tmpbuf + sizeof(TcpMarshallHeader),
                                         info->cParms, true, resp_len - sizeof(TcpMarshallHeader));
    uxen_debug("BRHVSF: sfdebug: unmarshall rc=0x%x\n", rc);
    if (!rc) {
        info->result = resp_hdr->u.status;
        if (resp_hdr)
            uxen_debug("BRHVSF: sfdebug: resp.u.status 0x%x\n", resp_hdr->u.status);
    }
    free(tmpbuf);
    return rc;
}

