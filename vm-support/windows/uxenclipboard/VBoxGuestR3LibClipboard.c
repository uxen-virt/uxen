/* $Id: VBoxGuestR3LibClipboard.cpp 33540 2010-10-28 09:27:05Z vboxsync $ */
/** @file
 * VBoxGuestR3Lib - Ring-3 Support Library for VirtualBox guest additions, Clipboard.
 */

/*
 * Copyright (C) 2007 Oracle Corporation
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

/*******************************************************************************
*   Header Files                                                               *
*******************************************************************************/
#include <VBoxClipboardSvc.h>
#include <iprt/assert.h>
#include <iprt/string.h>
#include <vbox/VBoxGuestLib.h>
#include "channel.h"

void VbglHGCMParmUInt32Set(HGCMFunctionParameter *pParm, uint32_t u32)
{
    pParm->type = VMMDevHGCMParmType_32bit;
    pParm->u.value64 = 0; /* init unused bits to 0 */
    pParm->u.value32 = u32;
}
void VbglHGCMParmPtrSet(HGCMFunctionParameter *pParm, void *pv, uint32_t cb,
    HGCMFunctionParameterType type)
{
    pParm->type                    = type;
    pParm->u.Pointer.size          = cb;
    pParm->u.Pointer.u.linearAddr  = (uintptr_t)pv;
}

int VbglHGCMParmUInt32Get(HGCMFunctionParameter *pParm, uint32_t *pu32)
{
    if (pParm->type == VMMDevHGCMParmType_32bit) {
        *pu32 = pParm->u.value32;
        return VINF_SUCCESS;
    }
    return VERR_INVALID_PARAMETER;
}

/**
 * Connects to the clipboard service.
 *
 * @returns VBox status code
 * @param   pu32ClientId    Where to put the client id on success. The client id
 *                          must be passed to all the other clipboard calls.
 */
VBGLR3DECL(int) VbglR3ClipboardConnect(uint32_t *pu32ClientId)
{
    return 0;
}


/**
 * Disconnect from the clipboard service.
 *
 * @returns VBox status code.
 * @param   u32ClientId     The client id returned by VbglR3ClipboardConnect().
 */
VBGLR3DECL(int) VbglR3ClipboardDisconnect(uint32_t u32ClientId)
{
    return 0;
}

#if 0
/**
 * Get a host message.
 *
 * This will block until a message becomes available.
 *
 * @returns VBox status code.
 * @param   u32ClientId     The client id returned by VbglR3ClipboardConnect().
 * @param   pMsg            Where to store the message id.
 * @param   pfFormats       Where to store the format(s) the message applies to.
 */
VBGLR3DECL(int) VbglR3ClipboardGetHostMsg(uint32_t u32ClientId, uint32_t *pMsg, uint32_t *pfFormats)
{
    return ChannelRecvHostMsg(pMsg, pfFormats);
}
#endif


/**
 * Reads data from the host clipboard.
 *
 * @returns VBox status code.
 * @retval  VINF_BUFFER_OVERFLOW    If there is more data available than the caller provided buffer space for.
 *
 * @param   u32ClientId     The client id returned by VbglR3ClipboardConnect().
 * @param   fFormat         The format we're requesting the data in.
 * @param   pv              Where to store the data.
 * @param   cb              The size of the buffer pointed to by pv.
 * @param   pcb             The actual size of the host clipboard data. May be larger than cb.
 */
VBGLR3DECL(int) VbglR3ClipboardReadData(uint32_t u32ClientId, uint32_t fFormat, void *pv, uint32_t cb, uint32_t *pcb)
{
    VBoxClipboardReadData Msg;

    Msg.hdr.result = VERR_WRONG_ORDER;
    Msg.hdr.u32ClientID = u32ClientId;
    Msg.hdr.u32Function = VBOX_SHARED_CLIPBOARD_FN_READ_DATA;
    Msg.hdr.cParms = 3;
    VbglHGCMParmUInt32Set(&Msg.format, fFormat);
    VbglHGCMParmPtrSet(&Msg.ptr, pv, cb, VMMDevHGCMParmType_LinAddr_Out);
    VbglHGCMParmUInt32Set(&Msg.size, 0);

    int rc = VbglHGCMCall(NULL, (VBoxGuestHGCMCallInfo*)&Msg, sizeof(Msg));
    if (RT_SUCCESS(rc))
    {
        rc = Msg.hdr.result;
        if (RT_SUCCESS(rc))
        {
            uint32_t cbActual;
            rc = VbglHGCMParmUInt32Get(&Msg.size, &cbActual);
            if (RT_SUCCESS(rc))
            {
                *pcb = cbActual;
                if (cbActual > cb)
                    return VINF_BUFFER_OVERFLOW;
                return Msg.hdr.result;
            }
        }
    }
    return rc;
}


/**
 * Advertises guest clipboard formats to the host.
 *
 * @returns VBox status code.
 * @param   u32ClientId     The client id returned by VbglR3ClipboardConnect().
 * @param   fFormats        The formats to advertise.
 */
VBGLR3DECL(int) VbglR3ClipboardReportFormats(uint32_t u32ClientId, uint32_t fFormats)
{
    VBoxClipboardFormats Msg;

    Msg.hdr.result = VERR_WRONG_ORDER;
    Msg.hdr.u32ClientID = u32ClientId;
    Msg.hdr.u32Function = VBOX_SHARED_CLIPBOARD_FN_FORMATS;
    Msg.hdr.cParms = 1;
    VbglHGCMParmUInt32Set(&Msg.formats, fFormats);

    int rc = VbglHGCMCall(NULL, (VBoxGuestHGCMCallInfo*)&Msg, sizeof(Msg));
    if (RT_SUCCESS(rc))
        rc = Msg.hdr.result;
    return rc;
}


/**
 * Advertises guest clipboard formats to the host, version 2.
 *
 * @returns VBox status code.
 * @param   u32ClientId     The client id returned by VbglR3ClipboardConnect().
 * @param   pv              The formats to advertise.
 * @param   cb              The length of formats blob
 */
VBGLR3DECL(int) VbglR3ClipboardReportFormatsV2(uint32_t u32ClientId, void *pv, uint32_t cb)
{
    VBoxClipboardFormatsV2 Msg;

    Msg.hdr.result = VERR_WRONG_ORDER;
    Msg.hdr.u32ClientID = u32ClientId;
    Msg.hdr.u32Function = VBOX_SHARED_CLIPBOARD_FN_FORMATS_V2;
    Msg.hdr.cParms = 1;
    VbglHGCMParmPtrSet(&Msg.ptr, pv, cb, VMMDevHGCMParmType_LinAddr_In);
    
    int rc = VbglHGCMCall(NULL, (VBoxGuestHGCMCallInfo*)&Msg, sizeof(Msg));
    if (RT_SUCCESS(rc))
        rc = Msg.hdr.result;
    return rc;
}

/**
 * Send guest clipboard data to the host.
 *
 * This is usually called in reply to a VBOX_SHARED_CLIPBOARD_HOST_MSG_READ_DATA message
 * from the host.
 *
 * @returns VBox status code.
 * @param   u32ClientId     The client id returned by VbglR3ClipboardConnect().
 * @param   fFormat         The format of the data.
 * @param   pv              The data.
 * @param   cb              The size of the data.
 */
VBGLR3DECL(int) VbglR3ClipboardWriteData(uint32_t u32ClientId, uint32_t fFormat, void *pv, uint32_t cb)
{
    VBoxClipboardWriteData Msg;
    Msg.hdr.result = VERR_WRONG_ORDER;
    Msg.hdr.u32ClientID = u32ClientId;
    Msg.hdr.u32Function = VBOX_SHARED_CLIPBOARD_FN_WRITE_DATA;
    Msg.hdr.cParms = 2;
    VbglHGCMParmUInt32Set(&Msg.format, fFormat);
    VbglHGCMParmPtrSet(&Msg.ptr, pv, cb, VMMDevHGCMParmType_LinAddr_In);

    int rc = VbglHGCMCall(NULL, (VBoxGuestHGCMCallInfo*)&Msg, sizeof(Msg));
    if (RT_SUCCESS(rc))
        rc = Msg.hdr.result;
    return rc;
}

