/** @file
 * Shared Clipboard:
 * Common header for host service and guest clients.
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

#ifndef ___VBox_HostService_VBoxClipboardSvc_h
#define ___VBox_HostService_VBoxClipboardSvc_h

#include <VBox/types.h>
#include <VBox/VMMDev.h>
#include <VBox/VBoxGuest2.h>
#include <VBox/hgcmsvc.h>

/*
 * The mode of operations.
 */
#define VBOX_SHARED_CLIPBOARD_MODE_OFF           0
#define VBOX_SHARED_CLIPBOARD_MODE_HOST_TO_GUEST 1
#define VBOX_SHARED_CLIPBOARD_MODE_GUEST_TO_HOST 2
#define VBOX_SHARED_CLIPBOARD_MODE_BIDIRECTIONAL 3

/*
 * Supported data formats. Bit mask.
 */
#define VBOX_SHARED_CLIPBOARD_FMT_UNICODETEXT 0x01
#define VBOX_SHARED_CLIPBOARD_FMT_BITMAP      0x02
#define VBOX_SHARED_CLIPBOARD_FMT_HTML        0x04
#define VBOX_SHARED_CLIPBOARD_FMT_UNSUPPORTED 0x08

/*
 * The service functions which are callable by host.
 */
#define VBOX_SHARED_CLIPBOARD_HOST_FN_SET_MODE      1
/** Run headless on the host, i.e. do not touch the host clipboard. */
#define VBOX_SHARED_CLIPBOARD_HOST_FN_SET_HEADLESS  2
/** Pass pVM to clipboard code */
#define VBOX_SHARED_CLIPBOARD_HOST_FN_SET_PVM       3

/*
 * The service functions which are called by guest.
 */
/* Call host and wait blocking for an host event VBOX_SHARED_CLIPBOARD_HOST_MSG_* */
#define VBOX_SHARED_CLIPBOARD_FN_GET_HOST_MSG      1
/* Send list of available formats to host. */
#define VBOX_SHARED_CLIPBOARD_FN_FORMATS           2
/* Obtain data in specified format from host. */
#define VBOX_SHARED_CLIPBOARD_FN_READ_DATA         3
/* Send data in requested format to host. */
#define VBOX_SHARED_CLIPBOARD_FN_WRITE_DATA        4
/* Send list of available formats to host, new style. */
#define VBOX_SHARED_CLIPBOARD_FN_FORMATS_V2        5

/*
 * The host messages for the guest.
 */
#define VBOX_SHARED_CLIPBOARD_HOST_MSG_QUIT        1
#define VBOX_SHARED_CLIPBOARD_HOST_MSG_READ_DATA   2
#define VBOX_SHARED_CLIPBOARD_HOST_MSG_FORMATS     3

/*
 * HGCM parameter structures.
 */
#pragma pack (1)
typedef struct _VBoxClipboardGetHostMsg
{
    VBoxGuestHGCMCallInfo hdr;

    /* VBOX_SHARED_CLIPBOARD_HOST_MSG_* */
    HGCMFunctionParameter msg;     /* OUT uint32_t */

    /* VBOX_SHARED_CLIPBOARD_FMT_*, depends on the 'msg'. */
    HGCMFunctionParameter formats; /* OUT uint32_t */
} VBoxClipboardGetHostMsg;

#define VBOX_SHARED_CLIPBOARD_CPARMS_GET_HOST_MSG 2

typedef struct _VBoxClipboardFormats
{
    VBoxGuestHGCMCallInfo hdr;

    /* VBOX_SHARED_CLIPBOARD_FMT_* */
    HGCMFunctionParameter formats; /* OUT uint32_t */
} VBoxClipboardFormats;

#define VBOX_SHARED_CLIPBOARD_CPARMS_FORMATS 1

typedef struct _VBoxClipboardReadData
{
    VBoxGuestHGCMCallInfo hdr;

    /* Requested format. */
    HGCMFunctionParameter format; /* IN uint32_t */

    /* The data buffer. */
    HGCMFunctionParameter ptr;    /* IN linear pointer. */

    /* Size of returned data, if > ptr->cb, then no data was
     * actually transferred and the guest must repeat the call.
     */
    HGCMFunctionParameter size;   /* OUT uint32_t */

} VBoxClipboardReadData;

#define VBOX_SHARED_CLIPBOARD_CPARMS_READ_DATA 3

typedef struct _VBoxClipboardWriteData
{
    VBoxGuestHGCMCallInfo hdr;

    /* Returned format as requested in the VBOX_SHARED_CLIPBOARD_HOST_MSG_READ_DATA message. */
    HGCMFunctionParameter format; /* IN uint32_t */

    /* Data.  */
    HGCMFunctionParameter ptr;    /* IN linear pointer. */
} VBoxClipboardWriteData;

#define VBOX_SHARED_CLIPBOARD_CPARMS_WRITE_DATA 2

typedef struct _VBoxClipboardFormatsV2
{
    VBoxGuestHGCMCallInfo hdr;

    /* Data.  */
    HGCMFunctionParameter ptr;    /* IN linear pointer. */
} VBoxClipboardFormatsV2;

#define VBOX_SHARED_CLIPBOARD_CPARMS_FORMATS_V2 1

#pragma pack ()

#endif
