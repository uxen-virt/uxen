/*++

Copyright (c) Microsoft Corporation.  All rights reserved.

    THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF ANY
    KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE
    IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A PARTICULAR
    PURPOSE.

Module Name:

   TcbRcb.H

Abstract:

    This module declares the TCB and RCB structures, and the functions to
    manipulate them.

    See the comments in TcbRcb.c.

--*/
/*
 * uXen changes:
 *
 * Copyright 2015, Bromium, Inc.
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

#ifndef _TCBRCB_H
#define _TCBRCB_H



//
// TCB (Transmit Control Block)
// -----------------------------------------------------------------------------
//

typedef struct _TCB
{
    LIST_ENTRY              TcbLink;
    PNET_BUFFER             NetBuffer;
    ULONG                   FrameType;
    ULONG                   BytesActuallySent;
} TCB, *PTCB;



VOID
ReturnTCB(
    PMP_ADAPTER  Adapter,
    PTCB         Tcb);


//
// RCB (Receive Control Block)
// -----------------------------------------------------------------------------
//

typedef struct _RCB
{
    LIST_ENTRY              RcbLink;
    PNET_BUFFER_LIST        Nbl;
    PVOID                   Data;
#if (NDIS_SUPPORT_NDIS620)    
    PVOID                   LookaheadData;
#endif
} RCB, *PRCB;

PRCB
GetRCB(
    PMP_ADAPTER  Adapter,
    PNDIS_NET_BUFFER_LIST_8021Q_INFO Nbl1QInfo,
    PFRAME       Frame);

VOID
ReturnRCB(
    PMP_ADAPTER   Adapter,
    PRCB          Rcb);



#endif // _TCBRCB_H

