/*++

Copyright (c) Microsoft Corporation.  All rights reserved.

    THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF ANY
    KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE
    IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A PARTICULAR
    PURPOSE.

Module Name:

   MpHAL.H

Abstract:

    This module declares the structures and functions that abstract the
    adapter and medium's (emulated) hardware capabilities.

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

#ifndef _MPHAL_H
#define _MPHAL_H


//
// A FRAME represents the physical bits as they are being transmitted on the
// wire.  Normally, a miniport wouldn't need to implement any such tracking,
// but we have to simulate our own Ethernet hub.
//
typedef struct _FRAME
{
    volatile LONG           Ref;
    PMDL                    Mdl;
    ULONG                   ulSize;
    UCHAR                   Data[NIC_BUFFER_SIZE];
} FRAME, *PFRAME;

ALLOCATE_FUNCTION HWFrameAllocate;
FREE_FUNCTION HWFrameFree;

struct _TCB;
struct _RCB;

//
// Structures and utility macros to retrieve and set VLAN tag related data
//
#define FRAME_8021Q_ETHER_TYPE      0x81
#define IS_FRAME_8021Q(_Frame)\
    (((PNIC_FRAME_HEADER)(_Frame)->Data)->EtherType[0] == FRAME_8021Q_ETHER_TYPE)

typedef struct _VLAN_TAG_HEADER
{
    UCHAR       TagInfo[2];    
} VLAN_TAG_HEADER, *PVLAN_TAG_HEADER;

#define GET_FRAME_VLAN_TAG_HEADER(_Frame)\
    ((VLAN_TAG_HEADER UNALIGNED *)((PNIC_FRAME_HEADER)(_Frame)->Data)->EtherType+1)

#define USER_PRIORITY_MASK          0xe0
#define CANONICAL_FORMAT_ID_MASK    0x10
#define HIGH_VLAN_ID_MASK           0x0F

#define COPY_TAG_INFO_FROM_HEADER_TO_PACKET_INFO(_Ieee8021qInfo, _pTagHeader)                                   \
{                                                                                                               \
    (_Ieee8021qInfo).TagHeader.UserPriority = ((_pTagHeader->TagInfo[0] & USER_PRIORITY_MASK) >> 5);              \
    (_Ieee8021qInfo).TagHeader.CanonicalFormatId = ((_pTagHeader->TagInfo[0] & CANONICAL_FORMAT_ID_MASK) >> 4);   \
    (_Ieee8021qInfo).TagHeader.VlanId = (((USHORT)(_pTagHeader->TagInfo[0] & HIGH_VLAN_ID_MASK) << 8)| (USHORT)(_pTagHeader->TagInfo[1]));                                                                \
}

VOID
HWFrameReference(PFRAME  Frame);

VOID
HWFrameRelease(PFRAME  Frame);

NDIS_STATUS
HWInitialize(PMP_ADAPTER Adapter,
             NDIS_HANDLE  WrapperConfigurationContext);

VOID
HWReadPermanentMacAddress(
    PMP_ADAPTER  Adapter,
    NDIS_HANDLE  ConfigurationHandle,
    PUCHAR  PermanentMacAddress);

NDIS_STATUS
HWGetDestinationAddress(
    PNET_BUFFER  NetBuffer,
    PUCHAR DestAddress);

BOOLEAN
HWIsFrameAcceptedByPacketFilter(
    PMP_ADAPTER  Adapter,
    PUCHAR  DestAddress,
    ULONG        FrameType);

NDIS_MEDIA_CONNECT_STATE
HWGetMediaConnectStatus(
    PMP_ADAPTER Adapter);

VOID
HWProgramDmaForSend(
    PMP_ADAPTER   Adapter,
    struct _TCB  *Tcb,
    PNET_BUFFER   NetBuffer,
    BOOLEAN       fAtDispatch);

ULONG
HWGetBytesSent(
    PMP_ADAPTER  Adapter,
    struct _TCB *Tcb);

NDIS_STATUS
HWBeginReceiveDma(
    PMP_ADAPTER   Adapter,
    PNDIS_NET_BUFFER_LIST_8021Q_INFO Nbl1QInfo,
    struct _RCB *Rcb,
    PFRAME       Frame);

#endif // _MPHAL_H
