/*++

Copyright (c) Microsoft Corporation.  All rights reserved.

    THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF ANY
    KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE
    IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A PARTICULAR
    PURPOSE.

Module Name:

        SendRCV.C

Abstract:

    This module contains miniport functions for handling Send & Receive
    packets and other helper routines called by these miniport functions.

    In order to excercise the send and receive code path of this driver,
    you should install more than one instance of the miniport. If there
    is only one instance installed, the driver throws the send packet on
    the floor and completes the send successfully. If there are more
    instances present, it indicates the incoming send packet to the other
    instances. For example, if there 3 instances: A, B, & C installed.
    Packets coming in for A instance would be indicated to B & C; packets
    coming into B would be indicated to C, & A; and packets coming to C
    would be indicated to A & B.

Revision History:

Notes:

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

#include "uxennet_private.h"

NDIS_STATUS
NICSendPacket(
    PMP_ADAPTER Adapter,
    PNDIS_PACKET Packet)
{
    NDIS_STATUS       Status = NDIS_STATUS_SUCCESS;
    ULONG  nbs;

    if (!MP_IS_READY(Adapter))
        return NDIS_STATUS_FAILURE;


    nbs = NdisInterlockedIncrement(&Adapter->nBusySend);
    ASSERT(nbs <= NIC_MAX_BUSY_SENDS);

    Status = uxen_net_send_packet(&Adapter->uxen_net, Packet);

    if (Status == NDIS_STATUS_PENDING) {
        NdisAcquireSpinLock(&Adapter->SendLock);
        InsertTailList( &Adapter->SendWaitList, (PLIST_ENTRY)&Packet->MiniportReserved[0] );
        NdisReleaseSpinLock(&Adapter->SendLock);
    }

    NDIS_SET_PACKET_STATUS(Packet, Status);

    switch (Status) {
        case NDIS_STATUS_PENDING:
            break;
        case NDIS_STATUS_SUCCESS:
            Adapter->GoodTransmits++;
        default:
            NdisMSendComplete(
                Adapter->AdapterHandle,
                Packet,
                Status
            );
            NdisInterlockedDecrement(&Adapter->nBusySend);
    }

    return (Status);
}


void NICSendQueuedPackets( PMP_ADAPTER Adapter)
{
    PNDIS_PACKET Packet;
    NDIS_STATUS status;
    PLIST_ENTRY pEntry;

    for (;;) {

        pEntry = (PLIST_ENTRY) NdisInterlockedRemoveHeadList(
                     &Adapter->SendWaitList,
                     &Adapter->SendLock);


        if (!pEntry) return;

        Packet = CONTAINING_RECORD(pEntry, NDIS_PACKET, MiniportReserved);
        status = NICSendPacket(Adapter, Packet);

        if (status != NDIS_STATUS_SUCCESS)
            return;
    }

    return;
}


VOID
MPSendPackets(
    IN  NDIS_HANDLE             MiniportAdapterContext,
    IN  PPNDIS_PACKET           PacketArray,
    IN  UINT                    NumberOfPackets)
/*++

Routine Description:

    Send Packet Array handler. Called by NDIS whenever a protocol
    bound to our miniport sends one or more packets.

    The input packet descriptor pointers have been ordered according
    to the order in which the packets should be sent over the network
    by the protocol driver that set up the packet array. The NDIS
    library preserves the protocol-determined ordering when it submits
    each packet array to MiniportSendPackets

    As a deserialized driver, we are responsible for holding incoming send
    packets in our internal queue until they can be transmitted over the
    network and for preserving the protocol-determined ordering of packet
    descriptors incoming to its MiniportSendPackets function.
    A deserialized miniport driver must complete each incoming send packet
    with NdisMSendComplete, and it cannot call NdisMSendResourcesAvailable.

    Runs at IRQL <= DISPATCH_LEVEL

Arguments:

    MiniportAdapterContext    Pointer to our adapter context
    PacketArray               Set of packets to send
    NumberOfPackets           Length of above array

Return Value:

    None

--*/
{
    PMP_ADAPTER       Adapter;
    NDIS_STATUS       Status;
    UINT              PacketCount;

    Adapter = (PMP_ADAPTER)MiniportAdapterContext;

    NICSendQueuedPackets( Adapter);

    for (PacketCount = 0; PacketCount < NumberOfPackets; PacketCount++) {
        //
        // Check for a zero pointer
        //
        ASSERT(PacketArray[PacketCount]);

        Status = NICSendPacket(Adapter, PacketArray[PacketCount]);
        if ( Status != NDIS_STATUS_SUCCESS ) {
            // you may do something
        }

    }

    return;
}





