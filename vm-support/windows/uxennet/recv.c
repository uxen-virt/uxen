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

#undef FISH
#define FISH do { DEBUGP(MP_TRACE, ("%s:%s:%d\n",__FILE__,__FUNCTION__,__LINE__)); } while (0)


VOID
NICFreeRCB(
    IN PRCB pRCB)
/*++

Routine Description:

    pRCB      - pointer to RCB block

Arguments:

    This routine reinitializes the RCB block and puts it back
    into the RecvFreeList for reuse.


Return Value:

    VOID

--*/
{
    PMP_ADAPTER Adapter = pRCB->Adapter;
    BOOLEAN schedule;

    DEBUGP(MP_TRACE, ("--> NICFreeRCB %p\n", pRCB));

    ASSERT(!pRCB->Buffer->Next); // should be NULL
    ASSERT(!pRCB->Ref); // should be 0
    ASSERT(pRCB->Adapter); // shouldn't be NULL

    NdisAdjustBufferLength(pRCB->Buffer, NIC_BUFFER_SIZE);

    //DbgPrint("NICFreeRCB, returning packet to list\n");

    NdisAcquireSpinLock(&Adapter->RecvLock);
    schedule = IsListEmpty(&Adapter->RecvFreeList);
//    RemoveEntryList(&pRCB->List);
    InsertTailList(&Adapter->RecvFreeList, &pRCB->List);
    NdisInterlockedDecrement(&Adapter->nBusyRecv);
    ASSERT(Adapter->nBusyRecv >= 0);

    NdisReleaseSpinLock(&Adapter->RecvLock);

    if (schedule)
        KeInsertQueueDpc(&Adapter->RecvDpc, NULL, NULL);
}




VOID
MPReturnPacket(
    IN NDIS_HANDLE  MiniportAdapterContext,
    IN PNDIS_PACKET Packet)
/*++

Routine Description:

    NDIS Miniport entry point called whenever protocols are done with
    a packet that we had indicated up and they had queued up for returning
    later.

Arguments:

    MiniportAdapterContext    - pointer to MP_ADAPTER structure
    Packet    - packet being returned.

Return Value:

    None.

--*/
{
    PRCB pRCB = NULL;
    PMP_ADAPTER Adapter;
    LONG l;

    UNREFERENCED_PARAMETER(MiniportAdapterContext);

    DEBUGP(MP_TRACE, ("---> MPReturnPacket\n"));

    pRCB = *(PRCB *)Packet->MiniportReserved;

    // DbgPrint("MPReturnPacket, rcb->ref is %d\n",pRCB->Ref);


    Adapter = pRCB->Adapter;

    ASSERT(Adapter);

    //Adapter->nPacketsReturned++;

    if (pRCB->magic != 0x12345678)
        KeBugCheckEx(0xdead, 0xbeef, 0xfee1, 0xbad, 0xdead);

    l = pRCB->Ref;


    if (NdisInterlockedDecrement(&pRCB->Ref) != 0) {
        DbgPrint("R1! %p\n", pRCB);
        KeBugCheckEx(0xdead, 0xbeef, 0xfee1, 0xbad, 0xdead);
    }
//    DbgPrint("R- %p (%d)\n",pRCB,l);
    NICFreeRCB(pRCB);

    DEBUGP(MP_TRACE, ("<--- MPReturnPacket\n"));
}





VOID
NICIndicateReceivedPacket(
    IN PRCB             pRCB,
    IN ULONG            BytesToIndicate
)
/*++

Routine Description:

    Initialize the packet to describe the received data and
    indicate to NDIS.

Arguments:

    pRCB - pointer to the RCB block
    BytesToIndicate - number of bytes to indicate

Return value:

    VOID
--*/
{
    ULONG           PacketLength;
    PNDIS_BUFFER    CurrentBuffer = NULL;
    PMP_ADAPTER     Adapter = pRCB->Adapter;
    PNDIS_PACKET    Packet = pRCB->Packet;
//    KIRQL           oldIrql;

    NdisAdjustBufferLength(pRCB->Buffer, BytesToIndicate);

    //
    // Prepare the recv packet
    //

    NdisReinitializePacket(Packet);

    *((PRCB *)Packet->MiniportReserved) = pRCB;


    //
    // Chain the TCB buffers to the packet
    //
    NdisChainBufferAtBack(Packet, pRCB->Buffer);

    NdisQueryPacket(Packet, NULL, NULL, &CurrentBuffer, (PUINT) &PacketLength);

    ASSERT(CurrentBuffer == pRCB->Buffer);

    NdisInterlockedIncrement(&pRCB->Ref);
//    DbgPrint("R+ %p\n",pRCB);


    NDIS_SET_PACKET_STATUS(pRCB->Packet, NDIS_STATUS_SUCCESS);
    //Adapter->nPacketsIndicated++;


    //DbgPrint("Received packet of %d bytes\n",(int) BytesToIndicate);
    NdisMIndicateReceivePacket(Adapter->AdapterHandle, &pRCB->Packet, 1);
}




int RecvPackets(MP_ADAPTER *adapter)
{
    ssize_t        len;
    RCB     *pRCB;

    uxen_v4v_ring_handle_t *rh = adapter->uxen_net.recv_ring;

    int notify = 0;
    do {
        len = uxen_v4v_copy_out(rh, NULL, NULL, NULL, 0, 0);

//    DbgPrint("Packet of size %d on ring\n",len);

        if (len < 0) //Finished return
            return notify;

        NdisAcquireSpinLock(&adapter->RecvLock);

        if (IsListEmpty(&adapter->RecvFreeList)) {
            NdisReleaseSpinLock(&adapter->RecvLock);
            DbgPrint("No RCBs - leaving on ring\n", len);
            return notify;
        }

        pRCB = (PRCB) RemoveHeadList(&adapter->RecvFreeList);
        NdisReleaseSpinLock(&adapter->RecvLock);


        ASSERT(pRCB);
        if (pRCB->Ref) {
            DbgPrint("R2! %p (%d)\n", pRCB, pRCB->Ref);
            KeBugCheckEx(0xdead, 0xbeef, 0xfee1, 0xbad, 0xdead);
        }
        NdisInterlockedIncrement(&adapter->nBusyRecv);


        len = min(len, NIC_BUFFER_SIZE);

        uxen_v4v_copy_out(rh, NULL, NULL, pRCB->Data, len, 1);

        if (len < ETH_MIN_PACKET_SIZE) {
            memset(pRCB->Data + len, 0, ETH_MIN_PACKET_SIZE - len);
            len = ETH_MIN_PACKET_SIZE;
        }


        //XXX: small packets are expanded do that here

        //adapter->GoodReceives++;


        if (pRCB->magic != 0x12345678)
            KeBugCheckEx(0xdead, 0xbeef, 0xfee1, 0xbad, 0xdead);

        NICIndicateReceivedPacket(pRCB, len);

        notify++;

    } while (1);
}



VOID RecvDpcFunc(
    IN    PVOID                    SystemSpecific1,
    IN    PVOID                    FunctionContext,
    IN    PVOID                    SystemSpecific2,
    IN    PVOID                    SystemSpecific3)
{
    PMP_ADAPTER Adapter = (PMP_ADAPTER)FunctionContext;
    static LONG fish;

    SystemSpecific1;
    SystemSpecific2;
    SystemSpecific3;

#if 0
    if (NdisInterlockedIncrement(&fish) == 1) {
//        DbgPrint("C\n");

#endif
        if (RecvPackets(Adapter))
            KeInsertQueueDpc(&Adapter->NotifyDpc, NULL, NULL);
        NdisInterlockedDecrement(&fish);
#if 0
    } else {
        DbgPrint("N\n");
        NdisInterlockedDecrement(&fish);
    }
#endif

    NICSendQueuedPackets( Adapter);

}

VOID NotifyDpcFunc(

    IN    PVOID                    SystemSpecific1,
    IN    PVOID                    FunctionContext,
    IN    PVOID                    SystemSpecific2,
    IN    PVOID                    SystemSpecific3)
{
    PMP_ADAPTER Adapter = (PMP_ADAPTER)FunctionContext;

    SystemSpecific1;
    SystemSpecific2;
    SystemSpecific3;

    Adapter;
    uxen_v4v_notify();

}








