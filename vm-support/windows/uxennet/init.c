/*++

Copyright (c) Microsoft Corporation.  All rights reserved.

    THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF ANY
    KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE
    IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A PARTICULAR
    PURPOSE.

Module Name:

   INIT.C

Abstract:

    This module contains initialization helper routines called during
    MiniportInitialize.

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

#pragma warning(disable:4201)  //standard extension used : nameless struct/union
#include "uxennet_private.h"

#pragma NDIS_PAGEABLE_FUNCTION(NICAllocAdapter)
#pragma NDIS_PAGEABLE_FUNCTION(NICFreeAdapter)
#pragma NDIS_PAGEABLE_FUNCTION(NICInitializeAdapter)
#pragma NDIS_PAGEABLE_FUNCTION(NICReadRegParameters)





NDIS_STATUS
NICAllocRecvResources(
    PMP_ADAPTER Adapter)
/*++
Routine Description:

    Allocate resources required to receive packets from the WDM driver


Arguments:

    Adapter - Pointer to our adapter

    Should be called at IRQL = PASSIVE_LEVEL.

Return Value:

    NDIS_STATUS_SUCCESS
    NDIS_STATUS_FAILURE
    NDIS_STATUS_RESOURCES

--*/
{
    PUCHAR pRCBMem = NULL;
    PNDIS_PACKET Packet = NULL;
    PNDIS_BUFFER Buffer = NULL;
    UINT index;
    NDIS_STATUS Status;
    BOOLEAN         bFalse = FALSE;

    DEBUGP(MP_TRACE, ("--> NICAllocRecvResources\n"));

    do {

        //
        // Following are the lists to hold packets at different
        // stages of processing.
        // RecvFreeList - Packets available for received operation
        // RecvBusyList - Packets posted  to the lower WDM stack
        // RecvLock is used to synchronize access to these lists.
        //
        NdisInitializeListHead(&Adapter->RecvFreeList);
        NdisInitializeListHead(&Adapter->RecvBusyList);
        NdisAllocateSpinLock(&Adapter->RecvLock);

        //
        // Let us set the flag to indicate that resources are allocated.
        // NICFreeRecvResources will check this flag to determine whether there
        // is any resource that needs to be freed.
        //

        MP_SET_FLAG(Adapter, fMP_RECV_SIDE_RESOURCE_ALLOCATED);

        //
        // Allocate a huge block of memory for all RCB's
        //
        Status = NdisAllocateMemoryWithTag(
                     &pRCBMem,
                     sizeof(RCB) * NIC_MAX_BUSY_RECVS,
                     NIC_TAG);

        if (Status != NDIS_STATUS_SUCCESS) {
            DEBUGP(MP_ERROR, ("Failed to allocate memory for RCB's\n"));
            break;
        }

        NdisZeroMemory(pRCBMem, sizeof(RCB) * NIC_MAX_BUSY_RECVS);
        Adapter->RCBMem = pRCBMem;

        //
        // Allocate a buffer pool for recv buffers.
        //

        NdisAllocateBufferPool(
            &Status,
            &Adapter->RecvBufferPoolHandle,
            NIC_MAX_BUSY_RECVS);
        if (Status != NDIS_STATUS_SUCCESS) {
            DEBUGP(MP_ERROR, ("NdisAllocateBufferPool for recv buffer failed\n"));
            break;
        }

        //
        // Allocate packet pool for receive indications
        //
        NdisAllocatePacketPool(
            &Status,
            &Adapter->RecvPacketPoolHandle,
            NIC_MAX_BUSY_RECVS,
            PROTOCOL_RESERVED_SIZE_IN_PACKET);

        if (Status != NDIS_STATUS_SUCCESS) {
            DEBUGP(MP_ERROR, ("NdisAllocatePacketPool failed\n"));
            break;
        }

        //
        // Divide the RCBMem blob into RCBs and create a buffer
        // descriptor for the Data portion of the RCBs.
        //
        for (index = 0; index < NIC_MAX_BUSY_RECVS; index++) {
            PRCB pRCB = (PRCB) pRCBMem;
            //
            // Create a buffer descriptor for the Data portion of the RCBs.
            // Buffer descriptors are nothing but MDLs on NT systems.
            //
            NdisAllocateBuffer(
                &Status,
                &Buffer,
                Adapter->RecvBufferPoolHandle,
                (PVOID)&pRCB->Data[0],
                NIC_BUFFER_SIZE);
            if (Status != NDIS_STATUS_SUCCESS) {
                DEBUGP(MP_ERROR, ("NdisAllocateBuffer for Recv failed\n"));
                break;
            }

            //
            // Initialize the RCB structure.
            //
            pRCB->Buffer = Buffer;
            pRCB->pData = (PUCHAR) &pRCB->Data[0];
            pRCB->Adapter = Adapter;
            pRCB->magic = 0x12345678;


            // Allocate a packet descriptor for receive packets
            // from a preallocated pool.
            //
            NdisAllocatePacket(
                &Status,
                &Packet,
                Adapter->RecvPacketPoolHandle);
            if (Status != NDIS_STATUS_SUCCESS) {
                DEBUGP(MP_ERROR, ("NdisAllocatePacket failed\n"));
                break;
            }

            pRCB->Packet = Packet;

            NDIS_SET_PACKET_HEADER_SIZE(Packet, ETH_HEADER_SIZE);

            NdisInterlockedInsertTailList(
                &Adapter->RecvFreeList,
                &pRCB->List,
                &Adapter->RecvLock);

            pRCBMem = pRCBMem + sizeof(RCB);

        }
    } while (bFalse);

    DEBUGP(MP_TRACE, ("--> NICAllocRecvResources %x\n", Status));

    return Status;

}


VOID
NICFreeRecvResources(
    PMP_ADAPTER Adapter)
/*++
Routine Description:

   Free resources allocated for receive operation

Arguments:

    Adapter - Pointer to our adapter

    Should be called at IRQL = PASSIVE_LEVEL.

Return Value:


--*/
{
    PRCB           pRCB;

    DEBUGP(MP_TRACE, ("--> NICFreeRecvResources\n"));

    PAGED_CODE();

    //
    // Free all the resources we allocated for receive.
    //
    if (!MP_TEST_FLAG(Adapter, fMP_RECV_SIDE_RESOURCE_ALLOCATED)) {
        return;
    }

    while (!IsListEmpty(&Adapter->RecvFreeList)) {
        pRCB = (PRCB) NdisInterlockedRemoveHeadList(
                   &Adapter->RecvFreeList,
                   &Adapter->RecvLock);
        if (!pRCB) {
            break;
        }

        if (pRCB->Buffer) {
            NdisFreeBuffer(pRCB->Buffer);
        }
        if (pRCB->Packet) {
            NdisFreePacket(pRCB->Packet);
        }

    }

    if (Adapter->RecvPacketPoolHandle) {
        NdisFreePacketPool(Adapter->RecvPacketPoolHandle);
        Adapter->RecvPacketPoolHandle = NULL;
    }

    if (Adapter->RecvBufferPoolHandle) {
        NdisFreeBufferPool(Adapter->RecvBufferPoolHandle);
        Adapter->RecvBufferPoolHandle = NULL;
    }

    if (Adapter->RCBMem) {
        NdisFreeMemory(Adapter->RCBMem, sizeof(RCB) * NIC_MAX_BUSY_RECVS, 0);
    }

    ASSERT(IsListEmpty(&Adapter->RecvFreeList));
    ASSERT(IsListEmpty(&Adapter->RecvBusyList));

    NdisFreeSpinLock(&Adapter->RecvLock);

    MP_CLEAR_FLAG(Adapter, fMP_RECV_SIDE_RESOURCE_ALLOCATED);

    return;
}

NDIS_STATUS
NICAllocSendResources(
    PMP_ADAPTER Adapter)
/*++
Routine Description:

    Allocate resources required to Send packets to the device

Arguments:

    Adapter    Pointer to our adapter
    Should be called at IRQL = PASSIVE_LEVEL.

Return Value:

    NDIS_STATUS_SUCCESS
    NDIS_STATUS_FAILURE
    NDIS_STATUS_RESOURCES

--*/
{
    NDIS_STATUS Status = NDIS_STATUS_SUCCESS;
#if 0
    UINT index;
    PNDIS_BUFFER Buffer = NULL;
    PUCHAR pTCBMem = NULL;
#endif
    BOOLEAN     bFalse = FALSE;

    DEBUGP(MP_TRACE, ("--> NICAllocSendResources\n"));

    do {
        //
        // Following are the lists to hold packets at different
        // stages of processing.
        // SendWaitList - Original send packets waiting to be processed
        // SendFreeList - Packets available for send operation
        // SendBusyList - Packets sent to the lower WDM stack
        // SendLock is used to synchronize access to these lists.
        //
        NdisInitializeListHead(&Adapter->SendWaitList);
        NdisInitializeListHead(&Adapter->SendFreeList);
        NdisInitializeListHead(&Adapter->SendBusyList);
        NdisAllocateSpinLock(&Adapter->SendLock);

        //
        // Let us set the flag to indicate resources are allocated.
        // NICFreeSendResources will check this flag to determine whether there
        // is any resource that needs to be freed.
        //

        MP_SET_FLAG(Adapter, fMP_SEND_SIDE_RESOURCE_ALLOCATED);

#if 0
        //
        // Allocate a huge block of memory for all TCB's
        //
        Status = NdisAllocateMemoryWithTag(
                     &pTCBMem,
                     sizeof(TCB) * NIC_MAX_BUSY_SENDS,
                     NIC_TAG);

        if (Status != NDIS_STATUS_SUCCESS) {
            DEBUGP(MP_ERROR, ("Failed to allocate memory for TCB's\n"));
            break;
        }
        NdisZeroMemory(pTCBMem, sizeof(TCB) * NIC_MAX_BUSY_SENDS);
        Adapter->TCBMem = pTCBMem;

        //
        // Allocate a buffer pool for send buffers.
        //

        NdisAllocateBufferPool(
            &Status,
            &Adapter->SendBufferPoolHandle,
            NIC_MAX_BUSY_SENDS);
        if (Status != NDIS_STATUS_SUCCESS) {
            DEBUGP(MP_ERROR, ("NdisAllocateBufferPool for send buffer failed\n"));
            break;
        }

        //
        // Divide the TCBMem blob into TCBs and create a buffer
        // descriptor for the Data portion of the TCBs. The reason for doing
        // this instead of using the OriginalSend Packet buffers is because
        // the target driver we are talking to is not capable of handling
        // chained buffers (MDLs).
        //
        for (index = 0; index < NIC_MAX_BUSY_SENDS; index++) {
            PTCB pTCB = (PTCB) pTCBMem;
            //
            // Create a buffer descriptor for the Data portion of the TCBs.
            // Buffer descriptors are nothing but MDLs on NT systems.
            //
            NdisAllocateBuffer(
                &Status,
                &Buffer,
                Adapter->SendBufferPoolHandle,
                (PVOID)&pTCB->Data[0],
                NIC_BUFFER_SIZE);
            if (Status != NDIS_STATUS_SUCCESS) {
                DEBUGP(MP_ERROR, ("NdisAllocateBuffer failed\n"));
                break;
            }

            //
            // Initialize the TCB structure.
            //
            pTCB->Buffer = Buffer;
            pTCB->pData = (PUCHAR) &pTCB->Data[0];
            pTCB->Adapter = Adapter;

            //
            // Insert TCB blocks into FreeList.
            //
            NdisInterlockedInsertTailList(
                &Adapter->SendFreeList,
                &pTCB->List,
                &Adapter->SendLock);

            pTCBMem = pTCBMem + sizeof(TCB);

        }
#endif
    } while (bFalse);

    DEBUGP(MP_TRACE, ("<-- NICAllocSendResources %x\n", Status));

    return Status;
}


VOID
NICFreeSendResources(
    PMP_ADAPTER Adapter)
/*++
Routine Description:

  Free resources allocated for send operation

Arguments:

    Adapter     Pointer to our adapter
    Should be called at IRQL = PASSIVE_LEVEL.

Return Value:

--*/
{
#if 0
    PTCB           pTCB;
#endif

    DEBUGP(MP_TRACE, ("--> NICFreeSendResources\n"));

    PAGED_CODE();

    //
    // Did we allocate any resources for send?
    //
    if (!MP_TEST_FLAG(Adapter, fMP_SEND_SIDE_RESOURCE_ALLOCATED)) {
        return;
    }

#if 0
    while (!IsListEmpty(&Adapter->SendFreeList)) {
        pTCB = (PTCB) NdisInterlockedRemoveHeadList(
                   &Adapter->SendFreeList,
                   &Adapter->SendLock);
        if (!pTCB) {
            break;
        }

        if (pTCB->Buffer) {
            NdisFreeBuffer(pTCB->Buffer);
        }
    }
#endif

#if 0
    if (Adapter->SendBufferPoolHandle) {
        NdisFreeBufferPool(Adapter->SendBufferPoolHandle);
        Adapter->SendBufferPoolHandle = NULL;
    }

    if (Adapter->TCBMem) {
        NdisFreeMemory(Adapter->TCBMem, sizeof(TCB) * NIC_MAX_BUSY_SENDS, 0);
        Adapter->TCBMem = NULL;
    }
#endif

    ASSERT(IsListEmpty(&Adapter->SendFreeList));

    //Hmm
    ASSERT(IsListEmpty(&Adapter->SendWaitList));

    NdisFreeSpinLock(&Adapter->SendLock);

    MP_CLEAR_FLAG(Adapter, fMP_SEND_SIDE_RESOURCE_ALLOCATED);

}

#pragma NDIS_PAGEABLE_FUNCTION(NICAllocAdapter)
#pragma NDIS_PAGEABLE_FUNCTION(NICFreeAdapter)
#pragma NDIS_PAGEABLE_FUNCTION(NICInitializeAdapter)
#pragma NDIS_PAGEABLE_FUNCTION(NICReadRegParameters)

NDIS_STATUS NICAllocAdapter(
    PMP_ADAPTER *pAdapter)
{
    PMP_ADAPTER Adapter = NULL;
    NDIS_STATUS Status;

    BOOLEAN     bFalse = FALSE;

    DEBUGP(MP_TRACE, ("--> NICAllocAdapter\n"));

    PAGED_CODE();

    *pAdapter = NULL;

    do {
        //
        // Allocate memory for adapter context
        //
        Status = NdisAllocateMemoryWithTag(
                     &Adapter,
                     sizeof(MP_ADAPTER),
                     NIC_TAG);
        if (Status != NDIS_STATUS_SUCCESS) {
            DEBUGP(MP_ERROR, ("Failed to allocate memory for adapter context\n"));
            break;
        }
        //
        // Zero the memory block
        //
        NdisZeroMemory(Adapter, sizeof(MP_ADAPTER));
        NdisInitializeListHead(&Adapter->List);

#if 1
        Status = NICAllocSendResources(Adapter);
        if (Status != NDIS_STATUS_SUCCESS) {
            DEBUGP(MP_ERROR, ("alloc send failed\n"));
            break;
        }
#endif

        Status = NICAllocRecvResources(Adapter);
        if (Status != NDIS_STATUS_SUCCESS) {
            DEBUGP(MP_ERROR, ("alloc recv failed\n"));
            break;
        }

        Adapter->uxen_net.parent = Adapter;

        Status = uxen_net_init_adapter(&Adapter->uxen_net);
        if (Status != NDIS_STATUS_SUCCESS) {
            DEBUGP(MP_ERROR, ("uxen_net_setup failed\n"));
            break;
        }


    } while (bFalse);


    *pAdapter = Adapter;

    //
    // In the failure case, the caller of this routine will end up
    // calling NICFreeAdapter to free all the successfully allocated
    // resources.
    //
    DEBUGP(MP_TRACE, ("<-- NICAllocAdapter\n"));

    return (Status);

}

void NICFreeAdapter(
    PMP_ADAPTER Adapter)
{

    DEBUGP(MP_TRACE, ("--> NICFreeAdapter\n"));

    PAGED_CODE();

    ASSERT(Adapter);
    ASSERT(!Adapter->RefCount);

    uxen_net_free_adapter(&Adapter->uxen_net);


    NICFreeSendResources(Adapter);
    NICFreeRecvResources(Adapter);



    //
    // Finally free the memory for adapter context.
    //
    NdisFreeMemory(Adapter, sizeof(MP_ADAPTER), 0);

    DEBUGP(MP_TRACE, ("<-- NICFreeAdapter\n"));
}

void NICAttachAdapter(PMP_ADAPTER Adapter)
{
    DEBUGP(MP_TRACE, ("--> NICAttachAdapter\n"));

    NdisInterlockedInsertTailList(
        &GlobalData.AdapterList,
        &Adapter->List,
        &GlobalData.Lock);

    DEBUGP(MP_TRACE, ("<-- NICAttachAdapter\n"));
}

void NICDetachAdapter(PMP_ADAPTER Adapter)
{
    DEBUGP(MP_TRACE, ("--> NICDetachAdapter\n"));

    NdisAcquireSpinLock(&GlobalData.Lock);
    RemoveEntryList(&Adapter->List);
    NdisReleaseSpinLock(&GlobalData.Lock);
    DEBUGP(MP_TRACE, ("<-- NICDetachAdapter\n"));
}

NDIS_STATUS
NICReadRegParameters(
    PMP_ADAPTER Adapter,
    NDIS_HANDLE WrapperConfigurationContext)
/*++
Routine Description:

    Read device configuration parameters from the registry

Arguments:

    Adapter                         Pointer to our adapter
    WrapperConfigurationContext     For use by NdisOpenConfiguration

    Should be called at IRQL = PASSIVE_LEVEL.

Return Value:

    NDIS_STATUS_SUCCESS
    NDIS_STATUS_FAILURE
    NDIS_STATUS_RESOURCES

--*/
{
    NDIS_STATUS     Status = NDIS_STATUS_SUCCESS;
    NDIS_HANDLE     ConfigurationHandle;
    PUCHAR          NetworkAddress;
    UINT            Length;
    PUCHAR          pAddr;
    static ULONG    g_ulAddress = 0;
    PNDIS_CONFIGURATION_PARAMETER param;
    NDIS_STRING ReportedMTUKey = NDIS_STRING_CONST("ReportedMTUKey");

    DEBUGP(MP_TRACE, ("--> NICReadRegParameters\n"));

    PAGED_CODE();

    //
    // Open the registry for this adapter to read advanced
    // configuration parameters stored by the INF file.
    //
    NdisOpenConfiguration(
        &Status,
        &ConfigurationHandle,
        WrapperConfigurationContext);
    if (Status != NDIS_STATUS_SUCCESS) {
        DEBUGP(MP_ERROR, ("NdisOpenConfiguration failed\n"));
        return NDIS_STATUS_FAILURE;
    }

    //
    // Read all of our configuration parameters using NdisReadConfiguration
    // and parse the value.
    //

    NdisReadConfiguration(&Status, &param, ConfigurationHandle, &ReportedMTUKey, NdisParameterInteger);

    Adapter->ulMTU = 1500;

    if (Status == NDIS_STATUS_SUCCESS) {
        if (param->ParameterType == NdisParameterInteger) {
            Adapter->ulMTU = param->ParameterData.IntegerData;
            DbgPrint("ReportedMTU from registry is %d\n", (int) Adapter->ulMTU);
        }
    }


    {
        ULONG qemu_mtu = 0;

        uxen_net_get_mtu(Adapter->Pdo, &qemu_mtu);
        DbgPrint("ReportedMTU from qemu is %d\n", (int) qemu_mtu);

        if (qemu_mtu && (qemu_mtu != 1500))
            Adapter->ulMTU = qemu_mtu;

    }

    DbgPrint("Using ReportedMTU of %d\n", (int) Adapter->ulMTU);

    //
    // Just for testing purposes, let us make up a dummy mac address.
    // In order to avoid conflicts with MAC addresses, it is usually a good
    // idea to check the IEEE OUI list (e.g. at
    // http://standards.ieee.org/regauth/oui/oui.txt). According to that
    // list 00-50-F2 is owned by Microsoft.
    //
    // An important rule to "generating" MAC addresses is to have the
    // "locally administered bit" set in the address, which is bit 0x02 for
    // LSB-type networks like Ethernet. Also make sure to never set the
    // multicast bit in any MAC address: bit 0x01 in LSB networks.
    //

    pAddr = (PUCHAR) &g_ulAddress;

    ++g_ulAddress;
    Adapter->PermanentAddress[0] = 0x02;
    Adapter->PermanentAddress[1] = 0x50;
    Adapter->PermanentAddress[2] = 0xF2;
    Adapter->PermanentAddress[3] = 0x00;
    Adapter->PermanentAddress[4] = 0x00;
    Adapter->PermanentAddress[5] = pAddr[0];

    ETH_COPY_NETWORK_ADDRESS(
        Adapter->CurrentAddress,
        Adapter->PermanentAddress);

    //
    // Read NetworkAddress registry value and use it as the current address
    // if there is a software configurable NetworkAddress specified in
    // the registry.
    //
    NdisReadNetworkAddress(
        &Status,
        &NetworkAddress,
        &Length,
        ConfigurationHandle);

    if ((Status == NDIS_STATUS_SUCCESS) && (Length == ETH_LENGTH_OF_ADDRESS) ) {
        if ((ETH_IS_MULTICAST(NetworkAddress)
             || ETH_IS_BROADCAST(NetworkAddress))
            || !ETH_IS_LOCALLY_ADMINISTERED (NetworkAddress)) {
            DEBUGP(MP_ERROR,
                   ("Overriding NetworkAddress is invalid - %02x-%02x-%02x-%02x-%02x-%02x\n",
                    NetworkAddress[0], NetworkAddress[1], NetworkAddress[2],
                    NetworkAddress[3], NetworkAddress[4], NetworkAddress[5]));
        } else {
            ETH_COPY_NETWORK_ADDRESS(Adapter->CurrentAddress, NetworkAddress);
        }
    }


    DbgPrint("Getting acpi address\n");
    uxen_net_get_mac_address(Adapter->Pdo, Adapter->PermanentAddress);
    uxen_net_get_mac_address(Adapter->Pdo, Adapter->CurrentAddress);

    DEBUGP(MP_LOUD, ("Permanent Address = %02x-%02x-%02x-%02x-%02x-%02x\n",
                     Adapter->PermanentAddress[0],
                     Adapter->PermanentAddress[1],
                     Adapter->PermanentAddress[2],
                     Adapter->PermanentAddress[3],
                     Adapter->PermanentAddress[4],
                     Adapter->PermanentAddress[5]));

    DEBUGP(MP_LOUD, ("Current Address = %02x-%02x-%02x-%02x-%02x-%02x\n",
                     Adapter->CurrentAddress[0],
                     Adapter->CurrentAddress[1],
                     Adapter->CurrentAddress[2],
                     Adapter->CurrentAddress[3],
                     Adapter->CurrentAddress[4],
                     Adapter->CurrentAddress[5]));

    Adapter->ulLinkSpeed = NIC_LINK_SPEED;

    //
    // Close the configuration registry
    //
    NdisCloseConfiguration(ConfigurationHandle);
    DEBUGP(MP_TRACE, ("<-- NICReadRegParameters\n"));

    return NDIS_STATUS_SUCCESS;
}

NDIS_STATUS NICInitializeAdapter(
    IN  PMP_ADAPTER  Adapter,
    IN  NDIS_HANDLE  WrapperConfigurationContext
)
/*++
Routine Description:

    Query assigned resources and initialize the adapter.

Arguments:

    Adapter     Pointer to our adapter

Return Value:

    NDIS_STATUS_SUCCESS
    NDIS_STATUS_ADAPTER_NOT_FOUND

--*/
{

    NDIS_STATUS         Status = NDIS_STATUS_ADAPTER_NOT_FOUND;
    typedef __declspec(align(MEMORY_ALLOCATION_ALIGNMENT)) NicResourceCharBuf;
    NicResourceCharBuf  resBuf[NIC_RESOURCE_BUF_SIZE];
    PNDIS_RESOURCE_LIST resList = (PNDIS_RESOURCE_LIST)resBuf;
    UINT                bufSize = NIC_RESOURCE_BUF_SIZE;
    PCM_PARTIAL_RESOURCE_DESCRIPTOR pResDesc;
    ULONG               index;
    BOOLEAN     bFalse = FALSE;

#ifndef NDIS50_MINIPORT
    UNREFERENCED_PARAMETER(Adapter);
#endif

    DEBUGP(MP_TRACE, ("---> InitializeAdapter\n"));
    PAGED_CODE();

    do {
        //
        // Get the resources assigned by the PNP manager. NDIS gets
        // these resources in IRP_MN_START_DEVICE request.
        //
        NdisMQueryAdapterResources(
            &Status,
            WrapperConfigurationContext,
            resList,
            &bufSize);

        if (Status == NDIS_STATUS_SUCCESS) {
#pragma prefast(suppress: 8199, "resList is initialized by NdisMQueryAdapterResources")
            for (index = 0; index < resList->Count; index++) {
                pResDesc = &resList->PartialDescriptors[index];

                switch (pResDesc->Type) {
                    case CmResourceTypePort:
                        DEBUGP(MP_INFO, ("IoBaseAddress = 0x%x\n",
                                         NdisGetPhysicalAddressLow(pResDesc->u.Port.Start)));
                        DEBUGP(MP_INFO, ("IoRange = x%x\n",
                                         pResDesc->u.Port.Length));
                        break;

                    case CmResourceTypeInterrupt:
                        DEBUGP(MP_INFO, ("InterruptLevel = x%x\n",
                                         pResDesc->u.Interrupt.Level));
                        break;

                    case CmResourceTypeMemory:
                        DEBUGP(MP_INFO, ("MemPhysAddress(Low) = 0x%0x\n",
                                         NdisGetPhysicalAddressLow(pResDesc->u.Memory.Start)));
                        DEBUGP(MP_INFO, ("MemPhysAddress(High) = 0x%0x\n",
                                         NdisGetPhysicalAddressHigh(pResDesc->u.Memory.Start)));
                        break;
                }
            }
        }

        Status = NDIS_STATUS_SUCCESS;

        //
        // Map bus-relative IO range to system IO space using
        // NdisMRegisterIoPortRange
        //

        //
        // Map bus-relative registers to virtual system-space
        // using NdisMMapIoSpace
        //


        //
        // Disable interrupts here as soon as possible
        //

        //
        // Register the interrupt using NdisMRegisterInterrupt
        //

        //
        // Initialize the hardware with mapped resources
        //

#ifdef NDIS50_MINIPORT
        //
        // Register a shutdown handler for NDIS50 or earlier miniports
        // For NDIS51 miniports, set AdapterShutdownHandler.
        //
        NdisMRegisterAdapterShutdownHandler(
            Adapter->AdapterHandle,
            (PVOID) Adapter,
            (ADAPTER_SHUTDOWN_HANDLER) MPShutdown);
#endif

        //
        // Enable the interrupt
        //

    } while (bFalse);

    DEBUGP(MP_TRACE, ("<--- InitializeAdapter, Status=%x\n", Status));

    return Status;

}





/******************************************************************************************/
/******************************************************************************************/
/******************************************************************************************/
/******************************************************************************************/
/******************************************************************************************/
/******************************************************************************************/
/******************************************************************************************/
/******************************************************************************************/
/******************************************************************************************/
/******************************************************************************************/
/******************************************************************************************/
/******************************************************************************************/
/******************************************************************************************/
/******************************************************************************************/
/******************************************************************************************/
/******************************************************************************************/
/******************************************************************************************/
/******************************************************************************************/
/******************************************************************************************/
/******************************************************************************************/
/******************************************************************************************/
/******************************************************************************************/
/******************************************************************************************/
/******************************************************************************************/
/******************************************************************************************/
/******************************************************************************************/
/******************************************************************************************/
/******************************************************************************************/
/******************************************************************************************/
/******************************************************************************************/
/******************************************************************************************/
/******************************************************************************************/
/******************************************************************************************/
/******************************************************************************************/
/******************************************************************************************/
/******************************************************************************************/
/******************************************************************************************/
/******************************************************************************************/
/******************************************************************************************/
/******************************************************************************************/
/******************************************************************************************/
/******************************************************************************************/





#if 0
NDIS_STATUS NICAllocAdapter(
    PMP_ADAPTER *pAdapter)
{
    PMP_ADAPTER Adapter = NULL;
    PNDIS_PACKET Packet;
    PNDIS_BUFFER Buffer;
    PUCHAR pRCBMem;
    PUCHAR pTCBMem;
    PTCB  pTCB;
    NDIS_STATUS Status;

    LONG index;
    BOOLEAN     bFalse = FALSE;

    DEBUGP(MP_TRACE, ("--> NICAllocAdapter\n"));

    PAGED_CODE();

    *pAdapter = NULL;

    do {
        //
        // Allocate memory for adapter context
        //
        Status = NdisAllocateMemoryWithTag(
                     &Adapter,
                     sizeof(MP_ADAPTER),
                     NIC_TAG);
        if (Status != NDIS_STATUS_SUCCESS) {
            DEBUGP(MP_ERROR, ("Failed to allocate memory for adapter context\n"));
            break;
        }
        //
        // Zero the memory block
        //
        NdisZeroMemory(Adapter, sizeof(MP_ADAPTER));
        NdisInitializeListHead(&Adapter->List);

        //
        // Initialize Send & Recv listheads and corresponding
        // spinlocks.

        NdisInitializeListHead(&Adapter->SendWaitList);
        NdisInitializeListHead(&Adapter->SendFreeList);
        NdisAllocateSpinLock(&Adapter->SendLock);

        NdisInitializeListHead(&Adapter->RecvFreeList);
        NdisAllocateSpinLock(&Adapter->RecvLock);

        //
        // Allocate lookside list for Receive Control blocks.
        //
        NdisInitializeNPagedLookasideList(
            &Adapter->RecvLookaside,
            NULL, // No Allocate function
            NULL, // No Free function
            0,    // Reserved for system use
            sizeof(RCB),
            NIC_TAG,
            0); // Reserved for system use

        MP_SET_FLAG(Adapter, fMP_ADAPTER_RECV_LOOKASIDE);

        //
        // Allocate packet pool for receive indications
        //
        NdisAllocatePacketPool(
            &Status,
            &Adapter->RecvPacketPoolHandle,
            NIC_MAX_BUSY_RECVS,
            PROTOCOL_RESERVED_SIZE_IN_PACKET);

        if (Status != NDIS_STATUS_SUCCESS) {
            DEBUGP(MP_ERROR, ("NdisAllocatePacketPool failed\n"));
            break;
        }
        //
        // Initialize receive packets
        //
        for (index = 0; index < NIC_MAX_BUSY_RECVS; index++) {
            //
            // Allocate a packet descriptor for receive packets
            // from a preallocated pool.
            //
            NdisAllocatePacket(
                &Status,
                &Packet,
                Adapter->RecvPacketPoolHandle);
            if (Status != NDIS_STATUS_SUCCESS) {
                DEBUGP(MP_ERROR, ("NdisAllocatePacket failed\n"));
                break;
            }

            NDIS_SET_PACKET_HEADER_SIZE(Packet, ETH_HEADER_SIZE);

            //
            // Insert it into the list of free receive packets.
            //
            NdisInterlockedInsertTailList(
                &Adapter->RecvFreeList,
                (PLIST_ENTRY)&Packet->MiniportReserved[0],
                &Adapter->RecvLock);
        }

        //
        // Allocate a huge block of memory for all TCB's
        //
        Status = NdisAllocateMemoryWithTag(
                     &pTCBMem,
                     sizeof(TCB) * NIC_MAX_BUSY_SENDS,
                     NIC_TAG);

        if (Status != NDIS_STATUS_SUCCESS) {
            DEBUGP(MP_ERROR, ("Failed to allocate memory for TCB's\n"));
            break;
        }
        NdisZeroMemory(pTCBMem, sizeof(TCB) * NIC_MAX_BUSY_SENDS);
        Adapter->TCBMem = pTCBMem;

        //
        // Allocate a buffer pool for send buffers.
        //

        NdisAllocateBufferPool(
            &Status,
            &Adapter->SendBufferPoolHandle,
            NIC_MAX_BUSY_SENDS);
        if (Status != NDIS_STATUS_SUCCESS) {
            DEBUGP(MP_ERROR, ("NdisAllocateBufferPool for send buffer failed\n"));
            break;
        }

        //
        // Divide the TCBMem blob into TCBs and create a buffer
        // descriptor for the Data portion of the TCBs.
        //
        for (index = 0; index < NIC_MAX_BUSY_SENDS; index++) {
            pTCB = (PTCB) pTCBMem;
            //
            // Create a buffer descriptor for the Data portion of the TCBs.
            // Buffer descriptors are nothing but MDLs on NT systems.
            //
            NdisAllocateBuffer(
                &Status,
                &Buffer,
                Adapter->SendBufferPoolHandle,
                (PVOID)&pTCB->Data[0],
                NIC_BUFFER_SIZE);
            if (Status != NDIS_STATUS_SUCCESS) {
                DEBUGP(MP_ERROR, ("NdisAllocateBuffer failed\n"));
                break;
            }

            //
            // Initialize the TCB structure.
            //
            pTCB->Buffer = Buffer;
            pTCB->pData = (PUCHAR) &pTCB->Data[0];
            pTCB->Adapter = Adapter;

            NdisInterlockedInsertTailList(
                &Adapter->SendFreeList,
                &pTCB->List,
                &Adapter->SendLock);

            pTCBMem = pTCBMem + sizeof(TCB);

        }

        Adapter->uxen_net.parent = Adapter;

        Status = uxen_net_init_adapter(&Adapter->uxen_net);
        if (Status != NDIS_STATUS_SUCCESS) {
            DEBUGP(MP_ERROR, ("uxen_net_setup failed\n"));
            break;
        }


    } while (bFalse);


    *pAdapter = Adapter;

    //
    // In the failure case, the caller of this routine will end up
    // calling NICFreeAdapter to free all the successfully allocated
    // resources.
    //
    DEBUGP(MP_TRACE, ("<-- NICAllocAdapter\n"));

    return (Status);

}

void NICFreeAdapter(
    PMP_ADAPTER Adapter)
{
    PNDIS_PACKET   Packet;
    PTCB           pTCB;
    PLIST_ENTRY    pEntry;

    DEBUGP(MP_TRACE, ("--> NICFreeAdapter\n"));

    PAGED_CODE();

    ASSERT(Adapter);
    ASSERT(!Adapter->RefCount);

    //
    // Free all the resources we allocated for send.
    //
    while (!IsListEmpty(&Adapter->SendFreeList)) {
        pTCB = (PTCB) NdisInterlockedRemoveHeadList(
                   &Adapter->SendFreeList,
                   &Adapter->SendLock);
        if (!pTCB) {
            break;
        }

        if (pTCB->Buffer) {
            NdisFreeBuffer(pTCB->Buffer);
        }
    }

    uxen_net_free_adapter(&Adapter->uxen_net);


    if (Adapter->SendBufferPoolHandle) {
        NdisFreeBufferPool(Adapter->SendBufferPoolHandle);
    }

    NdisFreeMemory(Adapter->TCBMem, sizeof(TCB) * NIC_MAX_BUSY_SENDS, 0);
    ASSERT(IsListEmpty(&Adapter->SendFreeList));
    ASSERT(IsListEmpty(&Adapter->SendWaitList));
    NdisFreeSpinLock(&Adapter->SendLock);

    //
    // Free all the resources we allocated for receive.
    //

    if (MP_TEST_FLAG(Adapter, fMP_ADAPTER_RECV_LOOKASIDE)) {
        NdisDeleteNPagedLookasideList(&Adapter->RecvLookaside);
        MP_CLEAR_FLAG(Adapter, fMP_ADAPTER_RECV_LOOKASIDE);
    }

    while (!IsListEmpty(&Adapter->RecvFreeList)) {
        pEntry = (PLIST_ENTRY) NdisInterlockedRemoveHeadList(
                     &Adapter->RecvFreeList,
                     &Adapter->RecvLock);
        if (pEntry) {
            Packet = CONTAINING_RECORD(pEntry, NDIS_PACKET, MiniportReserved);
            NdisFreePacket(Packet);
        }
    }

    if (Adapter->RecvPacketPoolHandle) {
        NdisFreePacketPool(Adapter->RecvPacketPoolHandle);
    }

    ASSERT(IsListEmpty(&Adapter->RecvFreeList));
    NdisFreeSpinLock(&Adapter->RecvLock);

    //
    // Finally free the memory for adapter context.
    //
    NdisFreeMemory(Adapter, sizeof(MP_ADAPTER), 0);

    DEBUGP(MP_TRACE, ("<-- NICFreeAdapter\n"));
}

void NICAttachAdapter(PMP_ADAPTER Adapter)
{
    DEBUGP(MP_TRACE, ("--> NICAttachAdapter\n"));

    NdisInterlockedInsertTailList(
        &GlobalData.AdapterList,
        &Adapter->List,
        &GlobalData.Lock);

    DEBUGP(MP_TRACE, ("<-- NICAttachAdapter\n"));
}

void NICDetachAdapter(PMP_ADAPTER Adapter)
{
    DEBUGP(MP_TRACE, ("--> NICDetachAdapter\n"));

    NdisAcquireSpinLock(&GlobalData.Lock);
    RemoveEntryList(&Adapter->List);
    NdisReleaseSpinLock(&GlobalData.Lock);
    DEBUGP(MP_TRACE, ("<-- NICDetachAdapter\n"));
}

NDIS_STATUS
NICReadRegParameters(
    PMP_ADAPTER Adapter,
    NDIS_HANDLE WrapperConfigurationContext)
/*++
Routine Description:

    Read device configuration parameters from the registry

Arguments:

    Adapter                         Pointer to our adapter
    WrapperConfigurationContext     For use by NdisOpenConfiguration

    Should be called at IRQL = PASSIVE_LEVEL.

Return Value:

    NDIS_STATUS_SUCCESS
    NDIS_STATUS_FAILURE
    NDIS_STATUS_RESOURCES

--*/
{
    NDIS_STATUS     Status = NDIS_STATUS_SUCCESS;
    NDIS_HANDLE     ConfigurationHandle;
    PUCHAR          NetworkAddress;
    UINT            Length;
    PUCHAR          pAddr;
    static ULONG    g_ulAddress = 0;

    DEBUGP(MP_TRACE, ("--> NICReadRegParameters\n"));

    PAGED_CODE();

    //
    // Open the registry for this adapter to read advanced
    // configuration parameters stored by the INF file.
    //
    NdisOpenConfiguration(
        &Status,
        &ConfigurationHandle,
        WrapperConfigurationContext);
    if (Status != NDIS_STATUS_SUCCESS) {
        DEBUGP(MP_ERROR, ("NdisOpenConfiguration failed\n"));
        return NDIS_STATUS_FAILURE;
    }

    //
    // Read all of our configuration parameters using NdisReadConfiguration
    // and parse the value.
    //
    //
    //

    //
    // Just for testing purposes, let us make up a dummy mac address.
    // In order to avoid conflicts with MAC addresses, it is usually a good
    // idea to check the IEEE OUI list (e.g. at
    // http://standards.ieee.org/regauth/oui/oui.txt). According to that
    // list 00-50-F2 is owned by Microsoft.
    //
    // An important rule to "generating" MAC addresses is to have the
    // "locally administered bit" set in the address, which is bit 0x02 for
    // LSB-type networks like Ethernet. Also make sure to never set the
    // multicast bit in any MAC address: bit 0x01 in LSB networks.
    //



    pAddr = (PUCHAR) &g_ulAddress;

    ++g_ulAddress;

    Adapter->PermanentAddress[0] = 0x02;
    Adapter->PermanentAddress[1] = 0x50;
    Adapter->PermanentAddress[2] = 0xF2;
    Adapter->PermanentAddress[3] = 0x00;
    Adapter->PermanentAddress[4] = 0x00;
    Adapter->PermanentAddress[5] = pAddr[0];


    ETH_COPY_NETWORK_ADDRESS(
        Adapter->CurrentAddress,
        Adapter->PermanentAddress);

    //
    // Read NetworkAddress registry value and use it as the current address
    // if there is a software configurable NetworkAddress specified in
    // the registry.
    //
    NdisReadNetworkAddress(
        &Status,
        &NetworkAddress,
        &Length,
        ConfigurationHandle);

    if ((Status == NDIS_STATUS_SUCCESS) && (Length == ETH_LENGTH_OF_ADDRESS) ) {
        if ((ETH_IS_MULTICAST(NetworkAddress)
             || ETH_IS_BROADCAST(NetworkAddress))
            || !ETH_IS_LOCALLY_ADMINISTERED (NetworkAddress)) {
            DEBUGP(MP_ERROR,
                   ("Overriding NetworkAddress is invalid - %02x-%02x-%02x-%02x-%02x-%02x\n",
                    NetworkAddress[0], NetworkAddress[1], NetworkAddress[2],
                    NetworkAddress[3], NetworkAddress[4], NetworkAddress[5]));
        } else {
            ETH_COPY_NETWORK_ADDRESS(Adapter->CurrentAddress, NetworkAddress);
        }
    }

    DEBUGP(MP_LOUD, ("Permanent Address = %02x-%02x-%02x-%02x-%02x-%02x\n",
                     Adapter->PermanentAddress[0],
                     Adapter->PermanentAddress[1],
                     Adapter->PermanentAddress[2],
                     Adapter->PermanentAddress[3],
                     Adapter->PermanentAddress[4],
                     Adapter->PermanentAddress[5]));

    DEBUGP(MP_LOUD, ("Current Address = %02x-%02x-%02x-%02x-%02x-%02x\n",
                     Adapter->CurrentAddress[0],
                     Adapter->CurrentAddress[1],
                     Adapter->CurrentAddress[2],
                     Adapter->CurrentAddress[3],
                     Adapter->CurrentAddress[4],
                     Adapter->CurrentAddress[5]));

    Adapter->ulLinkSpeed = NIC_LINK_SPEED;

    //
    // Close the configuration registry
    //
    NdisCloseConfiguration(ConfigurationHandle);
    DEBUGP(MP_TRACE, ("<-- NICReadRegParameters\n"));

    return NDIS_STATUS_SUCCESS;
}

NDIS_STATUS NICInitializeAdapter(
    IN  PMP_ADAPTER  Adapter,
    IN  NDIS_HANDLE  WrapperConfigurationContext
)
/*++
Routine Description:

    Query assigned resources and initialize the adapter.

Arguments:

    Adapter     Pointer to our adapter

Return Value:

    NDIS_STATUS_SUCCESS
    NDIS_STATUS_ADAPTER_NOT_FOUND

--*/
{

    NDIS_STATUS         Status = NDIS_STATUS_ADAPTER_NOT_FOUND;
    typedef __declspec(align(MEMORY_ALLOCATION_ALIGNMENT)) NicResourceCharBuf;
    NicResourceCharBuf  resBuf[NIC_RESOURCE_BUF_SIZE];
    PNDIS_RESOURCE_LIST resList = (PNDIS_RESOURCE_LIST)resBuf;
    UINT                bufSize = NIC_RESOURCE_BUF_SIZE;
    PCM_PARTIAL_RESOURCE_DESCRIPTOR pResDesc;
    ULONG               index;
    BOOLEAN     bFalse = FALSE;

#ifndef NDIS50_MINIPORT
    UNREFERENCED_PARAMETER(Adapter);
#endif

    DEBUGP(MP_TRACE, ("---> InitializeAdapter\n"));
    PAGED_CODE();

    do {
        //
        // Get the resources assigned by the PNP manager. NDIS gets
        // these resources in IRP_MN_START_DEVICE request.
        //
        NdisMQueryAdapterResources(
            &Status,
            WrapperConfigurationContext,
            resList,
            &bufSize);

        if (Status == NDIS_STATUS_SUCCESS) {
#pragma prefast(suppress: 8199, "resList is initialized by NdisMQueryAdapterResources")
            for (index = 0; index < resList->Count; index++) {
                pResDesc = &resList->PartialDescriptors[index];

                switch (pResDesc->Type) {
                    case CmResourceTypePort:
                        DEBUGP(MP_INFO, ("IoBaseAddress = 0x%x\n",
                                         NdisGetPhysicalAddressLow(pResDesc->u.Port.Start)));
                        DEBUGP(MP_INFO, ("IoRange = x%x\n",
                                         pResDesc->u.Port.Length));
                        break;

                    case CmResourceTypeInterrupt:
                        DEBUGP(MP_INFO, ("InterruptLevel = x%x\n",
                                         pResDesc->u.Interrupt.Level));
                        break;

                    case CmResourceTypeMemory:
                        DEBUGP(MP_INFO, ("MemPhysAddress(Low) = 0x%0x\n",
                                         NdisGetPhysicalAddressLow(pResDesc->u.Memory.Start)));
                        DEBUGP(MP_INFO, ("MemPhysAddress(High) = 0x%0x\n",
                                         NdisGetPhysicalAddressHigh(pResDesc->u.Memory.Start)));
                        break;
                }
            }
        }

        Status = NDIS_STATUS_SUCCESS;

        //
        // Map bus-relative IO range to system IO space using
        // NdisMRegisterIoPortRange
        //

        //
        // Map bus-relative registers to virtual system-space
        // using NdisMMapIoSpace
        //


        //
        // Disable interrupts here as soon as possible
        //

        //
        // Register the interrupt using NdisMRegisterInterrupt
        //

        //
        // Initialize the hardware with mapped resources
        //

#ifdef NDIS50_MINIPORT
        //
        // Register a shutdown handler for NDIS50 or earlier miniports
        // For NDIS51 miniports, set AdapterShutdownHandler.
        //
        NdisMRegisterAdapterShutdownHandler(
            Adapter->AdapterHandle,
            (PVOID) Adapter,
            (ADAPTER_SHUTDOWN_HANDLER) MPShutdown);
#endif

        //
        // Enable the interrupt
        //

    } while (bFalse);

    DEBUGP(MP_TRACE, ("<--- InitializeAdapter, Status=%x\n", Status));

    return Status;

}
#endif


