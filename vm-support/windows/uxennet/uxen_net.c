/*
 * Copyright 2015, Bromium, Inc.
 * SPDX-License-Identifier: ISC
 */

#include "uxennet_private.h"

Uxennet_globals globals;

#define MAX_IOV 16


NDIS_STATUS
uxen_net_send_packet (Uxennet *n, PNDIS_PACKET p)
{
    UINT num_buffers;
    UINT pktlen, buflen, len;
    PNDIS_BUFFER buffer;
    void *va;
    v4v_iov_t iov[MAX_IOV];
    unsigned niov = 0, ret;


    UNREFERENCED_PARAMETER (n);

    num_buffers = 0;
    len = 0;

    NdisQueryPacket (p, NULL, &num_buffers, &buffer, &pktlen);

    if ((!num_buffers) || (!buffer))
        return NDIS_STATUS_FAILURE;

    while (buffer) {

        va = NULL;

        NdisQueryBufferSafe (buffer, &va, &buflen, NormalPagePriority);

        if (!va)
            return NDIS_STATUS_FAILURE;

        iov[niov].iov_base = (uint64_t) (uintptr_t) va; // XXX: 32bit
        iov[niov].iov_len = buflen;
        niov++;

        if (niov == MAX_IOV)
            return NDIS_STATUS_FAILURE;

        len += buflen;

        NdisGetNextBuffer (buffer, &buffer);
    }


    ret = uxen_v4v_sendv_from_ring(n->recv_ring, &n->dest_addr, iov, niov, V4V_PROTO_DGRAM);

//  DbgPrint ("uxen_send_packet: Total bytes %d expected %d sendv returns %d\n", pktlen, len,ret);

    if (ret != len)
        return NDIS_STATUS_FAILURE;

    return NDIS_STATUS_SUCCESS;
}

#if 0
void uxen_net_resume_dpc(void *SystemSpecific1, void *FunctionContext, void *SystemSpecific2, void *SystemSpecific3)
{
    Uxennet *n = (Uxennet *)FunctionContext;

    SystemSpecific1;
    SystemSpecific2;
    SystemSpecific3;

    /*Wake up the other side*/
    uxen_v4v_send_from_ring(n->recv_ring, &n->dest_addr, "", 1, V4V_PROTO_DGRAM);

}
#endif


void
uxen_net_free_adapter (Uxennet *n)
{
    NdisAcquireSpinLock (&globals.lock);
    RemoveEntryList (&n->list);
    NdisReleaseSpinLock (&globals.lock);

#if 0
    uxen_v4vlib_unset_resume_dpc(&n->resume_dpc, n);
#endif


    if (n->recv_ring) {
        (void) uxen_v4v_ring_free (n->recv_ring);
        n->recv_ring = NULL;
    }

}


static
is_adapternum_free (int anum)
{
    Uxennet *n;


    n = (Uxennet *) globals.adapter_list.Flink;

    while ((PLIST_ENTRY) n != &globals.adapter_list) {
        if (n->anum == anum)
            return 0;
        n = (Uxennet *) n->list.Flink;
    }

    return 1;
}


static int
get_free_adapternum (void)
{
    int anum = 0;

    while (!is_adapternum_free (anum))
        anum++;

    return anum;
}



void uxen_net_callback(uxen_v4v_ring_handle_t *r, void *_a, void *_b)
{
    static LONG fish;
    PMP_ADAPTER adapter = (PMP_ADAPTER) _a;
    r;
    _b;

    if (!adapter->uxen_net.ready) return;

    /*In a guest, this is called from the v4v ISR's DPC*/
    /*so there is no need to schedule another dpc to */
    /*do this*/
    RecvDpcFunc(NULL, adapter, NULL, NULL);
}



NTSTATUS
uxen_net_init_adapter (Uxennet *n)
{

    n->anum = -1;

    NdisAcquireSpinLock (&globals.lock);
    n->anum = get_free_adapternum ();
    InsertTailList (&globals.adapter_list, &n->list);
    NdisReleaseSpinLock (&globals.lock);

    DbgPrint("Adapter num %d\n", n->anum);

    n->recv_ring = uxen_v4v_ring_bind(0xc0000 + n->anum, 0, V4V_RING_LEN, uxen_net_callback, n->parent, NULL);

    n->dest_addr.port = 0xc0000 + n->anum;
    n->dest_addr.domain = 0;

    DbgPrint("recv_ring %p\n", n->recv_ring);

    if (!n->recv_ring)
        return STATUS_NO_MEMORY;

#if 0
    KeInitializeDpc(&n->resume_dpc, uxen_net_resume_dpc, (PVOID) n);
    uxen_v4vlib_set_resume_dpc(&n->resume_dpc, n);
#endif

    return STATUS_SUCCESS;
}

NTSTATUS
uxen_net_start_adapter(MP_ADAPTER *a)
{
    a->uxen_net.ready = !0;
    uxen_net_callback(NULL, a, NULL);
    return STATUS_SUCCESS;
}

NTSTATUS
uxen_net_stop_adapter(MP_ADAPTER *a)
{
    a->uxen_net.ready = 0;
    uxen_net_callback(NULL, a, NULL);
    return STATUS_SUCCESS;
}

void
uxen_net_free (void)
{
    ASSERT (IsListEmpty (&globals.adapter_list));
    NdisFreeSpinLock (&globals.lock);
}

void
uxen_net_init (void)
{
    NdisAllocateSpinLock (&globals.lock);
    NdisInitializeListHead (&globals.adapter_list);
}

void uxen_net_soh(Uxennet *n, PMP_ADAPTER adapter)
{
    static int q;

    q++;

    if (q < 100) return;
    q = 0;
    DbgPrint("un: rx_ptr=%u tx_ptr=%u free rcbs? %s\n",
             (unsigned) n->recv_ring->ring->rx_ptr,
             (unsigned) n->recv_ring->ring->tx_ptr,
             IsListEmpty(&adapter->RecvFreeList) ? "No" : "Yes");
}
