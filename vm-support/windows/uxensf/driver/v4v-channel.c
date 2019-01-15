/*
 * Copyright 2015-2019, Bromium, Inc.
 * SPDX-License-Identifier: ISC
 */

#include <wdm.h>
#include <ndis.h>
#include <uxenv4vlib.h>
#include "channel.h"

#define PORT 44444
#define PRIORITY_INCREMENT 4
#define MEMTAG_HGCMBUF ((ULONG)'30cr')

static uxen_v4v_ring_handle_t *ring;
static KSPIN_LOCK channel_lock;
static LIST_ENTRY send_queue;

static ssize_t ndata_in_ring(void)
{
    v4v_addr_t src = { PORT, V4V_DOMID_DM };

    return uxen_v4v_copy_out(ring, &src, NULL, NULL, 0, 0);
}

static NTSTATUS __recv(char *buf, int buf_size, int *recv_size)
{
    v4v_addr_t src = { PORT, V4V_DOMID_DM };
    uint32_t proto;
    ssize_t n;

    *recv_size = 0;

    n = ndata_in_ring();
    if (n > buf_size)
        return STATUS_BUFFER_OVERFLOW;
    if (n < 0)
        return STATUS_UNEXPECTED_IO_ERROR;

    n = uxen_v4v_recv(ring, &src, buf, buf_size, &proto);
    if (n < 0)
        return STATUS_UNEXPECTED_IO_ERROR;

    *recv_size = n;

    return STATUS_SUCCESS;
}

static void v4v_callback(uxen_v4v_ring_handle_t *r, void *_a, void *_b)
{
    v4v_addr_t src = { PORT, V4V_DOMID_DM };
    uint32_t proto;
    KLOCK_QUEUE_HANDLE lqh;
    PLIST_ENTRY le;

    r; _a; _b;

    KeAcquireInStackQueuedSpinLock(&channel_lock, &lqh);

    for (;;) {
        /* responses in ring are ordered, pair with earlier request and notify the waiter */
        le = RemoveHeadList(&send_queue);
        if (le && le != &send_queue) {
            struct channel_req *req = CONTAINING_RECORD(le, struct channel_req, le);

            req->rc = __recv(req->buf, req->buf_size, &req->recv_size);
            uxen_v4v_notify();

            KeSetEvent(&req->resp_ev, PRIORITY_INCREMENT, FALSE);

            if (ndata_in_ring() <= 0)
                break; /* no more responses in ring */
        }
    }
    KeReleaseInStackQueuedSpinLock(&lqh);
}

NTSTATUS ChannelConnect(void)
{
    if (ring)
        return STATUS_SUCCESS;

    KeInitializeSpinLock(&channel_lock);

    InitializeListHead(&send_queue);

    ring = uxen_v4v_ring_bind(PORT, V4V_DOMID_DM, RING_SIZE, v4v_callback,
                              NULL, NULL);
    if (!ring)
        return STATUS_UNEXPECTED_IO_ERROR;

    return STATUS_SUCCESS;
}

void ChannelDisconnect(void)
{
    if (ring) {
        uxen_v4v_ring_free(ring);
        ring = NULL;
    }
}

NTSTATUS ChannelPrepareReq(struct channel_req *req, void *buffer,
    int buffer_size, int send_size)
{
    RtlZeroMemory(req, sizeof(*req));
    KeInitializeEvent(&req->resp_ev, SynchronizationEvent, FALSE);
    req->buf = buffer;
    req->buf_size = buffer_size;
    req->send_size = send_size;

    return STATUS_SUCCESS;
}

NTSTATUS ChannelSendReq(struct channel_req *req)
{
    v4v_addr_t dst = { PORT, V4V_DOMID_DM };
    ssize_t n;
    KLOCK_QUEUE_HANDLE lqh;

    KeAcquireInStackQueuedSpinLock(&channel_lock, &lqh);
    n = uxen_v4v_send_from_ring(ring, &dst, req->buf, req->send_size, V4V_PROTO_DGRAM);
    if (n != req->send_size) {
        KeReleaseInStackQueuedSpinLock(&lqh);

        return STATUS_UNEXPECTED_IO_ERROR;
    }

    InsertTailList(&send_queue, &req->le);

    KeReleaseInStackQueuedSpinLock(&lqh);

    return STATUS_SUCCESS;
}

NTSTATUS ChannelRecvResp(struct channel_req *req, int *recv_size)
{
    KeWaitForSingleObject(&req->resp_ev, Executive, KernelMode, FALSE, NULL);

    *recv_size = req->recv_size;

    return req->rc;
}

NTSTATUS ChannelReleaseReq(struct channel_req *req)
{
    return STATUS_SUCCESS;
}
