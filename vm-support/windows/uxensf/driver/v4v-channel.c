/*
 * Copyright 2015-2019, Bromium, Inc.
 * SPDX-License-Identifier: ISC
 */

#include <wdm.h>
#include <ndis.h>
#include <uxenv4vlib.h>
#include "channel.h"
#include "../../common/debug.h"

#define PORT 44444
#define PRIORITY_INCREMENT 4
#define MEMTAG_HGCMBUF ((ULONG)'30cr')
#define EAGAIN (11)

NTSTATUS ChannelSendReq(struct channel_req *req);

static uxen_v4v_ring_handle_t *ring;
static KSPIN_LOCK channel_lock;
static LIST_ENTRY requests_sent;

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
        le = RemoveHeadList(&requests_sent);
        if (le && le != &requests_sent) {
            struct channel_req *req = CONTAINING_RECORD(le, struct channel_req, le_sent);

            req->rc = __recv(req->buf, req->buf_size, &req->recv_size);
            uxen_v4v_notify();

            KeSetEvent(&req->resp_ev, PRIORITY_INCREMENT, FALSE);

            if (ndata_in_ring() <= 0)
                break; /* no more responses in ring */
        }
    }

    KeReleaseInStackQueuedSpinLock(&lqh);
}

static void send_again_callback(uxen_v4v_ring_handle_t *r, void *_a, void *_b)
{
    struct channel_req *req = _a;

    ChannelSendReq(req);
}

NTSTATUS ChannelConnect(void)
{
    if (ring)
        return STATUS_SUCCESS;

    KeInitializeSpinLock(&channel_lock);

    InitializeListHead(&requests_sent);

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
    n = uxen_v4v_send_from_ring_async(ring, &dst, req->buf, req->send_size, V4V_PROTO_DGRAM,
        send_again_callback, req, NULL);
    if (n == -EAGAIN) {
        KeReleaseInStackQueuedSpinLock(&lqh);

        return STATUS_PENDING;
    } else if (n != req->send_size) {
        KeReleaseInStackQueuedSpinLock(&lqh);

        uxen_err("send error, n=%d, send_size=%d\n", (int)n, (int)req->send_size);

        return STATUS_UNEXPECTED_IO_ERROR;
    }

    InsertTailList(&requests_sent, &req->le_sent);

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
