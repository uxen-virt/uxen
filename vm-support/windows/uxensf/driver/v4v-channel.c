/*
 * Copyright 2015-2016, Bromium, Inc.
 * SPDX-License-Identifier: ISC
 */

#include <ntddk.h>
#include <ndis.h>
#include <uxenv4vlib.h>
#include "channel.h"

#define PORT 44444
#define PRIORITY_INCREMENT 4

static uxen_v4v_ring_handle_t *ring;
static KEVENT resp_ev;

static NTSTATUS __recv(char *buf, int buf_size, int *recv_size)
{
    v4v_addr_t src = { PORT, V4V_DOMID_DM };
    uint32_t proto;
    ssize_t n;

    *recv_size = 0;

    n = uxen_v4v_copy_out(ring, &src, NULL, NULL, 0, 0);
    if (n > buf_size)
        return STATUS_BUFFER_OVERFLOW;

    n = uxen_v4v_recv(ring, &src, buf, buf_size, &proto);
    if (n < 0)
        return STATUS_UNEXPECTED_IO_ERROR;

    *recv_size = n;
    return STATUS_SUCCESS;
}

void v4v_callback(uxen_v4v_ring_handle_t *r,void *_a, void *_b)
{
    r;
    _a;
    _b;

    KeSetEvent(&resp_ev, PRIORITY_INCREMENT, FALSE);
}

NTSTATUS ChannelConnect(void)
{
    if (ring)
        return STATUS_SUCCESS;

    KeInitializeEvent(&resp_ev, SynchronizationEvent, FALSE);
    ring = uxen_v4v_ring_bind(PORT, V4V_DOMID_DM, RING_SIZE, v4v_callback,
                              NULL, NULL);
    if (!ring)
        return STATUS_UNEXPECTED_IO_ERROR;

    return STATUS_SUCCESS;
}

void ChannelDisconnect(void)
{
    if (ring)
        uxen_v4v_ring_free(ring);
    ring = NULL;
}

NTSTATUS ChannelPrepareReq(void)
{
    KeResetEvent(&resp_ev);
    return STATUS_SUCCESS;
}

NTSTATUS ChannelSend(char *data, int len)
{
    v4v_addr_t dst = { PORT, V4V_DOMID_DM };
    ssize_t n;

    if (!NT_SUCCESS(ChannelConnect()))
        return STATUS_UNEXPECTED_IO_ERROR;

    n = uxen_v4v_send_from_ring(ring, &dst, data, len, V4V_PROTO_DGRAM);
    if (n != len)
        return STATUS_UNEXPECTED_IO_ERROR;

    return STATUS_SUCCESS;
}

NTSTATUS ChannelRecv(char *buf, int buf_size, int *recv_size)
{
    NTSTATUS rc;

    if (!NT_SUCCESS(ChannelConnect()))
        return STATUS_UNEXPECTED_IO_ERROR;

    KeWaitForSingleObject(&resp_ev, Executive, KernelMode, FALSE, NULL);

    rc = __recv(buf, buf_size, recv_size);
    uxen_v4v_notify();
    return rc;
}


