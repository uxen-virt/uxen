/*
 * Copyright 2015, Bromium, Inc.
 * Author: Tomasz Wroblewski <tomasz.wroblewski@gmail.com>
 * SPDX-License-Identifier: ISC
 */

#undef  _WIN32_WINNT
#define _WIN32_WINNT 0x0600
#define V4V_USE_INLINE_API

#include <stdint.h>
#include <windows.h>
#include <windowsx.h>
#include <winioctl.h>
#include <windows/uxenv4vlib/gh_v4vapi.h>

#include <dm/clipboard-protocol.h>

#define CLIP_RING_SIZE 65536
#define CLIP_MAX_PACKET_LEN (CLIP_RING_SIZE - sizeof(struct clip_msg) - 1024)
#define CLIP_MAX_DATA_LEN (200 * 1024 * 1024)
#define CLIP_MAGIC 0x4C43504941504B43
#define CLIP_MSG_DATA 0
#define CLIP_MSG_ACK 1
#define CLIP_MSG_NACK 2

#define CLIP_TIMEOUT 15000

#ifndef CLIPLOG
 #include <dm/debug.h>
 #define CLIPLOG debug_printf
#endif

struct clip_ctx {
    v4v_context_t v4v;
    HANDLE ev;
    int domain;
    int port;
    void* (*alloc)(size_t);
    void (*free)(void*);
};

struct __attribute__((packed)) clip_msg {
    v4v_datagram_t dgram;
    uint64_t magic;
    uint8_t type;
    uint32_t seqid;
    uint32_t data_offset;
    uint32_t data_totallen;
    uint8_t data[0];
};

static int
connect_v4v(v4v_context_t *ctx, int domain, int port)
{
    v4v_ring_id_t id;
    int ret;

    ret = v4v_open(ctx, CLIP_RING_SIZE, NULL);
    if (!ret) {
        CLIPLOG("%s: v4v_open error %d", __FUNCTION__, ret);
        return -1;
    }
    id.addr.port = port;
    id.addr.domain = V4V_DOMID_ANY;
    id.partner = domain;
    ret = v4v_bind(ctx, &id, NULL);
    if (!ret) {
        CLIPLOG("%s: v4v_bind error %d", __FUNCTION__, ret);
        v4v_close(ctx);
        return -1;
    }
    return 0;
}

struct clip_ctx*
clip_open(int domain, int port, void* (*mem_alloc)(size_t),
          void (*mem_free)(void*))
{
    struct clip_ctx *ctx = calloc(1, sizeof(struct clip_ctx));

    if (!ctx)
        return NULL;
    ctx->domain = domain;
    ctx->port = port;
    ctx->alloc = mem_alloc;
    ctx->free = mem_free;
    ctx->ev = CreateEvent(NULL, TRUE, FALSE, NULL);
    if (connect_v4v(&ctx->v4v, domain, port)) {
        free(ctx);
        return NULL;
    }
    return ctx;
}

void
clip_close(struct clip_ctx* ctx)
{
    if (ctx) {
        v4v_close(&ctx->v4v);
        CloseHandle(ctx->ev);
        free(ctx);
    }
}

void
clip_wait_io(struct clip_ctx* ctx)
{
    WaitForSingleObject(ctx->v4v.recv_event, INFINITE);
}

void
clip_cancel_io(struct clip_ctx* ctx)
{
    SetEvent(ctx->v4v.recv_event);
}

static int
read_file_timeout(struct clip_ctx *ctx, LPVOID buf, DWORD len, DWORD *nout)
{
    OVERLAPPED ov;
    HANDLE h = ctx->v4v.v4v_handle;
    int ret;

    *nout = 0;
    memset(&ov, 0, sizeof(ov));
    ov.hEvent = ctx->ev;
    ResetEvent(ov.hEvent);
    if (!ReadFile(h, buf, len, NULL, &ov)) {
        if (GetLastError() != ERROR_IO_PENDING)
            return (int)GetLastError();
    }
    ret = WaitForSingleObject(ctx->ev, CLIP_TIMEOUT);
    switch (ret) {
    case WAIT_TIMEOUT:
        CLIPLOG("clipboard: read timeout");
        break;
    case WAIT_OBJECT_0:
        ret = 0;
        if (!GetOverlappedResult(h, &ov, nout, FALSE))
            ret = (int)GetLastError();
        break;
    default:
        CLIPLOG("clipboard: wait error %d\n", ret);
        break;
    }
    if (ret)
        CancelIoEx(h, &ov);
    return ret;
}

static int
recv_ack(struct clip_ctx *ctx)
{
    struct clip_msg msg;
    DWORD read = 0;
    int ret;

    ret = read_file_timeout(ctx, &msg, sizeof(msg), &read);
    if (ret)
        return ret;
    if (read != sizeof(msg)) {
        CLIPLOG("short read, have %d expected %d\n", (int)read, (int)sizeof(msg));
        return -1;
    }
    if (msg.type == CLIP_MSG_NACK) {
        CLIPLOG("nack received\n");
        return -1;
    }
    if (msg.magic != CLIP_MAGIC ||
        msg.type != CLIP_MSG_ACK) {
        CLIPLOG("message type/magic mismatch\n");
        return -1;
    }
    return 0;
}

static int
_send_ack(struct clip_ctx *ctx, int isnack)
{
    struct clip_msg msg;
    DWORD written;

    memset(&msg, 0, sizeof(msg));
    msg.dgram.addr.port = ctx->port;
    msg.dgram.addr.domain = ctx->domain;
    //msg.dgram.flags = V4V_DATAGRAM_FLAG_IGNORE_DLO;
    msg.magic = CLIP_MAGIC;
    msg.type = isnack ? CLIP_MSG_NACK : CLIP_MSG_ACK;

    if (!WriteFile(ctx->v4v.v4v_handle, &msg, sizeof(msg), &written, NULL))
        return (int)GetLastError();
    if (written != sizeof(msg)) {
        CLIPLOG("short write, have %d expected %d\n", (int)written, (int)sizeof(msg));
        return -1;
    }
    return 0;
}

static int
send_ack(struct clip_ctx *ctx)
{
    return _send_ack(ctx, 0);
}

static int
send_nack(struct clip_ctx *ctx)
{
    return _send_ack(ctx, 1);
}

int
clip_send_bytes(struct clip_ctx *ctx, void *data, int len)
{
    uint8_t *p = data;
    uint8_t buffer[CLIP_RING_SIZE];
    struct clip_msg *msg = (struct clip_msg*) buffer;
    int seqid = 0;
    DWORD written;
    uint32_t offset;
    int ret;

    if (len > CLIP_MAX_DATA_LEN)
        return -1;

    /* send header */
    memset(msg, 0, sizeof(*msg));
    msg->dgram.addr.port = ctx->port;
    msg->dgram.addr.domain = ctx->domain;
    //msg->dgram.flags = V4V_DATAGRAM_FLAG_IGNORE_DLO;
    msg->type = CLIP_MSG_DATA;
    msg->magic = CLIP_MAGIC;
    msg->seqid = seqid++;
    msg->data_totallen = len;

    if (!WriteFile(ctx->v4v.v4v_handle, msg, sizeof(*msg), &written, NULL))
        return (int)GetLastError();
    if (written != sizeof(*msg)) {
        CLIPLOG("short write, have %d expected %d\n", (int)written, (int)sizeof(*msg));
        return -1;
    }
    if ((ret = recv_ack(ctx))) {
        CLIPLOG("recv ack error %d\n", ret);
        return ret;
    }

    /* send data packets */
    offset = 0;
    while (len) {
        int chunk = len;

        if (chunk > CLIP_MAX_PACKET_LEN)
            chunk = CLIP_MAX_PACKET_LEN;
        msg->dgram.addr.port = ctx->port;
        msg->dgram.addr.domain = ctx->domain;
        //msg->dgram.flags = V4V_DATAGRAM_FLAG_IGNORE_DLO;
        msg->type = CLIP_MSG_DATA;
        msg->magic = CLIP_MAGIC;
        msg->seqid = seqid++;
        msg->data_offset = offset;
        msg->data_totallen = len;
        memcpy(msg->data, p, chunk);
        if (!WriteFile(ctx->v4v.v4v_handle, msg, sizeof(*msg) + chunk, &written, NULL)) {
            CLIPLOG("write error %d\n", (int)GetLastError());
            return (int)GetLastError();
        }
        if (written != sizeof(*msg) + chunk) {
            CLIPLOG("short write, have %d expected %d\n", (int)written, (int)sizeof(*msg) + chunk);
            return -1;
        }
        if ((ret = recv_ack(ctx))) {
            CLIPLOG("recv ack error %d\n", ret);
            return ret;
        }

        p += chunk;
        offset += chunk;
        len -= chunk;
    }
    return 0;
}

int
clip_recv_bytes(struct clip_ctx *ctx,
                void **data, int *len)
{
    uint8_t buffer[CLIP_RING_SIZE];
    struct clip_msg *msg = (struct clip_msg*) buffer;
    uint32_t totlen, offset;
    DWORD read = 0;
    int ret;
    void *p = NULL;
    int seqid = 0;

    *data = NULL;
    *len = 0;

    /* recv header */
    ret = read_file_timeout(ctx, msg, sizeof(*msg), &read);
    if (ret) {
        CLIPLOG("read error %d\n", ret);
        return ret;
    }
    if (read != sizeof(*msg)) {
        CLIPLOG("short read, have %d expected %d\n", (int)read, (int)sizeof(*msg));
        return -1;
    }
    if (msg->magic != CLIP_MAGIC || msg->type != CLIP_MSG_DATA ||
        msg->seqid != 0) {
        CLIPLOG("bad msg header\n");
        return -1;
    }
    totlen = msg->data_totallen;
    if (totlen > CLIP_MAX_DATA_LEN) {
        CLIPLOG("message too long\n");
        return -1;
    }

    p = ctx->alloc(totlen);
    if (!p) {
        send_nack(ctx);
        CLIPLOG("allocation failed\n");
        return -1;
    }

    if ((ret = send_ack(ctx))) {
        CLIPLOG("send ack error %d\n", ret);
        return ret;
    }

    /* recv data packets */
    offset = 0;
    while (offset < totlen) {
        int chunk;

        ++seqid;

        ret = read_file_timeout(ctx, msg, sizeof(buffer), &read);
        if (ret) {
            send_nack(ctx);
            CLIPLOG("read error %d\n", ret);
            goto out;
        }
        if (read < sizeof(struct clip_msg)) {
            send_nack(ctx);
            CLIPLOG("chunk message short read (missing header?): %d\n", (int)read);
            ret = -1;
            goto out;
        }
        if (msg->magic != CLIP_MAGIC || msg->type != CLIP_MSG_DATA ||
            msg->seqid != seqid || msg->data_offset != offset) {
            send_nack(ctx);
            CLIPLOG("bad chunk msg header\n");
            ret = -1;
            goto out;
        }
        chunk = read - sizeof(struct clip_msg);
        if (chunk > CLIP_MAX_PACKET_LEN || offset + chunk > totlen) {
            send_nack(ctx);
            CLIPLOG("chunk message too long\n");
            ret = -1;
            goto out;
        }
        if ((ret = send_ack(ctx))) {
            CLIPLOG("chunk send ack error %d\n", ret);
            goto out;
        }
        memcpy(p + offset, msg->data, chunk);
        offset += chunk;
    }
    *data = p;
    *len = totlen;
    p = NULL;
    ret = 0;
out:
    if (p)
        ctx->free(p);

    return ret;
}


