/*
 * Copyright 2015-2018, Bromium, Inc.
 * Author: Tomasz Wroblewski <tomasz.wroblewski@gmail.com>
 * SPDX-License-Identifier: ISC
 */

#include <dm/config.h>
#include <dm/debug.h>
#include <dm/hw/uxen_v4v.h>
#include <dm/clipboard-protocol.h>

#define CLIPLOG debug_printf

struct clip_ctx {
    v4v_context_t v4v;
    ioh_event ev;
    v4v_async_t async;
    int domain;
    int port;
    void* (*alloc)(size_t);
    void (*free)(void*);
};

static int
connect_v4v(struct clip_ctx *ctx, unsigned char *v4v_idtoken)
{
    v4v_bind_values_t bind = { };
    int err;

    if ((err = dm_v4v_open(&ctx->v4v, CLIP_RING_SIZE))) {
        CLIPLOG("%s: v4v_open error %d\n", __FUNCTION__, err);
        return -1;
    }
    bind.ring_id.addr.port = ctx->port;
    bind.ring_id.addr.domain = V4V_DOMID_ANY;
    bind.ring_id.partner = ctx->domain;
    if (ctx->domain == -1 && v4v_idtoken) {
        bind.ring_id.partner = V4V_DOMID_UUID;
        memcpy(&bind.partner, v4v_idtoken, sizeof(bind.partner));
    }
    if ((err = dm_v4v_bind(&ctx->v4v, &bind))) {
        CLIPLOG("%s: v4v_bind error %d\n", __FUNCTION__, err);
        dm_v4v_close(&ctx->v4v);
        return -1;
    }
    ctx->domain = bind.ring_id.partner;

    return 0;
}

struct clip_ctx*
clip_open(int domain, int port, unsigned char *v4v_idtoken,
          void* (*mem_alloc)(size_t), void (*mem_free)(void*))
{
    struct clip_ctx *ctx = calloc(1, sizeof(struct clip_ctx));

    if (!ctx)
        return NULL;
    ctx->domain = domain;
    ctx->port = port;
    ctx->alloc = mem_alloc;
    ctx->free = mem_free;
    ioh_event_init(&ctx->ev);
    if (connect_v4v(ctx, v4v_idtoken)) {
        free(ctx);
        return NULL;
    }
    return ctx;
}

void
clip_close(struct clip_ctx* ctx)
{
    if (ctx) {
        dm_v4v_close(&ctx->v4v);
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
    dm_v4v_async_cancel(&ctx->async);
    SetEvent(ctx->v4v.recv_event);
    SetEvent(ctx->ev);
}

static int
sync_recv(struct clip_ctx *ctx, LPVOID buf, DWORD len, DWORD *nout)
{
    size_t bytes = 0;
    int err;

    *nout = 0;
    ioh_event_reset(&ctx->ev);
    dm_v4v_async_init(&ctx->v4v, &ctx->async, ctx->ev);
    err = dm_v4v_recv(&ctx->v4v, (v4v_datagram_t*)buf, len,
        &ctx->async);
    if (err && err != ERROR_IO_PENDING) {
        debug_printf("%s:%d: error receiving = %d\n", __FILE__, __LINE__, err);
        return err;
    }
    err = dm_v4v_async_get_result(&ctx->async, &bytes, true);
    if (err) {
        debug_printf("%s:%d: error getting result = %d\n", __FILE__, __LINE__, err);
        return err;
    }

    *nout = bytes;

    return 0;
}

static int
sync_send(struct clip_ctx *ctx, LPVOID buf, DWORD len, DWORD *nout)
{
    size_t bytes = 0;
    int err;

    *nout = 0;
    ioh_event_reset(&ctx->ev);
    dm_v4v_async_init(&ctx->v4v, &ctx->async, ctx->ev);
    err = dm_v4v_send(&ctx->v4v, (v4v_datagram_t*)buf, len,
        &ctx->async);
    if (err && err != ERROR_IO_PENDING) {
        debug_printf("%s:%d: error sending = %d\n", __FILE__, __LINE__, err);
        return err;
    }
    err = dm_v4v_async_get_result(&ctx->async, &bytes, true);
    if (err) {
        debug_printf("%s:%d: error getting result = %d\n", __FILE__, __LINE__, err);
        return err;
    }
    assert(bytes == len);

    *nout = bytes;

    return 0;
}

static int
recv_ack(struct clip_ctx *ctx)
{
    struct clip_msg msg;
    DWORD read = 0;
    int ret;

    ret = sync_recv(ctx, &msg, sizeof(msg), &read);
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
    int ret;

    memset(&msg, 0, sizeof(msg));
    msg.dgram.addr.port = ctx->port;
    msg.dgram.addr.domain = ctx->domain;
    //msg.dgram.flags = V4V_DATAGRAM_FLAG_IGNORE_DLO;
    msg.magic = CLIP_MAGIC;
    msg.type = isnack ? CLIP_MSG_NACK : CLIP_MSG_ACK;

    ret = sync_send(ctx, &msg, sizeof(msg), &written);
    if (ret)
        return ret;
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
#ifdef CLIP_CLIENT
    msg->dgram.flags = V4V_DATAGRAM_FLAG_IGNORE_DLO;
#endif  /* CLIP_CLIENT */
    msg->type = CLIP_MSG_DATA;
    msg->magic = CLIP_MAGIC;
    msg->seqid = seqid++;
    msg->data_totallen = len;

    ret = sync_send(ctx, msg, sizeof(*msg), &written);
    if (ret)
        return ret;
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
        ret = sync_send(ctx, msg, sizeof(*msg) + chunk, &written);
        if (ret) {
            CLIPLOG("write error %d\n", ret);
            return ret;
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
    ret = sync_recv(ctx, msg, sizeof(*msg), &read);
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

        ret = sync_recv(ctx, msg, sizeof(buffer), &read);
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


