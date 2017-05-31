/*
 * Copyright 2017, Bromium, Inc.
 * Author: Piotr Foltyn <piotr.foltyn@gmail.com>
 * SPDX-License-Identifier: ISC
 */

#include <windows.h>
#include <stdint.h>
#include <stdio.h>

#include <intrin.h>
#include <winioctl.h>
#define V4V_USE_INLINE_API
#pragma warning(push)
#pragma warning(disable: 4127) // conditional expression is constant
#pragma warning(disable: 4244) // conversion from 'BOOL' to 'BOOLEAN', possible loss of data
#include <gh_v4vapi.h>
#pragma warning(pop)

#include "uxenh264lib.h"
#include "uxenh264libinternal.h"
#include "uxenh264-common.h"
#include "debug-user.h"

struct context {
    OVERLAPPED recv_overlapped;
    BOOLEAN recv_pending;
    struct brh264_meta_msg recv_msg;
    struct brh264_data recv_data;
    HANDLE recv_event;
    HANDLE send_event;
    v4v_channel_t v4v;
    v4v_bind_values_t bind;
    void* priv;
    LONG exit;
    brh264_recv_callbacks cb;
};

static BOOL brh264_send_meta(struct context* ctx, __int32 type, struct brh264_data* data)
{
    DWORD bytes = 0;
    OVERLAPPED overlapped = {};
    BOOL result = TRUE;
    struct brh264_meta_msg meta = {};
    int cnt = 2;

    meta.dgram.addr.port = ctx->bind.ring_id.addr.port;
    meta.dgram.addr.domain = ctx->bind.ring_id.partner;
    meta.dgram.flags = 0;
    meta.type = type;

    if (data) {
        meta.params_size = data->params_size;
        meta.data_size = data->data_size;

        CopyMemory(meta.params_hdr, data->params, sizeof(meta.params_hdr));
        if (data->data) {
            CopyMemory(meta.data_hdr, data->data, sizeof(meta.data_hdr));
        }
    }

    overlapped.hEvent = ctx->send_event;
    result = WriteFile(ctx->v4v.v4v_handle, &meta, sizeof(meta), NULL, &overlapped);
    if (!result && (type == BRH264_READY)) {
        while (cnt--) {
            result = GetOverlappedResult(ctx->v4v.v4v_handle, &overlapped, &bytes, FALSE);
            if (!result) {
                WaitForSingleObject(overlapped.hEvent, UXENH264_DM_TIMEOUT_MS);
            }
            else {
                break;
            }
        }
    }
    else {
        result = GetOverlappedResult(ctx->v4v.v4v_handle, &overlapped, &bytes, TRUE);
        if (!result) {
            uxen_err("GetOverlappedResult failed: %d; type: %d; p_size: %d; d_size: %d",
                GetLastError(), type, meta.params_size, meta.data_size);
        }
    }

    return result;
}

static BOOL brh264_send_data(struct context* ctx, __int32 data_size, PBYTE data)
{
    DWORD bytes = 0;
    __int32 total = data_size;
    OVERLAPPED overlapped = {};
    BOOL result = TRUE;
    PBYTE ptr = NULL;
    v4v_datagram_t *dgram = NULL;
    PBYTE hdr[sizeof(v4v_datagram_t)] = {};

    while (total > sizeof(v4v_datagram_t)) {
        ZeroMemory(&overlapped, sizeof(overlapped));
        overlapped.hEvent = ctx->send_event;

        if (total <= (BRH264_RING_SIZE - USN_PAGE_SIZE)) {
            bytes = total;
        }
        else {
            bytes = BRH264_RING_SIZE - USN_PAGE_SIZE;
        }

        ptr = data + total - bytes;
        CopyMemory(hdr, ptr, sizeof(v4v_datagram_t));

        dgram = (v4v_datagram_t *)ptr;
        dgram->addr.port = ctx->bind.ring_id.addr.port;
        dgram->addr.domain = ctx->bind.ring_id.partner;
        dgram->flags = 0;

        WriteFile(ctx->v4v.v4v_handle, ptr, bytes, NULL, &overlapped);
        result = GetOverlappedResult(ctx->v4v.v4v_handle, &overlapped, &bytes, TRUE);
        if (!result) {
            uxen_err("GetOverlappedResult failed: %d", GetLastError());
            goto exit;
        }

        total -= bytes - sizeof(v4v_datagram_t);
        CopyMemory(ptr, hdr, sizeof(v4v_datagram_t));
    }

exit:
    return result;
}

static void brh264_send(struct context* ctx, __int32 type, struct brh264_data* data)
{
    BOOL result = FALSE;

    result = brh264_send_meta(ctx, type, data);
    if (!result) {
        uxen_err("brh264_send_meta failed: %d", GetLastError());
        return;
    }

    if (data) {
        result = brh264_send_data(ctx, data->params_size, data->params);
        if (!result) {
            uxen_err("brh264_send_data params failed: %d", GetLastError());
            return;
        }

        result = brh264_send_data(ctx, data->data_size, data->data);
        if (!result) {
            uxen_err("brh264_send_data data failed: %d", GetLastError());
            return;
        }
    }
}

void brh264_send_dec(brh264_ctx c, struct brh264_data* dec)
{
    struct context* ctx = (struct context*)c;
    brh264_send(ctx, BRH264_DEC_DATA, dec);
}

void brh264_send_enc(brh264_ctx c, struct brh264_data* enc)
{
    struct context* ctx = (struct context*)c;
    brh264_send(ctx, BRH264_ENC_DATA, enc);
}

void brh264_send_mt(brh264_ctx c, struct brh264_data* mt)
{
    struct context* ctx = (struct context*)c;
    brh264_send(ctx, BRH264_MT_DATA, mt);
}

void brh264_send_res(brh264_ctx c, __int32 res)
{
    struct context* ctx = (struct context*)c;
    brh264_send(ctx, (res >= 0) ? BRH264_ACK : BRH264_NACK, NULL);
}

static BOOL brh264_recv_data(struct context* ctx, __int32 data_size, PBYTE data)
{
    DWORD bytes = 0;
    __int32 total = data_size;
    OVERLAPPED overlapped = {};
    BOOL result = TRUE;
    PBYTE ptr = NULL;

    while (total > sizeof(v4v_datagram_t)) {
        ZeroMemory(&overlapped, sizeof(overlapped));
        overlapped.hEvent = ctx->recv_event;

        if (total <= (BRH264_RING_SIZE - USN_PAGE_SIZE)) {
            bytes = total;
        }
        else {
            bytes = BRH264_RING_SIZE - USN_PAGE_SIZE;
        }

        ptr = data + total - bytes;

        ReadFile(ctx->v4v.v4v_handle, ptr, bytes, NULL, &overlapped);
        result = GetOverlappedResult(ctx->v4v.v4v_handle, &overlapped, &bytes, TRUE);
        if (!result) {
            uxen_err("GetOverlappedResult failed: %d", GetLastError());
            goto exit;
        }

        total -= bytes - sizeof(v4v_datagram_t);
    }

exit:
    return result;
}

static BOOL brh264_recv(struct context* ctx)
{
    BOOL result = TRUE;

    ctx->recv_data.params_size = ctx->recv_msg.params_size;
    ctx->recv_data.data_size = ctx->recv_msg.data_size;

    if (ctx->recv_msg.params_size + ctx->recv_msg.data_size > UXENH264_SIZE_LIMIT) {
        uxen_err("payload too large: size %d, limit: %d",
                ctx->recv_msg.params_size + ctx->recv_msg.data_size, UXENH264_SIZE_LIMIT);
        return FALSE;
    }

    ctx->recv_data.params = (PBYTE)malloc(ctx->recv_msg.params_size + ctx->recv_msg.data_size);
    if (!ctx->recv_data.params) {
        uxen_err("malloc failed: size %d", ctx->recv_msg.params_size + ctx->recv_msg.data_size);
        return FALSE;
    }
    ctx->recv_data.data = ctx->recv_data.params + ctx->recv_msg.params_size;

    result = brh264_recv_data(ctx, ctx->recv_data.params_size, ctx->recv_data.params);
    if (!result) {
        uxen_err("brh264_recv_data params failed: size %d", ctx->recv_msg.params_size);
        goto exit;
    }

    if (ctx->recv_msg.params_size >= sizeof(ctx->recv_msg.params_hdr)) {
        CopyMemory(ctx->recv_data.params, ctx->recv_msg.params_hdr, sizeof(ctx->recv_msg.params_hdr));
    }

    result = brh264_recv_data(ctx, ctx->recv_data.data_size, ctx->recv_data.data);
    if (!result) {
        uxen_err("brh264_recv_data data failed: size %d", ctx->recv_msg.data_size);
        goto exit;
    }
    if (ctx->recv_msg.data_size >= sizeof(ctx->recv_msg.data_hdr)) {
        CopyMemory(ctx->recv_data.data, ctx->recv_msg.data_hdr, sizeof(ctx->recv_msg.data_hdr));
    }

exit:
    if (!result && ctx->recv_data.params) {
        free(ctx->recv_data.params);
        ctx->recv_data.params = NULL;
    }
    return result;
}

static void
recv_dispatch(struct context* ctx)
{
    struct brh264_data *data = NULL;

    brh264_recv(ctx);

    if (ctx->recv_msg.params_size || ctx->recv_msg.data_size) {
        data = &ctx->recv_data;
    }

    switch (ctx->recv_msg.type) {
    case BRH264_ACK:
        if (ctx->cb.brh264_recv_res) {
            ctx->cb.brh264_recv_res(ctx->priv, 0);
        }
        break;
    case BRH264_NACK:
        if (ctx->cb.brh264_recv_res) {
            ctx->cb.brh264_recv_res(ctx->priv, -1);
        }
        break;
    case BRH264_MT_DATA:
        if (ctx->cb.brh264_recv_mt) {
            ctx->cb.brh264_recv_mt(ctx->priv, data);
        }
        break;
    case BRH264_ENC_DATA:
        if (ctx->cb.brh264_recv_enc) {
            ctx->cb.brh264_recv_enc(ctx->priv, data);
        }
        break;
    case BRH264_DEC_DATA:
        if (ctx->cb.brh264_recv_dec) {
            ctx->cb.brh264_recv_dec(ctx->priv, data);
        }
        break;
    default:
        uxen_err("unknown message type %d", ctx->recv_msg.type);
        break;
    }

    if (ctx->recv_data.params) {
        free(ctx->recv_data.params);
    }

    ZeroMemory(&ctx->recv_msg, sizeof(ctx->recv_msg));
    ZeroMemory(&ctx->recv_data, sizeof(ctx->recv_data));
}

static int
recv_setup(struct context* ctx);

HANDLE
brh264_recv_collect(brh264_ctx c, BOOL wait)
{
    struct context* ctx = (struct context*)c;
    DWORD bytes;

    if (!ctx->recv_pending) goto exit;

    if (!GetOverlappedResult(ctx->v4v.v4v_handle, &ctx->recv_overlapped, &bytes, wait)) {
        switch(GetLastError()) {
            case ERROR_IO_INCOMPLETE:
                goto exit;
        }
        uxen_err("GetOverLappedResult failed: %d", GetLastError());
    }
    else {
        recv_dispatch(ctx);
    }

    ctx->recv_pending = 0;
    if (recv_setup(ctx) < 0) {
        uxen_err("recv_setup failed: %d", GetLastError());
    }

exit:
    return ctx->recv_event;
}

static int
recv_setup(struct context* ctx)
{
    if (ctx->recv_pending) brh264_recv_collect(ctx);
    if (ctx->recv_pending) return 0;

    memset(&ctx->recv_overlapped, 0, sizeof(ctx->recv_overlapped));
    ctx->recv_overlapped.hEvent = ctx->recv_event;

    while (ReadFile(ctx->v4v.v4v_handle, &ctx->recv_msg, sizeof(ctx->recv_msg), NULL, &ctx->recv_overlapped))  {
        recv_dispatch(ctx);
        memset(&ctx->recv_overlapped, 0, sizeof(ctx->recv_overlapped));
        ctx->recv_overlapped.hEvent = ctx->recv_event;
    }

    DWORD gle = GetLastError();
    switch(gle) {
        case ERROR_IO_PENDING:
            break;
        default:
            uxen_err("ReadFile failed: %d", gle);
            return -1;
    }

    ctx->recv_pending = 1;
    return 0;
}

void brh264_destroy(brh264_ctx c)
{
    struct context* ctx = (struct context*)c;
    int retry_cnt = UXENH264_RETRY_COUNT;

    if (!ctx || InterlockedCompareExchange(&ctx->exit, 1, 1)) {
        return;
    }

    InterlockedIncrement(&ctx->exit);
    SetEvent(ctx->recv_event);
    while (InterlockedCompareExchange(&ctx->exit, 1, 1) && retry_cnt--) {
        Sleep(UXENH264_DM_TIMEOUT_MS);
    }

    CancelIoEx(ctx->v4v.v4v_handle, NULL);

    if (ctx->recv_event) {
        CloseHandle(ctx->recv_event);
    }
    if (ctx->send_event) {
        CloseHandle(ctx->send_event);
    }
    if (ctx->v4v.v4v_handle) {
        v4v_close(&ctx->v4v);
    }
    if (ctx) {
        free(ctx);
    }
}

static DWORD WINAPI read_thread_run(PVOID opaque)
{
    DWORD ec = 0;
    struct context *ctx = (struct context *)opaque;
    uxen_msg("Read thread starting");
    while (!InterlockedCompareExchange(&ctx->exit, 0, 0)) {
        ec = WaitForSingleObject(ctx->recv_event, UXENH264_DM_TIMEOUT_MS);
        if ((ec == WAIT_OBJECT_0) && !InterlockedCompareExchange(&ctx->exit, 0, 0)) {
            brh264_recv_collect(ctx, TRUE);
        }
    }
    uxen_msg("Read thread finishing");
    InterlockedDecrement(&ctx->exit);
    return ec;
}

brh264_ctx brh264_create(void *priv, struct brh264_recv_callbacks *cb, unsigned char *tokenid, bool thread)
{
    struct context *ctx = NULL;
    int cnt = UXENH264_DM_MAX_DEC;
    bool send_nop = !tokenid;

    ctx = (struct context*)calloc(1, sizeof(*ctx));
    if (!ctx) {
        uxen_err("Call to calloc has failed");
        goto error;
    }

    ctx->priv = (priv) ? priv : ctx;
    ctx->cb = *cb;

    if (!v4v_open(&ctx->v4v, BRH264_RING_SIZE, V4V_FLAG_ASYNC))
    {
        uxen_err("Call to v4v_open has failed %d", GetLastError());
        goto error;
    }

    ctx->bind.ring_id.addr.port = BRH264_BASE_PORT;
    ctx->bind.ring_id.addr.domain = V4V_DOMID_NONE;
    if (!tokenid)
    {
        ctx->bind.ring_id.partner = V4V_DOMID_DM;
    }
    else
    {
        ctx->bind.ring_id.partner = V4V_DOMID_UUID;
        for (int i = 0; i < 16; ++i)
        {
            ctx->bind.partner.o[i] = tokenid[i];
        }
    }

    while (!v4v_bind(&ctx->v4v, &ctx->bind))
    {
        ctx->bind.ring_id.addr.port++;
        if (cnt-- == 0)
        {
            uxen_err("Call to v4v_bind has failed %d", GetLastError());
            goto error;
        }
        Sleep(200);
    }

    ctx->recv_event = CreateEvent(NULL, FALSE, FALSE, NULL);
    if (!ctx->recv_event)
    {
        uxen_err("Call to CreateEvent recv_event has failed %d", GetLastError());
        goto error;
    }

    ctx->send_event = CreateEvent(NULL, FALSE, FALSE, NULL);
    if (!ctx->send_event)
    {
        uxen_err("Call to CreateEvent send_event has failed %d", GetLastError());
        goto error;
    }

    if (send_nop && !brh264_send_meta(ctx, BRH264_READY, NULL)) {
        uxen_err("Call to brh264_send_meta has failed");
        goto error;
    }

    recv_setup(ctx);

    if (thread) {
        HANDLE thandle = CreateThread(NULL, 0, read_thread_run, ctx, 0, NULL);
        if (!thandle) {
            uxen_err("Call to CreateThread has failed");
            goto error;
        }
        else {
            CloseHandle(thandle);
        }
    }

    return ctx;

error:
    brh264_destroy(ctx);
    return NULL;
}
