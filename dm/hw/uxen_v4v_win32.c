/*
 * Copyright 2015-2019, Bromium, Inc.
 * Author: Phil Dennis-Jordan <phil@philjordan.eu>
 * SPDX-License-Identifier: ISC
 */

#include "uxen_v4v.h"
#include <dm/whpx/v4v-whpx.h>

bool
dm_v4v_have_v4v(void)
{
    v4v_channel_t v4v = { };

    if (!whpx_enable) {
        if (_v4v_open(&v4v, 4096, V4V_FLAG_NONE, NULL)) {
            _v4v_close(&v4v);
            return 1;
        }
    }
    else
        return 1;

    return 0;
}

void
dm_v4v_close(v4v_context_t *v4v)
{
    if (!whpx_enable)
        _v4v_close(&v4v->v4v_channel);
    else
        whpx_v4v_close(v4v);
}

int
dm_v4v_open(v4v_context_t *v4v, uint32_t ring_size)
{
    uint32_t flags = V4V_FLAG_ASYNC;

    if (vm_restore_mode == VM_RESTORE_TEMPLATE)
        err(1, "v4v_open for template vm");

    if (vm_attovm_mode == ATTOVM_MODE_AX)
        flags |= V4V_FLAG_AX;

    if (!whpx_enable) {
        if (!_v4v_open(&v4v->v4v_channel, ring_size, flags, NULL))
            return GetLastError();
        return 0;
    } else
        return whpx_v4v_open(v4v, ring_size, flags);
}

int
dm_v4v_bind(v4v_context_t *v4v, v4v_bind_values_t *bind)
{
    if (!whpx_enable) {
        if (!_v4v_bind(&v4v->v4v_channel, bind, NULL))
            return GetLastError();

        return 0;
    } else
        return whpx_v4v_bind(v4v, bind);
}

static BOOLEAN
uxenv4v_notify_complete(v4v_context_t *v4v)
{
    DWORD writ;

    if (!v4v->notify_pending)
        return TRUE;

    if (GetOverlappedResult(v4v->v4v_handle, &v4v->notify_overlapped,
                            &writ, FALSE /* don't wait */)) {
        v4v->notify_pending = FALSE;
        return TRUE;
    }

    if (GetLastError() == ERROR_IO_INCOMPLETE)
        return FALSE;

    /* XXX: does false mean complete? in this case */
    v4v->notify_pending = FALSE;

    return TRUE;
}

bool
dm_v4v_notify(v4v_context_t *v4v)
{
    if (!whpx_enable) {
        if (!uxenv4v_notify_complete(v4v))
            return false;

        memset(&v4v->notify_overlapped, 0, sizeof(v4v->notify_overlapped));

        _v4v_notify(&v4v->v4v_channel, &v4v->notify_overlapped);

        v4v->notify_pending = TRUE;

        return true;
    } else
        return whpx_v4v_notify(v4v);
}

int
dm_v4v_init_tx_event(v4v_context_t *v4v, ioh_event *out_event)
{
    HANDLE ev;

    ev = *out_event = CreateEvent(NULL, FALSE, FALSE, NULL);
    if (!ev)
        return GetLastError();

    return 0;
}

int
dm_v4v_ring_map(v4v_context_t *v4v, v4v_ring_t **out_ring)
{
    v4v_mapring_values_t mr;

    if (!whpx_enable) {
        *out_ring = NULL;
        mr.ring = NULL;
        if (!_v4v_map(&v4v->v4v_channel, &mr, NULL))
            return GetLastError();

        *out_ring = mr.ring;

        return 0;
    } else
        return whpx_v4v_ring_map(v4v, out_ring);
}

int
dm_v4v_async_init(v4v_context_t *ctx, v4v_async_t *async, ioh_event ev)
{
    if (!whpx_enable) {
        memset(async, 0, sizeof(*async));
        async->context = ctx;
        async->ov.hEvent = ev;

        return 0;
    } else
        return whpx_v4v_async_init(ctx, async, ev);
}

bool
dm_v4v_async_is_completed(v4v_async_t *async)
{
    if (!whpx_enable)
        return HasOverlappedIoCompleted(&async->ov);
    else
        return whpx_v4v_async_is_completed(async);
}

int
dm_v4v_async_get_result(v4v_async_t *async, size_t *bytes, bool wait)
{
    if (!whpx_enable) {
        DWORD b = 0;
        BOOL ret = GetOverlappedResult(
            async->context->v4v_channel.v4v_handle,
            &async->ov,
            &b,
            wait);
        if (bytes)
            *bytes = b;
        return ret ? 0 : GetLastError();
    } else
        return whpx_v4v_async_get_result(async, bytes, wait);
}

int
dm_v4v_async_cancel(v4v_async_t *async)
{
    if (!whpx_enable) {
        if (async->ov.hEvent) {
            DWORD bytes;
            BOOL r = CancelIoEx(async->context->v4v_channel.v4v_handle,
                &async->ov);
            if (r || (GetLastError() != ERROR_NOT_FOUND))
                GetOverlappedResult(async->context->v4v_channel.v4v_handle,
                    &async->ov, &bytes, TRUE);
        }
        return 0;
    }
    else
        return whpx_v4v_async_cancel(async);
}

int
dm_v4v_recv(v4v_context_t *v4v, v4v_datagram_t *dgram,
    size_t buffer_size, v4v_async_t *async)
{
    assert(async != NULL);

    if (!whpx_enable) {
        int err = 0;

        if (!ReadFile(v4v->v4v_channel.v4v_handle, dgram,
                buffer_size, NULL, &async->ov)) {
            err = GetLastError();
            if (err != ERROR_IO_PENDING)
                return err;
        }

        return err;
    } else
        return whpx_v4v_recv(v4v, dgram, buffer_size, async);
}

int
dm_v4v_send(v4v_context_t *v4v, v4v_datagram_t *dgram,
    size_t size, v4v_async_t *async)
{
    assert(async != NULL);

    if (!whpx_enable) {
        int err = 0;

        if (!WriteFile(v4v->v4v_channel.v4v_handle, dgram,
                size, NULL, &async->ov)) {
            err = GetLastError();
            if (err != ERROR_IO_PENDING)
                return err;
        }

        return err;
    } else
        return whpx_v4v_send(v4v, dgram, size, async);
}

