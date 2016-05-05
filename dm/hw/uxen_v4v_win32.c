/*
 * Copyright 2015-2016, Bromium, Inc.
 * Author: Phil Dennis-Jordan <phil@philjordan.eu>
 * SPDX-License-Identifier: ISC
 */

#include "uxen_v4v.h"

#undef v4v_close

int
v4v_have_v4v(void)
{
    _v4v_context_t c = {{ 0 }};

    if (v4v_open (&c.c, 4096, NULL)) {
        v4v_close_win32 (&c);
        return 1;
    }

    return 0;
}

void 
v4v_close_win32(_v4v_context_t *ctx)
{
    v4v_close(&ctx->c);
}

int
v4v_open_sync(_v4v_context_t *v4v, uint32_t ring_size, int *out_error)
{
    OVERLAPPED o = { 0 };
    DWORD t;

    v4v->c.flags = V4V_FLAG_OVERLAPPED;
    memset (&o, 0, sizeof (o));

    if (!v4v_open (&v4v->c, ring_size, &o)) {
        *out_error = GetLastError();
        return false;
    }

    if (!GetOverlappedResult (v4v->c.v4v_handle, &o, &t, TRUE)) {
        *out_error = GetLastError();
        return false;
    }

    return true;
}

int
v4v_bind_sync(_v4v_context_t *v4v, v4v_ring_id_t *r, int *out_error)
{
    OVERLAPPED o = { 0 };
    DWORD t;

    memset (&o, 0, sizeof (o));

    if (!v4v_bind (&v4v->c, r, &o)) {
        *out_error = GetLastError();
        return false;
    }


    if (!GetOverlappedResult (v4v->c.v4v_handle, &o, &t, TRUE)) {
        *out_error = GetLastError();
        return false;
    }

    return true;
}

static BOOLEAN
uxenv4v_notify_complete(_v4v_context_t *ctx)
{
    DWORD writ;

    if (!ctx->notify_pending)
        return TRUE;

    if (GetOverlappedResult
        (ctx->c.v4v_handle, &ctx->notify_overlapped,
         &writ, FALSE /* don't wait */)) {
        ctx->notify_pending = FALSE;
        return TRUE;
    }

    if (GetLastError () == ERROR_IO_INCOMPLETE)
        return FALSE;

    /* XXX: does false mean complete? in this case */
    ctx->notify_pending = FALSE;

    return TRUE;
}

int
_v4v_notify(_v4v_context_t *ctx)
{
    if (!uxenv4v_notify_complete(ctx)) {
        return false;
    }
    memset (&ctx->notify_overlapped, 0, sizeof (OVERLAPPED));

    gh_v4v_notify(&ctx->c, &ctx->notify_overlapped);

    ctx->notify_pending = TRUE;
    
    return true;
}

int
v4v_init_tx_event(_v4v_context_t *ctx, ioh_event *out_event, int *out_error)
{
    HANDLE ev = *out_event = CreateEvent (NULL, FALSE, FALSE, NULL);
    *out_error = (int)GetLastError();
    return (ev != NULL);
}

v4v_ring_t *
v4v_ring_map_sync(_v4v_context_t *ctx, int *out_error)
{
    DWORD t;
    v4v_mapring_values_t mr;
    OVERLAPPED o = { 0 };

    memset (&o, 0, sizeof (o));

    mr.ring = NULL;
    if (!v4v_map (&ctx->c, &mr, &o)) {
		*out_error = GetLastError();
        return NULL;
    }

    if (!GetOverlappedResult (ctx->c.v4v_handle, &o, &t, TRUE)) {
		*out_error = GetLastError();
        return NULL;
    }

    return mr.ring;
}

