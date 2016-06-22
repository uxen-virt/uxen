/*
 * Copyright 2015-2016, Bromium, Inc.
 * Author: Phil Dennis-Jordan <phil@philjordan.eu>
 * SPDX-License-Identifier: ISC
 */

#include "uxen_v4v.h"

int
v4v_have_v4v(void)
{
    v4v_channel_t v4v = { };

    if (_v4v_open(&v4v, 4096, V4V_FLAG_NONE, NULL)) {
        _v4v_close(&v4v);
        return 1;
    }

    return 0;
}

void
v4v_close(v4v_context_t *v4v)
{

    _v4v_close(&v4v->v4v_channel);
}

int
v4v_open_sync(v4v_context_t *v4v, uint32_t ring_size, int *out_error)
{

    if (!_v4v_open(&v4v->v4v_channel, ring_size, V4V_FLAG_ASYNC, NULL)) {
        *out_error = GetLastError();
        return false;
    }

    return true;
}

int
v4v_bind_sync(v4v_context_t *v4v, v4v_ring_id_t *r, int *out_error)
{

    if (!_v4v_bind (&v4v->v4v_channel, r, NULL)) {
        *out_error = GetLastError();
        return false;
    }

    return true;
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

int
v4v_notify(v4v_context_t *v4v)
{

    if (!uxenv4v_notify_complete(v4v))
        return false;

    memset(&v4v->notify_overlapped, 0, sizeof(v4v->notify_overlapped));

    _v4v_notify(&v4v->v4v_channel, &v4v->notify_overlapped);

    v4v->notify_pending = TRUE;

    return true;
}

int
v4v_init_tx_event(v4v_context_t *v4v, ioh_event *out_event, int *out_error)
{
    HANDLE ev;

    ev = *out_event = CreateEvent(NULL, FALSE, FALSE, NULL);
    *out_error = (int)GetLastError();

    return (ev != NULL);
}

v4v_ring_t *
v4v_ring_map_sync(v4v_context_t *v4v, int *out_error)
{
    v4v_mapring_values_t mr;

    mr.ring = NULL;
    if (!_v4v_map(&v4v->v4v_channel, &mr, NULL)) {
        *out_error = GetLastError();
        return NULL;
    }

    return mr.ring;
}

