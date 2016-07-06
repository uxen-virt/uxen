/*
 * Copyright 2015-2016, Bromium, Inc.
 * Author: Phil Dennis-Jordan <phil@philjordan.eu>
 * SPDX-License-Identifier: ISC
 */

#include <dm/config.h>
#include "uxen_v4v.h"
#include <osx/uxenv4vservice/uxenv4vlib.c>

int
v4v_open_sync(v4v_context_t *v4v, uint32_t ring_size, int *out_error)
{

    if (!v4v_open(&v4v->v4v_channel, ring_size)) {
        *out_error = errno;
        return false;
    }

    ioh_event_init_with_mach_port(
        &v4v->recv_event, v4v_get_receive_port(&v4v->v4v_channel));
    return true;
}

int
v4v_bind_sync(v4v_context_t *v4v, v4v_ring_id_t *r, int *out_error)
{

    if (!v4v_bind(&v4v->v4v_channel, r->addr.port, r->partner)) {
        *out_error = errno;
        return false;
    }

    return true;
}

int
v4v_have_v4v(void)
{
    v4v_channel_t v4v = { };

    if (_v4v_open(&v4v, 4096)) {
        _v4v_close(&v4v);
        return 1;
    }

    return 0;
}

void
v4v_close(v4v_context_t *v4v)
{

    if (_v4v_opened(&v4v->v4v_channel)) {
        _v4v_close(&v4v->v4v_channel);
        ioh_event_close(&v4v->recv_event);
    }
}

int
v4v_notify(v4v_context_t *v4v)
{

    _v4v_notify(&v4v->v4v_channel);
    return 1;
}

int
v4v_init_tx_event(v4v_context_t *v4v, ioh_event *out_event, int *out_error)
{
    mach_port_t port;

    port = v4v_get_send_port(&v4v->v4v_channel);
    ioh_event_init_with_mach_port(out_event, port);

    return 1;
}

v4v_ring_t *
v4v_ring_map_sync(v4v_context_t *v4v, int *out_error)
{

    return v4v_get_mapped_ring(&v4v->v4v_channel);
}

