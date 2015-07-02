/*
 * Copyright 2015-2016, Bromium, Inc.
 * Author: Phil Dennis-Jordan <phil@philjordan.eu>
 * SPDX-License-Identifier: ISC
 */

#include "uxen_v4v.h"
#undef v4v_close
#include "../../osx/uxenv4vservice/uxenv4vlib.c"

int
v4v_open_sync(_v4v_context_t *v4v, uint32_t ring_size, int *out_error)
{
    errno_t err;
    
    err = v4v_open_service(&v4v->v4v_handle);
    if (err == 0) {
        ioh_event_init_with_mach_port(
            &v4v->recv_event, v4v_get_receive_port(v4v->v4v_handle));
        v4v->ring_size = ring_size;
        return true;
    } else {
        *out_error = err;
        return false;
    }
}
int
v4v_bind_sync(_v4v_context_t *v4v, v4v_ring_id_t *r, int *out_error)
{
    errno_t err;
    
    err = v4v_bind(v4v->v4v_handle, v4v->ring_size, r->addr.port, r->partner);
    *out_error = err;
    return err == 0;
}

int
v4v_have_v4v(void)
{
    int error;
    _v4v_context_t c = {};

    if (v4v_open_sync(&c,0, &error)) {
        v4v_close_osx(&c);
        return 1;
    }

    return 0;
}

void
v4v_close_osx(_v4v_context_t *ctx)
{

    if (ctx->v4v_handle) {
        v4v_close(ctx->v4v_handle);
        ioh_event_close(&ctx->recv_event);
    }
}

int
_v4v_notify(_v4v_context_t *ctx)
{

    v4v_notify(ctx->v4v_handle);
    return 1;
}

int
v4v_init_tx_event(_v4v_context_t *ctx, ioh_event *out_event, int *out_error)
{
    mach_port_t port;
    
    port = v4v_get_send_port(ctx->v4v_handle);
    ioh_event_init_with_mach_port(out_event, port);
    return 1;
}

v4v_ring_t *
v4v_ring_map_sync(_v4v_context_t *ctx, int *out_error)
{

    return v4v_get_mapped_ring(ctx->v4v_handle);
}

