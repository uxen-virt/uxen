/*
 * Copyright 2018-2019, Bromium, Inc.
 * Author: Tomasz Wroblewski <tomasz.wroblewski@gmail.com>
 * SPDX-License-Identifier: ISC
 */

#ifndef WHPX_V4V_WHPX_H_
#define WHPX_V4V_WHPX_H_

#include <dm/hw/uxen_v4v.h>

#define V4V_FLAG_PROXY (1<<31)

void whpx_v4v_proxy_init(void);
void whpx_v4v_init(void);
void whpx_v4v_shutdown(void);
bool whpx_v4v_have_v4v(void);
/* called when host is notified about pending v4v data */
void whpx_v4v_handle_signal(void);
void whpx_v4v_close(v4v_context_t *v4v);
int whpx_v4v_open(v4v_context_t *v4v, uint32_t ring_size, uint32_t flags);
int whpx_v4v_bind(v4v_context_t *v4v, v4v_bind_values_t *bind);
void whpx_v4v_set_recv_callback(v4v_context_t *v4v, void *opaque, void (*cb)(void*));
int whpx_v4v_ring_map(v4v_context_t *v4v, v4v_ring_t **out_ring);
bool whpx_v4v_notify(v4v_context_t *v4v);

/* init async reported via event */
int whpx_v4v_async_init(v4v_context_t *v4v, v4v_async_t *async, ioh_event ev);
/* init async reported via callback. callback can be invoked on non-main thread, usually vcpu thread */
int whpx_v4v_async_init_cb(v4v_context_t *v4v, v4v_async_t *async, void *opaque, void (*cb)(void*));
bool whpx_v4v_async_is_completed(v4v_async_t *async);
int whpx_v4v_async_get_result(v4v_async_t *async, size_t *bytes, bool wait);
int whpx_v4v_async_cancel(v4v_async_t *async);

int whpx_v4v_send(v4v_context_t *v4v, v4v_datagram_t *dgram,
    size_t size, v4v_async_t *async);
int whpx_v4v_recv(v4v_context_t *v4v, v4v_datagram_t *dgram,
    size_t buffer_size, v4v_async_t *async);


#endif
