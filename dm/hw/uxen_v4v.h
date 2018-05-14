/*
 * Copyright 2015-2018, Bromium, Inc.
 * Author: Phil Dennis-Jordan <phil@philjordan.eu>
 * SPDX-License-Identifier: ISC
 */

#ifndef _UXEN_V4V_H_
#define _UXEN_V4V_H_

#ifdef _WIN32
#include "uxen_v4v_win32.h"
#elif defined(__APPLE__)
#include "uxen_v4v_osx.h"
#else
#error No v4v helper functions defined for this platform
#endif

bool dm_v4v_have_v4v(void);
void dm_v4v_close(v4v_context_t *v4v);
int dm_v4v_open(v4v_context_t *v4v, uint32_t ring_size);
int dm_v4v_bind(v4v_context_t *v4v, v4v_bind_values_t *bind);
/* resulting event is using automatic reset */
int dm_v4v_init_tx_event(
    v4v_context_t *v4v, ioh_event *out_event);
int dm_v4v_ring_map(v4v_context_t *v4v, v4v_ring_t **out_ring);
bool dm_v4v_notify(v4v_context_t *v4v);

/* pending async op handling */
int dm_v4v_async_init(v4v_context_t *v4v, v4v_async_t *async, ioh_event ev);
bool dm_v4v_async_is_completed(v4v_async_t *async);
int dm_v4v_async_get_result(v4v_async_t *async, size_t *bytes, bool wait);
int dm_v4v_async_cancel(v4v_async_t *async);

/* send asynchronously; return error code, or 0 on success. Sends complete fully (all bytes sent)
 * or not at all. */
int dm_v4v_send(v4v_context_t *v4v, v4v_datagram_t *dgram,
    size_t size, v4v_async_t *async);

/* receive asynchronously; return error code, or 0 on success. */
int dm_v4v_recv(v4v_context_t *v4v, v4v_datagram_t *dgram,
    size_t buffer_size, v4v_async_t *async);

#endif  /* _UXEN_V4V_H_ */
