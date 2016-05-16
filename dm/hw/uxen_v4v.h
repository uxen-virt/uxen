/*
 * Copyright 2015-2016, Bromium, Inc.
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

int v4v_have_v4v(void);
#undef v4v_close
void v4v_close(v4v_context_t *v4v);
int v4v_open_sync(v4v_context_t *v4v, uint32_t ring_size, int *out_error);
int v4v_bind_sync(v4v_context_t *v4v, v4v_ring_id_t *r, int *out_error);
#undef v4v_notify
int v4v_notify(v4v_context_t *v4v);
int v4v_init_tx_event(
    v4v_context_t *v4v, ioh_event *out_event, int *out_error);
v4v_ring_t *v4v_ring_map_sync(v4v_context_t *v4v, int *out_error);

#endif  /* _UXEN_V4V_H_ */
