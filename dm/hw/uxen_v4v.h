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
int v4v_open_sync(_v4v_context_t *v4v, uint32_t ring_size, int *out_error);
int v4v_bind_sync(_v4v_context_t *v4v, v4v_ring_id_t *r, int *out_error);
int _v4v_notify(_v4v_context_t *ctx);
int v4v_init_tx_event(
	_v4v_context_t *ctx, ioh_event *out_event, int *out_error);
v4v_ring_t *v4v_ring_map_sync(_v4v_context_t *ctx, int *out_error);

#endif
