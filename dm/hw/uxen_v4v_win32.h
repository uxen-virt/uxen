/*
 * Copyright 2015-2016, Bromium, Inc.
 * Author: Phil Dennis-Jordan <phil@philjordan.eu>
 * SPDX-License-Identifier: ISC
 */

#ifndef _UXEN_V4V_WIN32_H_
#define _UXEN_V4V_WIN32_H_

#include <dm/qemu_glue.h>

#include <winioctl.h>
#define V4V_USE_INLINE_API
#include <windows/uxenv4vlib/gh_v4vapi.h>
#define _POSIX

typedef struct v4v_context {
    union {
        v4v_channel_t;
        v4v_channel_t v4v_channel;
    };
    OVERLAPPED notify_overlapped;
    BOOLEAN notify_pending;
} v4v_context_t;

#define v4v_close v4v_close_win32
void
v4v_close_win32(v4v_context_t *v4v);

#endif
