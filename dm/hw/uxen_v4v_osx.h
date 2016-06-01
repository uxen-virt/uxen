/*
 * Copyright 2015-2016, Bromium, Inc.
 * Author: Phil Dennis-Jordan <phil@philjordan.eu>
 * SPDX-License-Identifier: ISC
 */

#ifndef _UXEN_V4V_OSX_H_
#define _UXEN_V4V_OSX_H_

#include <stdint.h>
#include <sys/types.h>
#include <string.h>
#include <xen/v4v.h>
#include "../../osx/uxenv4vservice/uxenv4vlib.h"
#include "../ioh.h"

typedef struct v4v_datagram_struct {
    v4v_addr_t addr;
    uint16_t flags;
    /* data starts here */
} V4V_PACKED v4v_datagram_t;

typedef struct v4v_context {
    union {
        v4v_channel_t;
        v4v_channel_t v4v_channel;
    };
    ioh_event recv_event;
} v4v_context_t;

#endif
