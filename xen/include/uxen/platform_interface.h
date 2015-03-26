/*
 * Copyright 2013-2015, Bromium, Inc.
 * Author: Christian Limpach <Christian.Limpach@gmail.com>
 * SPDX-License-Identifier: ISC
 */

#ifndef _PLATFORM_INTERFACE_H_
#define _PLATFORM_INTERFACE_H_

#define CTL_MMIO_EVENT_SYNC_TIME 0x1
#define CTL_MMIO_EVENT_SET_BALLOON 0x2

struct ctl_mmio {
    uint32_t cm_events_enabled;
    uint32_t cm_events;
    uint32_t cm_balloon_min;
    uint32_t cm_balloon_max;
    uint32_t cm_balloon_current;
    uint32_t cm_filetime_low;
    uint32_t cm_filetime_high;
};

#define UXEN_STATE_BAR_MAGIC	0x47531628

struct uxp_state_bar {
    uint32_t magic;
    uint32_t v4v_running;
};


#endif  /* _PLATFORM_INTERFACE_H_ */
