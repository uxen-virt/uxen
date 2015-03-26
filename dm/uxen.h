/*
 * Copyright 2012-2015, Bromium, Inc.
 * Author: Christian Limpach <Christian.Limpach@gmail.com>
 * SPDX-License-Identifier: ISC
 */

#ifndef _UXEN_H_
#define _UXEN_H_

#include <xen/version.h>
#include <uxenctllib.h>
#include <uxen/uxen_desc.h>

extern UXEN_HANDLE_T uxen_handle;

extern char *uxen_opt_debug;

#define HV_SIZE_MIN 512
#define HV_SIZE_MAX (512*1024*1024)

int uxen_setup(UXEN_HANDLE_T);

int uxen_destroy(xen_domain_handle_t);

int uxen_run(int);

int uxen_fd(void);

int uxen_xc_keyhandler(const char *);

enum uxen_ioemu_events {
    UXEN_IOEMU_EVENT_EXCEPTION,
    UXEN_IOEMU_EVENT_VRAM,
};

int uxen_ioemu_event(enum uxen_ioemu_events, uxen_notification_event *);
int uxen_setup_event_channel(uint32_t, uint32_t, uxen_notification_event *,
                             uxen_user_notification_event *);

void uxen_log_version(void);

#endif	/* _UXEN_H_ */
