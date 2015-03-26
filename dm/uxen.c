/*
 *  uxen.c
 *  uxen
 *
 * Copyright 2012-2015, Bromium, Inc.
 * Author: Christian Limpach <Christian.Limpach@gmail.com>
 * SPDX-License-Identifier: ISC
 *
 */

#include "config.h"

#include <err.h>
#include <errno.h>
#include <stdint.h>
#ifdef __APPLE__
#include <sys/syslimits.h> // PATH_MAX
#endif

#include <uxenctllib.h>
#include <uxen/uxen_desc.h>
#include <uxen/uxen_info.h>

#include <xenctrl.h>

#include "dm.h"
#include "uxen.h"

UXEN_HANDLE_T uxen_handle = INVALID_HANDLE_VALUE;

char *uxen_opt_debug = NULL;

static void
close_and_unload(void)
{
    if (uxen_handle != INVALID_HANDLE_VALUE)
	uxen_close(uxen_handle);
    uxen_handle = INVALID_HANDLE_VALUE;

    // (void)uxen_manage_driver(FALSE, FALSE, NULL);
}

int
uxen_setup(UXEN_HANDLE_T h)
{
    int ret;
#ifdef __APPLE__
    char *path;
#endif

    atexit(close_and_unload);

    if (h != INVALID_HANDLE_VALUE)
	uxen_handle = h;
    else {
        uxen_handle = uxen_open(0, TRUE, dm_path);
	if (uxen_handle == INVALID_HANDLE_VALUE)
	    err(1, "uxen_open");
    }

#ifdef __APPLE__
    ret = uxen_load_xnu_symbols(uxen_handle, "/mach_kernel");
    if (ret)
        ret = uxen_load_xnu_symbols(uxen_handle,
                                    "/System/Library/Kernels/kernel");
    if (ret)
        errx(1, "load symbols failed");

    path = malloc(PATH_MAX);
    if (!path)
        errx(1, "can't allocate memory");
    snprintf(path, PATH_MAX, "%s/uxen.elf", dm_path);
    ret = uxen_load(uxen_handle, path);
    free(path);
    if (ret)
	err(1, "uxen_load");
#endif /* __APPLE */

    ret = uxen_init(uxen_handle, NULL);
    if (ret)
	err(1, "uxen_init");

    uxen_opt_debug = calloc(1, sizeof(xen_opt_debug_t) + 1);
    if (!uxen_opt_debug)
        err(1, "calloc(uxen_opt_debug)");

    ret = xc_version(xc_handle, XENVER_opt_debug, uxen_opt_debug);
    if (ret)
        err(1, "xc_version(XENVER_opt_debug)");
    debug_printf("%s: opt debug %s\n", __FUNCTION__, uxen_opt_debug);

    return 0;
}

int
uxen_destroy(xen_domain_handle_t uuid)
{
    int ret;

    ret = uxen_destroy_vm(uxen_handle, uuid);
    if (ret && errno != EAGAIN)
	err(1, "uxen_destroy_vm");

    return 0;
}

int
uxen_run(int vcpu)
{
    int ret;
    struct uxen_execute_desc ued = { };

    ued.ued_vcpu = vcpu;

    ret = uxen_execute(uxen_handle, &ued);
    return ret;
}

int
uxen_xc_keyhandler(const char *keys)
{
    int ret;

    ret = uxen_trigger_keyhandler(uxen_handle, keys);
    return ret;
}

int
uxen_ioemu_event(enum uxen_ioemu_events id, uxen_notification_event *event)
{
    int ret;
    struct uxen_event_desc ued = { };

    switch (id) {
    case UXEN_IOEMU_EVENT_EXCEPTION:
	ued.ued_id = UXEN_EVENT_EXCEPTION;
	break;
    case UXEN_IOEMU_EVENT_VRAM:
	ued.ued_id = UXEN_EVENT_VRAM;
	break;
    default:
	warn("uxen_ioemu_event: unknown id %d", id);
	return -ENOENT;
    }
    ued.ued_event = *event;
    ret = uxen_setup_event(uxen_handle, &ued);
    return ret;
}

int
uxen_setup_event_channel(uint32_t vcpu, uint32_t port,
                         uxen_notification_event *requestEvent,
                         uxen_user_notification_event *completedEvent)
{
    int ret;
    struct uxen_event_channel_desc uecd = { };

    uecd.uecd_vcpu = vcpu;
    uecd.uecd_port = port;
    uecd.uecd_request_event = *requestEvent;
    uecd.uecd_completed_event = completedEvent ? *completedEvent : NULL;
    ret = uxen_setup_host_event_channel(uxen_handle, &uecd);
    return ret;
}

void
uxen_log_version(void)
{
    xen_changeset_info_t changeset_info;
    xen_compile_info_t compile_info;
    int ret;

    ret = xc_version(xc_handle, XENVER_changeset, changeset_info);
    if (ret)
        strncpy(changeset_info, "<unknown>", sizeof(changeset_info));
    debug_printf("uxen changeset: %.*s\n", (int)sizeof(changeset_info),
                 changeset_info);

    ret = xc_version(xc_handle, XENVER_compile_info, &compile_info);
    if (ret) {
        strncpy(compile_info.compile_date, "<unknown>",
                sizeof(compile_info.compile_date));
    }
    debug_printf("uxen built on:  %.*s\n",
                 (int)sizeof(compile_info.compile_date),
                 compile_info.compile_date);
}
