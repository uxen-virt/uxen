/*
 * Copyright 2013-2015, Bromium, Inc.
 * Author: Kris Uchronski <kuchronski@gmail.com>
 * SPDX-License-Identifier: ISC
 */

#include "config.h"

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>

#include "debug.h"
#include "control.h"
#include "dict.h"
#include "dict-rpc.h"
#include "dmpdev.h"

#if defined(_WIN32)

struct rpc_callback_arg_t {
    ioh_event event;
    bool decision;
};

static void rpc_callback(void *opaque, dict d)
{
    const char *info;
    struct rpc_callback_arg_t *arg = (struct rpc_callback_arg_t*)opaque;
    info = dict_get_string(d, "info");
    arg->decision = info && !strcmp(info, "allowed");
    ioh_event_set(&arg->event);
    dict_free(d);
}

bool dmpdev_query_dump_allowed(void)
{
    ioh_event event;
    struct rpc_callback_arg_t rpc_callback_arg;
    uint32_t wait_result;

    ioh_event_init(&event);
    if (!event)
        return false;

    rpc_callback_arg.event = event;
    rpc_callback_arg.decision = 0;
    control_send_command("dmpdev-is-dump-allowed", NULL, rpc_callback,
                         &rpc_callback_arg);

    wait_result = ioh_event_wait(&event);
    if (WAIT_OBJECT_0 != wait_result) {
        Wwarn("dmpdev-rpc: WaitForSingleObject() failed: %d", wait_result);
        rpc_callback_arg.decision = false;
    } else
        debug_printf("dmpdev: dump creation is %s\n",
                     rpc_callback_arg.decision ? "allowed" : "denied");

    ioh_event_close(&event);

    return rpc_callback_arg.decision;
}

void dmpdev_notify_dump_complete(bool dump_save_sucessful)
{
    dict args;

    args = dict_new();
    dict_put_integer(args, "dump-status", dump_save_sucessful ? 1 : 0);
    control_send_command("dmpdev-dump-status", args, NULL, NULL);
}

#elif defined(__APPLE__)

bool dmpdev_query_dump_allowed(void)
{
    /* not implemented */
    return false;
}

void dmpdev_notify_dump_complete(bool dump_save_successful)
{
    /* not implemented */
}

#endif
