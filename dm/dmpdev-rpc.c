/*
 * Copyright 2013-2016, Bromium, Inc.
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

bool dmpdev_notify_vm_crash(uint32_t code,
                            uint64_t param1, uint64_t param2,
                            uint64_t param3, uint64_t param4)
{
    ioh_event event;
    struct rpc_callback_arg_t rpc_callback_arg;
    uint32_t wait_result;
    dict args;

    ioh_event_init(&event);
    if (!event)
        return false;

    rpc_callback_arg.event = event;
    rpc_callback_arg.decision = 0;

    args = dict_new();
    dict_put_integer(args, "crash-code", code);
    dict_put_integer(args, "crash-param1", param1);
    dict_put_integer(args, "crash-param2", param2);
    dict_put_integer(args, "crash-param3", param3);
    dict_put_integer(args, "crash-param4", param4);
    control_send_command("dmpdev-notify-vm-crash", args, rpc_callback,
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

bool dmpdev_notify_vm_crash(void)
{
    /* not implemented */
    return false;
}

void dmpdev_notify_dump_complete(bool dump_save_successful)
{
    /* not implemented */
}

#endif
