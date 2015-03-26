/*
 * Copyright 2012-2015, Bromium, Inc.
 * SPDX-License-Identifier: ISC
 */

#include "config.h"

#include "dict.h"
#include "dict-rpc.h"
#include "control.h"
struct rpc_callback_arg_t {
    HANDLE event;
    int decision;
};

static void
rpc_callback(void *opaque, dict d)
{
    const char *info;
    struct rpc_callback_arg_t *arg = (struct rpc_callback_arg_t*)opaque;
    arg->decision = 0;
    info = dict_get_string(d, "info");
    if (info) {
        if (!strcmp(info, "access_granted"))
            arg->decision = 1;
    }
    SetEvent(arg->event);
    dict_free(d);
}

int BrPolicyGetClipboardAccessDecision(int *retval, int is_copy)
{
    static HANDLE event;
    struct rpc_callback_arg_t rpc_callback_arg;
    dict args;

    *retval = 0;
    if (!event) {
        event = CreateEvent(NULL, FALSE, FALSE, NULL);
        if (!event)
            return 0;
    }
    
    rpc_callback_arg.event = event;
    rpc_callback_arg.decision = 0;
    args = dict_new();
    dict_put_integer(args, "access-type", is_copy);
    control_send_command("clipboard-access", args, rpc_callback, 
        &rpc_callback_arg);

    WaitForSingleObject(event, INFINITE);
    *retval = rpc_callback_arg.decision;
    return 0;
}
