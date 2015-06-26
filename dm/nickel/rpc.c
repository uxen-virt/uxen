/*
 * Copyright 2014-2015, Bromium, Inc.
 * Author: Paulian Marinca <paulian@marinca.net>
 * SPDX-License-Identifier: ISC
 */

#include <dm/config.h>
#include <dm/yajl.h>
#include <dm/dict.h>
#include <dm/dict-rpc.h>
#include <dm/control.h>
#include <dm/timer.h>
#include "nickel.h"
#include "log.h"
#include "rpc.h"

#define RPC_DELAY_WARN  500 /* ms */

struct rpc_ctx {
    struct nickel *ni;
    void (*cb) (void *, dict);
    void *opaque;
    ioh_event event;
    int complete;

    dict response;
};

static void rpc_response_cb(void *opaque)
{
    struct rpc_ctx *ctx = opaque;

    if (!ctx)
        goto out;

    if (ctx->cb)
        ctx->cb(ctx->opaque, ctx->response);
out:
    if (ctx && ctx->response)
        dict_free(ctx->response);
    free(ctx);
}

static void rpc_cb(void *opaque, dict d)
{
    struct rpc_ctx *rcx = opaque;

    if (!rcx)
        goto cleanup;

    rcx->response = d;
    if (ni_schedule_bh(rcx->ni, NULL, rpc_response_cb, rcx))
        goto cleanup;
    return;

cleanup:
    if (d)
        dict_free(d);
    free(rcx);
}

static void
rpc_sync_cb(void *opaque, dict d)
{
    struct rpc_ctx *ctx = opaque;

    ctx->response = d;
    ctx->complete = 1;
    ioh_event_set(&ctx->event);
}

int ni_rpc_send(struct nickel *ni, const char *command, dict args, void (*cb) (void *, dict),
        void *opaque)
{
    int ret = -1;
    struct rpc_ctx *rcx;

    rcx = calloc(1, sizeof(*rcx));
    if (!rcx)
        goto out;
    rcx->ni = ni;
    rcx->cb = cb;
    rcx->opaque = opaque;
    if (control_send_command(command, args, rpc_cb, rcx))
        goto out;

    ret = 0;
out:
    return ret;
}

int ni_rpc_send_sync(struct nickel *ni, const char *command, const dict args, dict *response)
{
    int ret;
    const char *status;
    int64_t rpc_ts;
    struct rpc_ctx *ctx;

    NETLOG2("sending rpc command %s", command);

    ret = -1;

    rpc_ts = get_clock_ms(rt_clock);
    ctx = calloc(1, sizeof(*ctx));
    if (!ctx) {
        warnx("%s: memory error", __FUNCTION__);
        goto out;
    }
    ctx->ni = ni;
    ioh_event_init(&ctx->event);
    if (!ioh_event_valid(&ctx->event)) {
        warnx("%s: ioh_event_init failed", __FUNCTION__);
        goto out;
    }
    if ((ret = control_send_command(command, args, rpc_sync_cb, ctx))) {
        warnx("control_send_command failed, %d", ret);
        goto out;
    }

    ioh_event_wait(&ctx->event);
    if (!ctx->complete) {
        warnx("%s: callback not completed!", __FUNCTION__);
        goto out;
    }
    *response = ctx->response;
    ioh_event_close(&ctx->event);
    free(ctx);

    rpc_ts = get_clock_ms(rt_clock) - rpc_ts;
    NETLOG3("debug: rpc command %s, response in %" PRIu64 " ms", command, rpc_ts);
    if (rpc_ts > RPC_DELAY_WARN)
        NETLOG("%s: warning! blocking rpc command %s took %lu ms to execute", __FUNCTION__,
                command, (unsigned long) rpc_ts);

    if (!response)
        goto out;

    status = dict_get_string(*response, "status");
    if (status && !strcmp(status, "error")) {
        NETLOG("rpc command %s failed", command);
        dict_free(*response);
        *response = NULL;
        goto out;
    }

    ret = 0;

out:
    return ret;
}
int rpc_http_event(struct nickel *ni, void *opaque, const char *id, const char *opt,
        dict d, void *command_opaque)
{
    int ret = 0;
    struct ni_rpc_response *r = NULL;

    NETLOG3("received rpc_http_event");

    if (!ni->http_evt_cb)
        goto out;
    r = calloc(1, sizeof(*r));
    if (!r)
        goto mem_err;
    r->ni = ni;
    r->d = dict_new();
    if (!r->d)
        goto mem_err;
    if (dict_merge(d, r->d)) {
        warnx("%s: dict_merge failed", __FUNCTION__);
        ret = -1;
        goto out;
    }
    if (ni_schedule_bh(ni, NULL, ni->http_evt_cb, r)) {
        NETLOG("%s: ni_schedule_bh failed", __FUNCTION__);
        ret = -1;
    }
out:
    return ret;
mem_err:
    warnx("%s: memory error", __FUNCTION__);
    ret = -1;
    goto out;
}

int rpc_ac_event(struct nickel *ni, void *opaque, const char *id, const char *opt,
        dict d, void *command_opaque)
{
    int ret = 0;
    struct ni_rpc_response *r = NULL;

    NETLOG3("received rpc_ac_event");

    if (!ni->ac_evt_cb)
        goto out;
    r = calloc(1, sizeof(*r));
    if (!r)
        goto mem_err;
    r->ni = ni;
    r->d = dict_new();
    if (!r->d)
        goto mem_err;
    if (dict_merge(d, r->d)) {
        warnx("%s: dict_merge failed", __FUNCTION__);
        ret = -1;
        goto out;
    }
    if (ni_schedule_bh(ni, NULL, ni->ac_evt_cb, r)) {
        NETLOG("%s: ni_schedule_bh failed", __FUNCTION__);
        ret = -1;
    }
out:
    return ret;
mem_err:
    warnx("%s: memory error", __FUNCTION__);
    ret = -1;
    goto out;
}
