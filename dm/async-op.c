/*
 * Copyright 2013-2016, Bromium, Inc.
 * Author: Paulian Marinca <paulian@marinca.net>
 * SPDX-License-Identifier: ISC
 */

#include "config.h"
#include "queue.h"
#include "async-op.h"

struct async_op_ctx {
    LIST_HEAD(, async_op_t) list;
    critical_section mx;
    ioh_event thread_exit_ev;
    int threads;
    int max_threads;
};

static struct async_op_ctx *default_ctx = NULL;

struct async_op_ctx *
async_op_init(void)
{
    struct async_op_ctx *ctx;

    ctx = calloc(1, sizeof(struct async_op_ctx));
    if (!ctx)
        err(1, "%s: calloc failed", __FUNCTION__);

    LIST_INIT(&ctx->list);
    critical_section_init(&ctx->mx);
    ioh_event_init(&ctx->thread_exit_ev);
    ctx->threads = 0;
    ctx->max_threads = 0;

    return ctx;
}

void
async_op_free(struct async_op_ctx *ctx)
{

    if (!ctx && !(ctx = default_ctx))
        return;

    critical_section_enter(&ctx->mx);
    if (ctx->threads) {
        /* leak if there are pending threads */
        debug_printf("%s: leaked ctx: %d threads\n", __FUNCTION__, ctx->threads);
        critical_section_leave(&ctx->mx);
        return;
    }
    critical_section_leave(&ctx->mx);

    critical_section_free(&ctx->mx);
    free(ctx);
}

void
async_op_exit_wait(struct async_op_ctx *ctx)
{
    if (!ctx && !(ctx = default_ctx))
        return;

    for (;;) {
        critical_section_enter(&ctx->mx);
        ioh_event_reset(&ctx->thread_exit_ev);
        if (ctx->threads == 0) {
            critical_section_leave(&ctx->mx);
            break;
        }
        critical_section_leave(&ctx->mx);
        ioh_event_wait(&ctx->thread_exit_ev);
    }
    async_op_free(ctx);
}

#if defined(_WIN32)
static DWORD WINAPI
async_op_run(void *opaque)
#elif defined(__APPLE__)
static void *
async_op_run(void *opaque)
#else
#error "async_op_run: unknown arch"
#endif
{
    struct async_op_ctx *ctx = (struct async_op_ctx *)opaque;

    for (;;) {
        struct async_op_t *elm, *op;

        critical_section_enter(&ctx->mx);
        op = NULL;
        LIST_FOREACH(elm, &ctx->list, entry) {
            if (elm->state == ASOP_SCHED_ASYNC) {
                elm->state = ASOP_PROCESS_ASYNC;
                op = elm;
                break;
            }
        }
        if (!op)
            break;
        critical_section_leave(&ctx->mx);

        if (op->cb_process_async)
            op->cb_process_async(op->opaque);

        critical_section_enter(&ctx->mx);
        op->state = ASOP_PROCESS;
        ioh_event_set(op->event);
        critical_section_leave(&ctx->mx);
    }

    ctx->threads--;
    ioh_event_set(&ctx->thread_exit_ev);
    critical_section_leave(&ctx->mx);

    return 0;
}

int
async_op_add(struct async_op_ctx *ctx, void *opaque, ioh_event *event,
             void (*cb_process_async)(void *), void (*cb_process)(void *))
{
    int ret = -1;
    struct async_op_t *op;
    uxen_thread thread_handle;

    if (!ctx && !(ctx = default_ctx))
        goto out;

    op = calloc(1, sizeof(*op));
    if (!op)
        goto out;

    ret = 0;
    op->state = cb_process_async ? ASOP_SCHED_ASYNC : ASOP_PROCESS;
    op->opaque = opaque;
    op->event = event;
    op->cb_process_async = cb_process_async;
    op->cb_process = cb_process;

    if (!cb_process_async) {
        critical_section_enter(&ctx->mx);
        op->state = ASOP_PROCESS;
        LIST_INSERT_HEAD(&ctx->list, op, entry);
        ioh_event_set(op->event);
        critical_section_leave(&ctx->mx);
        goto out;
    }

    critical_section_enter(&ctx->mx);
    LIST_INSERT_HEAD(&ctx->list, op, entry);
    if (ctx->max_threads && ctx->threads >= ctx->max_threads) {
        critical_section_leave(&ctx->mx);
        goto out;
    }
    ctx->threads++;
    if (create_thread(&thread_handle, async_op_run, ctx) < 0) {
        Wwarn("%s: create_thread failed", __FUNCTION__);
        LIST_REMOVE(op, entry);
        free(op);
        ctx->threads--;
        ioh_event_set(&ctx->thread_exit_ev);
        critical_section_leave(&ctx->mx);
        ret = -1;
        goto out;
    }
    critical_section_leave(&ctx->mx);

    elevate_thread(thread_handle);
    close_thread_handle(thread_handle);

out:
    return ret;
}

int
async_op_add_bh(struct async_op_ctx *ctx, void *opaque, void (*cb)(void *))
{
    struct async_op_t *op;

    if (!ctx && !(ctx = default_ctx))
        return -1;

    op = calloc(1, sizeof(*op));
    if (!op)
        return -1;

    op->state = ASOP_PERMANENT;
    op->opaque = opaque;
    op->cb_process = cb;

    critical_section_enter(&ctx->mx);
    LIST_INSERT_HEAD(&ctx->list, op, entry);
    critical_section_leave(&ctx->mx);

    return 0;
}

void
async_op_process(struct async_op_ctx *ctx)
{
    struct async_op_t *elm, *op;
    bool permanent = false;

    if (!ctx && !(ctx = default_ctx))
        return;

    for (;;) {
        critical_section_enter(&ctx->mx);
        op = NULL;
        LIST_FOREACH(elm, &ctx->list, entry) {
            if (elm->state == ASOP_PROCESS) {
                elm->state = ASOP_DONE;
                op = elm;
                break;
            }

            if (elm->state == ASOP_PERMANENT) {
                elm->state = ASOP_PERMANENT_DONE;
                op = elm;
                permanent = true;
                break;
            }
        }
        critical_section_leave(&ctx->mx);

        if (!op)
            break;

        if (op->cb_process)
            op->cb_process(op->opaque);

        if (op->state == ASOP_PERMANENT_DONE)
            continue;

        critical_section_enter(&ctx->mx);
        LIST_REMOVE(op, entry);
        critical_section_leave(&ctx->mx);
        free(op);
    }

    if (permanent) {
        critical_section_enter(&ctx->mx);
        LIST_FOREACH(elm, &ctx->list, entry) {
            if (elm->state == ASOP_PERMANENT_DONE)
                elm->state = ASOP_PERMANENT;
        }
        critical_section_leave(&ctx->mx);
    }
}

void async_op_set_max_threads(struct async_op_ctx *ctx, int max_threads)
{
    if (ctx && max_threads >= 0)
        ctx->max_threads = max_threads;
}

static void __attribute__((constructor)) async_op_init_default(void)
{
    default_ctx = async_op_init();
}
