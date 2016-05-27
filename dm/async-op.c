/*
 * Copyright 2013-2016, Bromium, Inc.
 * Author: Paulian Marinca <paulian@marinca.net>
 * SPDX-License-Identifier: ISC
 */

#include "config.h"
#include "queue.h"
#include "async-op.h"

struct async_op_thread {
    LIST_ENTRY(async_op_thread) entry;
    struct async_op_ctx *ctx;
    uxen_thread handle;
    int complete;
};

struct async_op_ctx {
    LIST_HEAD(, async_op_t) list;
    LIST_HEAD(, async_op_thread) threads;
    critical_section mx;
    ioh_event *threads_event;
    int exiting;
    int number_threads;

    int max_threads;
    int threads_cancel;
    int threads_detach;
};

static struct async_op_ctx *default_ctx = NULL;

static void wait_completed_threads(struct async_op_ctx *ctx)
{
    struct async_op_thread *thread_ctx, *thread_next;

    LIST_FOREACH_SAFE(thread_ctx, &ctx->threads, entry, thread_next) {
        if (!thread_ctx->complete)
            continue;
        LIST_REMOVE(thread_ctx, entry);
        if (ctx->exiting && ctx->threads_detach) {
            detach_thread(thread_ctx->handle);
            close_thread_handle(thread_ctx->handle);
            thread_ctx->handle = NULL;
            continue; /* leak thread_ctx if exiting in detach mode */
        }

        wait_thread(thread_ctx->handle);
        close_thread_handle(thread_ctx->handle);
        thread_ctx->handle = NULL;
        free(thread_ctx);
    }
}

struct async_op_ctx *
async_op_init(void)
{
    struct async_op_ctx *ctx;

    ctx = calloc(1, sizeof(struct async_op_ctx));
    if (!ctx)
        err(1, "%s: calloc failed", __FUNCTION__);

    LIST_INIT(&ctx->list);
    LIST_INIT(&ctx->threads);
    critical_section_init(&ctx->mx);
    ctx->number_threads = 0;
    ctx->max_threads = 0;

    return ctx;
}

void
async_op_free(struct async_op_ctx *ctx)
{

    if (!ctx && !(ctx = default_ctx))
        return;

    critical_section_enter(&ctx->mx);
    if (!LIST_EMPTY(&ctx->threads) || ctx->number_threads) {
        /* leak if there are pending threads */
        debug_printf("%s: leaked ctx: %d threads\n", __FUNCTION__, ctx->number_threads);
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
    struct async_op_thread *thread_ctx;

    if (!ctx && !(ctx = default_ctx))
        return;

    ctx->exiting = 1;
    LIST_FOREACH(thread_ctx, &ctx->threads, entry) {
        if (ctx->threads_cancel)
            cancel_thread(thread_ctx->handle);
        thread_ctx->complete = 1;
    }
    wait_completed_threads(ctx);
    async_op_process(ctx);
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
    struct async_op_thread *thread_ctx = (struct async_op_thread *)opaque;
    struct async_op_ctx *ctx = thread_ctx->ctx;

    if (ctx->threads_cancel)
        setcancel_thread();

    for (;;) {
        struct async_op_t *elm, *op;

        critical_section_enter(&ctx->mx);
        op = NULL;

        if (ctx->exiting)
            break;

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

    ctx->number_threads--;
    thread_ctx->complete = 1;
    if (ctx->threads_event)
        ioh_event_set(ctx->threads_event);
    critical_section_leave(&ctx->mx);

    return 0;
}

int
async_op_add(struct async_op_ctx *ctx, void *opaque, ioh_event *event,
             void (*cb_process_async)(void *), void (*cb_process)(void *))
{
    int ret = -1;
    struct async_op_t *op;
    struct async_op_thread *thread_ctx = NULL;
    uxen_thread thread_handle;

    if (!ctx && !(ctx = default_ctx))
        goto out;
    if (ctx->exiting)
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
    if (ctx->max_threads && ctx->number_threads >= ctx->max_threads) {
        critical_section_leave(&ctx->mx);
        goto out;
    }
    ctx->number_threads++;
    thread_ctx = calloc(1, sizeof(*thread_ctx));
    if (!thread_ctx) {
        warnx("%s: malloc error", __FUNCTION__);
        goto cleanup_unlock;
    }
    thread_ctx->ctx = ctx;
    if (create_thread(&thread_handle, async_op_run, thread_ctx) < 0) {
        Wwarn("%s: create_thread failed", __FUNCTION__);
        goto cleanup_unlock;
    }
    critical_section_leave(&ctx->mx);
    thread_ctx->handle = thread_handle;
    LIST_INSERT_HEAD(&ctx->threads, thread_ctx, entry);
    elevate_thread(thread_handle);

out:
    return ret;
cleanup_unlock:
    free(thread_ctx);
    LIST_REMOVE(op, entry);
    free(op);
    ctx->number_threads--;
    critical_section_leave(&ctx->mx);
    ret = -1;
    goto out;
}

int
async_op_add_bh(struct async_op_ctx *ctx, void *opaque, void (*cb)(void *))
{
    struct async_op_t *op;

    if (!ctx && !(ctx = default_ctx))
        return -1;
    if (ctx->exiting)
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

        if (!ctx->exiting && op->state == ASOP_PERMANENT_DONE)
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

    wait_completed_threads(ctx);
}

void async_op_set_prop(struct async_op_ctx *ctx, ioh_event *threads_event,
                       int max_threads, int threads_cancel, int threads_detach)
{
    if (!ctx)
        return;
    if (max_threads >= 0)
        ctx->max_threads = max_threads;
    ctx->threads_event = threads_event;
    ctx->threads_cancel = threads_cancel;
    ctx->threads_detach = threads_detach;
}

void early_init_async_op(void)
{
    default_ctx = async_op_init();
}
