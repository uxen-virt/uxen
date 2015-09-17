/*
 * Copyright 2013-2015, Bromium, Inc.
 * Author: Paulian Marinca <paulian@marinca.net>
 * SPDX-License-Identifier: ISC
 */

#include "config.h"
#include "queue.h"
#include "async-op.h"
#include "bh.h"

struct async_op_ctx {
    LIST_HEAD(, async_op_t) list;
    critical_section mx;
    ioh_event thread_exit_ev;
    int threads;
};

static struct async_op_ctx *default_ctx = NULL;

static void
list_lock(struct async_op_ctx *ctx)
{
    critical_section_enter(&ctx->mx);
}

static void
list_unlock(struct async_op_ctx *ctx)
{
    critical_section_leave(&ctx->mx);
}

/* async_op_ctx lock needs to be acquired */
static int sched_bh(struct async_op_t *op)
{
    int ret = 0;
    BH *bh;

    if (!op)
       return 0;

    if (op->event) {
        ioh_event_set(op->event);
        return 0;
    }

    if (!op->process)
        goto out_remove;

    bh = bh_new(op->process, op->opaque);
    if (!bh) {
        warnx("%s: bh_new failed", __FUNCTION__);
        ret = -1;
        goto out_remove;
    }

    bh_schedule(bh);
out_remove:
    LIST_REMOVE(op, entry);
    free(op);
    return ret;
}

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

    return ctx;
}

void
async_op_free(struct async_op_ctx *ctx)
{

    if (!ctx) {
        ctx = default_ctx;
        if (!ctx)
            return;
    }

    list_lock(ctx);
    if (ctx->threads) {
        /* leak if there are pending threads */
        debug_printf("%s: leaked ctx: %d threads\n", __FUNCTION__, ctx->threads);
        list_unlock(ctx);
        return;
    }
    list_unlock(ctx);

    critical_section_free(&ctx->mx);
    free(ctx);
}

void
async_op_exit_wait(struct async_op_ctx *ctx)
{
    if (!ctx) {
        ctx = default_ctx;
        if (!ctx)
            return;
    }

    for (;;) {
        list_lock(ctx);
        ioh_event_reset(&ctx->thread_exit_ev);
        if (ctx->threads == 0) {
            list_unlock(ctx);
            break;
        }
        list_unlock(ctx);
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

        list_lock(ctx);
        op = NULL;
        LIST_FOREACH(elm, &ctx->list, entry) {
            if (elm->state == ASOP_INIT) {
                elm->state = ASOP_HANDLER;
                op = elm;
                break;
            }
        }
        list_unlock(ctx);
        if (!op)
            break;
        if (op->handle)
            op->handle(op->opaque);

        list_lock(ctx);
        op->state = ASOP_PROCESS;
        sched_bh(op);
        list_unlock(ctx);
    }

    list_lock(ctx);
    ctx->threads--;
    ioh_event_set(&ctx->thread_exit_ev);
    list_unlock(ctx);

    return 0;
}

int
async_op_add(struct async_op_ctx *ctx, void *opaque, ioh_event *event,
             void (*handle)(void *), void (*process)(void *))
{
    struct async_op_t *op;
    uxen_thread thread_h;

    if (!ctx) {
        ctx = default_ctx;
        if (!ctx)
            return -1;
    }

    op = calloc(1, sizeof(*op));
    if (!op)
        return -1;

    op->state = handle ? ASOP_INIT : ASOP_PROCESS;
    op->opaque = opaque;
    op->event = event;
    op->handle = handle;
    op->process = process;

    if (!handle) {
        int ret;

        list_lock(ctx);
        LIST_INSERT_HEAD(&ctx->list, op, entry);
        ret = sched_bh(op);
        list_unlock(ctx);

        return ret;
    }

    list_lock(ctx);
    LIST_INSERT_HEAD(&ctx->list, op, entry);
    ctx->threads++;
    if (create_thread(&thread_h, async_op_run, ctx) < 0) {
        Wwarn("%s: create_thread failed", __FUNCTION__);
        LIST_REMOVE(op, entry);
        free(op);
        ctx->threads--;
        ioh_event_set(&ctx->thread_exit_ev);
        list_unlock(ctx);
        return -1;
    }
    list_unlock(ctx);

    elevate_thread(thread_h);
    close_thread_handle(thread_h);

    return 0;
}

int
async_op_add_bh(struct async_op_ctx *ctx, void *opaque, void (*cb)(void *))
{
    struct async_op_t *op;

    if (!ctx) {
        ctx = default_ctx;
        if (!ctx)
            return -1;
    }

    op = calloc(1, sizeof(*op));
    if (!op)
        return -1;

    op->state = ASOP_PERMANENT;
    op->opaque = opaque;
    op->process = cb;

    list_lock(ctx);
    LIST_INSERT_HEAD(&ctx->list, op, entry);
    list_unlock(ctx);

    return 0;
}

static int
async_op_delete(struct async_op_ctx *ctx, struct async_op_t *op)
{
    if (!ctx) {
        ctx = default_ctx;
        if (!ctx)
            return -1;
    }

    list_lock(ctx);
    LIST_REMOVE(op, entry);
    list_unlock(ctx);
    free(op);
    return 0;
}

void
async_op_process(struct async_op_ctx *ctx)
{
    struct async_op_t *elm, *op;
    bool permanent = false;

    if (!ctx) {
        ctx = default_ctx;
        if (!ctx)
            return;
    }

    for (;;) {
        list_lock(ctx);
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
        list_unlock(ctx);

        if (!op)
            break;

        if (op->process)
            op->process(op->opaque);
        if (elm->state != ASOP_PERMANENT_DONE)
            async_op_delete(ctx, op);
    }

    if (permanent) {
        list_lock(ctx);
        LIST_FOREACH(elm, &ctx->list, entry) {
            if (elm->state == ASOP_PERMANENT_DONE)
                elm->state = ASOP_PERMANENT;
        }
        list_unlock(ctx);
    }
}

static void __attribute__((constructor)) async_op_init_default(void)
{
    default_ctx = async_op_init();
}
