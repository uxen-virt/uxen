/*
 * Copyright 2015-2017, Bromium, Inc.
 * Author: Piotr Foltyn <piotr.foltyn@gmail.com>
 * SPDX-License-Identifier: ISC
 */

#include <Wdm.h>
#include <uxenvmlib.h>
#include <uxenv4vlib.h>
#include <uxendisp_ioctl.h>
#include <uxendisp-common.h>
#include "../common/debug.h"
#include "dirty_rect.h"

#define DR_CTX_TAG 'TCRD'
#define DR_BRODER_SIZE 50
#define DR_PERIOD_MS 5
#define DR_TIMEOUT_MS 10
#define DR_ONE_MS_IN_HNS 10000
#define DR_USHRT_MAX 0xffff

struct dr_context
{
    void *dev;
    disable_tracking_ptr disable_tracking;
    get_last_mode_ptr get_last_mode;
    v4v_addr_t peer;
    v4v_addr_t alt_peer;
    uxen_v4v_ring_handle_t *ring;
    uxen_v4v_ring_handle_t *alt_ring;
    KTIMER timer;
    KDPC dpc;
    LARGE_INTEGER due_time;
    KEVENT safe_to_draw;
    KEVENT safe_to_send;
    struct rect dirty;
    struct rect dirty_copy;
    BOOLEAN force_update;
    BOOLEAN alt_ring_active;
    KSPIN_LOCK lock;
};

static void dr_timer_dpc(
    struct _KDPC *dpc, void *deferred_context, void *unused1, void *unused2)
{
    struct dr_context *ctx = deferred_context;

    LONG signaled = 0;
    ULONG last_mode_width = 0;
    ULONG last_mode_height = 0;

    ASSERT(KeGetCurrentIrql() == DISPATCH_LEVEL);

    KeAcquireSpinLockAtDpcLevel(&ctx->lock);
    signaled = KeReadStateEvent(&ctx->safe_to_send);
    if ((ctx->dirty.right > 0) && (ctx->dirty.bottom > 0) && 
        (signaled || ctx->force_update))
    {
        struct dirty_rect_msg msg = { 0 };

        KeClearEvent(&ctx->safe_to_draw);
        ctx->force_update = FALSE;

        if (ctx->dirty.left > DR_BRODER_SIZE)
            ctx->dirty.left -= DR_BRODER_SIZE;
        if (ctx->dirty.top > DR_BRODER_SIZE)
            ctx->dirty.top -= DR_BRODER_SIZE;
        ctx->dirty.right += DR_BRODER_SIZE;
        ctx->dirty.bottom += DR_BRODER_SIZE;

        ctx->dirty_copy = ctx->dirty;

        ctx->get_last_mode(&last_mode_width, &last_mode_height);
        if (ctx->dirty_copy.top > last_mode_height) {
            ctx->dirty_copy.top = 0;
        }
        if (ctx->dirty_copy.left > last_mode_width) {
            ctx->dirty_copy.left = 0;
        }
        if (ctx->dirty_copy.bottom > last_mode_height) {
            ctx->dirty_copy.bottom = last_mode_height;
        }
        if (ctx->dirty_copy.right > last_mode_width) {
            ctx->dirty_copy.right = last_mode_width;
        }

        msg.left = ctx->dirty_copy.left;
        msg.top = ctx->dirty_copy.top;
        msg.right = ctx->dirty_copy.right;
        msg.bottom = ctx->dirty_copy.bottom;

        uxen_v4v_send_from_ring(ctx->ring, &ctx->peer, &msg,
                                sizeof(msg), V4V_PROTO_DGRAM);
        if (ctx->alt_ring_active)
        {
            uxen_v4v_send_from_ring(ctx->alt_ring, &ctx->alt_peer, &msg,
                                    sizeof(msg), V4V_PROTO_DGRAM);
        }

        ctx->dirty.left = DR_USHRT_MAX;
        ctx->dirty.top = DR_USHRT_MAX;
        ctx->dirty.right = 0;
        ctx->dirty.bottom = 0;
    }

    if (!signaled)
    {
        ctx->force_update = TRUE;
        KeSetTimerEx(&ctx->timer, ctx->due_time, DR_PERIOD_MS, &ctx->dpc);
    }
    KeReleaseSpinLockFromDpcLevel(&ctx->lock);
}

static void dr_v4v_dpc(uxen_v4v_ring_handle_t *ring, void *ctx1, void *ctx2)
{
    struct dr_context *ctx = ctx1;
    ssize_t len;
    struct update_msg dummy;

    ASSERT(KeGetCurrentIrql() == DISPATCH_LEVEL);

    KeAcquireSpinLockAtDpcLevel(&ctx->lock);
    len = uxen_v4v_copy_out(ring, NULL, NULL, &dummy, sizeof(dummy), 0);
    if (len > 0) {
        uxen_v4v_copy_out(ring, NULL, NULL, NULL, 0, 1);
        if (ctx->disable_tracking)
        {
            ctx->disable_tracking(ctx->dev);
            ctx->disable_tracking = NULL;
            KeSetTimerEx(&ctx->timer, ctx->due_time, DR_PERIOD_MS, &ctx->dpc);
        }
        if ((ctx->alt_ring_active == FALSE) && (ctx->alt_ring == ring))
        {
            ctx->alt_ring_active = TRUE;
        }
        KeSetEvent(&ctx->safe_to_draw, 0, FALSE);
    }
    KeReleaseSpinLockFromDpcLevel(&ctx->lock);

    uxen_v4v_notify();
}

dr_ctx_t dr_init(void *dev, disable_tracking_ptr fn, get_last_mode_ptr fn2)
{
    NTSTATUS status = STATUS_SUCCESS;
    struct dr_context *ctx = NULL;

    ctx = ExAllocatePoolWithTag(NonPagedPool,
                                sizeof(*ctx),
                                DR_CTX_TAG);
    if (ctx == NULL)
    {
        return NULL;
    }

    RtlZeroMemory(ctx, sizeof(*ctx));

    ctx->dev = dev;
    ctx->disable_tracking = fn;
    ctx->get_last_mode = fn2;

    ctx->due_time.QuadPart = -DR_PERIOD_MS * DR_ONE_MS_IN_HNS;
    KeInitializeTimer(&ctx->timer);
    KeInitializeDpc(&ctx->dpc, dr_timer_dpc, ctx);
    KeInitializeSpinLock(&ctx->lock);
    KeInitializeEvent(&ctx->safe_to_draw, NotificationEvent, TRUE);
    KeInitializeEvent(&ctx->safe_to_send, NotificationEvent, TRUE);

    ctx->peer.port = UXENDISP_PORT;
    ctx->peer.domain = V4V_DOMID_DM;
    ctx->ring = uxen_v4v_ring_bind(UXENDISP_PORT, V4V_DOMID_DM,
                                   UXENDISP_RING_SIZE,
                                   dr_v4v_dpc, ctx, NULL);
    if (!ctx->ring)
    {
        ExFreePoolWithTag(ctx, DR_CTX_TAG);
        return NULL;
    }

    ctx->alt_peer.port = UXENDISP_ALT_PORT;
    ctx->alt_peer.domain = V4V_DOMID_DM;
    ctx->alt_ring = uxen_v4v_ring_bind(UXENDISP_ALT_PORT, V4V_DOMID_DM,
                                       UXENDISP_RING_SIZE,
                                       dr_v4v_dpc, ctx, NULL);
    if (!ctx->alt_ring)
    {
        uxen_v4v_ring_free(ctx->ring);
        ExFreePoolWithTag(ctx, DR_CTX_TAG);
        return NULL;
    }

    return ctx;
}

void dr_safe_to_draw(dr_ctx_t context)
{
    struct dr_context *ctx = context;
    KIRQL irql;
    LARGE_INTEGER timeout;

#if defined(_WIN64)
    irql = KeAcquireSpinLockRaiseToDpc(&ctx->lock);
#else
    KeAcquireSpinLock(&ctx->lock, &irql);
#endif
    KeClearEvent(&ctx->safe_to_send);
    KeReleaseSpinLock(&ctx->lock, irql);

    timeout.QuadPart = -DR_TIMEOUT_MS * DR_ONE_MS_IN_HNS;
    KeWaitForSingleObject(&ctx->safe_to_draw, Executive, KernelMode, FALSE,
                          &timeout);
}

void dr_update(dr_ctx_t context, struct rect *rect)
{
    struct dr_context *ctx = context;
    KIRQL irql;

#if defined(_WIN64)
    irql = KeAcquireSpinLockRaiseToDpc(&ctx->lock);
#else
    KeAcquireSpinLock(&ctx->lock, &irql);
#endif

    ctx->dirty.left = min(ctx->dirty.left, rect->left);
    ctx->dirty.top = min(ctx->dirty.top, rect->top);
    ctx->dirty.right = max(ctx->dirty.right, rect->right);
    ctx->dirty.bottom = max(ctx->dirty.bottom, rect->bottom);
    KeSetEvent(&ctx->safe_to_send, 0, FALSE);
    KeReleaseSpinLock(&ctx->lock, irql);
}

void dr_deinit(dr_ctx_t context)
{
    struct dr_context *ctx = context;

    if (ctx)
    {
        KeCancelTimer(&ctx->timer);
        uxen_v4v_ring_free(ctx->alt_ring);
        uxen_v4v_ring_free(ctx->ring);
        ExFreePoolWithTag(ctx, DR_CTX_TAG);
    }
}
