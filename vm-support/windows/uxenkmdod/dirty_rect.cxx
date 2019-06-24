/*
 * Copyright 2015-2019, Bromium, Inc.
 * Author: Piotr Foltyn <piotr.foltyn@gmail.com>
 * SPDX-License-Identifier: ISC
 */

#include "BDD.hxx"
extern "C"
{
    #include <uxenvmlib.h>
    #include <uxenv4vlib.h>
    #include <uxendisp-common.h>
}

#define DR_BORDER 5
#define DR_CTX_TAG 'TCRD'
#define DR_TIMEOUT_MS 10
#define DR_ONE_MS_IN_HNS 10000
#define DR_USHRT_MAX 0xffff

#define FLUSH_TIMEOUT_MS 250

struct dr_context
{
    void *dev;
    disable_tracking_ptr disable_tracking;
    v4v_addr_t peer;
    v4v_addr_t alt_peer;
    uxen_v4v_ring_handle_t *ring;
    uxen_v4v_ring_handle_t *alt_ring;
    KEVENT rect_done_update_ev;

    BOOLEAN enabled;
    BOOLEAN alt_ring_active;
    KMUTEX flush_mutex;
    KSPIN_LOCK rect_lock;
    uint64_t rect_sent;
    uint64_t rect_done;
};

static void dr_v4v_dpc(uxen_v4v_ring_handle_t *ring, void *ctx1, void *ctx2)
{
    struct dr_context *ctx = (struct dr_context *)ctx1;
    ssize_t len;
    struct update_msg msg;

    UNREFERENCED_PARAMETER(ctx2);
    ASSERT(KeGetCurrentIrql() == DISPATCH_LEVEL);

    for (;;) {
        len = uxen_v4v_copy_out(ring, NULL, NULL, NULL, 0, 0);
        if (len <= 0)
            break;
        uxen_v4v_copy_out(ring, NULL, NULL, &msg, sizeof(msg), 1);
        if (len < sizeof(msg))
            continue;
        if (ctx->disable_tracking) {
            ctx->disable_tracking(ctx->dev);
            ctx->disable_tracking = NULL;
            ctx->enabled = TRUE;
        }
        if ((ctx->alt_ring_active == FALSE) && (ctx->alt_ring == ring))
            ctx->alt_ring_active = TRUE;

        KeAcquireSpinLockAtDpcLevel(&ctx->rect_lock);

        if (msg.rect_done != DISP_INVALID_RECT_ID)
            ctx->rect_done = msg.rect_done;

        KeReleaseSpinLockFromDpcLevel(&ctx->rect_lock);
        KeSetEvent(&ctx->rect_done_update_ev, 0, FALSE);
    }

    uxen_v4v_notify();
}

dr_ctx_t dr_init(void *dev, disable_tracking_ptr fn)
{
    struct dr_context *ctx = NULL;

    ctx = (struct dr_context *)ExAllocatePoolWithTag(NonPagedPool,
                                                     sizeof(*ctx),
                                                     DR_CTX_TAG);
    if (ctx == NULL)
    {
        return NULL;
    }

    RtlZeroMemory(ctx, sizeof(*ctx));

    ctx->dev = dev;
    ctx->disable_tracking = fn;
    ctx->rect_sent = 0;
    ctx->rect_done = 0;

    KeInitializeEvent(&ctx->rect_done_update_ev, NotificationEvent, FALSE);
    KeInitializeSpinLock(&ctx->rect_lock);
    KeInitializeMutex(&ctx->flush_mutex, 0);

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

void
dr_send(dr_ctx_t context, ULONG m_num, D3DKMT_MOVE_RECT *move_rect,
        ULONG d_num, RECT *dirty_rect)
{
    struct dr_context *ctx = (struct dr_context *)context;
    ULONG idx;
    struct dirty_rect_msg rect;

    if (!ctx->enabled)
        return;

    rect.left = DR_USHRT_MAX;
    rect.top = DR_USHRT_MAX;
    rect.right = 0;
    rect.bottom = 0;

    for (idx = 0; idx < m_num; ++idx)
    {
        rect.left = min(rect.left, move_rect[idx].DestRect.left);
        rect.top = min(rect.top, move_rect[idx].DestRect.top);
        rect.right = max(rect.right, move_rect[idx].DestRect.right);
        rect.bottom = max(rect.bottom, move_rect[idx].DestRect.bottom);
    }
    for (idx = 0; idx < d_num; ++idx)
    {
        rect.left = min(rect.left, dirty_rect[idx].left);
        rect.top = min(rect.top, dirty_rect[idx].top);
        rect.right = max(rect.right, dirty_rect[idx].right);
        rect.bottom = max(rect.bottom, dirty_rect[idx].bottom);
    }

    rect.left = max(rect.left - DR_BORDER, 0);
    rect.top = max(rect.top - DR_BORDER, 0);
    rect.right = min(rect.right + DR_BORDER, DR_USHRT_MAX);
    rect.bottom = min(rect.bottom + DR_BORDER, DR_USHRT_MAX);

    if ((rect.right > 0) && (rect.bottom > 0)) {
        KIRQL irq;

        KeAcquireSpinLock(&ctx->rect_lock, &irq);

        ctx->rect_sent++;
        rect.rect_id = ctx->rect_sent;

        KeReleaseSpinLock(&ctx->rect_lock, irq);

        uxen_v4v_send_from_ring(ctx->ring, &ctx->peer, &rect, sizeof(rect),
                                V4V_PROTO_DGRAM);
        if (ctx->alt_ring_active == TRUE) {
           uxen_v4v_send_from_ring(ctx->alt_ring, &ctx->alt_peer, &rect,
                                   sizeof(rect), V4V_PROTO_DGRAM);
        }

    }
}

void
dr_flush(dr_ctx_t context)
{
    struct dr_context *ctx = (struct dr_context *)context;
    LARGE_INTEGER timeout, t0, t1, freq;
    NTSTATUS status;

    if (ctx->rect_done >= ctx->rect_sent)
        return; /* nothing to flush */

    t0 = KeQueryPerformanceCounter(&freq);

    /* use mutex so there's max 1 concurrent flush */
    status = KeWaitForMutexObject(&ctx->flush_mutex, Executive, KernelMode, TRUE, NULL);
    if (status != STATUS_SUCCESS)
        return;

    while (ctx->rect_done < ctx->rect_sent) {
        int64_t delta_ms;

        t1 = KeQueryPerformanceCounter(&freq);
        delta_ms = (t1.QuadPart - t0.QuadPart) * 1000 / freq.QuadPart;

        if (delta_ms >= FLUSH_TIMEOUT_MS) {
            KIRQL irq;

            //uxen_msg("flush timeout, rect sent %d done %d, resetting\n", ctx->rect_sent, ctx->rect_done);
            KeAcquireSpinLock(&ctx->rect_lock, &irq);
            ctx->rect_sent = 0;
            ctx->rect_done = 0;
            KeReleaseSpinLock(&ctx->rect_lock, irq);
            break;
        }
        timeout.QuadPart = -50 * DR_ONE_MS_IN_HNS;
        KeWaitForSingleObject(&ctx->rect_done_update_ev, Executive,
                              KernelMode, TRUE, &timeout);
        KeResetEvent(&ctx->rect_done_update_ev);
    }
    KeReleaseMutex(&ctx->flush_mutex, FALSE);
}

void
dr_resume(dr_ctx_t context)
{
    struct dr_context *ctx = (struct dr_context *)context;
    KIRQL irq;

    /* end flushes and reset rect ID */
    KeAcquireSpinLock(&ctx->rect_lock, &irq);
    ctx->rect_sent = 0;
    ctx->rect_done = 0;
    KeReleaseSpinLock(&ctx->rect_lock, irq);
    KeSetEvent(&ctx->rect_done_update_ev, 0, FALSE);
}

void dr_deinit(dr_ctx_t context)
{
    struct dr_context *ctx = (struct dr_context *)context;

    if (ctx)
    {
        uxen_v4v_ring_free(ctx->alt_ring);
        uxen_v4v_ring_free(ctx->ring);
        ExFreePoolWithTag(ctx, DR_CTX_TAG);
    }
}
