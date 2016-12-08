/*
 * Copyright 2015-2017, Bromium, Inc.
 * Author: Piotr Foltyn <piotr.foltyn@gmail.com>
 * SPDX-License-Identifier: ISC
 */

#define _WIN32_WINNT 0x0601

#include <windows.h>
#include <stdint.h>
#include <assert.h>
#define V4V_USE_INLINE_API
#include <windows/uxenv4vlib/gh_v4vapi.h>

#include "uxenconsolelib.h"
#include "uxendisp-common.h"

#define ONE_MS_IN_HNS 10000
#define DUE_TIME_MS 100

struct disp_context {
    OVERLAPPED oread;
    OVERLAPPED owrite;
    void *priv;
    inv_rect_t inv_rect;
    v4v_channel_t v4v;
    uint8_t read_buf[UXENDISP_MAX_MSG_LEN];
    struct {
        v4v_datagram_t dgram;
        struct update_msg msg;
    } update_msg;
    HANDLE timer;
    LARGE_INTEGER due_time;
    DWORD thread_id;
    BOOL exit;
    uint64_t rect_done;
    uint32_t flags;
};

static void CALLBACK write_done(DWORD ec, DWORD count, LPOVERLAPPED ovlpd);

static BOOL
update_msg(struct disp_context *c)
{
    memset(&c->update_msg.msg, 0, sizeof(c->update_msg.msg));
    c->update_msg.msg.rect_done = c->rect_done;

    return WriteFileEx(c->v4v.v4v_handle,
                       (void *)&c->update_msg,
                       sizeof(c->update_msg),
                       &c->owrite,
                       write_done);
}

static void CALLBACK
timer_done(LPVOID context, DWORD unused1, DWORD unused2)
{
    struct disp_context *c = (struct disp_context *)context;

    if (c->exit)
        return;

    update_msg(c);
}

static int
parse_message(struct disp_context *c, void *buf, int size)
{
    if (size >= sizeof(struct dirty_rect_msg)) {
        struct dirty_rect_msg *rect = (struct dirty_rect_msg*)buf;

        /* auto confirm newest rect */
        if (!(c->flags & DISP_FLAG_MANUAL_ACK_RECT))
            c->rect_done = rect->rect_id;

        if (rect->rect_id < c->rect_done)
            c->rect_done = 0; /* reset */

        if (c->inv_rect)
            c->inv_rect(c->priv,
                        rect->left,
                        rect->top,
                        rect->right - rect->left,
                        rect->bottom - rect->top,
                        rect->rect_id);

        return sizeof(struct dirty_rect_msg);
    } else
        return size; /* eat unrecognized content */
}

static void
parse_messages(struct disp_context *c, void *buf, int size)
{
    void *p = buf;

    while (size >= sizeof(v4v_datagram_t)) {
        int bytes = parse_message(c, p + sizeof(v4v_datagram_t),
                                  size - sizeof(v4v_datagram_t));
        bytes += sizeof(v4v_datagram_t);
        p += bytes;
        size -= bytes;
    }
}

static void CALLBACK
read_done(DWORD ec, DWORD count, LPOVERLAPPED ovlpd)
{
    struct disp_context *c =
        CONTAINING_RECORD(ovlpd, struct disp_context, oread);

    if (c->exit)
        return;

    if (ec == 0)
        parse_messages(c, c->read_buf, count);

    /* if manually tracking rects, don't send auto confirm messages.
     * send them later from uxendisp_ack_rect */
    if (!(c->flags & DISP_FLAG_MANUAL_ACK_RECT));
        update_msg(c);
}

static void CALLBACK
write_done(DWORD ec, DWORD count, LPOVERLAPPED ovlpd)
{
    struct disp_context *c =
        CONTAINING_RECORD(ovlpd, struct disp_context, owrite);
    BOOL res;

    if (c->exit)
        return;

    if (ec != 0) {
        res = SetWaitableTimer(c->timer, &c->due_time, 0, timer_done, c, FALSE);
        if (!res) {
            // Last resort
            Sleep(DUE_TIME_MS);
            update_msg(c);
        }
    } else {
        ReadFileEx(c->v4v.v4v_handle,
                   c->read_buf,
                   UXENDISP_MAX_MSG_LEN,
                   &c->oread,
                   read_done);
    }
}

disp_context_t
uxenconsole_disp_init(int vm_id, const unsigned char *idtoken,
                      void *priv, inv_rect_t inv_rect,
                      uint32_t flags)
{
    struct disp_context *c;
    v4v_bind_values_t bind = { };
    DWORD err;
    BOOL rc;

    c = calloc(1, sizeof (*c));
    if (!c)
        return NULL;

    c->thread_id = GetCurrentThreadId();

    if (!v4v_open(&c->v4v, UXENDISP_RING_SIZE, V4V_FLAG_ASYNC)) {
        err = GetLastError();
        goto error;
    }

    bind.ring_id.addr.port = UXENDISP_PORT;
    bind.ring_id.addr.domain = V4V_DOMID_ANY;
    if (vm_id == -1) {
        bind.ring_id.partner = V4V_DOMID_UUID;
        memcpy(&bind.partner, idtoken, sizeof(bind.partner));
    } else
        bind.ring_id.partner = vm_id;

    if (!v4v_bind(&c->v4v, &bind)) {
        // Allow one additional console to be connected.
        bind.ring_id.addr.port = UXENDISP_ALT_PORT;
        if (!v4v_bind(&c->v4v, &bind)) {
            err = GetLastError();
            goto error;
        }
    }

    c->update_msg.dgram.addr.port = bind.ring_id.addr.port;
    c->update_msg.dgram.addr.domain = bind.ring_id.partner;
    rc = update_msg(c);
    if (rc == FALSE) {
        err = GetLastError();
        goto error;
    }

    c->due_time.QuadPart = -DUE_TIME_MS * ONE_MS_IN_HNS;
    c->timer = CreateWaitableTimer(NULL, TRUE, NULL);
    if (c->timer == NULL) {
        err = GetLastError();
        goto error;
    }

    c->priv = priv;
    c->inv_rect = inv_rect;
    c->flags = flags;
    c->rect_done = 0;

    return c;

error:
    uxenconsole_disp_cleanup(c);
    SetLastError(err);
    return NULL;
}

void
uxenconsole_disp_ack_rect(disp_context_t ctx, uint64_t rect_id)
{
    struct disp_context *c = ctx;

    if (rect_id > c->rect_done) {
        c->rect_done = rect_id;
        update_msg(c);
    }
}

void
uxenconsole_disp_cleanup(disp_context_t ctx)
{
    struct disp_context *c = ctx;
    DWORD bytes;

    if (c) {
        // Cleanup must be called on the same thread as init was.
        assert(c->thread_id == GetCurrentThreadId());

        c->exit = TRUE;

        if (CancelIoEx(c->v4v.v4v_handle, &c->owrite) ||
            (GetLastError() != ERROR_NOT_FOUND))
            GetOverlappedResult(c->v4v.v4v_handle,
                                &c->owrite,
                                &bytes,
                                TRUE);
        if (CancelIoEx(c->v4v.v4v_handle, &c->oread) ||
            (GetLastError() != ERROR_NOT_FOUND))
            GetOverlappedResult(c->v4v.v4v_handle,
                                &c->oread,
                                &bytes,
                                TRUE);

        // We need to put thread in alertable state to allow completion
        // routine to run.
        SleepEx(DUE_TIME_MS, TRUE);
        CloseHandle(c->timer);
        v4v_close(&c->v4v);
        free(c);
    }
}
