/*
 * Copyright 2018, Bromium, Inc.
 * Author: Tomasz Wroblewski <tomasz.wroblewski@gmail.com>
 * SPDX-License-Identifier: ISC
 */

/* handle dirty rects received from guest driver over v4v */
#include <dm/config.h>
#include <dm/qemu_glue.h>
#include <dm/dm.h>
#include <dm/hw/uxen_v4v.h>
#include "uxendisp-common.h"
#include "console-dr.h"

#define ONE_MS_IN_HNS 10000
#define DUE_TIME_MS 100

typedef void (*inv_rect_t)(void *priv, int x, int y, int w, int h, uint64_t rect_id);

struct console_dr_context {
    v4v_async_t as_read;
    v4v_async_t as_write;
    ioh_event ev_read;
    ioh_event ev_write;
    void *priv;
    inv_rect_t inv_rect;
    v4v_context_t v4v;
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

static int
update_msg(struct console_dr_context *c)
{
    memset(&c->update_msg.msg, 0, sizeof(c->update_msg.msg));
    c->update_msg.msg.rect_done = c->rect_done;

    ioh_event_reset(&c->ev_write);
    dm_v4v_async_init(&c->v4v, &c->as_write, c->ev_write);
    return dm_v4v_send(&c->v4v, (v4v_datagram_t*)&c->update_msg,
        sizeof(c->update_msg), &c->as_write);
}

static void CALLBACK
timer_done(LPVOID context, DWORD unused1, DWORD unused2)
{
    struct console_dr_context *c = (struct console_dr_context *)context;

    if (c->exit)
        return;

    update_msg(c);
}

static int
parse_message(struct console_dr_context *c, void *buf, int size)
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
parse_messages(struct console_dr_context *c, void *buf, int size)
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

static void
read_done(void *opaque)
{
    struct console_dr_context *c = opaque;
    int err = 0;
    size_t bytes = 0;

    if (c->exit)
        return;

    err = dm_v4v_async_get_result(&c->as_read, &bytes, false);
    if (err == 0)
        parse_messages(c, c->read_buf, bytes);

    /* if manually tracking rects, don't send auto confirm messages.
     * send them later from uxendisp_ack_rect */
    if (!(c->flags & DISP_FLAG_MANUAL_ACK_RECT));
        update_msg(c);
}

static void
write_done(void *opaque)
{
    struct console_dr_context *c = opaque;
    int err = 0;
    size_t bytes = 0;

    if (c->exit)
        return;

    err = dm_v4v_async_get_result(&c->as_write, &bytes, false);
    if (err) {
        BOOL res = SetWaitableTimer(c->timer, &c->due_time, 0, timer_done, c, FALSE);
        if (!res) {
            // Last resort
            Sleep(DUE_TIME_MS);
            update_msg(c);
        }
    } else {
        ioh_event_reset(&c->ev_read);
        dm_v4v_async_init(&c->v4v, &c->as_read, c->ev_read);
        dm_v4v_recv(&c->v4v, (v4v_datagram_t*)c->read_buf,
            UXENDISP_MAX_MSG_LEN, &c->as_read);
    }
}

console_dr_context_t
console_dr_init(int vm_id, const unsigned char *idtoken,
                      void *priv, inv_rect_t inv_rect,
                      uint32_t flags)
{
    struct console_dr_context *c;
    v4v_bind_values_t bind = { };
    int err = 0;

    c = calloc(1, sizeof (*c));
    if (!c)
        return NULL;

    c->thread_id = GetCurrentThreadId();

    err = dm_v4v_open(&c->v4v, UXENDISP_RING_SIZE);
    if (err)
        goto error;

    bind.ring_id.addr.port = UXENDISP_PORT;
    bind.ring_id.addr.domain = V4V_DOMID_ANY;
    bind.ring_id.partner = V4V_DOMID_UUID;
    memcpy(&bind.partner, idtoken, sizeof(bind.partner));

    err = dm_v4v_bind(&c->v4v, &bind);
    if (err) {
        // Allow one additional console to be connected.
        bind.ring_id.addr.port = UXENDISP_ALT_PORT;
        err = dm_v4v_bind(&c->v4v, &bind);
        if (err)
            goto error;
    }

    c->update_msg.dgram.addr.port = bind.ring_id.addr.port;
    c->update_msg.dgram.addr.domain = bind.ring_id.partner;
    err = update_msg(c);
    if (err && err != ERROR_IO_PENDING)
        goto error;

    c->due_time.QuadPart = -DUE_TIME_MS * ONE_MS_IN_HNS;
    c->timer = CreateWaitableTimer(NULL, TRUE, NULL);
    if (c->timer == NULL) {
        err = GetLastError();
        goto error;
    }

    ioh_event_init(&c->ev_read);
    ioh_event_init(&c->ev_write);

    ioh_add_wait_object(&c->ev_read, read_done, c, NULL);
    ioh_add_wait_object(&c->ev_write, write_done, c, NULL);

    c->priv = priv;
    c->inv_rect = inv_rect;
    c->flags = flags;
    c->rect_done = 0;

    dm_v4v_async_init(&c->v4v, &c->as_read, c->ev_read);
    dm_v4v_recv(&c->v4v, (v4v_datagram_t*)c->read_buf,
        UXENDISP_MAX_MSG_LEN, &c->as_read);

    return c;

error:
    console_dr_cleanup(c);
    SetLastError(err);
    return NULL;
}

void
console_dr_ack_rect(console_dr_context_t ctx, uint64_t rect_id)
{
    struct console_dr_context *c = ctx;

    if (rect_id > c->rect_done) {
        c->rect_done = rect_id;
        update_msg(c);
    }
}

void
console_dr_cleanup(console_dr_context_t ctx)
{
    struct console_dr_context *c = ctx;

    if (c) {
        // Cleanup must be called on the same thread as init was.
        assert(c->thread_id == GetCurrentThreadId());

        c->exit = TRUE;

        dm_v4v_async_cancel(&c->as_write);
        dm_v4v_async_cancel(&c->as_read);

        CloseHandle(c->timer);
        ioh_del_wait_object(&c->ev_read, NULL);
        ioh_del_wait_object(&c->ev_write, NULL);
        ioh_event_close(&c->ev_read);
        ioh_event_close(&c->ev_write);
        dm_v4v_close(&c->v4v);
        free(c);
    }
}
