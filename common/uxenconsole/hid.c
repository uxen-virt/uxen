/*
 * Copyright 2015, Bromium, Inc.
 * Author: Julian Pidancet <julian@pidancet.net>
 * SPDX-License-Identifier: ISC
 */

#include <windows.h>

#include <stdint.h>
#include <winioctl.h>
#define V4V_USE_INLINE_API
#include <windows/uxenv4vlib/gh_v4vapi.h>

#include "uxenconsolelib.h"
#include "uxenhid-common.h"

#include <stdio.h>

struct v4v_buf {
    struct v4v_buf *next;
    struct v4v_buf **pprev;

    OVERLAPPED ovlp;
    DWORD len;
    struct {
        v4v_datagram_t dgram;
        uint8_t data[0];
    } buf;
};

struct hid_context
{
    v4v_context_t v4v_context;
    int vm_id;
    int ready;
    CRITICAL_SECTION lock;
    struct {
        struct v4v_buf *first;
        struct v4v_buf **last;
    } txlist;
};

static struct v4v_buf *
alloc_v4v_buf(DWORD len, void **data, v4v_addr_t addr)
{
    struct v4v_buf *b = malloc(sizeof(*b) + len);

    if (b && data)
        *data = &b->buf.data;

    RtlZeroMemory(&b->ovlp, sizeof (OVERLAPPED));
    b->buf.dgram.addr = addr;
    b->buf.dgram.flags = V4V_DATAGRAM_FLAG_IGNORE_DLO;

    return b;
}

static void
free_v4v_buf(struct v4v_buf *b, DWORD len)
{
    (void)len;
    free(b);
}

static void xmit_complete(struct hid_context *c);

static int
send_async(struct hid_context *c, struct v4v_buf *b, DWORD len)
{
    BOOL rc;
    DWORD bytes;

    b->len = len + sizeof(v4v_datagram_t);

    rc = WriteFile(c->v4v_context.v4v_handle, (void *)&b->buf,
                   b->len, &bytes, &b->ovlp);
    if (!rc) {
        if (GetLastError() == ERROR_IO_PENDING) {
            EnterCriticalSection(&c->lock);
            b->next = NULL;
            b->pprev = c->txlist.last;
            *c->txlist.last = b;
            c->txlist.last = &b->next;
            LeaveCriticalSection(&c->lock);
            return 0;
        }
        free_v4v_buf(b, len);
        return -1;
    } else if (bytes != b->len) {
        free_v4v_buf(b, len);
        return -1;
    }

    free_v4v_buf(b, len);

    return 0;
}

static int
send_nop(struct hid_context *c)
{
    struct v4v_buf *b;
    UXENHID_MSG_HEADER *hdr;
    DWORD msglen = sizeof (*hdr);
    v4v_addr_t addr = { .port = UXENHID_PORT, .domain = c->vm_id };

    b = alloc_v4v_buf(msglen, (void **)&hdr, addr);
    if (!b)
        return -1;

    b->buf.dgram.flags &= ~V4V_DATAGRAM_FLAG_IGNORE_DLO;

    hdr->type = UXENHID_NOP;
    hdr->msglen = msglen;

    return send_async(c, b, msglen);
}

static void
xmit_complete(struct hid_context *c)
{
    struct v4v_buf *b, *bn;
    BOOL rc;
    DWORD bytes;
    int disconnected = 0;

    EnterCriticalSection(&c->lock);
    b = c->txlist.first;
    while (b) {
        bn = b->next;
        rc = GetOverlappedResult(c->v4v_context.v4v_handle, &b->ovlp, &bytes,
                                 FALSE);

        if (!rc && GetLastError() == ERROR_IO_INCOMPLETE) {
            b = bn;
            continue;
        }

        if (!rc && GetLastError() == ERROR_VC_DISCONNECTED) {
            c->ready = 0;
            disconnected = 1;
        }

        if (rc) {
            c->ready = 1;
            disconnected = 0;
        }

        if (bn)
            bn->pprev = b->pprev;
        else
            c->txlist.last = b->pprev;
        *b->pprev = bn;
        free_v4v_buf(b, b->len);
        b = bn;
    }
    LeaveCriticalSection(&c->lock);

    if (disconnected)
        send_nop(c);
}


hid_context_t
uxenconsole_hid_init(int vm_id)
{
    struct hid_context *c;
    OVERLAPPED o;
    DWORD t;
    v4v_ring_id_t id;

    c = calloc(1, sizeof (*c));
    if (!c)
        return NULL;

    memset(&o, 0, sizeof(o));
    if (!v4v_open(&c->v4v_context, UXENHID_RING_SIZE, &o) ||
        !GetOverlappedResult(c->v4v_context.v4v_handle, &o, &t, TRUE)) {
        free(c);
        return NULL;
    }

    id.addr.port = 0;
    id.addr.domain = V4V_DOMID_ANY;
    id.partner = vm_id;

    if (!v4v_bind(&c->v4v_context, &id, &o) ||
        !GetOverlappedResult(c->v4v_context.v4v_handle, &o, &t, TRUE)) {
        v4v_close(&c->v4v_context);
        return NULL;
    }

    InitializeCriticalSection(&c->lock);
    c->vm_id = vm_id;
    c->txlist.first = NULL;
    c->txlist.last = &c->txlist.first;

    send_nop(c);

    return c;
}

BOOL WINAPI CancelIoEx(HANDLE hFile, LPOVERLAPPED lpOverlapped);

void
uxenconsole_hid_cleanup(hid_context_t context)
{
    struct hid_context *c = context;
    struct v4v_buf *b, *bn;

    EnterCriticalSection(&c->lock);
    b = c->txlist.first;
    while (b) {
        DWORD bytes;

        bn = b->next;
        if (CancelIoEx(c->v4v_context.v4v_handle, &b->ovlp) ||
            GetLastError() != ERROR_NOT_FOUND)
            GetOverlappedResult(c->v4v_context.v4v_handle, &b->ovlp, &bytes, TRUE);
        free_v4v_buf(b, b->len);
        b = bn;
    }
    LeaveCriticalSection(&c->lock);
    DeleteCriticalSection(&c->lock);
    v4v_close(&c->v4v_context);
    free(c);
}

int
uxenconsole_hid_mouse_report(hid_context_t context,
                             int buttons, int x, int y,
                             int wheel, int hwheel)
{
    struct hid_context *c = context;
    struct v4v_buf *b;
    struct {
        UXENHID_MSG_HEADER hdr;
        struct mouse_report report;
    } __attribute__ ((packed)) *buf;
    DWORD msglen = sizeof (*buf);
    v4v_addr_t addr = { .port = UXENHID_PORT, .domain = c->vm_id };

    xmit_complete(c);

    if (!c->ready)
        return -1;

    b = alloc_v4v_buf(msglen, (void **)&buf, addr);
    if (!b)
        return -1;

    buf->hdr.type = UXENHID_REPORT;
    buf->hdr.msglen = msglen;

    buf->report.report_id = UXENHID_REPORT_ID_MOUSE;
    buf->report.buttons = buttons;
    buf->report.x = x;
    buf->report.y = y;
    buf->report.wheel = wheel;
    buf->report.hwheel = hwheel;

    return send_async(c, b, msglen);
}

int
uxenconsole_hid_pen_report(hid_context_t context,
                           int x, int y, int flags, int pressure)
{
    struct hid_context *c = context;
    struct v4v_buf *b;
    struct {
        UXENHID_MSG_HEADER hdr;
        struct pen_report report;
    } __attribute__ ((packed)) *buf;
    DWORD msglen = sizeof (*buf);
    v4v_addr_t addr = { .port = UXENHID_PORT, .domain = c->vm_id };

    xmit_complete(c);

    if (!c->ready)
        return -1;

    b = alloc_v4v_buf(msglen, (void **)&buf, addr);
    if (!b)
        return -1;

    buf->hdr.type = UXENHID_REPORT;
    buf->hdr.msglen = msglen;

    buf->report.report_id = UXENHID_REPORT_ID_PEN;
    buf->report.x = x;
    buf->report.y = y;
    buf->report.flags = flags;
    buf->report.pressure = pressure;

    return send_async(c, b, msglen);
}

int
uxenconsole_hid_touch_report(hid_context_t context,
                             int contact_count, int contact_id,
                             int x, int y, int width, int height,
                             int flags)
{
    struct hid_context *c = context;
    struct v4v_buf *b;
    struct {
        UXENHID_MSG_HEADER hdr;
        struct touch_report report;
    }  __attribute__ ((packed)) *buf;
    DWORD msglen = sizeof (*buf);
    v4v_addr_t addr = { .port = UXENHID_PORT, .domain = c->vm_id };

    xmit_complete(c);

    if (!c->ready)
        return -1;

    b = alloc_v4v_buf(msglen, (void **)&buf, addr);
    if (!b)
        return -1;

    buf->hdr.type = UXENHID_REPORT;
    buf->hdr.msglen = msglen;

    buf->report.contact_id = contact_id;
    buf->report.report_id = UXENHID_REPORT_ID_TOUCH;
    buf->report.x = x;
    buf->report.y = y;
    buf->report.width = width;
    buf->report.height = height;
    buf->report.flags = flags | 0x4;
    buf->report.contact_count = contact_count;

    return send_async(c, b, msglen);
}
