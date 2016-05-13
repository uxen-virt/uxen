/*
 * Copyright 2015-2016, Bromium, Inc.
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

struct hid_ring
{
    v4v_channel_t v4v;
    int port;
    int ready;
    CRITICAL_SECTION lock;
    struct {
        struct v4v_buf *first;
        struct v4v_buf **last;
    } txlist;
    int vm_id;
};

struct hid_context
{
    struct hid_ring mouse_ring;
    struct hid_ring pen_ring;
    struct hid_ring touch_ring;
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

static void xmit_complete(struct hid_ring *r);

static int
send_async(struct hid_ring *r, struct v4v_buf *b, DWORD len)
{
    BOOL rc;
    DWORD bytes;

    b->len = len + sizeof(v4v_datagram_t);

    rc = WriteFile(r->v4v.v4v_handle, (void *)&b->buf,
                   b->len, &bytes, &b->ovlp);
    if (!rc) {
        if (GetLastError() == ERROR_IO_PENDING) {
            EnterCriticalSection(&r->lock);
            b->next = NULL;
            b->pprev = r->txlist.last;
            *r->txlist.last = b;
            r->txlist.last = &b->next;
            LeaveCriticalSection(&r->lock);
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
send_nop(struct hid_ring *r)
{
    struct v4v_buf *b;
    UXENHID_MSG_HEADER *hdr;
    DWORD msglen = sizeof (*hdr);
    v4v_addr_t addr = { .port = r->port, .domain = r->vm_id };

    b = alloc_v4v_buf(msglen, (void **)&hdr, addr);
    if (!b)
        return -1;

    b->buf.dgram.flags &= ~V4V_DATAGRAM_FLAG_IGNORE_DLO;

    hdr->type = UXENHID_NOP;
    hdr->msglen = msglen;

    return send_async(r, b, msglen);
}

static void
xmit_complete(struct hid_ring *r)
{
    struct v4v_buf *b, *bn;
    BOOL rc;
    DWORD bytes;
    int disconnected = 0;

    EnterCriticalSection(&r->lock);
    b = r->txlist.first;
    while (b) {
        bn = b->next;
        rc = GetOverlappedResult(r->v4v.v4v_handle, &b->ovlp, &bytes,
                                 FALSE);

        if (!rc && GetLastError() == ERROR_IO_INCOMPLETE) {
            b = bn;
            continue;
        }

        if (!rc && GetLastError() == ERROR_VC_DISCONNECTED) {
            r->ready = 0;
            disconnected = 1;
        }

        if (rc) {
            r->ready = 1;
            disconnected = 0;
        }

        if (bn)
            bn->pprev = b->pprev;
        else
            r->txlist.last = b->pprev;
        *b->pprev = bn;
        free_v4v_buf(b, b->len);
        b = bn;
    }
    LeaveCriticalSection(&r->lock);

    if (disconnected)
        send_nop(r);
}

static int
ring_init(struct hid_ring *r, int vm_id, unsigned char *idtoken,
          int device_type)
{
    v4v_bind_values_t bind = { };

    if (!v4v_open(&r->v4v, UXENHID_RING_SIZE, V4V_FLAG_ASYNC))
        return -1;

    bind.ring_id.addr.port = 0;
    bind.ring_id.addr.domain = V4V_DOMID_ANY;
    if (vm_id == -1) {
        bind.ring_id.partner = V4V_DOMID_UUID;
        memcpy(&bind.partner, idtoken, sizeof(bind.partner));
    } else
        bind.ring_id.partner = vm_id;

    if (!v4v_bind(&r->v4v, &bind)) {
        v4v_close(&r->v4v);
        return -1;
    }

    InitializeCriticalSection(&r->lock);
    r->txlist.first = NULL;
    r->txlist.last = &r->txlist.first;
    r->port = UXENHID_BASE_PORT + device_type;
    r->vm_id = bind.ring_id.partner;

    send_nop(r);

    return 0;
}

BOOL WINAPI CancelIoEx(HANDLE hFile, LPOVERLAPPED lpOverlapped);

static void
ring_cleanup(struct hid_ring *r)
{
    struct v4v_buf *b, *bn;

    EnterCriticalSection(&r->lock);
    b = r->txlist.first;
    while (b) {
        DWORD bytes;

        bn = b->next;
        if (CancelIoEx(r->v4v.v4v_handle, &b->ovlp) ||
            GetLastError() != ERROR_NOT_FOUND)
            GetOverlappedResult(r->v4v.v4v_handle, &b->ovlp, &bytes, TRUE);
        free_v4v_buf(b, b->len);
        b = bn;
    }
    LeaveCriticalSection(&r->lock);
    DeleteCriticalSection(&r->lock);
    v4v_close(&r->v4v);
}

hid_context_t
uxenconsole_hid_init(int vm_id, unsigned char *idtoken)
{
    struct hid_context *c;

    c = calloc(1, sizeof (*c));
    if (!c)
        return NULL;

    if (ring_init(&c->mouse_ring, vm_id, idtoken, UXENHID_MOUSE_DEVICE))
        goto fail_mouse;
    if (ring_init(&c->pen_ring, vm_id, idtoken, UXENHID_PEN_DEVICE))
        goto fail_pen;
    if (ring_init(&c->touch_ring, vm_id, idtoken, UXENHID_TOUCH_DEVICE))
        goto fail_touch;

    return c;

fail_touch:
    ring_cleanup(&c->pen_ring);
fail_pen:
    ring_cleanup(&c->mouse_ring);
fail_mouse:
    free(c);
    return NULL;
}

void
uxenconsole_hid_cleanup(hid_context_t context)
{
    struct hid_context *c = context;

    ring_cleanup(&c->touch_ring);
    ring_cleanup(&c->pen_ring);
    ring_cleanup(&c->mouse_ring);

    free(c);
}

int
uxenconsole_hid_mouse_report(hid_context_t context,
                             int buttons, int x, int y,
                             int wheel, int hwheel)
{
    struct hid_context *c = context;
    struct hid_ring *r = &c->mouse_ring;
    struct v4v_buf *b;
    struct {
        UXENHID_MSG_HEADER hdr;
        struct mouse_report report;
    } __attribute__ ((packed)) *buf;
    DWORD msglen = sizeof (*buf);
    v4v_addr_t addr = { .port = r->port, .domain = r->vm_id };

    xmit_complete(r);

    if (!r->ready)
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

    return send_async(r, b, msglen);
}

int
uxenconsole_hid_pen_report(hid_context_t context,
                           int x, int y, int flags, int pressure)
{
    struct hid_context *c = context;
    struct hid_ring *r = &c->pen_ring;
    struct v4v_buf *b;
    struct {
        UXENHID_MSG_HEADER hdr;
        struct pen_report report;
    } __attribute__ ((packed)) *buf;
    DWORD msglen = sizeof (*buf);
    v4v_addr_t addr = { .port = r->port, .domain = r->vm_id };

    xmit_complete(r);

    if (!r->ready)
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

    return send_async(r, b, msglen);
}

int
uxenconsole_hid_touch_report(hid_context_t context,
                             int contact_count, int contact_id,
                             int x, int y, int width, int height,
                             int flags)
{
    struct hid_context *c = context;
    struct hid_ring *r = &c->touch_ring;
    struct v4v_buf *b;
    struct {
        UXENHID_MSG_HEADER hdr;
        struct touch_report report;
    }  __attribute__ ((packed)) *buf;
    DWORD msglen = sizeof (*buf);
    v4v_addr_t addr = { .port = r->port, .domain = r->vm_id };

    xmit_complete(r);

    if (!r->ready)
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

    return send_async(r, b, msglen);
}
