/*
 * Copyright 2015-2016, Bromium, Inc.
 * Author: Julian Pidancet <julian@pidancet.net>
 * SPDX-License-Identifier: ISC
 */

#include <dm/qemu_glue.h>
#include <dm/dev.h>

#include "../config.h"

#include <err.h>
#include <stdbool.h>
#include <stdint.h>

#include <dm/dm.h>

#include <winioctl.h>
#define V4V_USE_INLINE_API
#include <windows/uxenv4vlib/gh_v4vapi.h>

#include "uxen_platform.h"
#include <uxen/platform_interface.h>
#include "uxen_hid.h"
#include "uxenhid-common.h"

uint64_t hid_touch_enabled = 0;

#define _ENC8(v) ((v) & 0xff)
#define _ENC16(v) _ENC8(v), _ENC8((v) >> 8)
#define _ENC32(v) _ENC16(v), _ENC16((v) >> 16)

struct uxenhid_state {
    UXenPlatformDevice dev;

    const char *report_descriptor;
    size_t report_descriptor_len;

    uint32_t v4v_port;
    v4v_context_t v4v_context;
    HANDLE rx_event;
    HANDLE tx_event;

    TAILQ_HEAD(, async_buf) async_write_list;
    critical_section async_write_lock;

    int ready;

    struct {
        OVERLAPPED ovlp;
        struct {
            v4v_datagram_t dgram;
            uint8_t data[UXENHID_MAX_MSG_LEN];
        } buf;
    } async_read;
};

struct async_buf {
    TAILQ_ENTRY(async_buf) link;
    OVERLAPPED ovlp;
    DWORD len;
    struct {
        v4v_datagram_t dgram;
        uint8_t data[0];
    } buf;
};

static const char report_descriptor_mouse[] = {
    /* Mouse */
    0x05, 0x01,                        /* USAGE_PAGE (Generic Desktop) */
    0x09, 0x02,                        /* USAGE (Mouse) */
    0xa1, 0x01,                        /* COLLECTION (Application) */
    0x85, _ENC8(UXENHID_REPORT_ID_MOUSE),/*   REPORT_ID (mouse) */
    0x09, 0x01,                        /*   USAGE (Pointer) */
    0xa1, 0x00,                        /*   COLLECTION (Physical) */
    0x05, 0x09,                        /*     USAGE_PAGE (Button) */
    0x19, 0x01,                        /*     USAGE_MINIMUM (Button 1) */
    0x29, 0x05,                        /*     USAGE_MAXIMUM (Button 5) */
    0x15, 0x00,                        /*     LOGICAL_MINIMUM (0) */
    0x25, 0x01,                        /*     LOGICAL_MAXIMUM (1) */
    0x95, 0x05,                        /*     REPORT_COUNT (5) */
    0x75, 0x01,                        /*     REPORT_SIZE (1) */
    0x81, 0x02,                        /*     INPUT (Data,Var,Abs) */
    0x95, 0x01,                        /*     REPORT_COUNT (1) */
    0x75, 0x03,                        /*     REPORT_SIZE (3) */
    0x81, 0x03,                        /*     INPUT (Cnst,Var,Abs) */
    0x05, 0x01,                        /*     USAGE_PAGE (Generic Desktop) */
    0x09, 0x30,                        /*     USAGE (X) */
    0x09, 0x31,                        /*     USAGE (Y) */
    0x15, 0x00,                        /*     LOGICAL_MINIMUM (0) */
    0x26, _ENC16(UXENHID_XY_MAX),      /*     LOGICAL_MAXIMUM (max) */
    0x75, 0x10,                        /*     REPORT_SIZE (16) */
    0x95, 0x02,                        /*     REPORT_COUNT (2) */
    0x81, 0x02,                        /*     INPUT (Data,Var,Abs) */
    0x05, 0x01,                        /*     USAGE_PAGE (Generic Desktop) */
    0x09, 0x38,                        /*     USAGE (Wheel) */
    0x15, _ENC8(UXENHID_WHEEL_MIN),    /*     LOGICAL_MINIMUM (min) */
    0x25, _ENC8(UXENHID_WHEEL_MAX),    /*     LOGICAL_MAXIMUM (max) */
    0x75, 0x08,                        /*     REPORT_SIZE (8) */
    0x95, 0x01,                        /*     REPORT_COUNT (1) */
    0x81, 0x06,                        /*     INPUT (Data,Var,Rel) */
    0x05, 0x0c,                        /*     USAGE_PAGE (Consumer Devices) */
    0x0a, 0x38, 0x02,                  /*     USAGE (AC Pan) */
    0x15, _ENC8(UXENHID_WHEEL_MIN),    /*     LOGICAL_MINIMUM (min) */
    0x25, _ENC8(UXENHID_WHEEL_MAX),    /*     LOGICAL_MAXIMUM (max) */
    0x75, 0x08,                        /*     REPORT_SIZE (8) */
    0x95, 0x01,                        /*     REPORT_COUNT (1) */
    0x81, 0x06,                        /*     INPUT (Data,Var,Rel) */
    0xc0,                              /*   END_COLLECTION */
    0xc0,                              /* END_COLLECTION */
};

static const char report_descriptor_pen[] = {
    /* Pen */
    0x05, 0x0d,                        /* USAGE_PAGE (Digitizers) */
    0x09, 0x02,                        /* USAGE (Pen) */
    0xa1, 0x01,                        /* COLLECTION (Application) */
    0x85, _ENC8(UXENHID_REPORT_ID_PEN),/*   REPORT_ID (pen) */
    0x09, 0x20,                        /*   USAGE (Stylus) */
    0x35, 0x00,                        /*   PHYSICAL_MINIMUM (0) */
    0xa1, 0x00,                        /*   COLLECTION (Physical) */
    0x09, 0x32,                        /*     USAGE (In Range) */
    0x09, 0x42,                        /*     USAGE (Tip Switch) */
    0x09, 0x44,                        /*     USAGE (Barrel Switch) */
    0x09, 0x3c,                        /*     USAGE (Invert) */
    0x09, 0x45,                        /*     USAGE (Eraser) */
    0x15, 0x00,                        /*     LOGICAL_MINIMUM (0) */
    0x25, 0x01,                        /*     LOGICAL_MAXIMUM (1) */
    0x75, 0x01,                        /*     REPORT_SIZE (1) */
    0x95, 0x05,                        /*     REPORT_COUNT (5) */
    0x81, 0x02,                        /*     INPUT (Data,Var,Abs) */
    0x95, 0x03,                        /*     REPORT_COUNT (3) */
    0x81, 0x03,                        /*     INPUT (Cnst,Var,Abs) */
    0x05, 0x01,                        /*     USAGE_PAGE (Generic Desktop) */
    0x09, 0x30,                        /*     USAGE (X) */
    0x75, 0x10,                        /*     REPORT_SIZE (16) */
    0x95, 0x01,                        /*     REPORT_COUNT (1) */
    0xA4,                              /*     PUSH */
    0x55, 0x0e,                        /*     UNIT_EXPONENT (-2) */
    0x65, 0x11,                        /*     UNIT (cm) */
    0x46, _ENC16(UXENHID_PHYS_X),      /*     PHYSICAL_MAXIMUM (max) */
    0x15, 0x00,                        /*     LOGICAL_MINIMUM (0) */
    0x26, _ENC16(UXENHID_XY_MAX),      /*     LOGICAL_MAXIMUM (max) */
    0x81, 0x02,                        /*     INPUT (Data,Var,Abs) */
    0x09, 0x31,                        /*     USAGE (Y) */
    0x46, _ENC16(UXENHID_PHYS_Y),      /*     PHYSICAL_MAXIMUM (max) */
    0x26, _ENC16(UXENHID_XY_MAX),      /*     LOGICAL_MAXIMUM (max) */
    0x81, 0x02,                        /*     INPUT (Data,Var,Abs) */
    0xb4,                              /*     POP */
    0x05, 0x0d,                        /*     USAGE_PAGE (Digitizers) */
    0x09, 0x30,                        /*     USAGE (Tip Pressure) */
    0x15, 0x00,                        /*     LOGICAL_MINIMUM (0) */
    0x26, _ENC16(UXENHID_PRESSURE_MAX),/*     LOGICAL_MAXIMUM (max) */
    0x75, 0x10,                        /*     REPORT_SIZE (16) */
    0x95, 0x01,                        /*     REPORT_COUNT (1) */
    0x81, 0x02,                        /*     INPUT (Data,Var,Abs) */
    0xc0,                              /*   END_COLLECTION */
    0xc0,                              /* END_COLLECTION */
};

static const char report_descriptor_touch[] = {
    /* Touch */
    0x05, 0x0d,                        /* USAGE_PAGE (Digitizers) */
    0x09, 0x04,                        /* USAGE (Touch Screen) */
    0xa1, 0x01,                        /* COLLECTION (Application) */
    0x85, _ENC8(UXENHID_REPORT_ID_TOUCH),/*   REPORT_ID (touch) */
    0x09, 0x22,                        /*   USAGE (Finger) */
    0x35, 0x00,                        /*   PHYSICAL_MINIMUM (0) */
    0xa1, 0x02,                        /*   COLLECTION (Logical) */
    0x09, 0x32,                        /*     USAGE (In Range) */
    0x09, 0x42,                        /*     USAGE (Tip Switch) */
    0x09, 0x47,                        /*     USAGE (Valid) */
    0x15, 0x00,                        /*     LOGICAL_MINIMUM (0) */
    0x25, 0x01,                        /*     LOGICAL_MAXIMUM (1) */
    0x75, 0x01,                        /*     REPORT_SIZE (1) */
    0x95, 0x03,                        /*     REPORT_COUNT (3) */
    0x81, 0x02,                        /*     INPUT (Data,Var,Abs) */
    0x95, 0x05,                        /*     REPORT_COUNT (5) */
    0x81, 0x03,                        /*     INPUT (Cnst,Var,Abs) */
    0x09, 0x51,                        /*     USAGE (Contact Identifier) */
    0x75, 0x10,                        /*     REPORT_SIZE (16) */
    0x95, 0x01,                        /*     REPORT_COUNT (1) */
    0x27, 0xFF, 0xFF, 0x00, 0x00,      /*     LOGICAL_MAXIMUM (65535) */
    0x81, 0x02,                        /*     INPUT (Data,Var,Abs) */
    0x05, 0x01,                        /*     USAGE_PAGE (Generic Desktop) */
    0x09, 0x30,                        /*     USAGE (X) */
    0x75, 0x10,                        /*     REPORT_SIZE (16) */
    0x95, 0x01,                        /*     REPORT_COUNT (1) */
    0xA4,                              /*     PUSH */
    0x55, 0x0e,                        /*     UNIT_EXPONENT (-2) */
    0x65, 0x11,                        /*     UNIT (cm) */
    0x46, _ENC16(UXENHID_PHYS_X),      /*     PHYSICAL_MAXIMUM (max) */
    0x15, 0x00,                        /*     LOGICAL_MINIMUM (0) */
    0x26, _ENC16(UXENHID_XY_MAX),      /*     LOGICAL_MAXIMUM (max) */
    0x81, 0x02,                        /*     INPUT (Data,Var,Abs) */
    0x09, 0x31,                        /*     USAGE (Y) */
    0x46, _ENC16(UXENHID_PHYS_Y),      /*     PHYSICAL_MAXIMUM (max) */
    0x26, _ENC16(UXENHID_XY_MAX),      /*     LOGICAL_MAXIMUM (max) */
    0x81, 0x02,                        /*     INPUT (Data,Var,Abs) */
    0x05, 0x0d,                        /*     USAGE_PAGE (Digitizers) */
    0x09, 0x48,                        /*     USAGE (Width) */
    0x75, 0x10,                        /*     REPORT_SIZE (16) */
    0x95, 0x01,                        /*     REPORT_COUNT (1) */
    0x26, _ENC16(UXENHID_XY_MAX),      /*     LOGICAL_MAXIMUM (max) */
    0x81, 0x02,                        /*     INPUT (Data,Var,Abs) */
    0x09, 0x49,                        /*     USAGE (Height) */
    0x26, _ENC16(UXENHID_XY_MAX),      /*     LOGICAL_MAXIMUM (max) */
    0x81, 0x02,                        /*     INPUT (Data,Var,Abs) */
    0xb4,                              /*     POP */
    0xc0,                              /*   END_COLLECTION */
    0x05, 0x0d,                        /*   USAGE_PAGE (Digitizers) */
    0x09, 0x54,                        /*   USAGE (Contact count) */
    0x26, 0xff, 0x00,                  /*   LOGICAL_MAXIMUM (255) */
    0x75, 0x08,                        /*   REPORT_SIZE (8) */
    0x95, 0x01,                        /*   REPORT_COUNT (1) */
    0x81, 0x02,                        /*   INPUT (Data,Var,Abs) */
    0x85, _ENC8(UXENHID_REPORT_ID_MAX_CONTACT_COUNT),/*   REPORT_ID (max contact count) */
    0x09, 0x55,                        /*   USAGE (Contact count maximum) */
    0x75, 0x08,                        /*   REPORT_SIZE (8) */
    0x95, 0x01,                        /*   REPORT_COUNT (1) */
    0x15, 0x00,                        /*   LOGICAL_MINIMUM (0) */
    0x26, 0xff, 0x00,                  /*   LOGICAL_MAXIMUM (255) */
    0xB1, 0x02,                        /*   FEATURE (Data, Var, Abs) */
    0xc0                               /* END_COLLECTION */
};

static struct uxenhid_state *mouse_state = NULL;
static struct uxenhid_state *pen_state = NULL;
static struct uxenhid_state *touch_state = NULL;

static struct async_buf *
alloc_async_buf(DWORD len, void **data, v4v_addr_t addr)
{
    struct async_buf *b = malloc(sizeof(*b) + len);

    if (b && data)
        *data = &b->buf.data;

    RtlZeroMemory(&b->ovlp, sizeof (OVERLAPPED));
    b->buf.dgram.addr = addr;
    b->buf.dgram.flags = 0;

    return b;
}

static void
free_async_buf(struct async_buf *b, DWORD len)
{
    (void)len;
    free(b);
}

static int
send_async(struct uxenhid_state *s, struct async_buf *b, DWORD len)
{
    BOOL rc;
    DWORD bytes;

    b->len = len + sizeof(v4v_datagram_t);

    b->ovlp.hEvent = s->tx_event;

    rc = WriteFile(s->v4v_context.v4v_handle, (void *)&b->buf,
                   b->len, &bytes, &b->ovlp);
    if (!rc) {
        if (GetLastError() == ERROR_IO_PENDING) {
            critical_section_enter(&s->async_write_lock);
            TAILQ_INSERT_TAIL(&s->async_write_list, b, link);
            critical_section_leave(&s->async_write_lock);
            return 0;
        }

        Wwarn("%s: WriteFile", __FUNCTION__);
        free_async_buf(b, len);

        return -1;
    } else if (bytes != b->len) {
        debug_printf("%s: short write %ld/%ld\n", __FUNCTION__, bytes, b->len);
        free_async_buf(b, len);
        return -1;
    }

    free_async_buf(b, len);

    return 0;
}

int uxenhid_send_mouse_report(uint8_t buttons, uint16_t x, uint16_t y,
                              int8_t wheel, int8_t hwheel)
{
    struct async_buf *b;
    struct {
        UXENHID_MSG_HEADER hdr;
        struct mouse_report report;
    } __attribute__ ((packed)) *buf;
    DWORD msglen = sizeof (*buf);
    v4v_addr_t addr;

    if (!mouse_state || !mouse_state->ready)
        return -1;

    addr.port = mouse_state->v4v_port;
    addr.domain = vm_id;

    b = alloc_async_buf(msglen, (void **)&buf, addr);
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

    return send_async(mouse_state, b, msglen);
}

int uxenhid_send_pen_report(uint16_t x, uint16_t y, uint8_t flags,
                            uint16_t pressure)
{
    struct async_buf *b;
    struct {
        UXENHID_MSG_HEADER hdr;
        struct pen_report report;
    } __attribute__ ((packed)) *buf;
    DWORD msglen = sizeof (*buf);
    v4v_addr_t addr;

    if (!pen_state || !pen_state->ready)
        return -1;

    addr.port = pen_state->v4v_port;
    addr.domain = vm_id;

    b = alloc_async_buf(msglen, (void **)&buf, addr);
    if (!b)
        return -1;

    buf->hdr.type = UXENHID_REPORT;
    buf->hdr.msglen = msglen;

    buf->report.report_id = UXENHID_REPORT_ID_PEN;
    buf->report.x = x;
    buf->report.y = y;
    buf->report.flags = flags;
    buf->report.pressure = pressure;

    return send_async(pen_state, b, msglen);
}

int uxenhid_send_touch_report(uint8_t contact_count, uint16_t contact_id,
                              uint16_t x, uint16_t y,
                              uint16_t width, uint16_t height,
                              uint8_t flags)
{
    struct async_buf *b;
    struct {
        UXENHID_MSG_HEADER hdr;
        struct touch_report report;
    }  __attribute__ ((packed)) *buf;
    DWORD msglen = sizeof (*buf);
    v4v_addr_t addr;

    if (!touch_state || !touch_state->ready)
        return -1;

    addr.port = touch_state->v4v_port;
    addr.domain = vm_id;

    b = alloc_async_buf(msglen, (void **)&buf, addr);
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

    return send_async(touch_state, b, msglen);
}

static int
uxenhid_send_max_contact_count_report(void)
{
    struct async_buf *b;
    struct {
        UXENHID_MSG_HEADER hdr;
        struct max_contact_count_report report;
    } __attribute__ ((packed)) *buf;
    DWORD msglen = sizeof (*buf);
    v4v_addr_t addr;

    if (!touch_state || !touch_state->ready)
        return -1;

    addr.port = touch_state->v4v_port;
    addr.domain = vm_id;

    b = alloc_async_buf(msglen, (void **)&buf, addr);
    if (!b)
        return -1;

    buf->hdr.type = UXENHID_FEATURE_REPORT;
    buf->hdr.msglen = msglen;

    buf->report.report_id = UXENHID_REPORT_ID_MAX_CONTACT_COUNT;
    buf->report.max_contact_count = 11;

    return send_async(touch_state, b, msglen);
}

static void
uxenhid_recv(struct uxenhid_state *s, v4v_datagram_t *dgram,
             void *buf, DWORD len)
{
    UXENHID_MSG_HEADER *hdr = buf;
    UXENHID_MSG_HEADER *reply;
    struct async_buf *b;
    DWORD reply_len;

    if (len < sizeof(*hdr) ||
        len < hdr->msglen) {
        debug_printf("%s: incomplete read, bytes=%ld\n", __FUNCTION__, len);
        return;
    }

    switch (hdr->type) {
    case UXENHID_DEVICE_START:
        s->ready = 1;
        break;

    case UXENHID_DEVICE_STOP:
        s->ready = 0;
        break;

    case UXENHID_REQUEST_REPORT_DESCRIPTOR:
        {
            uint8_t *p;

            reply_len = sizeof(*reply) + s->report_descriptor_len;
            b = alloc_async_buf(reply_len, (void **)&reply, dgram->addr);
            if (!b)
                return;

            p = (uint8_t *)(reply + 1);
            memcpy(p, s->report_descriptor, s->report_descriptor_len);

            reply->type = UXENHID_REQUEST_REPORT_DESCRIPTOR;
            reply->msglen = reply_len;

            send_async(s, b, reply_len);
        }
        break;

    case UXENHID_FEATURE_QUERY:
        {
            uint8_t *report_id = (void *)(hdr + 1);

            if (hdr->msglen < (sizeof (*hdr) + sizeof (uint8_t)))
                return;

            switch (*report_id) {
            case UXENHID_REPORT_ID_MAX_CONTACT_COUNT:
                uxenhid_send_max_contact_count_report();
                break;
            default:
                return;
            }
        }
        break;

    case UXENHID_REPORT:
    default:
        debug_printf("%s: Unknown message id %d\n", __FUNCTION__, hdr->type);
        return;
    }
}

static void
rx_start(struct uxenhid_state *s)
{
    DWORD bytes;
    BOOL rc;

    ResetEvent(s->rx_event);
    s->async_read.ovlp.hEvent = s->rx_event;

    do {
        rc = ReadFile(s->v4v_context.v4v_handle, &s->async_read.buf,
                      sizeof (s->async_read.buf), &bytes, &s->async_read.ovlp);
        if (rc) {
            if (bytes >= sizeof (v4v_datagram_t))
                uxenhid_recv(s, &s->async_read.buf.dgram,
                             (void *)&s->async_read.buf.data,
                             bytes - sizeof (v4v_datagram_t));
        } else if (GetLastError() != ERROR_IO_PENDING)
            Wwarn("%s: ReadFile", __FUNCTION__);
    } while (rc);
}

static void
rx_complete(void *opaque)
{
    struct uxenhid_state *s = opaque;
    BOOL rc;
    DWORD bytes;

    rc = GetOverlappedResult(s->v4v_context.v4v_handle, &s->async_read.ovlp,
                             &bytes, FALSE);
    if (!rc) {
        if (GetLastError() == ERROR_IO_INCOMPLETE) {
            ResetEvent(s->rx_event);
            return;
        }

        Wwarn("%s: GetOverlappedresult", __FUNCTION__);
        return;
    }

    if (bytes >= sizeof (v4v_datagram_t))
        uxenhid_recv(s, &s->async_read.buf.dgram,
                     (void *)&s->async_read.buf.data,
                      bytes - sizeof (v4v_datagram_t));

    rx_start(s);
}

static void
tx_complete(void *opaque)
{
    struct uxenhid_state *s = opaque;
    struct async_buf *b, *bn;
    BOOL rc;
    DWORD bytes;

    critical_section_enter(&s->async_write_lock);
    TAILQ_FOREACH_SAFE(b, &s->async_write_list, link, bn) {
        rc = GetOverlappedResult(s->v4v_context.v4v_handle, &b->ovlp, &bytes,
                                 FALSE);
        if (!rc && GetLastError() == ERROR_IO_INCOMPLETE)
            continue;

        if (!rc)
            Wwarn("%s: GetOverlappedResult", __FUNCTION__);
        else if (bytes != b->len)
            debug_printf("%s: short write %ld/%ld\n", __FUNCTION__,
                         bytes, b->len);

        TAILQ_REMOVE(&s->async_write_list, b, link);
        free_async_buf(b, b->len);
    }
    critical_section_leave(&s->async_write_lock);
}

static int
uxenhid_exit(UXenPlatformDevice *dev)
{
    struct uxenhid_state *s = DO_UPCAST(struct uxenhid_state, dev, dev);
    struct async_buf *b, *bn;

    critical_section_enter(&s->async_write_lock);
    TAILQ_FOREACH_SAFE(b, &s->async_write_list, link, bn) {
        DWORD bytes;

        if (CancelIoEx(s->v4v_context.v4v_handle, &b->ovlp) ||
            GetLastError() != ERROR_NOT_FOUND)
            GetOverlappedResult(s->v4v_context.v4v_handle, &b->ovlp, &bytes, TRUE);

        TAILQ_REMOVE(&s->async_write_list, b, link);
        free_async_buf(b, b->len);
    }
    critical_section_leave(&s->async_write_lock);
    CancelIoEx(s->v4v_context.v4v_handle, &s->async_read.ovlp);

    ioh_del_wait_object(&s->rx_event, NULL);
    ioh_del_wait_object(&s->tx_event, NULL);

    v4v_close(&s->v4v_context);

    CloseHandle(s->tx_event);
    CloseHandle(s->rx_event);

    critical_section_free(&s->async_write_lock);

    return 0;
}

static int
uxenhid_init(UXenPlatformDevice *dev)
{
    struct uxenhid_state *s = DO_UPCAST(struct uxenhid_state, dev, dev);
    v4v_ring_id_t id;
    OVERLAPPED o;
    DWORD t;

    s->ready = 0;

    memset(&o, 0, sizeof(o));
    if (!v4v_open(&s->v4v_context, UXENHID_RING_SIZE, &o) ||
        !GetOverlappedResult(s->v4v_context.v4v_handle, &o, &t, TRUE)) {
        Wwarn("%s: v4v_open", __FUNCTION__);
        return -1;
    }

    s->v4v_port = UXENHID_PORT + uxenplatform_device_get_instance_id(dev);

    id.addr.port = s->v4v_port;
    id.addr.domain = V4V_DOMID_ANY;
    id.partner = vm_id;

    memset(&o, 0, sizeof(o));
    if (!v4v_bind(&s->v4v_context, &id, &o) ||
        !GetOverlappedResult(s->v4v_context.v4v_handle, &o, &t, TRUE)) {
        Wwarn("%s: v4v_bind", __FUNCTION__, id.addr.port);
        v4v_close(&s->v4v_context);
        return -1;
    }

    s->tx_event = CreateEvent(NULL, FALSE, FALSE, NULL);
    if (!s->tx_event) {
        Wwarn("%s: CreateEvent", __FUNCTION__);
        v4v_close(&s->v4v_context);
        return -1;
    }

    s->rx_event = CreateEvent(NULL, FALSE, FALSE, NULL);
    if (!s->rx_event) {
        Wwarn("%s: CreateEvent", __FUNCTION__);
        CloseHandle(s->tx_event);
        v4v_close(&s->v4v_context);
        return -1;
    }

    TAILQ_HEAD_INIT(&s->async_write_list);
    critical_section_init(&s->async_write_lock);

    ioh_add_wait_object(&s->rx_event, rx_complete, s, NULL);
    ioh_add_wait_object(&s->tx_event, tx_complete, s, NULL);

    rx_start(s);

    return 0;
}

int
uxenhid_create_devices(void)
{
    UXenPlatformDevice *dev;
    int ret = -1;

    dev = uxenplatform_device_create("uxen_hid");
    if (!dev)
        goto err;
    mouse_state = DO_UPCAST(struct uxenhid_state, dev, dev);
    mouse_state->report_descriptor = report_descriptor_mouse;
    mouse_state->report_descriptor_len = sizeof(report_descriptor_mouse);
    ret = qdev_init(&dev->qdev);
    if (ret < 0)
        goto err;

    if (hid_touch_enabled) {
        dev = uxenplatform_device_create("uxen_hid");
        if (!dev)
            goto err;
        pen_state = DO_UPCAST(struct uxenhid_state, dev, dev);
        pen_state->report_descriptor = report_descriptor_pen;
        pen_state->report_descriptor_len = sizeof(report_descriptor_pen);
        ret = qdev_init(&dev->qdev);
        if (ret < 0)
            goto err;
    }

    if (hid_touch_enabled) {
        dev = uxenplatform_device_create("uxen_hid");
        if (!dev)
            goto err;
        touch_state = DO_UPCAST(struct uxenhid_state, dev, dev);
        touch_state->report_descriptor = report_descriptor_touch;
        touch_state->report_descriptor_len = sizeof(report_descriptor_touch);
        ret = qdev_init(&dev->qdev);
        if (ret < 0)
            goto err;
    }

    return 0;
err:
    if (touch_state) {
        qdev_free(&touch_state->dev.qdev);
        touch_state = NULL;
    }
    if (pen_state) {
        qdev_free(&pen_state->dev.qdev);
        pen_state = NULL;
    }
    if (mouse_state) {
        qdev_free(&mouse_state->dev.qdev);
        mouse_state = NULL;
    }

    return ret;
}

void hotplug_touch_devices(int plug)
{
    if (!plug) {
        if (pen_state) {
            qdev_unplug(&pen_state->dev.qdev);
            qdev_free(&pen_state->dev.qdev);
            pen_state = NULL;
        }

        if (touch_state) {
            qdev_unplug(&touch_state->dev.qdev);
            qdev_free(&touch_state->dev.qdev);
            touch_state = NULL;
        }
    } else {
        UXenPlatformDevice *dev;

        if (!pen_state) {
            dev = uxenplatform_device_create("uxen_hid");
            pen_state = DO_UPCAST(struct uxenhid_state, dev, dev);
            pen_state->report_descriptor = report_descriptor_pen;
            pen_state->report_descriptor_len = sizeof(report_descriptor_pen);
            qdev_init(&dev->qdev);
        }

        if (!touch_state) {
            dev = uxenplatform_device_create("uxen_hid");
            touch_state = DO_UPCAST(struct uxenhid_state, dev, dev);
            touch_state->report_descriptor = report_descriptor_touch;
            touch_state->report_descriptor_len = sizeof(report_descriptor_touch);
            qdev_init(&dev->qdev);
        }
    }
}

#ifdef MONITOR
void
mc_touch_unplug(Monitor *mon, const dict args)
{
    hotplug_touch_devices(0);
}

void
mc_touch_plug(Monitor *mon, const dict args)
{
    hotplug_touch_devices(1);
}
#endif

static UXenPlatformDeviceInfo uxenhid_info = {
    .qdev.name = "uxen_hid",
    .qdev.size = sizeof(struct uxenhid_state),
    .init = uxenhid_init,
    .exit = uxenhid_exit,
    .unplug = NULL,
    .devtype = UXENBUS_DEVICE_TYPE_HID,
    .qdev.props = (Property[]) {
        DEFINE_PROP_END_OF_LIST(),
    },
};

static void
uxenhid_register_devices(void)
{
    uxenplatform_qdev_register(&uxenhid_info);
}

device_init(uxenhid_register_devices);
