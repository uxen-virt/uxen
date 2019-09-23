/*
 * Copyright 2019, Bromium, Inc.
 * Author: Tomasz Wroblewski <tomasz.wroblewski@gmail.com>
 * SPDX-License-Identifier: ISC
 */

#include <windowsx.h>

#include <dm/config.h>
#include <dm/dm.h>
#include <dm/timer.h>
#include <dm/console.h>
#include <dm/atto-agent.h>
#include <dm/atto-vm.h>
#include <dm/hw/uxen_v4v.h>
#include <dm/hw/uxen_fb.h>

#include <atto-agent-protocol.h>

#include <err.h>
#include <stdint.h>

//#define AGENT_DEBUG

#define RING_SIZE 262144

struct atto_agent_packet {
    v4v_datagram_t dgram;
    struct atto_agent_msg msg;
} __attribute__((packed));

struct atto_agent_varlen_packet {
    v4v_datagram_t dgram;
    struct atto_agent_msg msg;
    /* space for bigger datagrams */
    uint8_t extra_data[RING_SIZE - 4096 -
                       sizeof(struct atto_agent_msg)];
} __attribute__((packed));

typedef struct atto_agent_pending_send {
    TAILQ_ENTRY(atto_agent_pending_send) entry;
    void *buffer;
    uint32_t len;
    v4v_async_t async;
} atto_agent_pending_send_t;

#define MAX_STRING_LEN (sizeof(struct atto_agent_varlen_packet) - \
                        offsetof(struct atto_agent_varlen_packet, msg.string))

struct head_resize {
    uint32_t xres, yres;
    int pending;
};

struct atto_agent_state {
    int initialized;
    int can_send_resize;
    struct head_resize headres[FB_HEADMAX];
    v4v_context_t v4v;
    v4v_async_t async;
    ioh_event rx_event;
    ioh_event tx_event;
    struct atto_agent_varlen_packet packet;
    struct atto_agent_varlen_packet resp;
    uint32_t partner_id;
    Timer *resize_timer;
    critical_section cs;
    uint32_t keyboard_layout;
    TAILQ_HEAD(, atto_agent_pending_send) tx_queue;
    critical_section tx_queue_lock;
};

#define RESIZE_BACKOFF_MS 400

static struct atto_agent_state state;

static int atto_agent_rx_start(struct atto_agent_state *s);
static void send_latest_keyboard_layout(struct atto_agent_state *s);

static atto_agent_pending_send_t *
init_pending_send(struct atto_agent_state *s, void *buffer, size_t len)
{
    atto_agent_pending_send_t *ps = calloc(1, sizeof(atto_agent_pending_send_t));
    assert(ps);

    ps->buffer = malloc(len);;
    assert(ps->buffer);

    memcpy(ps->buffer, buffer, len);
    ps->len = len;

    dm_v4v_async_init(&s->v4v, &ps->async, s->tx_event);

    return ps;
}

static void
free_pending_send(atto_agent_pending_send_t *ps)
{
    free(ps->buffer);
    free(ps);
}

static int
send_message(struct atto_agent_state *s,
    struct atto_agent_varlen_packet *resp,
    size_t resp_len,
    uint32_t port)
{
    int err;

    resp->dgram.addr.port = port ? port : ATTO_AGENT_V4V_PORT;
    resp->dgram.addr.domain = s->partner_id;
    resp->dgram.flags = 0;

    /* init pending send packet */
    atto_agent_pending_send_t *ps = init_pending_send(s, resp, resp_len);
    assert(ps);

    critical_section_enter(&s->tx_queue_lock);
    ioh_event_reset(&s->tx_event);
    TAILQ_INSERT_TAIL(&s->tx_queue, ps, entry);
    err = dm_v4v_send(&s->v4v, (v4v_datagram_t*)ps->buffer,
        ps->len, &ps->async);
    if (err && err != ERROR_IO_PENDING) {
        TAILQ_REMOVE(&s->tx_queue, ps, entry);
        free_pending_send(ps);
        critical_section_leave(&s->tx_queue_lock);
        warnx("%s: dm_v4v_send failed with %d\n", __FUNCTION__, err);

        return -1;
    }

    critical_section_leave(&s->tx_queue_lock);

    return 0;
}

static void
send_latest_resize(struct atto_agent_state *s)
{
    int i;

    critical_section_enter(&s->cs);
    for (i = 0; i < FB_HEADMAX; i++) {
        struct head_resize *res = &s->headres[i];
        if (res->pending) {
            struct atto_agent_varlen_packet *resp = &s->resp;

            memset(resp, 0, sizeof(*resp));

            resp->msg.type = ATTO_MSG_RESIZE_RET;
            resp->msg.xres = res->xres;
            resp->msg.yres = res->yres;
            resp->msg.head_id = i;

            if (send_message(s, resp, sizeof(struct atto_agent_packet), 0) == 0) {
                debug_printf("sent resize to head %d = %ux%u\n",
                    i, (unsigned) res->xres, (unsigned) res->yres);
                res->pending = 0;
            }
        }
    }
    critical_section_leave(&s->cs);
}

static void
process_x11_cursor(
    struct atto_agent_state *s,
    struct display_state *ds,
    struct atto_agent_msg *msg,
    int len)
{
    if (msg->ctype == (uint32_t) (-2)) {
        attovm_unmap_x11_cursor(msg->ccursor);
        return;
    }

    /* custom x11 cursor */
    if (msg->ctype == (uint32_t) (-1)) {
        int bitmap_len = len - offsetof(struct atto_agent_msg, bitmap);
        if (len < (((uint8_t *) msg->bitmap) - ((uint8_t *) msg)) +
                 msg->len) {

           debug_printf("%s: too short message of x11 custom cursor, len=%d\n",
                        __FUNCTION__, len);
           return;
        }
        if (msg->nx > 256 || msg->ny > 256) {
            debug_printf("%s: Cursor size %" PRIu32 "x%" PRIu32 " too big\n",
                         __FUNCTION__, msg->nx, msg->ny);
            return;
        }
        debug_printf("%s: atto_create_custom_cursor xptr %lx bitmap_len %d\n",
                     __FUNCTION__, (unsigned long) msg->ccursor,
                     (unsigned) bitmap_len);
        attovm_create_custom_cursor(msg->ccursor, msg->xhot, msg->yhot, msg->nx,
                                    msg->ny, bitmap_len, (uint8_t *)&msg->bitmap);
        /* Apparently we also need to activate in this case */
        attovm_set_x11_cursor(ds, msg->ccursor);

        return;
    }

    /* normal x11 cursor */
    /* Note, we don't use these any more because Win32 cursor APIs are so bad */
    attovm_map_x11_cursor(msg->ctype, msg->ccursor);
}

static void
atto_agent_process_msg(struct atto_agent_state *s,
    struct atto_agent_varlen_packet *pkt,
    int len)
{
    struct atto_agent_varlen_packet *resp = &s->resp;
    int send_back = 1;
    struct atto_agent_msg *msg = &pkt->msg;
    size_t resp_len = sizeof(struct atto_agent_packet);

    memset(resp, 0, sizeof(*resp));

#ifdef AGENT_DEBUG
    debug_printf("atto-agent: process message type=%d head=%d\n",
        msg->type, msg->head_id);
#endif

    if (msg->type == ATTO_MSG_GETURL) {
        char *endp;
        resp->msg.type = ATTO_MSG_GETURL_RET;
        if (vm_attovm_url)
            strncpy(resp->msg.string, vm_attovm_url, MAX_STRING_LEN);
        endp = (char *)resp->msg.string +
               strnlen(resp->msg.string, MAX_STRING_LEN);
        resp_len = max(sizeof(struct atto_agent_packet), endp - (char *)resp);
    } else if (msg->type == ATTO_MSG_GETBOOT) {
        resp->msg.type = ATTO_MSG_GETBOOT_RET;
        strncpy(resp->msg.string, /*vm_attovm_boot*/ "0",
                sizeof(resp->msg.string));
    } else if (msg->type == ATTO_MSG_RESIZE) {
        s->can_send_resize = 1;
        resp->msg.type = ATTO_MSG_RESIZE_RET;
        resp->msg.xres = 0;
        resp->msg.yres = 0;
    } else if (msg->type == ATTO_MSG_CURSOR_TYPE) {
        struct display_state *ds = display_find(msg->head_id);

        if (ds)
            process_x11_cursor(s, ds, msg, len);
        else
            debug_printf("%s: could not find display head %d\n",
                         __FUNCTION__, (int) msg->head_id);

        send_back = 0;
    } else if (msg->type == ATTO_MSG_CURSOR_CHANGE) {
        struct display_state *ds = display_find(msg->head_id);

        if (ds)
            attovm_set_x11_cursor(ds, msg->ccursor);
        else
            debug_printf("%s: could not find display head %d\n",
                         __FUNCTION__, (int) msg->head_id);

        send_back = 0;
    } else if (msg->type == ATTO_MSG_CURSOR_GET_SM) {
        resp->msg.type = ATTO_MSG_CURSOR_GET_SM_RET;
        resp->msg.xres = GetSystemMetrics(SM_CXCURSOR);
        resp->msg.yres = GetSystemMetrics(SM_CYCURSOR);
    } else {
        warnx("%s: unknown message %d\n", __FUNCTION__, msg->type);
        return;
    }

    if (!send_back)
        return;
    critical_section_enter(&s->cs);
    send_message(s, resp, resp_len, pkt->dgram.addr.port);
    critical_section_leave(&s->cs);

    if (msg->type == ATTO_MSG_RESIZE && s->keyboard_layout) {
        /* Then we just became ready to send keyboard focus and layout change */
        attovm_check_keyboard_focus();
        send_latest_keyboard_layout(s);
    }
}

static void
atto_agent_tx_event(void *opaque)
{
    struct atto_agent_state *s = opaque;
    size_t bytes;
    int err;
    atto_agent_pending_send_t *ps, *ps_next;

    critical_section_enter(&s->tx_queue_lock);

    ioh_event_reset(&s->tx_event);

    TAILQ_FOREACH_SAFE(ps, &s->tx_queue, entry, ps_next) {
        err = dm_v4v_async_get_result(&ps->async, &bytes, false);
        if (err) {
            switch (err) {
            case ERROR_IO_INCOMPLETE:
                /* still pending */
                continue;
            }
            warnx("%s: dm_v4v_async_get_result failed with %d\n", __FUNCTION__,
                err);
        }

        /* async finished, dequeue & free */
        TAILQ_REMOVE(&s->tx_queue, ps, entry);

        free_pending_send(ps);
    }

    critical_section_leave(&s->tx_queue_lock);
}

static void
atto_agent_rx_event(void *opaque)
{
    struct atto_agent_state *s = opaque;
    size_t bytes;
    int err;

    err = dm_v4v_async_get_result(&s->async, &bytes, false);
    if (err) {
        switch (err) {
        case ERROR_IO_INCOMPLETE:
            ioh_event_reset(&s->rx_event);
            return;
        }
        warnx("%s: dm_v4v_async_get_result failed with %d\n", __FUNCTION__,
              err);
        atto_agent_rx_start(s);
        return;
    }

    if (bytes < sizeof(s->packet.dgram)) {
        warnx("%s: read too few bytes, %u\n", __FUNCTION__, (unsigned) bytes);
    } else {
        bytes -= sizeof(s->packet.dgram);
        atto_agent_process_msg(s, &s->packet, bytes);
    }
    atto_agent_rx_start(s);
}

static int
atto_agent_rx_start(struct atto_agent_state *s)
{
    int ret;

    dm_v4v_async_init(&s->v4v, &s->async, s->rx_event);
    ioh_event_reset(&s->rx_event);
    ret = dm_v4v_recv(&s->v4v, (v4v_datagram_t*)&s->packet, sizeof(s->packet),
        &s->async);
    if (ret == 0)
        return 0;

    switch (ret) {
    case ERROR_IO_PENDING:
        break;
    default:
        warnx("%s: ReadFile failed", __FUNCTION__);
        return -1;
    }
    return 0;
}

static void
resize_timer_notify(void *opaque)
{
    struct atto_agent_state *s = opaque;

    if (s->can_send_resize)
        send_latest_resize(s);
    else
        /* check again in 100 ms */
        mod_timer(s->resize_timer, get_clock_ms(vm_clock) + 100);
}

int
atto_agent_send_resize_event(head_id_t head_id, unsigned xres, unsigned yres)
{
    struct atto_agent_state *s = &state;

    assert(head_id >= 0 && head_id < FB_HEADMAX);

    if (!s->initialized)
        return -1;

    debug_printf("receive resize req %ux%u\n", xres, yres);
    mod_timer(s->resize_timer, get_clock_ms(vm_clock) + RESIZE_BACKOFF_MS);

    critical_section_enter(&s->cs);
    s->headres[head_id].xres = xres;
    s->headres[head_id].yres = yres;
    s->headres[head_id].pending = 1;
    critical_section_leave(&s->cs);

    return 0;
}

int
atto_agent_init(void)
{
    BOOLEAN ret;
    v4v_bind_values_t bind = { };
    struct atto_agent_state *s = &state;

    if (!vm_attovm_mode)
        return 0;

    debug_printf("initializing atto agent\n");
    ret = dm_v4v_open(&s->v4v, RING_SIZE);
    if (ret) {
        warnx("%s: v4v_open error %x", __FUNCTION__, ret);
        return -1;
    }

    bind.ring_id.addr.port = ATTO_AGENT_V4V_PORT;
    bind.ring_id.addr.domain = V4V_DOMID_ANY;
    bind.ring_id.partner = V4V_DOMID_UUID;
    memcpy(&bind.partner, v4v_idtoken, sizeof(bind.partner));

    ret = dm_v4v_bind(&s->v4v, &bind);
    if (ret) {
        warnx("%s: v4v_bind error %x", __FUNCTION__, ret);
        dm_v4v_close(&s->v4v);
        return -1;
    }

    critical_section_init(&s->tx_queue_lock);
    TAILQ_INIT(&s->tx_queue);

    s->partner_id = bind.ring_id.partner;
    s->resize_timer = new_timer_ms(vm_clock, resize_timer_notify, s);
    ioh_event_init(&s->rx_event);
    ioh_event_init(&s->tx_event);

    critical_section_init(&s->cs);
    ioh_add_wait_object(&s->rx_event, atto_agent_rx_event, s, NULL);
    ioh_add_wait_object(&s->tx_event, atto_agent_tx_event, s, NULL);
    atto_agent_rx_start(s);
    s->keyboard_layout = 0;
    debug_printf("atto agent: initialized\n");
    s->initialized = 1;

    /* we'll receive dirty rect events from guest atto-agent, mask periodic refresh */
    console_mask_periodic(1);

    return 0;
}

int
atto_agent_window_ready(void)
{
    struct atto_agent_state *s = &state;

    return s->initialized && s->can_send_resize;
}

static void
send_latest_keyboard_layout(struct atto_agent_state *s)
{
    struct atto_agent_varlen_packet *resp = &s->resp;

    critical_section_enter(&s->cs);
    memset(resp, 0, sizeof(*resp));
    resp->msg.type = ATTO_MSG_KBD_LAYOUT_RET;
    resp->msg.win_kbd_layout = s->keyboard_layout;

    if (send_message(s, resp, sizeof(struct atto_agent_packet), 0) == 0) {
        debug_printf("%s: sent keyboard layout changed to 0x%x\n",
                      __FUNCTION__,  s->keyboard_layout);
    }
    critical_section_leave(&s->cs);
}

void
atto_agent_change_kbd_layout(unsigned win_kbd_layout)
{
    struct atto_agent_state *s = &state;
    int changed = win_kbd_layout != s->keyboard_layout;
    s->keyboard_layout = win_kbd_layout;
    if (changed && atto_agent_window_ready()) {
        send_latest_keyboard_layout(s);
    }
}

void
atto_agent_request_keyboard_focus(unsigned offer, uint32_t head_id)
{
    struct atto_agent_state *s = &state;
    struct atto_agent_varlen_packet *resp = &s->resp;

    critical_section_enter(&s->cs);
    memset(resp, 0, sizeof(*resp));
    resp->msg.type = ATTO_MSG_KBD_FOCUS_RET;
    resp->msg.offer_kbd_focus = offer;
    resp->msg.head_id = head_id;

    if (send_message(s, resp, sizeof(struct atto_agent_packet), 0) == 0) {
#if 0
        debug_printf("%s: sent kbd focus offer %u\n",
                      __FUNCTION__,  offer);
#endif
    }
    critical_section_leave(&s->cs);
}

static void
tx_queue_cleanup(struct atto_agent_state *s)
{
    atto_agent_pending_send_t *ps;

    for (;;) {
        ps = TAILQ_FIRST(&s->tx_queue);
        if (ps == NULL)
            break;
        TAILQ_REMOVE(&s->tx_queue, ps, entry);
        dm_v4v_async_cancel(&ps->async);
        free_pending_send(ps);
    }
}

void
atto_agent_cleanup(void)
{
    struct atto_agent_state *s = &state;

    if (!vm_attovm_mode)
        return;

    if (s->initialized) {
        dm_v4v_close(&s->v4v);
        ioh_event_close(&s->tx_event);
        ioh_event_close(&s->rx_event);
        tx_queue_cleanup(s);
        critical_section_free(&s->tx_queue_lock);
        critical_section_free(&s->cs);
        del_timer(s->resize_timer);
        s->initialized = 0;
    }
}
