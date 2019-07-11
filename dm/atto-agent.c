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

#include <err.h>
#include <stdint.h>

#define RING_SIZE 262144
#define V4V_PORT 44449

#define ATTO_MSG_GETURL 0
#define ATTO_MSG_GETURL_RET 1
#define ATTO_MSG_GETBOOT 2
#define ATTO_MSG_GETBOOT_RET 3
#define ATTO_MSG_RESIZE 4
#define ATTO_MSG_RESIZE_RET 5

#define ATTO_MSG_CURSOR_TYPE        6
#define ATTO_MSG_CURSOR_TYPE_RET    7
#define ATTO_MSG_CURSOR_CHANGE      8
#define ATTO_MSG_CURSOR_CHANGE_RET  9
#define ATTO_MSG_CURSOR_GET_SM      10
#define ATTO_MSG_CURSOR_GET_SM_RET  11
#define ATTO_MSG_KBD_LAYOUT         12
#define ATTO_MSG_KBD_LAYOUT_RET     13
#define ATTO_MSG_KBD_FOCUS          14
#define ATTO_MSG_KBD_FOCUS_RET      15

struct atto_agent_msg {
    uint8_t type;
    union {
        char string[512];
        struct {
            uint32_t xres;
            uint32_t yres;
        };
        struct {
            uint32_t ctype;
            uint64_t ccursor;
            uint32_t xhot;
            uint32_t yhot;
            uint32_t nx;
            uint32_t ny;
            uint32_t len;
            uint8_t bitmap[];
        };
        unsigned win_kbd_layout;
        unsigned offer_kbd_focus;
    };
} __attribute__((packed));

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

#define MAX_STRING_LEN (sizeof(struct atto_agent_varlen_packet) - \
                        offsetof(struct atto_agent_varlen_packet, msg.string))

struct atto_agent_state {
    int initialized;
    int tx_busy;
    int can_send_resize;
    uint32_t xres_last;
    uint32_t yres_last;
    v4v_context_t v4v;
    v4v_async_t async;
    ioh_event rx_event;
    ioh_event tx_event;
    struct atto_agent_varlen_packet packet;
    struct atto_agent_varlen_packet resp;
    uint32_t partner_id;
    Timer *resize_timer;
    critical_section cs;
    struct display_state *ds;
    uint32_t keyboard_layout;
};

#define RESIZE_BACKOFF_MS 400

static struct atto_agent_state state;

static int atto_agent_rx_start(struct atto_agent_state *s);
static void send_latest_keyboard_layout(struct atto_agent_state *s);

static int
send_message(struct atto_agent_state *s,
    struct atto_agent_varlen_packet *resp,
    size_t resp_len,
    uint32_t port)
{
    int err;

#if 0
    if (s->tx_busy) {
        debug_printf("atto-agent: can't send, busy\n");
        return -1;
    }
#endif
    resp->dgram.addr.port = port ? port : V4V_PORT;
    resp->dgram.addr.domain = s->partner_id;
    resp->dgram.flags = 0;

    dm_v4v_async_init(&s->v4v, &s->async, s->tx_event);
    ioh_event_reset(&s->tx_event);
    s->tx_busy = 1;
    err = dm_v4v_send(&s->v4v, (v4v_datagram_t*)resp,
        resp_len, &s->async);
    if (err && err != ERROR_IO_PENDING) {
        warnx("%s: dm_v4v_send failed with %d\n", __FUNCTION__, err);
        s->tx_busy = 0;
        return -1;
    }

    return 0;
}

static void
send_latest_resize(struct atto_agent_state *s)
{
    critical_section_enter(&s->cs);
    if (s->xres_last && s->yres_last) {
        struct atto_agent_varlen_packet *resp = &s->resp;

        memset(resp, 0, sizeof(*resp));

        resp->msg.type = ATTO_MSG_RESIZE_RET;
        resp->msg.xres = s->xres_last;
        resp->msg.yres = s->yres_last;

        if (send_message(s, resp, sizeof(struct atto_agent_packet), 0) == 0) {
            debug_printf("sent resize to %ux%u\n",
                        (unsigned) s->xres_last, (unsigned) s->yres_last);
            s->xres_last = 0;
            s->yres_last = 0;
        }
    }
    critical_section_leave(&s->cs);
}

static void
process_x11_cursor(struct atto_agent_state *s,
    struct atto_agent_msg *msg,
    int len)
{
    if (msg->ctype == (uint32_t) (-2)) {
        attovm_unmap_x11_cursor(msg->ccursor);
        return;
    }

    /* custom x11 cursor */
    if (msg->ctype == (uint32_t) (-1)) {
        if (len < (((uint8_t *) msg->bitmap) - ((uint8_t *) msg)) +
                 msg->len) {

           debug_printf("%s: too short message of x11 custom cursor, len=%d\n",
                        __FUNCTION__, len);
           return;
        }
        debug_printf("%s: atto_create_custom_cursor xptr %lx nbytes %u\n",
                     __FUNCTION__, (unsigned long) msg->ccursor,
                     (unsigned) msg->len);
        attovm_create_custom_cursor(msg->ccursor, msg->xhot, msg->yhot, msg->nx,
                                    msg->ny, msg->len, (uint8_t *)&msg->bitmap);
        /* Apparently we also need to activate in this case */
        attovm_set_x11_cursor(s->ds, msg->ccursor);

        return;
    }

    /* normal x11 cursor */
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
        process_x11_cursor(s, msg, len);
        send_back = 0;
    } else if (msg->type == ATTO_MSG_CURSOR_CHANGE) {
        attovm_set_x11_cursor(s->ds, msg->ccursor);
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

    s->tx_busy = 0;
    err = dm_v4v_async_get_result(&s->async, &bytes, false);
    if (err) {
        switch (err) {
        case ERROR_IO_INCOMPLETE:
            ioh_event_reset(&s->tx_event);
            return;
        }
        warnx("%s: dm_v4v_async_get_result failed with %d\n", __FUNCTION__,
              err);
        return;
    }
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
atto_agent_send_resize_event(unsigned xres, unsigned yres)
{
    struct atto_agent_state *s = &state;

    if (!s->initialized)
        return -1;

    debug_printf("receive resize req %ux%u\n", xres, yres);
    mod_timer(s->resize_timer, get_clock_ms(vm_clock) + RESIZE_BACKOFF_MS);

    critical_section_enter(&s->cs);
    s->xres_last = xres;
    s->yres_last = yres;
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

    bind.ring_id.addr.port = V4V_PORT;
    bind.ring_id.addr.domain = V4V_DOMID_ANY;
    bind.ring_id.partner = V4V_DOMID_UUID;
    memcpy(&bind.partner, v4v_idtoken, sizeof(bind.partner));

    ret = dm_v4v_bind(&s->v4v, &bind);
    if (ret) {
        warnx("%s: v4v_bind error %x", __FUNCTION__, ret);
        dm_v4v_close(&s->v4v);
        return -1;
    }

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

    return 0;
}

void
atto_agent_set_display_state(struct display_state *ds)
{
    state.ds = ds;
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
atto_agent_request_keyboard_focus(unsigned offer)
{
    struct atto_agent_state *s = &state;
    struct atto_agent_varlen_packet *resp = &s->resp;

    critical_section_enter(&s->cs);
    memset(resp, 0, sizeof(*resp));
    resp->msg.type = ATTO_MSG_KBD_FOCUS_RET;
    resp->msg.offer_kbd_focus = offer;

    if (send_message(s, resp, sizeof(struct atto_agent_packet), 0) == 0) {
#if 0
        debug_printf("%s: sent kbd focus offer %u\n",
                      __FUNCTION__,  offer);
#endif
    }
    critical_section_leave(&s->cs);
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
        critical_section_free(&s->cs);
        del_timer(s->resize_timer);
        s->initialized = 0;
    }
}
