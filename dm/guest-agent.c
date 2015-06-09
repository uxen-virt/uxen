/*
 * Copyright 2015, Bromium, Inc.
 * Author: Julian Pidancet <julian@pidancet.net>
 * SPDX-License-Identifier: ISC
 */

#include <windowsx.h>

#include "config.h"

#include <err.h>
#include <stdbool.h>
#include <stdint.h>

#include <dm/dm.h>
#include "char.h"
#include "console.h"
#include "input.h"
#include "vmstate.h"

#include "guest-agent-proto.h"
#include "guest-agent.h"

#include <winioctl.h>
#define V4V_USE_INLINE_API
#include <windows/uxenv4vlib/gh_v4vapi.h>

#define GUEST_AGENT_PORT 44448
#define RING_SIZE 262144

static int v4v_up = 0 ;
static v4v_context_t v4v_context;
static HANDLE tx_event;
static HANDLE rx_event;

#define DECL_V4V_BUF(type) \
    struct { \
        v4v_datagram_t dgram; \
        struct type msg; \
    }

typedef struct GAbuf_struct {
    v4v_datagram_t dgram;
    union {
        struct ns_event_msg_header hdr;
        unsigned char data[NS_EVENT_MSG_MAX_LEN];
    };
} GAbuf;

static int read_pending = 0;
static OVERLAPPED read_ovlp = {0};
static GAbuf read_buf;

typedef struct WriteMsg_struct {
    LIST_ENTRY(WriteMsg_struct) node;

    OVERLAPPED o;
    GAbuf buf;
    DWORD len;

} WriteMsg;

static LIST_HEAD(,WriteMsg_struct) write_list =
    LIST_HEAD_INITIALIZER(&write_list);
static critical_section write_list_lock;

static int mouse_x = 0;
static int mouse_y = 0;

static int agent_present = 0;
static int agent_seen = 0;

static void
ps2_kbd_event(int scancode, int extended)
{
    struct input_event *input_event;
    BH *bh;

    bh = bh_new_with_data(input_event_cb, sizeof(*input_event),
                          (void **)&input_event);
    if (!bh)
        return;

    input_event->type = KEYBOARD_INPUT_EVENT;
    input_event->extended = extended;
    input_event->keycode = scancode;

    bh_schedule_one_shot(bh);
}

static void
ps2_mouse_event(int x, int y, int dz, int flags)
{
    struct input_event *input_event;
    BH *bh;

    bh = bh_new_with_data(input_event_cb, sizeof(struct input_event),
                          (void **)&input_event);
    if (!bh)
        return;

    input_event->type = MOUSE_INPUT_EVENT;
    if (input_mouse_is_absolute()) {
        input_event->x = x * 0x7fff /
                         (ds_get_width(display_state) - 1);
        input_event->y = y * 0x7fff /
                         (ds_get_height(display_state) - 1);
    } else {
        input_event->x = x - mouse_x;
        input_event->y = y - mouse_y;
    }
    input_event->dz = dz;
    input_event->button_state = flags;

    mouse_x = input_event->x;
    mouse_y = input_event->y;

    bh_schedule_one_shot(bh);
}


static void
guest_agent_recv_msg(GAbuf *buf)
{
    /*
     * This message was bounced back by the guest to notify us that
     * it failed to process it.
     *
     * As a result, if it was a keyboard or a mouse event, send them
     * back as PS2 events.
     */
    if (!ps2_fallback)
        return;

    switch (buf->hdr.proto) {
    case NS_EVENT_MSG_KBD_INPUT:
        {
            struct ns_event_msg_kbd_input *msg = (void *)&buf->hdr;

            if (buf->hdr.len != sizeof (*msg)) {
                debug_printf("%s: wrong message size %d\n", __FUNCTION__,
                             buf->hdr.len);
                break;
            }

            ps2_kbd_event(msg->scancode, msg->flags & 0x1);
        }
        break;
    case NS_EVENT_MSG_MOUSE_INPUT:
        {
            struct ns_event_msg_mouse_input *msg = (void *)&buf->hdr;

            if (buf->hdr.len != sizeof (*msg)) {
                debug_printf("%s: wrong message size %d\n", __FUNCTION__,
                             buf->hdr.len);
                break;
            }

            ps2_mouse_event(msg->x, msg->y,
                            (msg->dv < 0) ? 1 : ((msg->dv > 0) ? -1 : 0),
                            msg->flags & 0x13);
        }
        break;
    case NS_EVENT_MSG_PROTO_WINDOWS_WINDOW_PROC:
        {
            struct ns_event_msg_windows_window_proc *msg = (void *)&buf->hdr;

            if (buf->hdr.len != sizeof (*msg)) {
                debug_printf("%s: wrong message size %d\n", __FUNCTION__,
                             buf->hdr.len);
                break;
            }

            switch (msg->message) {
            case WM_LBUTTONDOWN:
            case WM_RBUTTONDOWN:
            case WM_MBUTTONDOWN:
            case WM_LBUTTONUP:
            case WM_RBUTTONUP:
            case WM_MBUTTONUP:
            case WM_MOUSEMOVE:
                ps2_mouse_event(msg->lParam & 0xffff,
                                (msg->lParam >> 16) & 0xffff,
                                0, msg->wParam & 0x13);
                break;

            case WM_MOUSEWHEEL:
                ps2_mouse_event(mouse_x, mouse_y,
                                GET_WHEEL_DELTA_WPARAM(msg->wParam) < 0 ? 1 : -1,
                                GET_KEYSTATE_WPARAM(msg->wParam) & 0x13);
                break;
            default:
                debug_printf("%s: unknown window message %"PRId64"\n",
                             __FUNCTION__, msg->message);
            }
        }
        break;
    default:
        debug_printf("%s: Unknown protocol id %d\n", __FUNCTION__,
                     buf->hdr.proto);
        break;
    }
}



static int
guest_agent_recv_start(void)
{
    DWORD bytes;
    DWORD ret;

    if (read_pending)
        return -1;


    memset(&read_ovlp, 0, sizeof(read_ovlp));
    read_ovlp.hEvent = rx_event;

    ret = ReadFile(v4v_context.v4v_handle, &read_buf, sizeof(read_buf), &bytes,
                  &read_ovlp);
    if (ret)
        return 0;

    switch (GetLastError()) {
    case ERROR_IO_PENDING:
        break;
    default:
        Wwarn("%s: ReadFile failed", __FUNCTION__);
        return -1;
    }

    read_pending = 1;
    return 0;
}

static void
guest_agent_recv_event(void *opaque)
{
    BOOL ret;
    DWORD bytes;

    ResetEvent(rx_event);

    if (!read_pending)
        return; /* XXX: shouldn't happen */

    ret = GetOverlappedResult(v4v_context.v4v_handle, &read_ovlp, &bytes,
                              FALSE);
    if (!ret) {
        switch (GetLastError()) {
        case ERROR_IO_INCOMPLETE:
            ResetEvent(rx_event);
            return;
        }

        Wwarn("%s: GetOverLappedResult", __FUNCTION__);

        read_pending = 0;
        guest_agent_recv_start();
        return;
    }
    read_pending = 0;

    if ((bytes < sizeof(read_buf.dgram) + sizeof(read_buf.hdr)) ||
        bytes < sizeof(read_buf.dgram) + read_buf.hdr.len) {
        debug_printf("%s: incomplete read, bytes=%ld\n", __FUNCTION__, bytes);

        guest_agent_recv_start();
        return;
    }

    guest_agent_recv_msg(&read_buf);
    guest_agent_recv_start();
}

static int guest_agent_nop(void);

static void
writelist_complete(void)
{
    WriteMsg *wm, *nwm;
    BOOL ret;
    DWORD bytes;

    critical_section_enter(&write_list_lock);
    LIST_FOREACH_SAFE(wm, &write_list, node, nwm) {
        ret = GetOverlappedResult(v4v_context.v4v_handle, &wm->o, &bytes,
                                  FALSE);
        if (!ret && (GetLastError() == ERROR_IO_INCOMPLETE))
            continue;

        LIST_REMOVE(wm, node);

        if (!ret) {
            switch(GetLastError()) {
            case ERROR_VC_DISCONNECTED:
                /* Fail buffer */
		guest_agent_recv_msg(&wm->buf);
		if (agent_seen)
                    agent_present = 0;
                debug_printf("%s: guest agent disconnected\n", __FUNCTION__);
                guest_agent_nop();
                break;
            default:
                Wwarn("%s: GetOverLappedResult proto=%d", __FUNCTION__,
                      wm->buf.hdr.proto);
            }
        } else {
            if (bytes != wm->len)
                debug_printf("%s: Short write %ld/%ld proto=%d\n", __FUNCTION__,
                             bytes, wm->len, wm->buf.hdr.proto);
            if (!agent_present)
                debug_printf("%s: guest agent connected\n", __FUNCTION__);
            agent_present = 1;
            agent_seen = 1;
        }
        free(wm);
    }
    critical_section_leave(&write_list_lock);
}

static void
guest_agent_xmit_event(void *opaque)
{
    ResetEvent(tx_event);
    writelist_complete();
}

static int
guest_agent_sendmsg(void *msg, size_t len, int dlo)
{
    BOOL ret;
    DWORD bytes;

    WriteMsg *wm;

    writelist_complete();

    if (agent_present && !agent_seen)
        dlo = 1;
    if (!dlo && !agent_present) {
        /* guest agent is not currently accepting input */
        return -1;
    }

    if (len > sizeof(wm->buf))
        return -1;

    wm = malloc(sizeof(WriteMsg));
    if (!wm)
        return -1;

    memset(&wm->o, 0, sizeof(wm->o));

    wm->o.hEvent = tx_event;

    memcpy(&wm->buf, msg, len);

    wm->buf.dgram.addr.port = GUEST_AGENT_PORT;
    wm->buf.dgram.addr.domain = vm_id;
    wm->buf.dgram.flags = dlo ? 0 : V4V_DATAGRAM_FLAG_IGNORE_DLO;
    wm->len = len;

    ret = WriteFile(v4v_context.v4v_handle, (void *)&wm->buf,
                    wm->len, &bytes, &wm->o);
    if (!ret) {
        switch (GetLastError()) {
        case ERROR_IO_PENDING:
            critical_section_enter(&write_list_lock);
            LIST_INSERT_HEAD(&write_list, wm, node);
            critical_section_leave(&write_list_lock);
            return 0;
        case ERROR_VC_DISCONNECTED:
            free(wm);
            return -1;
        default:
            Wwarn("%s: WriteFile", __FUNCTION__);
            free(wm);
            return -1;
        }
    }

    return 0;
}

static int
guest_agent_nop(void)
{
    DECL_V4V_BUF(ns_event_msg_nop) buf;

    buf.msg.msg.proto = NS_EVENT_MSG_NOP;
    buf.msg.msg.len = sizeof(buf.msg);

    return guest_agent_sendmsg(&buf, sizeof(buf), 1);
}

int
guest_agent_perf_collection(uint64_t mask, uint32_t interval, uint32_t samples)
{
    DECL_V4V_BUF(ns_event_msg_start_perf_data_collection) buf;

    buf.msg.msg.proto = NS_EVENT_MSG_PROTO_START_PERF_DATA_COLLECTION;
    buf.msg.msg.len = sizeof(buf.msg);

    buf.msg.counters_mask = mask;
    buf.msg.sampling_interval = interval;
    buf.msg.number_of_samples = samples;

    return guest_agent_sendmsg(&buf, sizeof(buf), 1);
}

int
guest_agent_execute(const char *command)
{
    DECL_V4V_BUF(ns_event_msg_remote_execute) *buf;
    int cmd_len, len;
    int ret;

    if (!command)
        return -1;

    cmd_len = strlen(command);
    len = sizeof(*buf) + cmd_len + 1;

    buf = calloc(1, len);
    if (!buf)
        return -1;

    buf->msg.msg.proto = NS_EVENT_MSG_PROTO_REMOTE_EXECUTE;
    buf->msg.msg.len = len - sizeof(buf->dgram);

    snprintf((void *)buf->msg.command, cmd_len + 1, "%s", command);

    ret = guest_agent_sendmsg(buf, len, 1);

    free(buf);

    return ret;
}

int
guest_agent_cmd_prompt(void)
{
    DECL_V4V_BUF(ns_event_msg_start_command_prompt) buf;

    buf.msg.msg.proto = NS_EVENT_MSG_PROTO_START_COMMAND_PROMPT;
    buf.msg.msg.len = sizeof(buf.msg);

    return guest_agent_sendmsg(&buf, sizeof(buf), 1);
}

int
guest_agent_kbd_event(uint8_t keycode, uint16_t repeat, uint8_t scancode,
                      uint8_t flags, int16_t nchars, wchar_t *chars)
{
    DECL_V4V_BUF(ns_event_msg_kbd_input) buf;
    size_t l;

    buf.msg.msg.proto = NS_EVENT_MSG_KBD_INPUT;
    buf.msg.msg.len = sizeof(buf.msg);

    buf.msg.keycode = keycode;
    buf.msg.repeat = repeat;
    buf.msg.scancode = scancode;
    buf.msg.flags = flags;

    l = ((nchars == -1) ? 1 : nchars) * sizeof(wchar_t);
    if (l > sizeof(buf.msg.buffer))
        l = sizeof(buf.msg.buffer);
    memcpy(buf.msg.buffer, chars, l);
    buf.msg.nchars = nchars;

    return guest_agent_sendmsg(&buf, sizeof(buf), 0);
}

int guest_agent_mouse_event(uint32_t x, uint32_t y, int32_t dv, int32_t dh,
                            uint32_t flags)
{
    DECL_V4V_BUF(ns_event_msg_mouse_input) buf;

    buf.msg.msg.proto = NS_EVENT_MSG_MOUSE_INPUT;
    buf.msg.msg.len = sizeof(buf.msg);

    buf.msg.x = x;
    buf.msg.y = y;
    buf.msg.dv = dv;
    buf.msg.dh = dh;
    buf.msg.flags = flags;

    return guest_agent_sendmsg(&buf, sizeof(buf), 0);
}

int
guest_agent_window_event(uint64_t hwnd, uint64_t message,
                         uint64_t wParam, uint64_t lParam)
{
    DECL_V4V_BUF(ns_event_msg_windows_window_proc) buf;

    buf.msg.msg.proto = NS_EVENT_MSG_PROTO_WINDOWS_WINDOW_PROC;
    buf.msg.msg.len = sizeof(buf.msg);

    buf.msg.hwnd = hwnd;
    buf.msg.message = message;
    buf.msg.wParam = wParam;
    buf.msg.lParam = lParam;

    switch (message) {
    case WM_LBUTTONDOWN:
    case WM_RBUTTONDOWN:
    case WM_MBUTTONDOWN:
    case WM_LBUTTONUP:
    case WM_RBUTTONUP:
    case WM_MBUTTONUP:
    case WM_MOUSEMOVE:
    case WM_XBUTTONDOWN:
    case WM_XBUTTONUP:
    case WM_MOUSEWHEEL:
    case WM_MOUSEHWHEEL:
        mouse_x = GET_X_LPARAM(lParam);
        mouse_y = GET_Y_LPARAM(lParam);
        break;
    }

    return guest_agent_sendmsg(&buf, sizeof(buf), 0);
}

int
guest_agent_set_time_zone(void *tzi)
{
    DECL_V4V_BUF(ns_event_msg_windows_set_time_zone_information) *buf;
    size_t len;
    int ret;

    if (!tzi)
        return -1;

    len = sizeof(*buf) + sizeof(TIME_ZONE_INFORMATION);

    buf = calloc(1, len);
    if (!buf)
        return -1;

    buf->msg.msg.proto = NS_EVENT_MSG_PROTO_WINDOWS_SET_TIME_ZONE_INFORMATION;
    buf->msg.msg.len = len - sizeof(buf->dgram);

    memcpy(buf->msg.time_zone_information, tzi, sizeof(TIME_ZONE_INFORMATION));

    ret = guest_agent_sendmsg(buf, len, 1);

    free(buf);

    return ret;
}

int
guest_agent_cleanup(void)
{
    WriteMsg *wm, *nwm;

    critical_section_enter(&write_list_lock);

    LIST_FOREACH_SAFE(wm, &write_list, node, nwm) {
        if (CancelIoEx(v4v_context.v4v_handle, &wm->o) &&
            GetOverlappedResult(v4v_context.v4v_handle, &wm->o, NULL, TRUE)) {
            LIST_REMOVE(wm, node);
            free(wm);
        }
    }

    if (read_pending)
        CancelIoEx(v4v_context.v4v_handle, &read_ovlp);

    critical_section_leave(&write_list_lock);

    if (v4v_up)
        v4v_close(&v4v_context);

    if (tx_event) {
        ioh_del_wait_object(&tx_event, NULL);
        CloseHandle(tx_event);
    }

    if (rx_event) {
        ioh_del_wait_object(&rx_event, NULL);
        CloseHandle(rx_event);
    }

    critical_section_free(&write_list_lock);

    return 0;
}

static void
guest_agent_save(QEMUFile *f, void *opaque)
{
    qemu_put_be32(f, agent_present);
}

static int
guest_agent_load(QEMUFile *f, void *opaque, int version_id)
{
    agent_present = qemu_get_be32(f);

    return 0;
}

int
guest_agent_init(void)
{
    BOOLEAN ret;
    v4v_ring_id_t id;
    OVERLAPPED o = {0};
    DWORD t;

    memset(&o, 0, sizeof(o));
    ret = v4v_open(&v4v_context, RING_SIZE, &o);
    if (!ret) {
        Wwarn("%s: v4v_open", __FUNCTION__);
        return -1;
    }

    if (!GetOverlappedResult(v4v_context.v4v_handle, &o, &t, TRUE)) {
        Wwarn("%s: v4v_open", __FUNCTION__);
        return -1;
    }

    id.addr.port = 0;
    id.addr.domain = V4V_DOMID_ANY;
    id.partner = vm_id;

    memset(&o, 0, sizeof(o));
    ret = v4v_bind(&v4v_context, &id, &o);
    if (!ret) {
        Wwarn("%s: v4v_bind", __FUNCTION__);
        v4v_close(&v4v_context);
        return -1;
    }

	v4v_up++;

     if (!GetOverlappedResult(v4v_context.v4v_handle, &o, &t, TRUE)) {
        Wwarn("%s: v4v_open", __FUNCTION__);
        return -1;
    }

    tx_event = CreateEvent(NULL, FALSE, FALSE, NULL);
    if (!tx_event) {
        v4v_close(&v4v_context);
        return -1;
    }

    rx_event = CreateEvent(NULL, FALSE, FALSE, NULL);
    if (!rx_event) {
        v4v_close(&v4v_context);
        CloseHandle(&tx_event);
        return -1;
    }

    critical_section_init(&write_list_lock);

    ioh_add_wait_object(&rx_event, guest_agent_recv_event, NULL, NULL);
    ioh_add_wait_object(&tx_event, guest_agent_xmit_event, NULL, NULL);

    guest_agent_recv_start();

    register_savevm(NULL, "guest-agent", 0, 0,
                    guest_agent_save,
                    guest_agent_load,
                    NULL);

    guest_agent_nop();

    return 0;
}
