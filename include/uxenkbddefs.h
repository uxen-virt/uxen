/*
 * Copyright 2019, Bromium, Inc.
 * Author: Paulian Marinca <paulian@marinca.net>
 * SPDX-License-Identifier: ISC
 */

#ifndef _UXENKBDDEF__H_
#define _UXENKBDDEF__H_

#define UXEN_KBD_V4V_PORT   44448
#define UXEN_KBD_RING_LEN   262144

#define UXEN_MIN_KBD_PKT_LEN 24

enum ns_event_msg_proto {
    NS_EVENT_MSG_PROTO_WINDOWS_WINDOW_PROC,
    NS_EVENT_MSG_PROTO_START_COMMAND_PROMPT,
    NS_EVENT_MSG_PROTO_WINDOWS_SET_TIME_ZONE_INFORMATION,
    NS_EVENT_MSG_PROTO_REMOTE_EXECUTE,
    NS_EVENT_MSG_PROTO_START_PERF_DATA_COLLECTION,
    NS_EVENT_MSG_PROTO_BLANK_DISPLAY,
    NS_EVENT_MSG_KBD_INPUT,
    NS_EVENT_MSG_MOUSE_INPUT,
    NS_EVENT_MSG_TOUCH_INPUT,
    NS_EVENT_MSG_NOP,
    NS_EVENT_MSG_PROTO_WINDOWS_SET_DYNAMIC_TIME_ZONE_INFORMATION,

    NS_EVENT_MSG_PROTO_MAX, /* Not a message ID */
};

#define NS_EVENT_MSG_KBD_INPUT_LEN 32
struct ns_event_msg_header {
    uint32_t proto;
    uint32_t len;
};

struct ns_event_msg_kbd_input {
    struct ns_event_msg_header hdr;
    uint8_t keycode;
    uint16_t repeat;
    uint8_t scancode;
    uint8_t flags;
    uint16_t nchars;
    uint8_t chars[NS_EVENT_MSG_KBD_INPUT_LEN];
    uint16_t nchars_bare;
    uint8_t chars_bare[NS_EVENT_MSG_KBD_INPUT_LEN];
};
#endif
