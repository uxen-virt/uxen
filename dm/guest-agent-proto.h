/*
 * Copyright 2015-2016, Bromium, Inc.
 * Author: Julian Pidancet <julian@pidancet.net>
 * SPDX-License-Identifier: ISC
 */

#ifndef _GUEST_AGENT_PROTO_H_
#define _GUEST_AGENT_PROTO_H_

#define NS_EVENT_MSG_MAX_LEN 1024

struct ns_event_msg_header {
    uint32_t proto;
    uint32_t len;
};

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

struct ns_event_msg_windows_window_proc {
    struct ns_event_msg_header msg;
    uint64_t hwnd;
    uint64_t message;
    uint64_t wParam;
    uint64_t lParam;
};

struct ns_event_msg_start_command_prompt {
    struct ns_event_msg_header msg;
};

struct ns_event_msg_windows_set_time_zone_information {
    struct ns_event_msg_header msg;
    uint8_t time_zone_information[];
};

struct ns_event_msg_windows_set_dynamic_time_zone_information {
    struct ns_event_msg_header msg;
    uint8_t dynamic_time_zone_information[];
};

struct ns_event_msg_change_kb_layout {
    struct ns_event_msg_header msg;
    char kb_layout[];
};

struct ns_event_msg_remote_execute {
    struct ns_event_msg_header msg;
    char command[];
};

struct ns_event_msg_start_perf_data_collection {
    struct ns_event_msg_header msg;
    uint64_t counters_mask;
    uint32_t sampling_interval;
    uint32_t number_of_samples;
};

struct ns_event_msg_blank_display {
    struct ns_event_msg_header msg;
    int enable;
};

struct ns_event_msg_kbd_input {
    struct ns_event_msg_header msg;
    uint8_t keycode;
    uint16_t repeat;
    uint8_t scancode;
    uint8_t flags;
    int16_t nchars;
    uint8_t buffer[8];
};

struct ns_event_msg_mouse_input {
    struct ns_event_msg_header msg;
    uint32_t x;
    uint32_t y;
    int32_t dv;
    int32_t dh;
    uint32_t flags;
};

struct ns_event_touch_contact {
        uint32_t id;
#define NS_EVENT_TOUCH_MASK_CONTACTAREA         0x00000001
#define NS_EVENT_TOUCH_MASK_ORIENTATION         0x00000002
#define NS_EVENT_TOUCH_MASK_PRESSURE            0x00000004
        uint32_t mask;
#define NS_EVENT_TOUCH_FLAG_PRIMARY             0x00000001
#define NS_EVENT_TOUCH_FLAG_INRANGE             0x00000002
#define NS_EVENT_TOUCH_FLAG_INCONTACT           0x00000004
#define NS_EVENT_TOUCH_FLAG_DOWN                0x00000008
#define NS_EVENT_TOUCH_FLAG_UP                  0x00000010
        uint32_t flags;
        uint32_t x;
        uint32_t y;
	uint32_t left;
	uint32_t right;
	uint32_t top;
	uint32_t bottom;
        uint32_t orientation;
        uint32_t pressure;
};

struct ns_event_msg_touch_input {
    struct ns_event_msg_header msg;
    uint32_t count;
    struct ns_event_touch_contact contacts[0];
};

struct ns_event_msg_nop {
    struct ns_event_msg_header msg;
};

#endif  /* _GUEST_AGENT_PROTO_H_ */
