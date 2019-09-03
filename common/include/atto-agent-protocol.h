/*
 * Copyright 2019, Bromium, Inc.
 * Author: Tomasz Wroblewski <tomasz.wroblewski@gmail.com>
 * SPDX-License-Identifier: ISC
 */

#ifndef _ATTO_AGENT_PROTOCOL_H_
#define _ATTO_AGENT_PROTOCOL_H_

#define ATTO_AGENT_V4V_PORT 44449

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
    uint8_t pad[3];
    uint32_t head_id;
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
        unsigned offer_kbd_focus;
        unsigned win_kbd_layout;
    };
} __attribute__((packed));

#endif
