/*
 * Copyright 2014-2015, Bromium, Inc.
 * Author: Julian Pidancet <julian@pidancet.net>
 * SPDX-License-Identifier: ISC
 */

#ifndef _CONSOLE_RPC_H_
#define _CONSOLE_RPC_H_

#include <stdint.h>

struct uxenconsole_msg_header
{
    uint32_t type;
    uint32_t len;
};

enum uxenconsole_msg_type
{
    UXENCONSOLE_MSG_TYPE_RESIZE_SURFACE     = 0,
    UXENCONSOLE_MSG_TYPE_INVALIDATE_RECT    = 1,
    UXENCONSOLE_MSG_TYPE_MOUSE_EVENT        = 2,
    UXENCONSOLE_MSG_TYPE_KEYBOARD_EVENT     = 3,
    UXENCONSOLE_MSG_TYPE_UPDATE_CURSOR      = 4,
    UXENCONSOLE_MSG_TYPE_REQUEST_RESIZE     = 5,
    UXENCONSOLE_MSG_TYPE_KEYBOARD_LEDSTATE  = 6,
    UXENCONSOLE_MSG_TYPE_CLIPBOARD_PERMIT   = 7,
};

struct uxenconsole_msg_resize_surface {
    struct uxenconsole_msg_header header;
    uint32_t width;
    uint32_t height;
    uint32_t linesize;
    uint32_t length;
    uint32_t bpp;
    uint32_t offset;
    uintptr_t shm_handle;
};

struct uxenconsole_msg_invalidate_rect {
    struct uxenconsole_msg_header header;
    int32_t x;
    int32_t y;
    int32_t w;
    int32_t h;
};

struct uxenconsole_msg_mouse_event {
    struct uxenconsole_msg_header header;
    uint32_t x;
    uint32_t y;
    int32_t dv;
    int32_t dh;
    unsigned int flags;
};

struct uxenconsole_msg_keyboard_event {
    struct uxenconsole_msg_header header;
    uint32_t keycode;
    uint32_t repeat;
    uint32_t scancode;
    uint32_t flags;
    uint8_t chars[0];
};

struct uxenconsole_msg_update_cursor {
    struct uxenconsole_msg_header header;
    uint32_t w;
    uint32_t h;
    uint32_t hot_x;
    uint32_t hot_y;
    uint32_t mask_offset;
    uint32_t flags;
    uintptr_t shm_handle;
};

struct uxenconsole_msg_request_resize {
    struct uxenconsole_msg_header header;
    uint32_t width;
    uint32_t height;
};

struct uxenconsole_msg_keyboard_ledstate {
    struct uxenconsole_msg_header header;
    uint32_t state;
};

struct uxenconsole_msg_clipboard_permit {
    struct uxenconsole_msg_header header;
    uint32_t permit_type;
};

#endif /* _CONSOLE_RPC_H_ */
