/*
 * Copyright 2015-2017, Bromium, Inc.
 * Author: Piotr Foltyn <piotr.foltyn@gmail.com>
 * SPDX-License-Identifier: ISC
 */

#ifndef _DISP_H_
#define _DISP_H_

#if !defined(_MSC_VER)
#include <stdint.h>
#else
typedef __int32 int32_t;
typedef unsigned __int32 uint32_t;
typedef unsigned __int64 uint64_t;
#endif

#define UXENDISP_PORT 0xd1580
#define UXENDISP_ALT_PORT 0xd1581
#define UXENDISP_VBLANK_PORT 0xd1582
#define UXENDISP_RING_SIZE 4096
#define UXENDISP_MAX_MSG_LEN 1024

#if defined(_MSC_VER)
#define UXENDISP_PACKED
#pragma pack(push, 1)
#pragma warning(push)
#else
#define UXENDISP_PACKED __attribute__((packed))
#endif

struct dirty_rect {
    int32_t left;
    int32_t top;
    int32_t right;
    int32_t bottom;
} UXENDISP_PACKED;

/* Escape code: GDI->display driver */
enum {
    UXENDISP_ESCAPE_SET_CUSTOM_MODE = 0x10001,
    UXENDISP_ESCAPE_SET_VIRTUAL_MODE = 0x10002,
    UXENDISP_ESCAPE_IS_VIRT_MODE_ENABLED = 0x10003,
    UXENDISP_ESCAPE_MAP_FB = 0x10004,
    UXENDISP_ESCAPE_UNMAP_FB = 0x10005,
    UXENDISP_ESCAPE_UPDATE_RECT = 0x10006,
    UXENDISP_ESCAPE_SET_USER_DRAW_ONLY = 0x10007,
    UXENDISP_ESCAPE_SET_NO_PRESENT_COPY = 0x10008,
};

struct _UXENDISPCustomMode {
    int32_t esc_code;
    uint32_t width;
    uint32_t height;
    uint32_t x, y;

    union {
        int user_draw;
        int no_present_copy;
        uint64_t ptr;
    } UXENDISP_PACKED;
    /* bpp ? */
} UXENDISP_PACKED;

typedef struct _UXENDISPCustomMode UXENDISPCustomMode;

#undef UXENDISP_PACKED
#if defined(_MSC_VER)
#pragma warning(pop)
#pragma pack(pop)
#endif

#endif // _DISP_H_
