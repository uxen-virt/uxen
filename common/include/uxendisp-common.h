/*
 * Copyright 2015-2016, Bromium, Inc.
 * Author: Piotr Foltyn <piotr.foltyn@gmail.com>
 * SPDX-License-Identifier: ISC
 */

#ifndef _DISP_H_
#define _DISP_H_

#if !defined(_MSC_VER)
#include <stdint.h>
#else
typedef __int32 int32_t;
#endif

#define UXENDISP_PORT 0xd1580
#define UXENDISP_ALT_PORT 0xd1581
#define UXENDISP_VBLANK_PORT 0xd1582
#define UXENDISP_RING_SIZE 4096
#define UXENDISP_MAX_MSG_LEN 24

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

#undef UXENDISP_PACKED
#if defined(_MSC_VER)
#pragma warning(pop)
#pragma pack(pop)
#endif


#endif // _DISP_H_
