/*
 * Copyright 2019, Bromium, Inc.
 * Author: Tomasz Wroblewski <tomasz.wroblewski@gmail.com>
 * SPDX-License-Identifier: ISC
 */

#ifndef UXEN_ECHO_COMMON_H_
#define UXEN_ECHO_COMMON_H_

#define UXEN_ECHO_PORT 8888
#define UXEN_ECHO_US_PORT 8889
#define UXEN_ECHO_RING_SIZE 4096

#if defined(_MSC_VER)
#define UXENECHO_PACKED
#pragma pack(push, 1)
#pragma warning(push)
#else
#define UXENECHO_PACKED __attribute__((packed))
#endif

struct uxenecho_msg {
  uint64_t id;
} UXENECHO_PACKED;

#undef UXENECHO_PACKED
#if defined(_MSC_VER)
#pragma warning(pop)
#pragma pack(pop)
#endif

#endif
