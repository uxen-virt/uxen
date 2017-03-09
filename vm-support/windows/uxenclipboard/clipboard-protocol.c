/*
 * Copyright 2015-2017, Bromium, Inc.
 * SPDX-License-Identifier: ISC
 */

#include "../common/debug-user.h"
#define CLIPLOG(fmt, ...) uxen_msg(fmt, ##__VA_ARGS__)

#define CLIP_CLIENT

#undef _WIN32_WINNT
#include <dm/clipboard-protocol.c>
