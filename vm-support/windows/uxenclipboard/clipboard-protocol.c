/*
 * Copyright 2015-2016, Bromium, Inc.
 * SPDX-License-Identifier: ISC
 */

#include <VBox/Log.h>
#define CLIPLOG(...) Log((__VA_ARGS__))

#undef _WIN32_WINNT
#include <dm/clipboard-protocol.c>
