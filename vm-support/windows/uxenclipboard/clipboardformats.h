/*
 * Copyright 2013-2015, Bromium, Inc.
 * SPDX-License-Identifier: ISC
 */

#ifndef _CLIPBOARD_FORMATS_H
#define _CLIPBOARD_FORMATS_H
int uxenclipboard_parse_remote_format_announce(char *data, int count);
int uxenclipboard_prepare_format_announce(char *outbuf, int len);
int uxenclipboard_get_announced_format(unsigned int idx, unsigned int *local,
    unsigned int *remote);
unsigned int uxenclipboard_translate_announced_format(unsigned int fmt);
#define UXENCLIPBOARD_DIRECTION_IN 0
#define UXENCLIPBOARD_DIRECTION_OUT 1
int uxenclipboard_is_allowed_format(int direction, unsigned int fmt,
    wchar_t* name);
int uxenclipboard_init_formats_critical_section();
int uxenclipboard_test_format_written(unsigned int remotefmt, int *written);
int uxenclipboard_mark_format_written(unsigned int remotefmt, int written);

BOOL WINAPI mingw_AddClipboardFormatListener(HWND hwnd);
#endif

