/*
 * Copyright 2013-2015, Bromium, Inc.
 * SPDX-License-Identifier: ISC
 */

#ifndef _UXEN_BMP_CONVERT_H
#define _UXEN_BMP_CONVERT_H
int uxenclipboard_convert_to_bmp(char* input, unsigned int input_size, char** output,
    unsigned int* output_size);
int uxenclipboard_gdi_startup();
void uxenclipboard_gdi_shutdown();
int uxenclipboard_getdata(int format, char** output, unsigned int* output_size);
int uxenclipboard_is_supported_graphics_format(wchar_t*);
#endif

