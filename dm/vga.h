/*
 * Copyright 2012-2015, Bromium, Inc.
 * SPDX-License-Identifier: ISC
 */

#ifndef _VGA_H_
#define _VGA_H_

typedef void (*vga_hw_update_ptr)(void *);
typedef void (*vga_hw_invalidate_ptr)(void *);
typedef void (*vga_hw_screen_dump_ptr)(void *, const char *);
typedef void (*vga_hw_text_update_ptr)(void *, console_ch_t *);

enum vga_retrace_method {
    VGA_RETRACE_DUMB,
    VGA_RETRACE_PRECISE
};

extern enum vga_retrace_method vga_retrace_method;

#endif	/* _VGA_H_ */
