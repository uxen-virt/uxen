/*
 * Copyright 2012-2015, Bromium, Inc.
 * Author: Julian Pidancet <julian@pidancet.net>
 * SPDX-License-Identifier: ISC
 */

#ifndef _UXENDISP_ESC_H_
#define _UXENDISP_ESC_H_

/* Escape code: GDI->display driver */
enum {
    UXENDISP_ESCAPE_SET_CUSTOM_MODE = 0x10001,
};

typedef struct {
    unsigned long width;
    unsigned long height;
    /* bpp ? */
} UXENDISPCustomMode;

#endif /* _UXENDISP_ESC_H_ */
