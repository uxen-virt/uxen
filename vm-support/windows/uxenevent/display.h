/*
 * Copyright 2013-2015, Bromium, Inc.
 * Author: Julian Pidancet <julian@pidancet.net>
 * SPDX-License-Identifier: ISC
 */

#ifndef _UXENDISP_RESIZE_H_
#define _UXENDISP_RESIZE_H_

int display_get_size(int *w, int *h);
int display_resize(int w, int h);
int display_init(void);
void display_blank(int blank);

#endif  /* _UXENDISP_RESIZE_H_ */
