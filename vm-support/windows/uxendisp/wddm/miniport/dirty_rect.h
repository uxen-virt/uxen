/*
 * Copyright 2015, Bromium, Inc.
 * Author: Piotr Foltyn <piotr.foltyn@gmail.com>
 * SPDX-License-Identifier: ISC
 */

#ifndef _DIRTY_RECT_H_
#define _DIRTY_RECT_H_

typedef void *dr_ctx_t;
typedef void (*disable_tracking_ptr)(void *);

dr_ctx_t dr_init(void *dev, disable_tracking_ptr fn);
void     dr_send(dr_ctx_t context, ULONG d_num, RECT *dirty_rect);
void     dr_deinit(dr_ctx_t context);

#endif // _DIRTY_RECT_H_
