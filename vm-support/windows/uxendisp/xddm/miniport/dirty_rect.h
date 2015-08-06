/*
 * Copyright 2015, Bromium, Inc.
 * Author: Piotr Foltyn <piotr.foltyn@gmail.com>
 * SPDX-License-Identifier: ISC
 */

#ifndef _DIRTY_RECT_H_
#define _DIRTY_RECT_H_

typedef void *dr_ctx_t;
typedef void (*disable_tracking_ptr)(void *);

struct rect;

dr_ctx_t dr_init(void *dev, disable_tracking_ptr fn);
void     dr_safe_to_draw(dr_ctx_t context);
void     dr_update(dr_ctx_t context, struct rect *rect);
void     dr_deinit(dr_ctx_t context);

#endif // _DIRTY_RECT_H_