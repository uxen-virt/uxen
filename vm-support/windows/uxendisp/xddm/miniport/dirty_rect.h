/*
 * Copyright 2015-2016, Bromium, Inc.
 * Author: Piotr Foltyn <piotr.foltyn@gmail.com>
 * SPDX-License-Identifier: ISC
 */

#ifndef _DIRTY_RECT_H_
#define _DIRTY_RECT_H_

typedef void *dr_ctx_t;
typedef void (*disable_tracking_ptr)(void *);
typedef void (*get_last_mode_ptr)(ULONG *, ULONG *);

struct rect;

dr_ctx_t dr_init(void *dev, disable_tracking_ptr fn, get_last_mode_ptr fn2);
void     dr_safe_to_draw(dr_ctx_t context);
void     dr_update(dr_ctx_t context, struct rect *rect);
void     dr_deinit(dr_ctx_t context);

#endif // _DIRTY_RECT_H_
