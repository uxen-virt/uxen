/*
 * Copyright 2015, Bromium, Inc.
 * Author: Tomasz Wroblewski <tomasz.wroblewski@gmail.com>
 * SPDX-License-Identifier: ISC
 */

#ifndef _CLIPBOARD_PROTOCOL_H_
#define _CLIPBOARD_PROTOCOL_H_

#include <stdint.h>

#define CLIP_PORT 44445
#define CLIP_NOTIFY_PORT 44446

struct __attribute__((packed)) clip_notify_data {
    uint32_t type;
    uint32_t len;
    uint8_t data[0];
};

struct clip_ctx;

struct clip_ctx *clip_open(int domain, int port, void* (*mem_alloc)(size_t),
                           void (*mem_free)(void*));
void clip_close(struct clip_ctx*);
int clip_send_bytes(struct clip_ctx *ctx, void *data, int len);
int clip_recv_bytes(struct clip_ctx *ctx, void **data, int *len);
void clip_wait_io(struct clip_ctx*);
void clip_cancel_io(struct clip_ctx*);

#endif
