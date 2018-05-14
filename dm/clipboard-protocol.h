/*
 * Copyright 2015-2018, Bromium, Inc.
 * Author: Tomasz Wroblewski <tomasz.wroblewski@gmail.com>
 * SPDX-License-Identifier: ISC
 */

#ifndef _CLIPBOARD_PROTOCOL_H_
#define _CLIPBOARD_PROTOCOL_H_

#include <stdint.h>

#define CLIP_PORT 44445
#define CLIP_NOTIFY_PORT 44446

#define CLIP_RING_SIZE 65536
#define CLIP_MAX_PACKET_LEN (CLIP_RING_SIZE - sizeof(struct clip_msg) - 1024)
#define CLIP_MAX_DATA_LEN (200 * 1024 * 1024)
#define CLIP_MAGIC 0x4C43504941504B43
#define CLIP_MSG_DATA 0
#define CLIP_MSG_ACK 1
#define CLIP_MSG_NACK 2

#define CLIP_TIMEOUT INFINITE


struct __attribute__((packed)) clip_notify_data {
    uint32_t type;
    uint32_t len;
    uint8_t data[0];
};

struct __attribute__((packed)) clip_msg {
    v4v_datagram_t dgram;
    uint64_t magic;
    uint8_t type;
    uint32_t seqid;
    uint32_t data_offset;
    uint32_t data_totallen;
    uint8_t data[0];
};

struct clip_ctx;

struct clip_ctx *clip_open(int domain, int port, unsigned char *v4v_idtoken,
                           void* (*mem_alloc)(size_t), void (*mem_free)(void*));
void clip_close(struct clip_ctx*);
int clip_send_bytes(struct clip_ctx *ctx, void *data, int len);
int clip_recv_bytes(struct clip_ctx *ctx, void **data, int *len);
void clip_wait_io(struct clip_ctx*);
void clip_cancel_io(struct clip_ctx*);

#endif
