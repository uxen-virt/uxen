/*
 * Copyright 2017, Bromium, Inc.
 * Author: Piotr Foltyn <piotr.foltyn@gmail.com>
 * SPDX-License-Identifier: ISC
 */

#pragma once

typedef void (*brh264_recv_mt_fn )(void* priv, struct brh264_data* mt);
typedef void (*brh264_recv_enc_fn)(void* priv, struct brh264_data* enc);
typedef void (*brh264_recv_dec_fn)(void* priv, struct brh264_data* dec);
typedef void (*brh264_recv_res_fn)(void* priv, __int32 res);

struct brh264_recv_callbacks
{
    brh264_recv_mt_fn  brh264_recv_mt;
    brh264_recv_enc_fn brh264_recv_enc;
    brh264_recv_dec_fn brh264_recv_dec;
    brh264_recv_res_fn brh264_recv_res;
};

typedef void* brh264_ctx;

struct brh264_data
{
    unsigned __int32 params_size;
    unsigned __int8* params;
    unsigned __int32 data_size;
    unsigned __int8* data;
};

void brh264_send_mt(brh264_ctx c, struct brh264_data* mt);
void brh264_send_enc(brh264_ctx c, struct brh264_data* enc);
void brh264_send_dec(brh264_ctx c, struct brh264_data* dec);
void brh264_send_res(brh264_ctx c, __int32 res);

brh264_ctx brh264_create(void* priv, struct brh264_recv_callbacks* cb, unsigned char* tokenid, bool thread = false);
void brh264_destroy(brh264_ctx);
HANDLE brh264_recv_collect(brh264_ctx, BOOL wait = TRUE);
