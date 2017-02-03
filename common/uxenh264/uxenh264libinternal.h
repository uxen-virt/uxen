/*
 * Copyright 2017, Bromium, Inc.
 * Author: Piotr Foltyn <piotr.foltyn@gmail.com>
 * SPDX-License-Identifier: ISC
 */

#pragma once

#define BRH264_BASE_PORT   0xf4c0
#define BRH264_RING_SIZE   (1024 * 1024)

#define BRH264_ACK         0x00
#define BRH264_NACK        0x01
#define BRH264_READY       0x02
#define BRH264_MT_DATA     0x03
#define BRH264_ENC_DATA    0x04
#define BRH264_DEC_DATA    0x05

#pragma pack(push, 1)
struct brh264_meta_msg
{
    v4v_datagram_t dgram;
    __int32 type;
    unsigned __int32 params_size;
    unsigned __int32 data_size;
    unsigned __int8 params_hdr[sizeof(v4v_datagram_t)];
    unsigned __int8 data_hdr[sizeof(v4v_datagram_t)];
};
#pragma pack(pop)
