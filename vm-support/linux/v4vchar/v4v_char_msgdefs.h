/*
 * Copyright 2020, Bromium, Inc.
 * Author: Simon Haggett <simon.haggett@gmail.com>
 * SPDX-License-Identifier: ISC
 */

#pragma once

/*
 * \file V4V interface for the v4vchar kernel module.
 *
 * This file describes the message types and data structures supported by the v4vchar kernel module. Clients of this
 * module send and receive V4V messages on a custom V4V port. Each message is a struct v4v_char_msg instance, with a
 * message type and a payload with output data. A client may send a connect message to start receiving data stream
 * messages for the module's character device. A client may subsequently send a disconnect message to stop receiving
 * the data stream.
 */

/*
 * \brief Request connection to the character device's data stream.
 *
 * This message is sent by the client.
 *
 * This message has no payload. On success, the module shall start sending V4V_CHAR_MSG_TYPE_DATA_STREAM messages.
 */
#define V4V_CHAR_MSG_TYPE_CONNECT 0

/*
 * \brief Request disconnection from the character device's data stream.
 *
 * This message is sent by the client.
 *
 * This message has no payload. On success, the module shall stop sending V4V_CHAR_MSG_TYPE_DATA_STREAM messages.
 */
#define V4V_CHAR_MSG_TYPE_DISCONNECT 1

/*
 * \brief A message containing the next block of data in the data stream.
 *
 * This message is sent by the module.
 *
 * The structure of the data is unknown. The payload is the data bytes.
 */
#define V4V_CHAR_MSG_TYPE_DATA_STREAM 2

/*
 * \brief The V4V ring size used by the v4vchar kernel module.
 */
#define V4V_CHAR_V4V_RING_SIZE_BYTES (256 * 1024)

#define V4V_CHAR_MSG_MAX_PAYLOAD_BYTES (4096 - sizeof(struct v4v_char_hdr))

/* Pack structures, using directives that GCC and MSVC both understand. */
#pragma pack(push, 1)

/*
 * \brief Message header structure.
 */
struct v4v_char_hdr
{
    /*
     * \brief The message type.
     *
     * This must be a V4V_CHAR_MSG_TYPE_ value.
     */
    uint16_t type;

    /*
     * \brief Reserved field.
     *
     * The value of this field is undefined and must be ignored when parsing messages. This field is currently used to
     * provide padding.
     */
    uint16_t reserved1;

    /*
     * \brief The message payload size (in bytes).
     *
     * This is the payload size only, the message header is not included in this size.
     */
    uint32_t payload_size;

};

/*
 * \brief Message structure.
 */
struct v4v_char_msg
{
    /*
     * \brief Message header.
     */
    struct v4v_char_hdr header;

    /*
     * \brief Message payload.
     *
     * The number of valid bytes is described by the payload_size member.
     */
    uint8_t payload[V4V_CHAR_MSG_MAX_PAYLOAD_BYTES];

};

#pragma pack(pop)     /* pack(push, 1) */
