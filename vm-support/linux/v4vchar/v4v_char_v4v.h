/*
 * Copyright 2020, Bromium, Inc.
 * Author: Simon Haggett <simon.haggett@gmail.com>
 * SPDX-License-Identifier: ISC
 */

#pragma once

#include "v4v_char.h"

/*
 * \brief Performs V4V initialisation.
 *
 * \param context The struct v4v_char_context instance.
 * \param port The V4V port to bind to.
 *
 * \return Zero on success, or an errno error value on failure.
 */
int v4v_char_v4v_init(struct v4v_char_context *context, uint32_t port);

/*
 * \brief Frees V4V structures.
 *
 * \param context The struct v4v_char_context instance.
 */
void v4v_char_v4v_free(struct v4v_char_context *context);

/*
 * \brief Returns the head of the send waitqueue.
 *
 * \param context The struct v4v_char_context instance.
 *
 * \return The head of the send waitqueue.
 */
wait_queue_head_t* v4v_char_v4v_send_waitqueue(struct v4v_char_context *context);

/*
 * \brief Indicates whether data can currently be sent to the V4V client.
 *
 * If this returns non-zero, then at least 1 byte of data can be sent without blocking.
 *
 * \param context The struct v4v_char_context instance.
 *
 * \return Non-zero if data can be sent without blocking, zero otherwise.
 */
int v4v_char_v4v_can_send_data(struct v4v_char_context *context);

/*
 * \brief Sends data from userspace to the V4V client.
 *
 * This implements non-blocking I/O semantics, and returns -EAGAIN if the operation would block.
 *
 * \param context The struct v4v_char_context instance.
 * \param buf The userspace buffer containing the data to send.
 * \param size The size of buffer in bytes.
 *
 * \return The number of bytes sent on success, a negative errno value on failure.
 */
ssize_t v4v_char_v4v_send_user_data(struct v4v_char_context *context, const char __user *buf, size_t size);

/*
 * \brief Flushes the V4V channel.
 *
 * \param context The struct v4v_char_context instance.
 *
 * \return Zero on success, a negative errno value on failure.
 */
int v4v_char_v4v_flush(struct v4v_char_context *context);
