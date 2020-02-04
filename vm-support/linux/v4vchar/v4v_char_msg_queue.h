/*
 * Copyright 2020, Bromium, Inc.
 * Author: Simon Haggett <simon.haggett@gmail.com>
 * SPDX-License-Identifier: ISC
 */

#pragma once

#include <linux/types.h>

#include "v4v_char_msgdefs.h"

/*
 * \brief Message queue structure.
 *
 * The memory for the buffer is allocated by the caller. The message queue operates as a circular queue, where all
 * elements are usable.
 */
struct v4v_char_msg_queue
{
    struct v4v_char_msg *buffer;
    size_t capacity;

    size_t head;
    size_t tail;
};

/*
 * \brief Initialises a message queue.
 *
 * \param queue The message queue to initialise.
 * \param buffer The message buffer to use for the queue.
 * \param capacity The number of messages that buffer can hold.
 */
void v4v_char_msg_queue_init(struct v4v_char_msg_queue *queue, struct v4v_char_msg *buffer, size_t capacity);

/*
 * \brief Indicates if a message queue is empty.
 *
 * \param pQueue Pointer to the message queue.
 *
 * \return Non-zero if the message queue is empty.
 */
#define v4v_char_msg_queue_is_empty(pQueue) \
    ((pQueue)->head == (pQueue)->capacity)

/*
 * \brief Indicates if a message queue is full.
 *
 * \param pQueue Pointer to the message queue.
 *
 * \return Non-zero if the message queue is full.
 */
#define v4v_char_msg_queue_is_full(pQueue) \
    ((((pQueue)->head == 0) && ((pQueue)->tail == (pQueue)->capacity - 1)) || \
        (((pQueue)->head < (pQueue)->capacity) && ((pQueue)->tail == (pQueue)->head - 1)))

/*
 * \brief Returns the current size of a message queue.
 *
 * This is the number of messages that the queue currently holds.
 *
 * \param queue The message queue.
 *
 * \return The current size.
 */
size_t v4v_char_msg_queue_size(struct v4v_char_msg_queue *queue);

/*
 * \brief Returns the head of a message queue.
 *
 * If the queue size is 1, then the head and tail are the same message.
 *
 * \param queue The message queue.
 *
 * \return The head of the queue, or NULL if the queue is empty.
 */
struct v4v_char_msg* v4v_char_msg_queue_head(struct v4v_char_msg_queue *queue);

/*
 * \brief Returns the tail of a message queue.
 *
 * If the queue size is 1, then the head and tail are the same message.
 *
 * \param queue The message queue.
 *
 * \return The tail of the queue, or NULL if the queue is empty.
 */
struct v4v_char_msg* v4v_char_msg_queue_tail(struct v4v_char_msg_queue *queue);

/*
 * \brief Dequeues the head of a message queue.
 *
 * This does nothing if the queue is empty.
 *
 * \param queue The message queue.
 */
void v4v_char_msg_queue_dequeue(struct v4v_char_msg_queue *queue);

/*
 * \brief Enqueues a new message to a message queue.
 *
 * \param queue The message queue.
 * \param type The message type.
 * \param payload The message payload (NULL if no payload).
 * \param payloadSize The message payload size (0 if no payload).
 *
 * \return The new message instance or NULL if the queue is full.
 */
struct v4v_char_msg* v4v_char_msg_enqueue(struct v4v_char_msg_queue *queue, uint16_t type, const void *payload,
        uint32_t payload_size);
