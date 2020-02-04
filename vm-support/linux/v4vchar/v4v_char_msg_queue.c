/*
 * Copyright 2020, Bromium, Inc.
 * Author: Simon Haggett <simon.haggett@gmail.com>
 * SPDX-License-Identifier: ISC
 */

#include <linux/string.h>

#include "v4v_char_msg_queue.h"

void v4v_char_msg_queue_init(struct v4v_char_msg_queue *queue, struct v4v_char_msg *buffer, size_t capacity)
{
    memset(queue, 0, sizeof(struct v4v_char_msg_queue));

    queue->buffer = buffer;
    queue->capacity = capacity;

    /* We mark an empty queue by setting head (and tail) to capacity. */
    queue->head = capacity;
    queue->tail = capacity;
}

size_t v4v_char_msg_queue_size(struct v4v_char_msg_queue *queue)
{
    size_t tail_unwrapped;

    if (v4v_char_msg_queue_is_empty(queue))
    {
        return 0;
    }

    tail_unwrapped = (queue->head > queue->tail) ? queue->tail + queue->capacity : queue->tail;
    return (tail_unwrapped - queue->head) + 1;
}

struct v4v_char_msg* v4v_char_msg_queue_head(struct v4v_char_msg_queue *queue)
{
    return v4v_char_msg_queue_is_empty(queue) ? NULL : &queue->buffer[queue->head];
}

struct v4v_char_msg* v4v_char_msg_queue_tail(struct v4v_char_msg_queue *queue)
{
    return v4v_char_msg_queue_is_empty(queue) ? NULL : &queue->buffer[queue->tail];
}

void v4v_char_msg_queue_dequeue(struct v4v_char_msg_queue *queue)
{
    if (v4v_char_msg_queue_is_empty(queue))
    {
        return;
    }

    if (queue->head == queue->tail)
    {
        queue->head = queue->capacity;
        queue->tail = queue->capacity;
    }
    else
    {
        ++queue->head;
        if (queue->head == queue->capacity)
        {
            queue->head = 0;
        }
    }
}

struct v4v_char_msg* v4v_char_msg_enqueue(struct v4v_char_msg_queue *queue, uint16_t type, const void *payload,
        uint32_t payload_size)
{
    if (v4v_char_msg_queue_is_full(queue))
    {
        return NULL;
    }

    if (v4v_char_msg_queue_is_empty(queue))
    {
        queue->head = 0;
        queue->tail = 0;
    }
    else
    {
        ++queue->tail;
        if (queue->tail == queue->capacity)
        {
            queue->tail = 0;
        }
    }

    queue->buffer[queue->tail].header.type = type;
    queue->buffer[queue->tail].header.payload_size = payload_size;

    if (payload_size > 0)
    {
        memcpy(queue->buffer[queue->tail].payload, payload, payload_size);
    }

    return &queue->buffer[queue->tail];
}
