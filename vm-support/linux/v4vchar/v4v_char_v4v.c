/*
 * Copyright 2020, Bromium, Inc.
 * Author: Simon Haggett <simon.haggett@gmail.com>
 * SPDX-License-Identifier: ISC
 */

#include <linux/errno.h>
#include <linux/uaccess.h>

#include "v4v_char_v4v.h"

static int v4vc_v4v_tail_has_data_space(struct v4v_char_msg_queue *queue)
{
    struct v4v_char_msg *tail = v4v_char_msg_queue_tail(queue);
    return tail != NULL && tail->header.type == V4V_CHAR_MSG_TYPE_DATA_STREAM &&
            tail->header.payload_size < V4V_CHAR_MSG_MAX_PAYLOAD_BYTES;
}

/* Call with v4v_char_context::v4v_lock held. */
static int v4vc_v4v_flush_needed_locked(struct v4v_char_context *context)
{
    return context->v4v_flush_send_queue || v4v_char_msg_queue_size(&context->v4v_send_queue) > 1 ||
            !v4vc_v4v_tail_has_data_space(&context->v4v_send_queue);
}

/* Call with v4v_char_context::v4v_lock held. */
static void v4vc_v4v_flush_locked(struct v4v_char_context *context)
{
    if (unlikely(!context->v4v_ring))
    {
        return;
    }
    if (context->v4v_send_addr.port == V4V_PORT_NONE)
    {
        /* No client to send data to. */
        return;
    }

    context->v4v_flush_send_queue = 0;
    while (!v4v_char_msg_queue_is_empty(&context->v4v_send_queue))
    {
        struct v4v_char_msg *buffer = v4v_char_msg_queue_head(&context->v4v_send_queue);
        if (buffer->header.type == V4V_CHAR_MSG_TYPE_DATA_STREAM && buffer->header.payload_size == 0)
        {
            /* No data stream bytes to write. If this is the last message in the queue, then it is still being
             * filled (so don't dequeue). */
            if (buffer == v4v_char_msg_queue_tail(&context->v4v_send_queue))
            {
                break;
            }
        }
        else
        {
            const ssize_t result = uxen_v4v_send_from_ring(context->v4v_ring, &context->v4v_send_addr, buffer,
                    sizeof(struct v4v_char_hdr) + buffer->header.payload_size, V4V_PROTO_DGRAM);
            if (result < 0)
            {
                if (result == -EAGAIN)
                {
                    /* Can't send V4V message at this time, we'll try again later. */
                    context->v4v_flush_send_queue = 1;
                }
                else
                {
                    /* An unexpected error occurred, assume this is fatal and disconnect client. */
                    printk(V4VC_ERR "client disconnected (port %u, send error %zi)\n", context->v4v_send_addr.port,
                            result);
                    context->v4v_send_addr.port = V4V_PORT_NONE;
                    context->v4v_send_addr.domain = V4V_DOMID_INVALID;
                }
                break;
            }
        }
        v4v_char_msg_queue_dequeue(&context->v4v_send_queue);
    }

    if (!v4v_char_msg_queue_is_full(&context->v4v_send_queue) || context->v4v_send_addr.port == V4V_PORT_NONE)
    {
        wake_up_interruptible(&context->v4v_send_wq);
    }
}

/* Call with v4v_char_context::v4v_lock held. */
static void v4vc_v4v_flush_if_needed_locked(struct v4v_char_context *context)
{
    if (v4vc_v4v_flush_needed_locked(context))
    {
        v4vc_v4v_flush_locked(context);
    }
}

static void v4vc_v4v_irq(void *callback_opaque)
{
    struct v4v_char_context *context = (struct v4v_char_context*) callback_opaque;
    tasklet_schedule(&context->v4v_tasklet);
}

static void v4vc_v4v_task(unsigned long data)
{
    unsigned long lock_flags;
    struct v4v_char_context *context = (struct v4v_char_context*) data;
    uint8_t did_consume = 0;

    if (unlikely(!context->v4v_ring))
    {
        return;
    }

    spin_lock_irqsave(&context->v4v_lock, lock_flags);

    /* Receive any messages from the client. */
    while (true)
    {
        v4v_addr_t from;
        int len;

        struct v4v_char_msg *request = &context->v4v_receive_buffer;

        len = uxen_v4v_copy_out(context->v4v_ring, &from, NULL, request, sizeof(struct v4v_char_msg), 1);
        if (len < 0)
        {
            break;
        }

        did_consume = 1;
        if (len < sizeof(struct v4v_char_hdr))
        {
            printk(V4VC_WARNING "ignoring message with invalid size\n");
            continue;
        }

        switch (request->header.type)
        {
            case V4V_CHAR_MSG_TYPE_CONNECT:
                if (context->v4v_send_addr.port == V4V_PORT_NONE)
                {
                    context->v4v_send_addr.port = from.port;
                    context->v4v_send_addr.domain = V4V_DOMID_DM;
                    printk(V4VC_INFO "client connected (port %u)\n", from.port);
                }
                break;

            case V4V_CHAR_MSG_TYPE_DISCONNECT:
                if (from.port == context->v4v_send_addr.port)
                {
                    context->v4v_send_addr.port = V4V_PORT_NONE;
                    context->v4v_send_addr.domain = V4V_DOMID_INVALID;
                    printk(V4VC_INFO "client disconnected (port %u)\n", from.port);
                }
                break;

            default:
                /* Ignore unknown client message. */
                break;
        }
    }

    if (did_consume)
    {
        uxen_v4v_notify();
    }

    v4vc_v4v_flush_if_needed_locked(context);
    spin_unlock_irqrestore(&context->v4v_lock, lock_flags);
}

int v4v_char_v4v_init(struct v4v_char_context *context, uint32_t port)
{
    int ret = 0;

    context->v4v_bind_addr.port = port;
    context->v4v_bind_addr.domain = V4V_DOMID_DM;

    tasklet_init(&context->v4v_tasklet, v4vc_v4v_task, (unsigned long) context);
    init_waitqueue_head(&context->v4v_send_wq);

    context->v4v_ring = uxen_v4v_ring_bind(context->v4v_bind_addr.port, context->v4v_bind_addr.domain,
            V4V_CHAR_V4V_RING_SIZE_BYTES, v4vc_v4v_irq, context);
    if (unlikely(!context->v4v_ring))
    {
        ret = -ENOMEM;
        goto out;
    }
    if (unlikely(IS_ERR(context->v4v_ring)))
    {
        ret = PTR_ERR(context->v4v_ring);
        goto out;
    }

    spin_lock_init(&context->v4v_lock);
    v4v_char_msg_queue_init(&context->v4v_send_queue, context->v4v_send_buffer, V4V_SEND_QUEUE_SIZE);

    printk(V4VC_INFO "bound to port %u\n", context->v4v_bind_addr.port);

out:
    if (unlikely(ret))
    {
        tasklet_kill(&context->v4v_tasklet);
        context->v4v_ring = NULL;
    }
    return ret;
}

void v4v_char_v4v_free(struct v4v_char_context *context)
{
    if (unlikely(!context || !context->v4v_ring))
    {
        return;
    }

    tasklet_kill(&context->v4v_tasklet);
    uxen_v4v_ring_free(context->v4v_ring);

    context->v4v_ring = NULL;
}

wait_queue_head_t* v4v_char_v4v_send_waitqueue(struct v4v_char_context *context)
{
    return &context->v4v_send_wq;
}

int v4v_char_v4v_can_send_data(struct v4v_char_context *context)
{
    unsigned long lock_flags;
    int result = 0;

    spin_lock_irqsave(&context->v4v_lock, lock_flags);
    result = !v4v_char_msg_queue_is_full(&context->v4v_send_queue) ||
            v4vc_v4v_tail_has_data_space(&context->v4v_send_queue);
    spin_unlock_irqrestore(&context->v4v_lock, lock_flags);

    return result;
}

ssize_t v4v_char_v4v_send_user_data(struct v4v_char_context *context, const char __user *buf, size_t size)
{
    unsigned long lock_flags;
    ssize_t ret = 0;
    struct v4v_char_msg *buffer = NULL;

    if (size == 0)
    {
        return 0;
    }

    spin_lock_irqsave(&context->v4v_lock, lock_flags);

    /* Ensure we have buffer space for at least 1 byte. */
    if (v4vc_v4v_tail_has_data_space(&context->v4v_send_queue))
    {
        buffer = v4v_char_msg_queue_tail(&context->v4v_send_queue);
    }
    else
    {
        buffer = v4v_char_msg_enqueue(&context->v4v_send_queue, V4V_CHAR_MSG_TYPE_DATA_STREAM, NULL, 0);
    }
    if (buffer)
    {
        /* We're not blocked from sending data stream bytes, so accept what we can. */
        const size_t remaining = V4V_CHAR_MSG_MAX_PAYLOAD_BYTES - buffer->header.payload_size;
        const size_t count = min(size, remaining);

        if (copy_from_user(&buffer->payload[buffer->header.payload_size], buf, count) != 0)
        {
            ret = -EFAULT;
        }
        else
        {
            buffer->header.payload_size += count;
            ret = count;
        }
    }
    else
    {
        /* We are blocked from sending data stream bytes. Notify the caller. */
        if (context->v4v_send_addr.port == V4V_PORT_NONE)
        {
            /* No client is connected, so stop accepting data. */
            printk(V4VC_WARNING "no space for data (no client connected)\n");
            ret = -ENOSPC;
        }
        else
        {
            /* Indicate that the operation would block. */
            ret = -EAGAIN;
        }
    }

    v4vc_v4v_flush_if_needed_locked(context);
    spin_unlock_irqrestore(&context->v4v_lock, lock_flags);

    return ret;
}

int v4v_char_v4v_flush(struct v4v_char_context *context)
{
    unsigned long lock_flags;

    spin_lock_irqsave(&context->v4v_lock, lock_flags);
    v4vc_v4v_flush_locked(context);
    spin_unlock_irqrestore(&context->v4v_lock, lock_flags);

    return 0;
}
