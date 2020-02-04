/*
 * Copyright 2020, Bromium, Inc.
 * Author: Simon Haggett <simon.haggett@gmail.com>
 * SPDX-License-Identifier: ISC
 */

#pragma once

#include <linux/interrupt.h>
#include <linux/miscdevice.h>
#include <linux/spinlock.h>
#include <linux/types.h>
#include <linux/wait.h>

#include <uxen-v4vlib.h>

#include "v4v_char_msgdefs.h"
#include "v4v_char_msg_queue.h"

#define V4VC_PREFIX KBUILD_MODNAME ": "

#define V4VC_INFO KERN_INFO V4VC_PREFIX
#define V4VC_ERR KERN_ERR V4VC_PREFIX
#define V4VC_WARNING KERN_WARNING V4VC_PREFIX

#define V4V_SEND_QUEUE_SIZE 64

/*
 * \brief Context structure.
 *
 * This also contains space for message buffers.
 */
struct v4v_char_context
{
    uxen_v4v_ring_t *v4v_ring;
    v4v_addr_t v4v_bind_addr;
    struct tasklet_struct v4v_tasklet;

    wait_queue_head_t v4v_send_wq;

    spinlock_t v4v_lock;
    struct v4v_char_msg v4v_receive_buffer;
    v4v_addr_t v4v_send_addr;
    struct v4v_char_msg v4v_send_buffer[V4V_SEND_QUEUE_SIZE];
    struct v4v_char_msg_queue v4v_send_queue;
    uint8_t v4v_flush_send_queue;

    struct miscdevice device;
};
