/*
 * Copyright 2020, Bromium, Inc.
 * Author: Simon Haggett <simon.haggett@gmail.com>
 * SPDX-License-Identifier: ISC
 */

#include <linux/errno.h>
#include <linux/fs.h>
#include <linux/module.h>
#include <linux/poll.h>
#include <linux/string.h>

#include "v4v_char_device.h"
#include "v4v_char_v4v.h"

static ssize_t v4vc_device_write(struct file *file, const char __user *buf, size_t size, loff_t *pos)
{
    struct v4v_char_context *context = container_of(file->private_data, struct v4v_char_context, device);
    ssize_t ret;

    while ((ret = v4v_char_v4v_send_user_data(context, buf, size)) == -EAGAIN)
    {
        if (file->f_flags & O_NONBLOCK)
        {
            /* Use non-blocking I/O semantics. */
            return ret;
        }
        else
        {
            /* Use blocking I/O semantics. */
            wait_queue_head_t *send_wq = v4v_char_v4v_send_waitqueue(context);
            wait_event_interruptible(*send_wq, v4v_char_v4v_can_send_data(context));
        }
    }

    return ret;
}

static __poll_t v4vc_device_poll(struct file *file, struct poll_table_struct *poll_table)
{
    struct v4v_char_context *context = container_of(file->private_data, struct v4v_char_context, device);
    wait_queue_head_t *send_wq = v4v_char_v4v_send_waitqueue(context);
    __poll_t mask = 0;

    poll_wait(file, send_wq, poll_table);

    if (v4v_char_v4v_can_send_data(context))
    {
        /* Indicate that we're writeable. */
        mask |= POLLOUT | POLLWRNORM;
    }

    return mask;
}

static int v4vc_device_flush(struct file *file, fl_owner_t id)
{
    struct v4v_char_context *context = container_of(file->private_data, struct v4v_char_context, device);
    return v4v_char_v4v_flush(context);
}

static int v4vc_device_fsync(struct file *file, loff_t start, loff_t end, int datasync)
{
    struct v4v_char_context *context = container_of(file->private_data, struct v4v_char_context, device);
    return v4v_char_v4v_flush(context);
}

static const struct file_operations v4vc_device_file_ops = {
    .owner = THIS_MODULE,
    .write = v4vc_device_write,
    .poll = v4vc_device_poll,
    .flush = v4vc_device_flush,
    .fsync = v4vc_device_fsync
};

int v4v_char_device_init(struct v4v_char_context *context, const char *name)
{
    int ret = 0;

    context->device.minor = MISC_DYNAMIC_MINOR;
    context->device.name = name;
    context->device.fops = &v4vc_device_file_ops;
    context->device.mode = 0600;

    ret = misc_register(&context->device);
    if (unlikely(ret != 0))
    {
        printk(V4VC_ERR "error %i registering character device\n", ret);
        goto out;
    }

    printk(V4VC_INFO "registered device %s\n", context->device.name);

out:
    return ret;
}

void v4v_char_device_free(struct v4v_char_context *context)
{
    if (unlikely(!context))
    {
        return;
    }

    misc_deregister(&context->device);
    memset(&context->device, 0, sizeof(struct miscdevice));
}
