/*
 * Copyright 2019, Bromium, Inc.
 * Author: Simon Haggett <simon.haggett@gmail.com>
 * SPDX-License-Identifier: ISC
 */

#include <asm-generic/param.h>

#include <linux/cpumask.h>
#include <linux/err.h>
#include <linux/init.h>
#include <linux/interrupt.h>
#include <linux/kernel_stat.h>
#include <linux/module.h>
#include <linux/rcupdate.h>
#include <linux/sched/signal.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/timekeeping.h>
#include <linux/types.h>

#include <uxen-v4vlib.h>

#include "vm_diagnostics_msgdefs.h"

#define VMD_PREFIX KBUILD_MODNAME ": "

#define VMD_INFO KERN_INFO VMD_PREFIX
#define VMD_ERR KERN_ERR VMD_PREFIX
#define VMD_WARNING KERN_WARNING VMD_PREFIX

/*
 * \brief Indicates whether a VM diagnostics message is waiting to being sent.
 *
 * Only one message can be sent at a time.
 *
 * \param context The struct vm_diagnostics_context instance.
 *
 * \return Non-zero if a VM diagnostics message is waiting to being sent.
 */
#define vmd_send_pending(context) (context->send_pending)

struct vm_diagnostics_context
{
    uxen_v4v_ring_t *v4v_ring;
    v4v_addr_t v4v_bind_addr;
    struct tasklet_struct v4v_tasklet;

    struct vm_diagnostics_msg receive_buffer;

    v4v_addr_t v4v_send_addr;
    struct vm_diagnostics_msg send_buffer;
    uint8_t send_pending;
};

static struct vm_diagnostics_context *vmd_context;

/*
 * \brief Gets a VM diagnostics message instance that can be sent.
 *
 * This message may be sent with vmd_send_msg(). Only one message can be sent at a time.
 *
 * \param context The struct vm_diagnostics_context instance.
 * \param type The message type.
 *
 * \return A VM diagnostics message instance that can be used to construct an outgoing message, or NULL if a message is
 * already waiting to be sent.
 */
static struct vm_diagnostics_msg * vmd_get_msg_to_send(struct vm_diagnostics_context *context, uint16_t type)
{
    if (context->send_pending)
    {
        printk(VMD_ERR "message send is pending\n");
        return NULL;
    }

    memset(&context->send_buffer, 0, sizeof(struct vm_diagnostics_msg));
    context->send_buffer.header.type = type;

    return &context->send_buffer;
}

/*
 * \brief Flushes the send buffer.
 *
 * If a VM diagnostics message is waiting to being sent, then this function tries to send it. The send buffer is
 * cleared if the send was successful, or failed with a non-recoverable error.
 *
 * \param context The struct vm_diagnostics_context instance.
 */
static void vmd_flush_send_buffer(struct vm_diagnostics_context *context)
{
    ssize_t result;

    if (!context->send_pending)
    {
        return;
    }

    result = uxen_v4v_send_from_ring(context->v4v_ring, &context->v4v_send_addr, &context->send_buffer,
            sizeof(struct vm_diagnostics_hdr) + context->send_buffer.header.payload_size, V4V_PROTO_DGRAM);
    if (result != -EAGAIN)
    {
        if (result < 0)
        {
            printk(VMD_ERR "error %li sending V4V message\n", result);
        }
        context->send_pending = 0;
    }
}

/*
 * \brief Sends an outgoing VM diagnostics message.
 *
 * The data may not be sent immediately. Only one message can be sent at a time. Sends are intended to be
 * fire-and-forget, hence no result is reported.
 *
 * \param context The struct vm_diagnostics_context instance.
 * \param addr The V4V address to send this message to.
 * \param msg The message instance. This must have been provided by vmd_get_msg_to_send().
 */
static void vmd_send_msg(struct vm_diagnostics_context *context, const v4v_addr_t *addr,
        const struct vm_diagnostics_msg *msg)
{
    if (msg != &context->send_buffer)
    {
        printk(VMD_ERR "cannot send invalid message\n");
        return;
    }
    else if (context->send_pending)
    {
        printk(VMD_ERR "cannot send message whilst send is pending\n");
        return;
    }

    context->v4v_send_addr.port = addr->port;
    context->v4v_send_addr.domain = V4V_DOMID_DM;
    context->send_pending = 1;

    vmd_flush_send_buffer(context);
}

/*
 * \brief Sends a VM diagonstics message of type VM_DIAGNOSTICS_MSG_TYPE_ERROR_INVALID_REQUEST.
 *
 * \param context The struct vm_diagnostics_context instance.
 * \param addr The V4V address to send this message to.
 */
static void vmd_send_invalid_request(struct vm_diagnostics_context *context, const v4v_addr_t *addr)
{
    struct vm_diagnostics_msg *response = vmd_get_msg_to_send(context,
            VM_DIAGNOSTICS_MSG_TYPE_ERROR_INVALID_REQUEST);
    if (response)
    {
        vmd_send_msg(context, addr, response);
    }
}

static void vm_handle_request_stat_system(struct vm_diagnostics_context *context, const v4v_addr_t *addr,
        uint32_t payload_size, uint8_t *payload)
{
    struct timespec64 ts;
    struct task_struct *task;

    struct vm_diagnostics_stat_system *stat;
    struct vm_diagnostics_msg *response;

    (void) payload_size;
    (void) payload;

    response = vmd_get_msg_to_send(context, VM_DIAGNOSTICS_MSG_TYPE_STAT_SYSTEM);
    if (!response)
    {
        return;
    }

    response->header.payload_size = sizeof(struct vm_diagnostics_stat_system);
    stat = (struct vm_diagnostics_stat_system *) response->payload;

    stat->ticks_per_second = CLOCKS_PER_SEC;
    stat->current_time_seconds = ktime_get_real_seconds();

    getboottime64(&ts);
    stat->boot_time_seconds = ts.tv_sec;

    stat->num_cpus = num_online_cpus();

    stat->num_tasks = 0;
    rcu_read_lock();
    for_each_process(task)
    {
        ++(stat->num_tasks);
    }
    rcu_read_unlock();

    vmd_send_msg(context, addr, response);
}

/*
 * \brief Receives V4V event notifications.
 *
 * This is invoked by uxenv4vlib, and so operates in an interrupt context. This function schedules a tasklet to do
 * the real work at a later time (without holding up the IRQ handler).
 *
 * \param callback_opaque The struct vm_diagnostics_context instance (as provided to uxenv4vlib).
 */
static void vm_diagnostics_irq(void *callback_opaque)
{
    struct vm_diagnostics_context *context = (struct vm_diagnostics_context*) callback_opaque;

    tasklet_schedule(&context->v4v_tasklet);
}

/*
 * \brief Handles V4V event notifications.
 *
 * This is invoked by a tasklet, and so operates in a sofware interrupt context. This function performs V4V
 * transactions.
 *
 * \param data The struct vm_diagnostics_context instance (as provided to the tasklet).
 */
static void vm_diagnostics_softirq(unsigned long data)
{
    struct vm_diagnostics_context *context = (struct vm_diagnostics_context*) data;
    struct vm_diagnostics_msg *request = &context->receive_buffer;
    uint8_t did_consume = 0;

    if (!context->v4v_ring)
    {
        return;
    }

    vmd_flush_send_buffer(context);

    while (!vmd_send_pending(context))
    {
        v4v_addr_t from;
        int len;

        len = uxen_v4v_copy_out(context->v4v_ring, &from, NULL, request, sizeof(struct vm_diagnostics_msg), 1);
        if (len < 0)
        {
            break;
        }

        did_consume = 1;
        if (len < sizeof(struct vm_diagnostics_hdr))
        {
            printk(VMD_WARNING "ignoring message with invalid size\n");
            continue;
        }

        switch (request->header.type)
        {
            case VM_DIAGNOSTICS_MSG_TYPE_STAT_SYSTEM:
                vm_handle_request_stat_system(context, &from, request->header.payload_size, request->payload);
                break;

            default:
                vmd_send_invalid_request(context, &from);
        }
    }

    if (did_consume)
    {
        uxen_v4v_notify();
    }
}

/*
 * \brief Performs V4V initialisation.
 *
 * \param context The struct vm_diagnostics_context instance.
 *
 * \return Zero on success, or an errno error value on failure.
 */
static int vmd_v4v_init(struct vm_diagnostics_context *context)
{
    int ret = 0;

    context->v4v_bind_addr.port = VM_DIAGNOSTICS_V4V_PORT;
    context->v4v_bind_addr.domain = V4V_DOMID_DM;

    tasklet_init(&context->v4v_tasklet, vm_diagnostics_softirq, (unsigned long) context);

    context->v4v_ring = uxen_v4v_ring_bind(context->v4v_bind_addr.port, context->v4v_bind_addr.domain,
            VM_DIAGNOSTICS_V4V_RING_SIZE_BYTES, vm_diagnostics_irq, context);
    if (!context->v4v_ring)
    {
        ret = -ENOMEM;
        goto out;
    }
    if (IS_ERR(context->v4v_ring))
    {
        ret = PTR_ERR(context->v4v_ring);
        goto out;
    }

out:
    if (ret)
    {
        tasklet_kill(&context->v4v_tasklet);
        context->v4v_ring = NULL;
    }
    return ret;
}

/*
 * \brief Frees V4V structures.
 *
 * \param context The struct vm_diagnostics_context instance.
 */
static void vmd_v4v_free(struct vm_diagnostics_context *context)
{
    if (!context->v4v_ring)
    {
        return;
    }

    tasklet_kill(&context->v4v_tasklet);
    uxen_v4v_ring_free(context->v4v_ring);

    context->v4v_ring = NULL;
}

/*
 * \brief Frees a struct vm_diagnostics_context instance.
 *
 * The context pointer is invalid after this function completes.
 *
 * \param context The struct vm_diagnostics_context instance.
 */
static void vmd_context_free(struct vm_diagnostics_context *context)
{
    vmd_v4v_free(context);
    kfree(context);
}


/*
 * Module definition.
 */

static int __init vm_diagnostics_init(void)
{
    int ret = 0;

    vmd_context = kmalloc(sizeof(struct vm_diagnostics_context), GFP_KERNEL | __GFP_ZERO);
    if (!vmd_context)
    {
        printk(VMD_ERR "failed to allocate memory for context\n");
        goto fail;
    }

    ret = vmd_v4v_init(vmd_context);
    if (ret)
    {
        printk(VMD_ERR "error %i initialising V4V\n", ret);
        goto fail;
    }
    
    printk(VMD_INFO "diagnostics reporting active\n");
    return ret;

fail:
    vmd_context_free(vmd_context);
    return ret;
}

static void __exit vm_diagnostics_exit(void)
{
    vmd_context_free(vmd_context);
}

module_init(vm_diagnostics_init);
module_exit(vm_diagnostics_exit);

MODULE_AUTHOR("simon.haggett@bromium.com");
MODULE_DESCRIPTION("VM Diagnostics");
MODULE_LICENSE("GPL");
