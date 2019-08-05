/*
 * Copyright 2019, Bromium, Inc.
 * Author: Simon Haggett <simon.haggett@gmail.com>
 * SPDX-License-Identifier: ISC
 */

#include <asm-generic/param.h>

#include <linux/cpumask.h>
#include <linux/cred.h>
#include <linux/err.h>
#include <linux/init.h>
#include <linux/interrupt.h>
#include <linux/kernel_stat.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/rcupdate.h>
#include <linux/sched.h>
#include <linux/sched/cputime.h>
#include <linux/sched/mm.h>
#include <linux/sched/signal.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/timekeeping.h>
#include <linux/types.h>
#include <linux/vmstat.h>

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

/*
 * \brief Context structure.
 *
 * This also contains space for receive and send message buffers.
 */
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

/*
 * \brief The context instance used by this module.
 *
 * Kernel memory for this instance is allocated during module initialisation, and maintaind for the lifetime of this
 * module. This instance is global so that it is accessible to the module exit function (which takes no parameters).
 */
static struct vm_diagnostics_context *vmd_context;

/*
 * \brief Gets a VM diagnostics message instance that can be sent.
 *
 * This message may be sent with vmd_send_msg(). Only one message can be sent at a time.
 *
 * \param context The struct vm_diagnostics_context instance.
 * \param type The message type.
 * \param payload_size The payload size.
 *
 * \return A VM diagnostics message instance that can be used to construct an outgoing message, or NULL if a message is
 * already waiting to be sent. The memory is zeroed beforehand.
 */
static struct vm_diagnostics_msg * vmd_get_msg_to_send(struct vm_diagnostics_context *context, uint16_t type,
        uint32_t payload_size)
{
    if (unlikely(vmd_send_pending(context)))
    {
        printk(VMD_ERR "message send is pending\n");
        return NULL;
    }

    memset(&context->send_buffer, 0, sizeof(struct vm_diagnostics_msg));
    context->send_buffer.header.type = type;
    context->send_buffer.header.payload_size = payload_size;

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

    if (!vmd_send_pending(context))
    {
        return;
    }

    result = uxen_v4v_send_from_ring(context->v4v_ring, &context->v4v_send_addr, &context->send_buffer,
            sizeof(struct vm_diagnostics_hdr) + context->send_buffer.header.payload_size, V4V_PROTO_DGRAM);
    if (result != -EAGAIN)
    {
        if (unlikely(result < 0))
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
    if (unlikely(msg != &context->send_buffer))
    {
        printk(VMD_ERR "cannot send invalid message\n");
        return;
    }
    else if (unlikely(vmd_send_pending(context)))
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
 * \brief Sends a VM diagnostics message of type VM_DIAGNOSTICS_MSG_TYPE_ERROR_INVALID_REQUEST.
 *
 * \param context The struct vm_diagnostics_context instance.
 * \param addr The V4V address to send this message to.
 */
static void vmd_send_invalid_request(struct vm_diagnostics_context *context, const v4v_addr_t *addr)
{
    struct vm_diagnostics_msg *response = vmd_get_msg_to_send(context,
            VM_DIAGNOSTICS_MSG_TYPE_ERROR_INVALID_REQUEST, 0);
    if (likely(response))
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

    response = vmd_get_msg_to_send(context, VM_DIAGNOSTICS_MSG_TYPE_STAT_SYSTEM,
            sizeof(struct vm_diagnostics_stat_system));
    if (unlikely(!response))
    {
        return;
    }

    stat = (struct vm_diagnostics_stat_system *) response->payload;

    ktime_get_real_ts64(&ts);
    stat->current_time_sec = ts.tv_sec;
    stat->current_time_nsec = ts.tv_nsec;

    getboottime64(&ts);
    stat->boot_time_sec = ts.tv_sec;
    stat->boot_time_nsec = ts.tv_nsec;

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

static void vm_handle_request_stat_memory(struct vm_diagnostics_context *context, const v4v_addr_t *addr,
        uint32_t payload_size, uint8_t *payload)
{
    struct sysinfo info;

    struct vm_diagnostics_stat_memory *mem;
    struct vm_diagnostics_msg *response;

    (void) payload_size;
    (void) payload;

    response = vmd_get_msg_to_send(context, VM_DIAGNOSTICS_MSG_TYPE_STAT_MEMORY,
            sizeof(struct vm_diagnostics_stat_memory));
    if (unlikely(!response))
    {
        return;
    }

    mem = (struct vm_diagnostics_stat_memory *) response->payload;

    si_meminfo(&info);

    mem->page_size_bytes = info.mem_unit;

    mem->total_ram_pages = info.totalram;
    mem->free_ram_pages = info.freeram;
    mem->shared_ram_pages = info.sharedram;
    mem->buffer_ram_pages = info.bufferram;

    mem->available_ram_pages = si_mem_available();

    mem->num_file_pages = global_node_page_state(NR_FILE_PAGES);

    vmd_send_msg(context, addr, response);
}

static void vm_handle_request_stat_cpu_summary(struct vm_diagnostics_context *context, const v4v_addr_t *addr,
        uint32_t payload_size, uint8_t *payload)
{
    struct vm_diagnostics_stat_cpu *summary;
    struct vm_diagnostics_msg *response;

    int i;

    (void) payload_size;
    (void) payload;

    response = vmd_get_msg_to_send(context, VM_DIAGNOSTICS_MSG_TYPE_STAT_CPU_SUMMARY,
            sizeof(struct vm_diagnostics_stat_cpu));
    if (unlikely(!response))
    {
        return;
    }

    summary = (struct vm_diagnostics_stat_cpu *) response->payload;

    for_each_online_cpu (i)
    {
        summary->user_nsec += kcpustat_cpu(i).cpustat[CPUTIME_USER];
        summary->nice_nsec += kcpustat_cpu(i).cpustat[CPUTIME_NICE];
        summary->system_nsec += kcpustat_cpu(i).cpustat[CPUTIME_SYSTEM];
        summary->idle_nsec += kcpustat_cpu(i).cpustat[CPUTIME_IDLE];
        summary->iowait_nsec += kcpustat_cpu(i).cpustat[CPUTIME_IOWAIT];
        summary->irq_nsec += kcpustat_cpu(i).cpustat[CPUTIME_IRQ];
        summary->softirq_nsec += kcpustat_cpu(i).cpustat[CPUTIME_SOFTIRQ];
        summary->steal_nsec += kcpustat_cpu(i).cpustat[CPUTIME_STEAL];
    }

    vmd_send_msg(context, addr, response);
}

static void vm_handle_request_stat_cpu(struct vm_diagnostics_context *context, const v4v_addr_t *addr,
        uint32_t payload_size, uint8_t *payload)
{
    struct vm_diagnostics_stat_cpu *cpu;
    struct vm_diagnostics_msg *response;

    uint32_t *cpu_id;

    if (payload_size < sizeof(uint32_t))
    {
        vmd_send_invalid_request(context, addr);
        return;
    }

    response = vmd_get_msg_to_send(context, VM_DIAGNOSTICS_MSG_TYPE_STAT_CPU, 0);
    if (unlikely(!response))
    {
        return;
    }

    /* Only provide a payload if we have a CPU with the requested ID (index). */
    cpu_id = (uint32_t *) payload;
    if (*cpu_id < num_online_cpus())
    {
        response->header.payload_size = sizeof(struct vm_diagnostics_stat_cpu);
        cpu = (struct vm_diagnostics_stat_cpu *) response->payload;

        cpu->cpu_id = *cpu_id;

        cpu->user_nsec = kcpustat_cpu(*cpu_id).cpustat[CPUTIME_USER];
        cpu->nice_nsec = kcpustat_cpu(*cpu_id).cpustat[CPUTIME_NICE];
        cpu->system_nsec = kcpustat_cpu(*cpu_id).cpustat[CPUTIME_SYSTEM];
        cpu->idle_nsec = kcpustat_cpu(*cpu_id).cpustat[CPUTIME_IDLE];
        cpu->iowait_nsec = kcpustat_cpu(*cpu_id).cpustat[CPUTIME_IOWAIT];
        cpu->irq_nsec = kcpustat_cpu(*cpu_id).cpustat[CPUTIME_IRQ];
        cpu->softirq_nsec = kcpustat_cpu(*cpu_id).cpustat[CPUTIME_SOFTIRQ];
        cpu->steal_nsec = kcpustat_cpu(*cpu_id).cpustat[CPUTIME_STEAL];
    }

    vmd_send_msg(context, addr, response);
}

static void vm_handle_request_stat_task(struct vm_diagnostics_context *context, const v4v_addr_t *addr,
        uint32_t payload_size, uint8_t *payload)
{
    struct vm_diagnostics_stat_task *task_payload;
    struct vm_diagnostics_msg *response;

    uint32_t *task_id;

    struct task_struct *task;

    if (payload_size < sizeof(uint32_t))
    {
        vmd_send_invalid_request(context, addr);
        return;
    }

    response = vmd_get_msg_to_send(context, VM_DIAGNOSTICS_MSG_TYPE_STAT_TASK, 0);
    if (unlikely(!response))
    {
        return;
    }

    /* Use the task ID as an index into the task list. Only provide a payload if we have a corresponding task. */
    task_id = (uint32_t *) payload;
    rcu_read_lock();
    for_each_process(task)
    {
        if (*task_id > 0)
        {
            --(*task_id);
        }
        else
        {
            const struct cred *cred;
            struct mm_struct *mm;

            response->header.payload_size = sizeof(struct vm_diagnostics_stat_task);
            task_payload = (struct vm_diagnostics_stat_task *) response->payload;

            /* Use PID values as seen from the init namespace. */
            task_payload->pid = task_pid_nr(task);
            task_payload->parent_pid = task_pid_nr(task->real_parent);

            cred = get_task_cred(task);
            if (cred)
            {
                task_payload->uid = cred->uid.val;
                task_payload->gid = cred->gid.val;
            }

            get_task_comm(task_payload->name, task);
 
            task_payload->state = task_state_to_char(task);
            task_payload->num_threads = get_nr_threads(task);
            task_payload->start_time_nsec = task->real_start_time;
            task_payload->last_run_cpu_id = task_cpu(task);

            thread_group_cputime_adjusted(task, &task_payload->user_nsec, &task_payload->system_nsec);

            mm = get_task_mm(task);
            if (mm)
            {
                task_payload->user_vm_size_pages = mm->total_vm;
                task_payload->user_rss_pages = get_mm_rss(mm);

                mmput(mm);
            }

            break;
        }
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

    if (unlikely(!context->v4v_ring))
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

            case VM_DIAGNOSTICS_MSG_TYPE_STAT_MEMORY:
                vm_handle_request_stat_memory(context, &from, request->header.payload_size, request->payload);
                break;

            case VM_DIAGNOSTICS_MSG_TYPE_STAT_CPU_SUMMARY:
                vm_handle_request_stat_cpu_summary(context, &from, request->header.payload_size, request->payload);
                break;

            case VM_DIAGNOSTICS_MSG_TYPE_STAT_CPU:
                vm_handle_request_stat_cpu(context, &from, request->header.payload_size, request->payload);
                break;

            case VM_DIAGNOSTICS_MSG_TYPE_STAT_TASK:
                vm_handle_request_stat_task(context, &from, request->header.payload_size, request->payload);
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

out:
    if (unlikely(ret))
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
    if (unlikely(!context || !context->v4v_ring))
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

    vmd_context = kzalloc(sizeof(struct vm_diagnostics_context), GFP_KERNEL);
    if (unlikely(!vmd_context))
    {
        printk(VMD_ERR "failed to allocate memory for context\n");
        goto fail;
    }

    ret = vmd_v4v_init(vmd_context);
    if (unlikely(ret))
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
