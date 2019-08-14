/*
 * Copyright 2019, Bromium, Inc.
 * Author: Simon Haggett <simon.haggett@gmail.com>
 * SPDX-License-Identifier: ISC
 */

#pragma once

/*
 * \file V4V interface for the vmdiagnostics kernel module.
 *
 * This file describes the message types and data structures supported by the vmdiagnostics kernel module. Clients talk
 * to the module by sending and receiving V4V messages on VM_DIAGNOSTICS_V4V_PORT. Clients send request messages, and
 * the module replies with response messages. Each request message yields a single response message. Each request and
 * response message is a struct vm_diagnostics_msg instance, with a message type and possibly a payload with input
 * parameters or output data.
 */

/*
 * \brief Request system statistics.
 *
 * This request takes no parameters.
 *
 * The response payload is a struct vm_diagnostics_stat_system instance.
 */
#define VM_DIAGNOSTICS_MSG_TYPE_STAT_SYSTEM 0

/*
 * \brief Request memory statistics.
 *
 * This request takes no parameters.
 *
 * The response payload is a struct vm_diagnostics_stat_memory instance.
 */
#define VM_DIAGNOSTICS_MSG_TYPE_STAT_MEMORY 1

/*
 * \brief Request CPU summary statistics.
 *
 * This request takes no parameters.
 *
 * The response payload is a struct vm_diagnostics_stat_cpu instance.
 */
#define VM_DIAGNOSTICS_MSG_TYPE_STAT_CPU_SUMMARY 2

/*
 * \brief Request statistics for a specific CPU.
 *
 * This request takes a single uint32_t parameter, specifying the zero-based index of the desired CPU. Use the
 * VM_DIAGNOSTICS_MSG_TYPE_STAT_SYSTEM request to identify the number of online CPUs. Note that this number may change
 * at any time.
 *
 * If a valid CPU is identified, the response payload is a struct vm_diagnostics_stat_cpu instance. Otherwise, no
 * payload is provided.
 */
#define VM_DIAGNOSTICS_MSG_TYPE_STAT_CPU 3

/*
 * \brief Request statistics for a specific task.
 *
 * This request takes a single uint32_t parameter, specifying the zero-based index of the desired task. Use the
 * VM_DIAGNOSTICS_MSG_TYPE_STAT_SYSTEM request to identify the current number of tasks. Note that this number may
 * change at any time.
 *
 * If a valid task is identified, the response payload is a struct vm_diagnostics_stat_task instance. Otherwise, no
 * payload is provided.
 */
#define VM_DIAGNOSTICS_MSG_TYPE_STAT_TASK 4

/*
 * \brief The base number for error message types.
 */
#define VM_DIAGNOSTICS_MSG_TYPE_ERROR 0x8000

/*
 * \brief Invalid request error.
 *
 * A message of this type is sent in response to a request with an unknown message type or invalid parameters.
 */
#define VM_DIAGNOSTICS_MSG_TYPE_ERROR_INVALID_REQUEST (VM_DIAGNOSTICS_MSG_TYPE_ERROR + 0)

/*
 * \brief The V4V port used by the vmdiagnostics kernel module.
 */
#define VM_DIAGNOSTICS_V4V_PORT 44461

/*
 * \brief The V4V ring size used by the vmdiagnostics kernel module.
 */
#define VM_DIAGNOSTICS_V4V_RING_SIZE_BYTES (256 * 1024)

#define VM_DIAGNOSTICS_MSG_MAX_PAYLOAD_BYTES 4089
#define VM_DIAGNOSTICS_MAX_TASK_NAME_BYTES 16

/* Pack structures, using directives that GCC and MSVC both understand. */
#pragma pack(push, 1)

/*
 * \brief Message header structure.
 */
struct vm_diagnostics_hdr
{
    /*
     * \brief The message type.
     *
     * This must be a VM_DIAGNOSTICS_MSG_TYPE_ value.
     */
    uint16_t type;

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
struct vm_diagnostics_msg
{
    /*
     * \brief Message header.
     */
    struct vm_diagnostics_hdr header;

    /*
     * \brief Message payload.
     *
     * The number of valid bytes is described by the payload_size member.
     */
    uint8_t payload[VM_DIAGNOSTICS_MSG_MAX_PAYLOAD_BYTES];

};

/*
 * \brief Response payload structure for VM_DIAGNOSTICS_MSG_TYPE_STAT_SYSTEM.
 */
struct vm_diagnostics_stat_system
{
    /*
     * \brief The current time of day.
     *
     * This is expressed as time elapsed since the UNIX epoch, in second and nanosecond parts.
     *
     * Negative values indicate that an error occurred whilst querying this statistic.
     */
    int64_t current_time_sec;
    int64_t current_time_nsec;

    /*
     * \brief The system boot time.
     *
     * This is expressed as time elapsed since the UNIX epoch, in second and nanosecond parts.
     *
     * Negative values indicate that an error occurred whilst querying this statistic.
     */
    int64_t boot_time_sec;
    int64_t boot_time_nsec;

    /*
     * \brief The number of online CPUs.
     */
    uint32_t num_cpus;

    /*
     * \brief The current number of tasks.
     *
     * This count specifies the number of kernel threads and user processes currently present in the kernel's task list.
     * User threads are not included.
     */
    uint32_t num_tasks;

};

/*
 * \brief Response payload structure for VM_DIAGNOSTICS_MSG_TYPE_STAT_MEMORY.
 */
struct vm_diagnostics_stat_memory
{
    /*
     * \brief The size of a single memory page in bytes.
     */
    uint32_t page_size_bytes;

    /*
     * \brief The system RAM size in pages.
     */
    uint64_t total_ram_pages;

    /*
     * \brief The number of free system RAM pages.
     */
    uint64_t free_ram_pages;

    /*
     * \brief The number of system RAM pages being used for shared memory.
     */
    uint64_t shared_ram_pages;

    /*
     * \brief The number of system RAM pages used by buffers.
     */
    uint64_t buffer_ram_pages;

    /*
     * \brief The number of system RAM pages that can be made available.
     *
     * As well as the number of free pages, this count includes pages from the page cache and reclaimable slab, as well
     * as kernel memory pages that can be released under memory pressure.
     *
     * A negative value indicates that an error occurred whilst querying this statistic.
     */
    int64_t available_ram_pages;

    /*
     * \brief The number of system RAM pages used for mapped files.
     */
    uint64_t num_file_pages;

};

/*
 * \brief Response payload structure for VM_DIAGNOSTICS_MSG_TYPE_STAT_CPU_SUMMARY and VM_DIAGNOSTICS_MSG_TYPE_STAT_CPU.
 *
 * For VM_DIAGNOSTICS_MSG_TYPE_STAT_CPU_SUMMARY, these values are summed across all online CPUs. For
 * VM_DIAGNOSTICS_MSG_TYPE_STAT_CPU, these values are reported for a specific CPU.
 */
struct vm_diagnostics_stat_cpu
{
    /*
     * \brief The CPU identifier.
     *
     * This value only has meaning for VM_DIAGNOSTICS_MSG_TYPE_STAT_CPU. For VM_DIAGNOSTICS_MSG_TYPE_STAT_CPU_SUMMARY,
     * the value is undefined and must not be used.
     */
    uint32_t cpu_id;

    /*
     * \brief Amount of time CPU has spent in user mode since boot (nanoseconds).
     */
    uint64_t user_nsec;

    /*
     * \brief Amount of time CPU has spent in user mode with low priority since boot (nanoseconds).
     */
    uint64_t nice_nsec;

    /*
     * \brief Amount of time CPU has spent in system (kernel) mode since boot (nanoseconds).
     */
    uint64_t system_nsec;

    /*
     * \brief Amount of time CPU has spent in the idle task since boot (nanoseconds).
     */
    uint64_t idle_nsec;

    /*
     * \brief Amount of time CPU has spent waiting for I/O to complete since boot (nanoseconds).
     */
    uint64_t iowait_nsec;

    /*
     * \brief Amount of time CPU has spent servicing hardware interrupts since boot (nanoseconds).
     */
    uint64_t irq_nsec;

    /*
     * \brief Amount of time CPU has spent servicing software interrupts (softirqs) since boot (nanoseconds).
     */
    uint64_t softirq_nsec;

    /*
     * \brief Amount of time CPU has spent servicing other virtual machines since boot (nanoseconds).
     */
    uint64_t steal_nsec;

};

/*
 * \brief Response payload structure for VM_DIAGNOSTICS_MSG_TYPE_STAT_TASK.
 */
struct vm_diagnostics_stat_task
{
    /*
     * \brief The Process ID (PID) assigned to the task.
     *
     * Both kernel threads and user processes are assigned PIDs. This value is as seen from the init namespace.
     */
    int32_t pid;

    /*
     * \brief The Process ID (PID) assigned to the task's parent.
     *
     * Both kernel threads and user processes are assigned PIDs. This value is as seen from the init namespace.
     */
    int32_t parent_pid;

    /*
     * \brief The User ID (UID) under which the task is running.
     */
    uint32_t uid;

    /*
     * \brief The Group ID (GID) under which the task is running.
     */
    uint32_t gid;

    /*
     * \brief The executable name for the task, as a NUL terminated string.
     *
     * This string does not include a path or command-line arguments. The name is truncated if it exceeds
     * VM_DIAGNOSTICS_MAX_TASK_NAME_BYTES (excluding NUL terminator).
     */
    char name[VM_DIAGNOSTICS_MAX_TASK_NAME_BYTES];

    /*
     * \brief The current state of the task.
     *
     * The Linux kernel maps the task state to a character. The current known mappings are:
     *
     *     'R': Running.
     *     'S': Sleeping.
     *     'D': Disk sleep.
     *     'T': Stopped.
     *     't': Tracing stopped.
     *     'X': Dead.
     *     'Z': Zombie.
     *     'P': Parked.
     *     'I': Idle.
     *
     * See task_state_to_char() (linux/sched.h) and task_state_array (fs/proc/array.c) for further details.
     */
    char state;

    /*
     * \brief The number of threads for this task.
     *
     * For kernel threads, this value is 1. User processes may have one or more threads.
     */
    int32_t num_threads;

    /*
     * \brief The start time of this task (nanoseconds).
     *
     * This is expressed as time elapsed since boot.
     */
    uint64_t start_time_nsec;

    /*
     * \brief The identifier of the CPU on which this task last ran.
     */
    uint32_t last_run_cpu_id;

    /*
     * \brief Amount of time CPU has spent in user mode with this task scheduled (nanoseconds).
     */
    uint64_t user_nsec;

    /*
     * \brief Amount of time CPU has spent in system (kernel) mode with this task scheduled (nanoseconds).
     */
    uint64_t system_nsec;

    /*
     * \brief The current user virtual memory size of this task, in pages.
     *
     * This is the total number of mapped pages in the user process's virtual memory address space. For kernel threads,
     * this is always zero.
     */
    uint64_t user_vm_size_pages;

    /*
     * \brief The user Resident Set Size (RSS) for this task, in pages.
     *
     * This is the number of pages currently mapped to system RAM. For kernel threads, this is always zero.
     */
    uint64_t user_rss_pages;

};

#pragma pack(pop)     /* pack(push, 1) */
