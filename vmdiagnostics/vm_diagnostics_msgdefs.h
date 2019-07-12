/*
 * Copyright 2019, Bromium, Inc.
 * Author: Simon Haggett <simon.haggett@gmail.com>
 * SPDX-License-Identifier: ISC
 */

#define VM_DIAGNOSTICS_MSG_TYPE_STAT_SYSTEM 0

#define VM_DIAGNOSTICS_MSG_TYPE_REQUEST 0x4000
#define VM_DIAGNOSTICS_MSG_TYPE_REQUEST_STAT_SYSTEM (VM_DIAGNOSTICS_MSG_TYPE_REQUEST + 0)

#define VM_DIAGNOSTICS_MSG_TYPE_ERROR 0x8000
#define VM_DIAGNOSTICS_MSG_TYPE_ERROR_INVALID_REQUEST (VM_DIAGNOSTICS_MSG_TYPE_ERROR + 0)

#define VM_DIAGNOSTICS_V4V_PORT 44461
#define VM_DIAGNOSTICS_MSG_MAX_PAYLOAD_BYTES 4089

/* Pack structures, using directives that GCC and MSVC both understand. */
#pragma pack(push, 1)

struct vm_diagnostics_hdr
{
    uint16_t type;
    uint32_t payload_size;

};

struct vm_diagnostics_msg
{
    struct vm_diagnostics_hdr header;
    uint8_t payload[VM_DIAGNOSTICS_MSG_MAX_PAYLOAD_BYTES];

};

struct vm_diagnostics_stat_system
{
    uint64_t ticks_per_second;

    uint64_t boot_time_seconds;

    uint64_t num_context_switches;
    uint32_t num_forks_since_boot;

    uint32_t cpu_count;

    uint32_t num_tasks;
    uint32_t num_tasks_running;
    uint32_t num_tasks_blocked;

};

#pragma pack(pop)     /* pack(push, 1) */
