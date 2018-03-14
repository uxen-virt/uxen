/*
 * Copyright 2018, Bromium, Inc.
 * SPDX-License-Identifier: ISC
 */

#ifndef WHPX_CPU_GLUE_H_
#define WHPX_CPU_GLUE_H_

#define qemu_cpu_is_self whpx_cpu_is_self
#define cpu_is_stopped whpx_cpu_is_stopped
#define cpu_reset_interrupt whpx_cpu_reset_interrupt
#define run_on_cpu whpx_run_on_cpu
#define qemu_mutex_lock_iothread whpx_lock_iothread
#define qemu_mutex_unlock_iothread whpx_unlock_iothread
#define cpu_is_bsp whpx_cpu_is_bsp
#define cpu_get_current_apic whpx_cpu_get_current_apic
#define do_cpu_init whpx_do_cpu_init
#define do_cpu_sipi whpx_do_cpu_sipi
#define cpu_get_pic_interrupt whpx_cpu_get_pic_interrupt

typedef void *run_on_cpu_data;
#define RUN_ON_CPU_NULL NULL

void qemu_cpu_kick(CPUState*);
int whpx_cpu_is_self(void *env);
void whpx_cpu_reset_interrupt(CPUState *env, int mask);

typedef void (*CPUInterruptHandler)(CPUState *, int);

extern CPUInterruptHandler cpu_interrupt_handler;

static inline void cpu_interrupt(CPUState *s, int mask)
{
    cpu_interrupt_handler(s, mask);
}

extern CPUState *current_cpu;

#endif
