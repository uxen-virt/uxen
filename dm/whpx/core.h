/*
 * Copyright 2018, Bromium, Inc.
 * Author: Tomasz Wroblewski <tomasz.wroblewski@gmail.com>
 * SPDX-License-Identifier: ISC
 */

#ifndef WHPX_CORE_H_
#define WHPX_CORE_H_

#define DEBUG_PORT_NUMBER 0xe9

#define WHPX_MSR_VMEXITS 0

struct CPUX86State;
typedef struct CPUX86State CPUState;

/**
 * CPU / IRQ
 */
int whpx_init_vcpu(CPUState *cpu);
int whpx_vcpu_exec(CPUState *cpu);
void whpx_destroy_vcpu(CPUState *cpu);
void whpx_vcpu_kick(CPUState *cpu);

void whpx_cpu_synchronize_state(CPUState *cpu);
void whpx_cpu_synchronize_post_reset(CPUState *cpu);
void whpx_cpu_synchronize_post_init(CPUState *cpu);
void whpx_cpu_synchronize_pre_loadvm(CPUState *cpu);

int whpx_cpu_is_self(void *env);
int whpx_cpu_is_stopped(CPUState *env);
void whpx_cpu_reset_interrupt(CPUState *env, int mask);
int whpx_cpu_get_pic_interrupt(CPUState *env);
void whpx_do_cpu_sipi(CPUState *env);
void whpx_do_cpu_init(CPUState *env);

void whpx_run_on_cpu(
    CPUState *env,
    void (*func)(CPUState *env, void *data),
    void *data);


int whpx_partition_setup(void);

/* low level partition mem mapping update */
void whpx_update_mapping(uint64_t start_pa, uint64_t size,
    void *host_va, int add, int rom,
    const char *name);

int whpx_translate_gva_to_gpa(CPUState *cpu, int write, uint64_t gva, uint64_t *gpa,
                              int *is_unmapped);


#endif
