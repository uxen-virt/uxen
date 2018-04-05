/*
 * Copyright 2018, Bromium, Inc.
 * Author: Tomasz Wroblewski <tomasz.wroblewski@gmail.com>
 * SPDX-License-Identifier: ISC
 */

#ifndef WHPX_CORE_H_
#define WHPX_CORE_H_

#define DEBUG_PORT_NUMBER 0xe9

#define WHPX_MSR_VMEXITS 0
#define WHPX_MAX_REGISTERS 256

struct CPUX86State;
typedef struct CPUX86State CPUState;

typedef struct whpx_reg_list {
    uint32_t num;
    uint32_t reg[WHPX_MAX_REGISTERS];
} whpx_reg_list_t;

typedef uint32_t whpx_reg_name_t;

typedef struct whpx_reg_val {
    uint64_t low64;
    uint64_t high64;
} whpx_reg_val_t;

struct whpx_vcpu_context {
    uint32_t    interrupt_request;
    uint32_t    interrupt_in_flight, interruptable;
    /* hv registers */
    uint32_t    nreg;
    whpx_reg_name_t reg [WHPX_MAX_REGISTERS];
    whpx_reg_val_t  regv[WHPX_MAX_REGISTERS];
};

struct whpx_vm_context {
    int version;
    int vcpus;
    struct whpx_vcpu_context vcpu[0];
};

#define whpx_reg_list_init(list, reg_array) \
  (list)->num = RTL_NUMBER_OF(reg_array);                               \
  memcpy(&(list)->reg[0], &(reg_array)[0], (list)->num * sizeof((list)->reg[0]));

/**
 * CPU / IRQ
 */
int whpx_init_vcpu(CPUState *cpu);
int whpx_vcpu_exec(CPUState *cpu);
void whpx_destroy_vcpu(CPUState *cpu);
void whpx_vcpu_kick(CPUState *cpu);
void whpx_vcpu_flush_dirty(CPUState *cpu);
int whpx_vcpu_get_context(CPUState *cpu, struct whpx_vcpu_context *ctx);
int whpx_vcpu_set_context(CPUState *cpu, struct whpx_vcpu_context *ctx);

int whpx_cpu_is_self(void *env);
int whpx_cpu_is_stopped(CPUState *env);
int whpx_cpu_has_work(CPUState *env);
void whpx_cpu_reset_interrupt(CPUState *env, int mask);
int whpx_cpu_get_pic_interrupt(CPUState *env);
void whpx_do_cpu_sipi(CPUState *env);
void whpx_do_cpu_init(CPUState *env);

void whpx_run_on_cpu(CPUState *env, int wait,
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
