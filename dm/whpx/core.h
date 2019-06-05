/*
 * Copyright 2018-2019, Bromium, Inc.
 * Author: Tomasz Wroblewski <tomasz.wroblewski@gmail.com>
 * SPDX-License-Identifier: ISC
 */

#ifndef WHPX_CORE_H_
#define WHPX_CORE_H_

#define DEBUG_PORT_NUMBER 0xe9

#define WHPX_MAX_REGISTERS 256
#define WHPX_MAX_XSAVE_AREA_SIZE 16384

struct CPUX86State;
typedef struct CPUX86State CPUState;

struct v4v_domain;

typedef struct domain {
    uint16_t domain_id;
    critical_section lock;
    struct v4v_domain *v4v;
    int is_host;
    int is_dying;
    int signalled;
} domain_t;

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
    uint32_t    interrupt_in_flight;
    uint32_t    ready_for_pic_interrupt;
    uint32_t    window_registered;
    /* hv registers */
    uint32_t    nreg;
    whpx_reg_name_t reg [WHPX_MAX_REGISTERS];
    whpx_reg_val_t  regv[WHPX_MAX_REGISTERS];
    /* other state */
    uint8_t irq_controller_state[PAGE_SIZE];
    uint8_t xsave_state[WHPX_MAX_XSAVE_AREA_SIZE];
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
void whpx_evaluate_load(int force_off);

int whpx_partition_init(void);
int whpx_partition_destroy(void);

/* low level partition mem mapping update */
void whpx_update_mapping(uint64_t start_pa, uint64_t size,
    void *host_va, int add, int rom,
    const char *name);

int whpx_translate_gva_to_gpa(CPUState *cpu, int write, uint64_t gva, uint64_t *gpa,
                              int *is_unmapped);

void whpx_v4v_signal(struct domain *);
void whpx_v4v_process_signals(void);

#endif
