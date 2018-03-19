/*
 * Copyright 2018, Bromium, Inc.
 * SPDX-License-Identifier: ISC
 */

#ifndef EMULATE_H_
#define EMULATE_H_

#include "x86_emulate.h"
#include <stdint.h>

whpx_reg_list_t *emu_get_read_registers(void);
whpx_reg_list_t *emu_get_write_registers(void);
void emu_registers_hv_to_cpustate(CPUState *cpu, WHV_REGISTER_VALUE *values);
int emu_registers_cpustate_to_hv(CPUState *cpu, size_t maxregs, WHV_REGISTER_NAME *names, WHV_REGISTER_VALUE *values);
int emu_simple_port_io(int is_write, unsigned int port, unsigned int bytes, uint64_t *val);
void emu_one(CPUState *cpu, void *instr, int instr_max_len);
void emu_init(void);

#endif
