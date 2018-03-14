/*
 * Copyright 2018, Bromium, Inc.
 * SPDX-License-Identifier: ISC
 */

#ifndef EMULATE_H_
#define EMULATE_H_

#include "x86_emulate.h"
#include <stdint.h>

#define NUM_EMU_REGISTERS 26
#define NUM_SET_EMU_REGISTERS (NUM_EMU_REGISTERS-6)

WHV_REGISTER_NAME *emu_get_hv_register_names(void);
void emu_registers_hv_to_cpustate(CPUState *cpu, WHV_REGISTER_VALUE *values);
void emu_registers_cpustate_to_hv(CPUState *cpu, size_t maxregs, WHV_REGISTER_NAME *names, WHV_REGISTER_VALUE *values);

int emu_simple_port_io(int is_write, unsigned int port, unsigned int bytes, uint64_t *val);
void emu_one(CPUState *cpu, void *instr, int instr_max_len);

#endif
