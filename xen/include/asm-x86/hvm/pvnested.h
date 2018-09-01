/*
 * Copyright 2018-2019, Bromium, Inc.
 * Author: Christian Limpach <Christian.Limpach@gmail.com>
 * SPDX-License-Identifier: ISC
 */

#ifndef __ASM_HVM_PVNESTED_H__
#define __ASM_HVM_PVNESTED_H__

#if defined(__x86_64__)

#include <pvnested-api/pvnested-constants.h>
#include <pvnested-api/pvnested-structures.h>

extern bool_t pvnested;

extern volatile struct pvnested_vmx_info pvnested_vmx_info;

void pvnested_setup(void);
struct cpuinfo_x86;
void pvnested_cpu_fixup(struct cpuinfo_x86 *);

void pvnested_rdmsrl(uint32_t msr, uint64_t *value);
void pvnested_wrmsrl(uint32_t msr, uint64_t value);

int pvnested_vmxon(u64 addr);

#endif  /* __x86_64__ */

#endif  /* __ASM_HVM_PVNESTED_H__ */
