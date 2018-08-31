/*
 * Copyright 2018-2019, Bromium, Inc.
 * Author: Christian Limpach <Christian.Limpach@gmail.com>
 * SPDX-License-Identifier: ISC
 */

#ifndef __ASM_HVM_PVNESTED_H__
#define __ASM_HVM_PVNESTED_H__

#if defined(__x86_64__)

extern bool_t pvnested;

void pvnested_setup(void);
struct cpuinfo_x86;
void pvnested_cpu_fixup(struct cpuinfo_x86 *);

#endif  /* __x86_64__ */

#endif  /* __ASM_HVM_PVNESTED_H__ */
