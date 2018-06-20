/*
 * Copyright 2018, Bromium, Inc.
 * Author: Tomasz Wroblewski <tomasz.wroblewski@gmail.com>
 * SPDX-License-Identifier: ISC
 */

#ifndef WHPX_VIRIDIAN_H_
#define WHPX_VIRIDIAN_H_

#define VIRIDIAN_CPUID_SIGNATURE_EBX 0x7263694d
#define VIRIDIAN_CPUID_SIGNATURE_ECX 0x666f736f
#define VIRIDIAN_CPUID_SIGNATURE_EDX 0x76482074

int cpuid_viridian_leaves(
  uint64_t leaf, uint64_t *eax,
  uint64_t *ebx, uint64_t *ecx,
  uint64_t *edx);
int viridian_hypercall(uint64_t *rax);

int rdmsr_viridian_regs(uint32_t msr, uint64_t *msr_content);
int wrmsr_viridian_regs(uint32_t msr, uint64_t msr_content);

#endif
