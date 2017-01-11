/*
 * Copyright 2017, Bromium, Inc.
 * SPDX-License-Identifier: ISC
 */

#ifndef __AX_STRUCTURES_H__
#define __AX_STRUCTURES_H__

typedef struct ax_vmcs_extensions_v1 {
  uint64_t flags;
  uint64_t msr_gs_shadow;
  uint64_t msr_star;
  uint64_t msr_cstar;
  uint64_t msr_lstar;
  uint64_t msr_syscall_mask;
} ax_vmcs_extensions_v1_t;

#endif /* __AX_STRUCTURES_H__ */
