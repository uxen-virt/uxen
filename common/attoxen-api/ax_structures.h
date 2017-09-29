/*
 * Copyright 2017-2018, Bromium, Inc.
 * SPDX-License-Identifier: ISC
 */

#ifndef __AX_STRUCTURES_H__
#define __AX_STRUCTURES_H__

typedef struct ax_vmcs_extensions_v1 {
  uint64_t pv_ept_gpa_level_and_flags;
  uint64_t pv_ept_base;
  uint64_t pv_ept_pte;
  uint64_t flags;
  uint64_t msr_gs_shadow;
  uint64_t msr_star;
  uint64_t msr_cstar;
  uint64_t msr_lstar;
  uint64_t msr_syscall_mask;
} ax_vmcs_extensions_v1_t;

struct ax_vmcb_extra {
    uint32_t flags;
    uint32_t g_cr8;
    uint64_t vmsave_pa;
    uint64_t vmsave_root_pa;
    uint64_t xsave_pa;
    uint64_t uregs_pa;
    ax_vmcs_extensions_v1_t ext;
} __attribute__ ((packed));

#endif /* __AX_STRUCTURES_H__ */
