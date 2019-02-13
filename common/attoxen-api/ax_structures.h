/*
 * Copyright 2017-2019, Bromium, Inc.
 * SPDX-License-Identifier: ISC
 */

#ifndef __AX_STRUCTURES_H__
#define __AX_STRUCTURES_H__

typedef struct ax_vmcs_extensions_v1 {
  uint64_t msr_spec_ctrl;
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

struct ax_vmcb_extra_v1 {
  uint32_t flags;
  uint32_t g_cr8;
  uint64_t vmsave_pa;
  uint64_t vmsave_root_pa;
  uint64_t xsave_pa;
  uint64_t uregs_pa;
} __attribute__ ((packed));


#define _DECL_REG(name) union { \
    uint64_t r ## name, e ## name; \
    uint32_t _e ## name; \
  }

struct ax_cpu_user_regs_v1 {
  uint64_t r15;
  uint64_t r14;
  uint64_t r13;
  uint64_t r12;
  uint64_t rbp;
  uint64_t rbx;
  uint64_t r11;
  uint64_t r10;
  uint64_t r9;
  uint64_t r8;
  uint64_t rax;
  uint64_t rcx;
  uint64_t rdx;
  uint64_t rsi;
  uint64_t rdi;
  uint32_t error_code;    /* private */
  uint32_t entry_vector;  /* private */
  uint64_t rip;
  uint16_t cs, _pad0[1];
  uint8_t  saved_upcall_mask;
  uint8_t  _pad1[3];
  uint64_t rflags;
  uint64_t rsp;
  uint16_t ss, _pad2[3];
  uint16_t es, _pad3[3];
  uint16_t ds, _pad4[3];
  uint16_t fs, _pad5[3]; /* Non-zero => takes precedence over fs_base.     */
  uint16_t gs, _pad6[3]; /* Non-zero => takes precedence over gs_base_usr. */
} __attribute__ ((packed));

#endif /* __AX_STRUCTURES_H__ */
