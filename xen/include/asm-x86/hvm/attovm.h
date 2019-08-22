/*
 * Copyright 2019, Bromium, Inc.
 * Author: Tomasz Wroblewski <tomasz.wroblewski@gmail.com>
 * SPDX-License-Identifier: ISC
 */

#ifndef __ASM_X86_HVM_ATTOVM_H__
#define __ASM_X86_HVM_ATTOVM_H__

#include <asm/hvm/vmx/vmx.h>
#include <asm/hvm/vmx/vmcs.h>
#include <attoxen-api/ax_attovm.h>
#include <attoxen-api/ax_attovm_stub.h>

void attovm_initialise(struct domain *d);
void attovm_vcpu_initialise(struct vcpu *v);
int  attovm_assign_token(struct domain *d, uint128_t *token);
void attovm_vcpu_destroy(struct vcpu *v);
void attovm_destroy(struct domain *d);
void attovm_inject_extint(uint8_t vector);
enum hvm_intblk attovm_intblk(void);
int  attovm_map_host_page(struct domain *d, uint64_t gpfn, uint64_t mfn );
void attovm_prepare_enter(struct vcpu *v);
void attovm_assist(struct vcpu *v);
int  attovm_seal(struct domain *d, struct attovm_definition_v1 *def);
int  attovm_get_guest_pages(struct domain *d, uint64_t pfn, uint64_t count, XEN_GUEST_HANDLE(void) buffer);
int  attovm_get_guest_cpu_state(struct domain *d, uint32_t vcpu, XEN_GUEST_HANDLE(void) buffer, uint32_t buffer_size);
int  attovm_do_cpuid(struct cpu_user_regs *regs);
int  attovm_kbd_focus(struct domain *d, uint32_t offer_focus);

#endif
