/*
 *  kdxinfo.c
 *  uxen
 *
 * Copyright 2015, Bromium, Inc.
 * Author: Christian Limpach <Christian.Limpach@gmail.com>
 * SPDX-License-Identifier: ISC
 *
 */

#include <xen/config.h>
#include <xen/types.h>
#include <xen/sched.h>

#include <uxen/kdxinfo.h>

uint16_t uxen_kdxinfo_size = sizeof(struct uxen_kdxinfo);

struct uxen_kdxinfo uxen_kdxinfo = {
    .version = KDXINFO_VERSION,

    .sizeof_struct_page_info = sizeof(struct page_info),

    .sizeof_struct_domain = sizeof(struct domain),
    .domain_domain_id = offsetof(struct domain, domain_id),
    .domain_page_list_next = offsetof(struct domain, page_list.next),
    .domain_page_list_tail = offsetof(struct domain, page_list.tail),
    .domain_max_vcpus = offsetof(struct domain, max_vcpus),
    .domain_next_in_list = offsetof(struct domain, next_in_list),
    .domain_vcpu = offsetof(struct domain, vcpu),
    .domain_vm_info_shared = offsetof(struct domain, vm_info_shared),

    .sizeof_struct_vcpu = sizeof(struct vcpu),
    .vcpu_vcpu_id = offsetof(struct vcpu, vcpu_id),
    .vcpu_is_running = offsetof(struct vcpu, is_running),
    .vcpu_arch_hvm_vmx_vmcs = offsetof(struct vcpu, arch.hvm_vmx.vmcs),
    .vcpu_arch_hvm_vmx_vmcs_ma = offsetof(struct vcpu, arch.hvm_vmx.vmcs_ma),
    .vcpu_arch_hvm_vmx_vmcs_shadow = offsetof(struct vcpu,
                                              arch.hvm_vmx.vmcs_shadow),
    .vcpu_arch_hvm_vmx_active_cpu = offsetof(struct vcpu,
                                             arch.hvm_vmx.active_cpu),
    .vcpu_arch_hvm_vmx_launched = offsetof(struct vcpu, arch.hvm_vmx.launched),
};
