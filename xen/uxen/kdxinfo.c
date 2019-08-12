/*
 *  kdxinfo.c
 *  uxen
 *
 * Copyright 2015-2019, Bromium, Inc.
 * Author: Christian Limpach <Christian.Limpach@gmail.com>
 * SPDX-License-Identifier: ISC
 *
 */

#include <xen/config.h>
#include <xen/types.h>
#include <xen/sched.h>
#include <asm/p2m.h>

#include <uxen/kdxinfo.h>

uint16_t uxen_kdxinfo_size = sizeof(struct uxen_kdxinfo);

struct uxen_kdxinfo uxen_kdxinfo = {
    .version = KDXINFO_VERSION,

    .sizeof_struct_page_info = sizeof(struct page_info),

    .sizeof_struct_domain = sizeof(struct domain),
    .domain_domain_id = offsetof(struct domain, domain_id),
    .domain_page_list_next = 0, // offsetof(struct domain, page_list.next),
    .domain_page_list_tail = 0, // offsetof(struct domain, page_list.tail),
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

    .page_info_list_next = offsetof(struct page_info, list.next),
    .page_info_list_prev = offsetof(struct page_info, list.prev),
    .page_info_count_info = offsetof(struct page_info, count_info),
    .page_info_domain = offsetof(struct page_info, domain),

    .page_list_next = offsetof(struct page_list_head, next),
    .page_list_tail = offsetof(struct page_list_head, tail),

    .domain_shared_info = offsetof(struct domain, shared_info),
    .domain_shared_info_gpfn = offsetof(struct domain, shared_info_gpfn),
    .domain_tot_pages = offsetof(struct domain, tot_pages),
    .domain_max_pages = offsetof(struct domain, max_pages),
    .domain_hidden_pages = offsetof(struct domain, hidden_pages),
    .domain_pod_pages = offsetof(struct domain, pod_pages),
    .domain_zero_shared_pages = offsetof(struct domain, zero_shared_pages),
    .domain_tmpl_shared_pages = offsetof(struct domain, tmpl_shared_pages),
    .domain_xenheap_pages = offsetof(struct domain, xenheap_pages),
    .domain_host_pages = offsetof(struct domain, host_pages),
    .domain_refcnt = offsetof(struct domain, refcnt),
    .domain_clone_of = offsetof(struct domain, clone_of ),
    .domain_arch_p2m = offsetof(struct domain, arch.p2m),

    .p2m_pages_list = offsetof(struct p2m_domain, pages),
    .p2m_max_mapped_pfn = offsetof(struct p2m_domain, max_mapped_pfn),
    .p2m_table = offsetof(struct p2m_domain, phys_table),
};
