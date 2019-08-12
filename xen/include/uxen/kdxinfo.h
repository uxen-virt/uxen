/*
 *  kdxinfo.h
 *  uxen
 *
 * Copyright 2015-2019, Bromium, Inc.
 * Author: Christian Limpach <Christian.Limpach@gmail.com>
 * SPDX-License-Identifier: ISC
 *
 */

#ifndef __KDXINFO_H__
#define __KDXINFO_H__

/* NOTE: increment VERSION whenever adding fields, catchup
 * VERSION_COMPAT to VERSION whenever changing (remove/change) fields
 * in struct uxen_kdxinfo in an incompatible way, */
#define KDXINFO_VERSION_COMPAT 1
#define KDXINFO_VERSION 3

struct uxen_kdxinfo {
    uint16_t version;

    uint16_t sizeof_struct_page_info;

    uint16_t sizeof_struct_domain;
    uint16_t domain_domain_id;
    uint16_t domain_page_list_next;
    uint16_t domain_page_list_tail;
    uint16_t domain_max_vcpus;
    uint16_t domain_next_in_list;
    uint16_t domain_vcpu;
    uint16_t domain_vm_info_shared;

    uint16_t sizeof_struct_vcpu;
    uint16_t vcpu_vcpu_id;
    uint16_t vcpu_is_running;
    uint16_t vcpu_arch_hvm_vmx_vmcs;
    uint16_t vcpu_arch_hvm_vmx_vmcs_ma;
    uint16_t vcpu_arch_hvm_vmx_vmcs_shadow;
    uint16_t vcpu_arch_hvm_vmx_active_cpu;
    uint16_t vcpu_arch_hvm_vmx_launched;

    uint16_t page_info_list_next;
    uint16_t page_info_list_prev;
    uint16_t page_info_count_info;
    uint16_t page_info_domain;

    uint16_t page_list_next;
    uint16_t page_list_tail;

    uint16_t domain_shared_info;
    uint16_t domain_shared_info_gpfn;
    uint16_t domain_tot_pages;
    uint16_t domain_max_pages;
    uint16_t domain_hidden_pages;
    uint16_t domain_pod_pages;
    uint16_t domain_zero_shared_pages;
    uint16_t __unused1;         /* was domain_retry_pages; */
    uint16_t domain_tmpl_shared_pages;
    uint16_t domain_xenheap_pages;
    uint16_t domain_host_pages;
    uint16_t domain_refcnt;
    uint16_t domain_clone_of;
    uint16_t domain_arch_p2m;

    uint16_t p2m_pages_list;
    uint16_t p2m_max_mapped_pfn;
    uint16_t p2m_table;
};

#endif  /* __KDXINFO_H__ */
