/*
 *  kdxinfo.h
 *  uxen
 *
 * Copyright 2015, Bromium, Inc.
 * Author: Christian Limpach <Christian.Limpach@gmail.com>
 * SPDX-License-Identifier: ISC
 *
 */

#ifndef __KDXINFO_H__
#define __KDXINFO_H__

/* NOTE: bump version whenever removing/chaging fields in struct
 * uxen_kdxinfo */
#define KDXINFO_VERSION 1

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
};

#endif  /* __KDXINFO_H__ */
