/*
 * Copyright 2015-2016, Bromium, Inc.
 * SPDX-License-Identifier: ISC
 */

#include "kdx.h"
#include "kdxinfo.h"

def_usym_sizeof (page_info) = 0x18;

def_usym_sizeof (domain) = 0x1000;
def_usym        (domain, domain_id) = 0x0000;
def_usym_ptr    (domain, page_list_next) = 0x0030;
def_usym_ptr    (domain, page_list_tail) = 0x0038;
def_usym_ptr    (domain, vm_info_shared) = 0x0090;
def_usym        (domain, max_vcpus) = 0x00a0;
def_usym_ptr    (domain, next_in_list) = 0x00b8;
def_usym_ptr    (domain, vcpu) = 0x0290;

def_usym_sizeof (vcpu) = 0x1000;
def_usym        (vcpu, vcpu_id) = 0x0000;
def_usym        (vcpu, is_running) = 0x020b;
def_usym        (vcpu, arch_hvm_vmx_vmcs) = 0x0620;
def_usym        (vcpu, arch_hvm_vmx_vmcs_ma) = 0x0628;
def_usym        (vcpu, arch_hvm_vmx_vmcs_shadow) = 0x0630;
def_usym        (vcpu, arch_hvm_vmx_active_cpu) = 0x0658;
def_usym        (vcpu, arch_hvm_vmx_launched) = 0x065c;

def_usym_offset (page_info, list_next) = 0;
def_usym_offset (page_info, list_prev) = 4;
def_usym_offset (page_info, count_info) = 8;
def_usym_offset (page_info, domain) = 16;

def_usym_offset (page_list, next) = 0;
def_usym_offset (page_list, tail) = 8;

def_usym_ptr    (domain, shared_info) = 0;
def_usym_offset (domain, shared_info_gpfn) = 0;
def_usym_offset (domain, tot_pages) = 0;
def_usym_offset (domain, max_pages) = 0;
def_usym_offset (domain, hidden_pages) = 0;
def_usym_offset (domain, pod_pages) = 0;
def_usym_offset (domain, zero_shared_pages) = 0;
def_usym_offset (domain, retry_pages) = 0;
def_usym_offset (domain, tmpl_shared_pages) = 0;
def_usym_offset (domain, xenheap_pages) = 0;
def_usym_offset (domain, host_pages) = 0;
def_usym_offset (domain, refcnt) = 0;
def_usym_ptr    (domain, clone_of) = 0;
def_usym_ptr    (domain, arch_p2m) = 0;
