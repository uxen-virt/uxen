/*
 * Copyright 2013-2015, Bromium, Inc.
 * Author: Kris Uchronski <kuchronski@gmail.com>
 * SPDX-License-Identifier: ISC
 */

#include "kdx.h"
#include "kdxinfo.h"

EXT_COMMAND(
    domain,
    "displays various information about uxen domains",
    "{;ed,o;expr;domain address}"
    "{v;b;;show page details}"
    "{b;b;;dump pages backwards}"
    "{d;ed;;show given first number of bytes}")
{
    RequireKernelMode();

    ULONG64 usym_addr(domain);
    ULONG64 phys_addr;

    if (HasUnnamedArg(0)) {
        /* dump specific domain details */
        ULONG64 frametable_addr = GetExpression("poi(uxen!frametable)");
        usym_addr(domain) = GetUnnamedArgU64(0);
        usym_fetch_struct(domain, return);
        usym_def_addr(domain, page_list_next);
        usym_def_addr(domain, page_list_tail);

        if (TranslateVirtualToPhysical(usym_addr(domain), &phys_addr))
            phys_addr >>= 12;
        else
            phys_addr = 0;

        Out("[domain %hd:0x%p(0x%08x)]\n"
            "  frametable:0x%p\n"
            "  page_list_next:0x%p, page_list_tail:0x%p\n",
            usym_read_u16(domain, domain_id), usym_addr(domain),
            phys_addr,
            frametable_addr,
            usym_addr(domain_page_list_next),
            usym_addr(domain_page_list_tail));

        dump_page_list(HasArg("db") ? usym_addr(domain_page_list_tail) :
                                      usym_addr(domain_page_list_next),
                       frametable_addr, HasArg("b"), HasArg("v"),
                       HasArg("d") ? GetArgU64("d", false) : 0);
    } else {
        /* domain address not provided - dump domain list */
        usym_addr(domain) = GetExpression("poi(uxen!domain_list)");
        while (0 != usym_addr(domain)) {
            usym_fetch_struct(domain, break);
            usym_def_u32(domain, max_vcpus);
            usym_def_addr(domain, vcpu);

            if (TranslateVirtualToPhysical(usym_addr(domain), &phys_addr))
                phys_addr >>= 12;
            else
                phys_addr = 0;

            Dml("[<exec cmd=\"!domain 0x%p\">domain %hd</exec>:0x%p(0x%08x)] max_vcpus:%d, vcpu:0x%p\n",
                usym_addr(domain), 
                usym_read_u16(domain, domain_id),
                usym_addr(domain),
                phys_addr,
                domain_max_vcpus, usym_addr(domain_vcpu));

            usym_fetch_array(domain_vcpu, domain_max_vcpus * VM_PTR_SIZE,
                             VM_PTR_TYPE, goto next_domain);

            for (ULONG i = 0; i < domain_max_vcpus; i++) {
                VM_PTR_TYPE usym_addr(vcpu) = usym_arr(domain_vcpu)[i];
                usym_fetch_struct(vcpu, continue);

                Dml("    vcpu[%d]:0x%p, vcpu_id:%d, "
                    "is_running:%d, active_cpu:0x%x, launched:0x%x, "
                    "vmcs:0x%p, vmcs_ma:0x%p, vmcs_shadow:0x%p\n",
                    i, usym_addr(vcpu), usym_read_u32(vcpu, vcpu_id),
                    usym_read_u8(vcpu, is_running),
                    usym_read_u32(vcpu, arch_hvm_vmx_active_cpu),
                    usym_read_u32(vcpu, arch_hvm_vmx_launched),
                    usym_read_u64(vcpu, arch_hvm_vmx_vmcs),
                    usym_read_u64(vcpu, arch_hvm_vmx_vmcs_ma),
                    usym_read_u64(vcpu, arch_hvm_vmx_vmcs_shadow));
            }

            usym_free_arr(domain_vcpu);
            
          next_domain:
            usym_addr(domain) = usym_read_addr(domain, next_in_list);               
        }
    }
}
