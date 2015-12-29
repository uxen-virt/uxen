/*
 * Copyright 2013-2016, Bromium, Inc.
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
        int has_page_list = !!usym_ptr(domain, page_list_next);
        usym_def_addr(domain, shared_info);

        if (TranslateVirtualToPhysical(usym_addr(domain), &phys_addr))
            phys_addr >>= 12;
        else
            phys_addr = 0;

        Out("[domain %hd:0x%p(0x%08x)]\n"
            "  refcnt:%d shared_info:0x%p(0x%x)\n",
            usym_read_u16(domain, domain_id), usym_addr(domain),
            phys_addr,
            usym_read_u32(domain, refcnt),
            usym_addr(domain_shared_info),
            usym_read_u32(domain, shared_info_gpfn));

        Out("  total:%d max:%d hidden:%d xen:%d host:%d\n",
            usym_read_u32(domain, tot_pages), usym_read_u32(domain, max_pages),
            usym_read_u32(domain, hidden_pages),
            usym_read_u32(domain, xenheap_pages),
            usym_read_u32(domain, host_pages));
        Out("  pod:%d zero_shared:%d tmpl_shared:%d retry:%d\n",
            usym_read_u32(domain, pod_pages),
            usym_read_u32(domain, zero_shared_pages),
            usym_read_u32(domain, tmpl_shared_pages),
            usym_read_u32(domain, retry_pages));

        if (has_page_list) {
            Dml("  page_list_next:<exec cmd=\"!pagelist -v 0x%p\">0x%p</exec>, page_list_tail:<exec cmd=\"!pagelist -v -b 0x%p\">0x%p</exec>\n",
                usym_addr(domain_page_list_next),
                usym_addr(domain_page_list_next),
                usym_addr(domain_page_list_tail),
                usym_addr(domain_page_list_tail));
            dump_page_list(HasArg("b") ? usym_addr(domain_page_list_tail) :
                           usym_addr(domain_page_list_next),
                           frametable_addr, HasArg("b"), HasArg("v"),
                           HasArg("d") ? GetArgU64("d", false) : 0);
        }
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

            for (ULONG i = 0; i < domain_max_vcpus; i++) {
                VM_PTR_TYPE usym_addr(vcpu) =
                  get_expr("poi(0x%p)", usym_addr(domain_vcpu) +
                           i * TARGET_VM_PTR_SIZE);
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

            usym_addr(domain) = usym_read_ptr(domain, next_in_list);
        }
    }
}
