/*
 * Copyright 2013-2015, Bromium, Inc.
 * Author: Kris Uchronski <kuchronski@gmail.com>
 * SPDX-License-Identifier: ISC
 */

#include "kdx.h"
#include "kdxinfo.h"

#include <uxen/kdxinfo.h>

#define PAGE_SHIFT 12

// Instantiate EngExtCpp framework's globals.
EXT_DECLARE_GLOBALS();

EXT_COMMAND(
    uxen,
    "uxen uber kd command center",
    "")
{
    RequireKernelMode();

    Dml("Dump uxen log        ->"
        " <exec cmd=\"!uxenkdx.dumplog\">!dumplog</exec>\n"
        "Dump uxen_info       ->"
        " <exec cmd=\"?? (uxen!uxen_info*)&uxen!_uxen_info\">?? (uxen!uxen_info*)&uxen!_uxen_info</exec>\n"
        "Show uxen pool usage ->"
        " <exec cmd=\"!poolused 1 nexu\">!poolused 1 nexu</exec>\n"
        "Dump domains         ->"
        " <exec cmd=\"!domain\">!domain</exec>\n"
        "Dump host page list  ->"
        " <exec cmd=\"!hostpages\">!hostpages</exec>\n");

    Out("\n");
}

ULONG64 get_expr(char *expr_fmt, ...)
{
    char expr[MAX_PATH];
    va_list args;

    va_start(args, expr_fmt);
    vsprintf_s(expr, ARRAYSIZE(expr), expr_fmt, args);
    return GetExpression(expr);
}

void
EXT_CLASS::dump_page_list(
    ULONG64 start_entry_addr,
    ULONG64 frametable_addr,
    bool dump_backwards, 
    bool verbose_output,
    ULONG64 bytes_to_display)
{
    ULONG64 page_info_addr;
    ULONG64 idx;
    ULONG number_of_pages = 0;
    ULONG link = (ULONG)-2;
    ULONG link_offset = dump_backwards ? 4 : 0;

    Out("Analyzing page list (%s) @ 0x%p...\n",
        dump_backwards ? "backwards" : "forwards",
        start_entry_addr);

    page_info_addr = start_entry_addr;
    while ((ULONG)-1 != link && NULL != page_info_addr) {
        if (CheckControlC()) {
            Out("--- user break ---\n");
            break;
        }

        if (verbose_output) {
            idx = (page_info_addr - frametable_addr) /
                ___usym_sizeof___page_info;
            if (page_info_addr < frametable_addr) {
                Dml("  !!! invalid [page_info @ 0x%p, <exec cmd=\"!db 0x%x l0x1000\">idx:0x%08x</exec>] next:0x%08x, prev:0x%08x"
                    ", count_info:%d, {last}:0x%08x\n",
                    page_info_addr,
                    idx << PAGE_SHIFT, idx,
                    get_expr("poi(0x%p)", page_info_addr) & ~0UL,
                    get_expr("poi(0x%p + 0x4)", page_info_addr) & ~0UL,
                    get_expr("poi(0x%p + 0x8)", page_info_addr) & ~0UL,
                    get_expr("poi(0x%p + 0x10)", page_info_addr) & ~0UL);
            } else {
                Dml("  [page_info @ 0x%p, <exec cmd=\"!db 0x%x l0x1000\">idx:0x%08x</exec>] next:0x%08x, prev:0x%08x"
                    ", count_info:%d, {last}:0x%08x\n",
                    page_info_addr,
                    idx << PAGE_SHIFT, idx,
                    get_expr("poi(0x%p)", page_info_addr) & ~0UL,
                    get_expr("poi(0x%p + 0x4)", page_info_addr) & ~0UL,
                    get_expr("poi(0x%p + 0x8)", page_info_addr) & ~0UL,
                    get_expr("poi(0x%p + 0x10)", page_info_addr) & ~0UL);
            }
            if (bytes_to_display > 0)
                Execute("!db 0x%x l0x%x", idx, bytes_to_display);
        }

        if (CheckControlC()) {
            Out("--- user break ---\n");
            break;
        }

        link = get_expr("poi(0x%p+0x%x)", page_info_addr, link_offset) & ~0UL;
        page_info_addr = frametable_addr + ___usym_sizeof___page_info * link;
        number_of_pages++;
    }

    Out("Total number of pages:0x%x (%d MB)\n",
        number_of_pages ? number_of_pages - 1 : 0, number_of_pages >> 8);
}

EXT_COMMAND(
    kdxinfo,
    "set uxen offsets from kdxinfo structure",
    "")
{
    struct uxen_kdxinfo kdxinfo;
    int ret;

    RequireKernelMode();

    ULONG64 kdxinfo_addr = GetExpression("uxen!uxen_kdxinfo");
    uint16_t kdxinfo_size =
        (uint16_t)GetExpression("poi(uxen!uxen_kdxinfo_size)");

    ExtRemoteData kdxinfo_r(kdxinfo_addr, kdxinfo_size);

    if (sizeof(kdxinfo) != kdxinfo_size) {
        Out("kdxinfo incompatible size %d, supported %d\n", sizeof(kdxinfo),
            kdxinfo_size);
        return;
    }

    ret = kdxinfo_r.ReadBuffer(&kdxinfo, kdxinfo_size, false);
    if (ret != kdxinfo_size) {
        Out("kdxinfo incomplete read %d of %d\n", ret, kdxinfo_size);
        return;
    }

    if (kdxinfo.version != KDXINFO_VERSION) {
        Out("kdxinfo incompatible version %d, supported %d\n", kdxinfo.version,
            KDXINFO_VERSION);
        return;
    }

    Out("kdxinfo %p size %x version %x\n", kdxinfo_addr, kdxinfo_size,
        kdxinfo.version);

    set_usym_sizeof (page_info) = kdxinfo.sizeof_struct_page_info;

    set_usym_sizeof (domain) = kdxinfo.sizeof_struct_domain;
    set_usym        (domain, domain_id) = kdxinfo.domain_domain_id;
    set_usym_addr   (domain, page_list_next) = kdxinfo.domain_page_list_next;
    set_usym_addr   (domain, page_list_tail) = kdxinfo.domain_page_list_tail;
    set_usym_addr   (domain, vm_info_shared) = kdxinfo.domain_vm_info_shared;
    set_usym        (domain, max_vcpus) = kdxinfo.domain_max_vcpus;
    set_usym_addr   (domain, next_in_list) = kdxinfo.domain_next_in_list;
    set_usym_addr   (domain, vcpu) = kdxinfo.domain_vcpu;

    set_usym_sizeof (vcpu) = kdxinfo.sizeof_struct_vcpu;
    set_usym        (vcpu, vcpu_id) = kdxinfo.vcpu_vcpu_id;
    set_usym        (vcpu, is_running) = kdxinfo.vcpu_is_running;
    set_usym        (vcpu, arch_hvm_vmx_vmcs) = kdxinfo.vcpu_arch_hvm_vmx_vmcs;
    set_usym        (vcpu, arch_hvm_vmx_vmcs_ma) =
        kdxinfo.vcpu_arch_hvm_vmx_vmcs_ma;
    set_usym        (vcpu, arch_hvm_vmx_vmcs_shadow) =
        kdxinfo.vcpu_arch_hvm_vmx_vmcs_shadow;
    set_usym        (vcpu, arch_hvm_vmx_active_cpu) =
        kdxinfo.vcpu_arch_hvm_vmx_active_cpu;
    set_usym        (vcpu, arch_hvm_vmx_launched) =
        kdxinfo.vcpu_arch_hvm_vmx_launched;
}
