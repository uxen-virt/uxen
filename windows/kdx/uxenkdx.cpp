/*
 * Copyright 2013-2019, Bromium, Inc.
 * Author: Kris Uchronski <kuchronski@gmail.com>
 * SPDX-License-Identifier: ISC
 */

#include "kdx.h"
#include "kdxinfo.h"
#include "uxen_defs.h"

#include <uxen/kdxinfo.h>

#define PAGE_SHIFT 12

EXT_DECLARE_GLOBALS();

static int page_info_domain_is_domid = 1;

EXT_COMMAND(
    uxen,
    "uxen uber kd command center",
    "")
{
    RequireKernelMode();

    Dml("Dump uxen log        ->"
        " <exec cmd=\"!uxenkdx.dumplog\">!dumplog</exec>\n"
        "Dump uxen_info       ->"
        " <exec cmd=\"?? (uxen!uxen_info*)&uxen!__uxen_info\">?? (uxen!uxen_info*)&uxen!__uxen_info</exec>\n"
        "Show uxen pool usage ->"
        " <exec cmd=\"!poolused 1 nexu\">!poolused 1 nexu</exec>\n"
        "Dump domains         ->"
        " <exec cmd=\"!domain\">!domain</exec>\n"
        "Dump host page list  ->"
        " <exec cmd=\"!hostpages\">!hostpages</exec>\n"
        "Update offsets       ->"
        " <exec cmd=\"!kdxinfo\">!kdxinfo</exec>\n");

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
EXT_CLASS::dump_page_info(
    ULONG64 frametable_addr,
    ULONG64 page_info_addr,
    bool decode_pgc)
{
    ULONG64 idx;
    ULONG count_info;
    bool invalid;
    char pgc[128];
    char page_info_state[128];

    idx = (page_info_addr - frametable_addr) / ___usym_sizeof___page_info;
    invalid = page_info_addr < frametable_addr;

    count_info = get_expr("poi(0x%p)", page_info_addr +
                          usym_offset(page_info, count_info)) & ~0UL;

    if (!page_state_is(count_info, inuse))
        sprintf(page_info_state, "%s",
                page_state_is(count_info, free) ? "free" :
                page_state_is(count_info, dirty) ? "dirty" : "host");
    else {
        if (page_info_domain_is_domid) {
            unsigned short domid =
                get_expr("poi(0x%p)", page_info_addr +
                         usym_offset(page_info, domain)) & 0xffff;
            if ((count_info & PGC_xen_page) && domid > 0x7ff0U)
                sprintf(page_info_state, "xen");
            else
                sprintf(page_info_state, "domain:0n%hd%s",
                        domid, (count_info & PGC_xen_page) ? " xen" : "");
        } else
            sprintf(page_info_state, "domain:0x%08x`%08x",
                    IsPtr64() ?
                    get_expr("poi(0x%p)", page_info_addr +
                             usym_offset(page_info, domain) + 4) & ~0UL : 0UL,
                    get_expr("poi(0x%p)", page_info_addr +
                             usym_offset(page_info, domain)) & ~0UL);
    }

    Dml("%s[page_info:0x%p, <exec cmd=\"!pageinfo 0x%x\">idx</exec>:0x%08x]"
        " <exec cmd=\"!pageinfo 0x%x\">prev</exec>:0x%08x"
        ", <exec cmd=\"!pageinfo 0x%x\">next</exec>:0x%08x"
        ", count_info:0x%08x, %s"
        " <exec cmd=\"!db 0x%x l0x1000\">[raw]</exec>\n",
        invalid ? "  !!! invalid " : "  ",
        page_info_addr,
        idx, idx,
        get_expr("poi(0x%p)",
                 page_info_addr + usym_offset(page_info, list_prev)) & ~0UL,
        get_expr("poi(0x%p)",
                 page_info_addr + usym_offset(page_info, list_prev)) & ~0UL,
        get_expr("poi(0x%p)",
                 page_info_addr + usym_offset(page_info, list_next)) & ~0UL,
        get_expr("poi(0x%p)",
                 page_info_addr + usym_offset(page_info, list_next)) & ~0UL,
        count_info & ~0UL,
        page_info_state,
        idx << PAGE_SHIFT);

    if (decode_pgc) {
        pgc2str(count_info, pgc, sizeof(pgc));
        Dml("    PGC flags:%s\n", pgc);
    }
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
            dump_page_info(frametable_addr, page_info_addr, false);
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
    pageinfo,
    "display page information",
    "{;ed,o;expr;page address}")
{
    RequireKernelMode();

    if (HasUnnamedArg(0)) {
        ULONG64 frametable_addr = GetExpression("poi(uxen!frametable)");
        ULONG64 idx = GetUnnamedArgU64(0);
        ULONG64 page_info_addr;

        if (idx >= frametable_addr)
            page_info_addr = idx;
        else
            page_info_addr = frametable_addr + ___usym_sizeof___page_info * idx;

        dump_page_info(frametable_addr, page_info_addr, true);
    }
}

EXT_COMMAND(
    pagelist,
    "display page list information",
    "{;ed,o;expr;page list head/tail address}"
    "{v;b;;show page details}"
    "{b;b;;dump pages backwards}"
    "{d;ed;;show given first number of bytes}")
{
    RequireKernelMode();

    if (HasUnnamedArg(0)) {
        ULONG64 frametable_addr = GetExpression("poi(uxen!frametable)");

        dump_page_list(GetUnnamedArgU64(0),
                       frametable_addr, HasArg("b"), HasArg("v"),
                       HasArg("d") ? GetArgU64("d", false) : 0);
    }
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

    if (sizeof(kdxinfo) < kdxinfo_size) {
        Out("kdxinfo incompatible size %d, needed %d\n",
            kdxinfo_size, sizeof(kdxinfo));
        return;
    }

    ret = kdxinfo_r.ReadBuffer(&kdxinfo, kdxinfo_size, false);
    if (ret != kdxinfo_size) {
        Out("kdxinfo incomplete read %d of %d\n", ret, kdxinfo_size);
        return;
    }

    if (kdxinfo.version < KDXINFO_VERSION_COMPAT ||
                          kdxinfo.version > KDXINFO_VERSION) {
        Out("kdxinfo incompatible version %d, supported %d-%d\n",
            kdxinfo.version, KDXINFO_VERSION_COMPAT, KDXINFO_VERSION);
        return;
    }

    Out("kdxinfo %p size %x version %x\n", kdxinfo_addr, kdxinfo_size,
        kdxinfo.version);

    page_info_domain_is_domid = (kdxinfo.version >= 3);

    set_usym_sizeof (page_info) = kdxinfo.sizeof_struct_page_info;

    set_usym_sizeof (domain) = kdxinfo.sizeof_struct_domain;
    set_usym        (domain, domain_id) = kdxinfo.domain_domain_id;
    set_usym_ptr    (domain, page_list_next) = kdxinfo.domain_page_list_next;
    set_usym_ptr    (domain, page_list_tail) = kdxinfo.domain_page_list_tail;
    set_usym_ptr    (domain, vm_info_shared) = kdxinfo.domain_vm_info_shared;
    set_usym        (domain, max_vcpus) = kdxinfo.domain_max_vcpus;
    set_usym_ptr    (domain, next_in_list) = kdxinfo.domain_next_in_list;
    set_usym_ptr    (domain, vcpu) = kdxinfo.domain_vcpu;

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

    if (kdxinfo.version <= 1)   // KDXINFO_VERSION compat
      return;

    set_usym_offset (page_info, list_next) = kdxinfo.page_info_list_next;
    set_usym_offset (page_info, list_prev) = kdxinfo.page_info_list_prev;
    set_usym_offset (page_info, count_info) = kdxinfo.page_info_count_info;
    set_usym_offset (page_info, domain) = kdxinfo.page_info_domain;

    set_usym_offset (page_list, next) = kdxinfo.page_list_next;
    set_usym_offset (page_list, tail) = kdxinfo.page_list_tail;

    set_usym_ptr    (domain, shared_info) = kdxinfo.domain_shared_info;
    set_usym_offset (domain, shared_info_gpfn) =
        kdxinfo.domain_shared_info_gpfn;
    set_usym_offset (domain, tot_pages) = kdxinfo.domain_tot_pages;
    set_usym_offset (domain, max_pages) = kdxinfo.domain_max_pages;
    set_usym_offset (domain, hidden_pages) = kdxinfo.domain_hidden_pages;
    set_usym_offset (domain, pod_pages) = kdxinfo.domain_pod_pages;
    set_usym_offset (domain, zero_shared_pages) =
        kdxinfo.domain_zero_shared_pages;
    set_usym_offset (domain, tmpl_shared_pages) =
        kdxinfo.domain_tmpl_shared_pages;
    set_usym_offset (domain, xenheap_pages) = kdxinfo.domain_xenheap_pages;
    set_usym_offset (domain, host_pages) = kdxinfo.domain_host_pages;
    set_usym_offset (domain, refcnt) = kdxinfo.domain_refcnt;
    set_usym_ptr    (domain, clone_of) = kdxinfo.domain_clone_of;
    set_usym_ptr    (domain, arch_p2m) = kdxinfo.domain_arch_p2m;
}
