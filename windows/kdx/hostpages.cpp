/*
 * Copyright 2014-2016, Bromium, Inc.
 * Author: Kris Uchronski <kuchronski@gmail.com>
 * SPDX-License-Identifier: ISC
 */

#include "kdx.h"
#include "kdxinfo.h"

EXT_COMMAND(
    hostpages,
    "dumps host pages",
    "{v;b;;show page details}"
    "{b;b;;dump pages backwards}"
    "{d;ed;;show given first number of bytes}")
{
    ULONG64 host_page_list_addr;
    ULONG64 frametable_addr;
    ULONG64 page_list_head_addr, page_list_tail_addr;

    RequireKernelMode();

    host_page_list_addr = get_expr("uxen!host_page_list");
    frametable_addr = get_expr("poi(uxen!frametable)");

    page_list_head_addr = get_expr("poi(0x%p)", host_page_list_addr +
                                   usym_offset(page_list, next));
    if (!page_list_head_addr) {
        Out("Host page list is empty\n");
        return;
    }
    page_list_tail_addr = get_expr("poi(0x%p)", host_page_list_addr +
                                   usym_offset(page_list, tail));

    dump_page_list(HasArg("b") ? page_list_tail_addr : page_list_head_addr,
                   frametable_addr, HasArg("b"), HasArg("v"),
                   HasArg("d") ? GetArgU64("d", false) : 0);
}
