/*
 * Copyright 2013-2015, Bromium, Inc.
 * Author: Kris Uchronski <kuchronski@gmail.com>
 * SPDX-License-Identifier: ISC
 */

#pragma once

#include <stdio.h>
#include <engextcpp.hpp>
#include "uxen_types.h"

/* for now this is x64 only */

#define VM_PTR_SIZE 8
#define VM_PTR_TYPE ULONG64

struct uxen_logging_buffer {
    volatile uint64_t ulb_consumer;
    volatile uint64_t ulb_producer;
    volatile uint32_t ulb_size;
    char ulb_buffer[1];
};

class EXT_CLASS
    : public ExtExtension
{
public:
    EXT_COMMAND_METHOD(kdxinfo);
    EXT_COMMAND_METHOD(domain);
    EXT_COMMAND_METHOD(dumplog);
    EXT_COMMAND_METHOD(hostpages);
    EXT_COMMAND_METHOD(pageinfo);
    EXT_COMMAND_METHOD(pagelist);
    EXT_COMMAND_METHOD(uxen);
    EXT_COMMAND_METHOD(ugdb);
    EXT_COMMAND_METHOD(udt);
private:
    void dump_page_info(ULONG64, ULONG64, bool);
    void dump_page_list(ULONG64, ULONG64, bool, bool, ULONG64);
    ULONG64 get_domain_by_id(uint16_t id);
    char *uxen_logging_read(struct uxen_logging_buffer *,
                            uint64_t *, uint32_t *, uint64_t *log_size);
    void execute_gdb_cmd(const char *, const char *, const char *);
    void refresh_uxen_paths(const bool);
};

ULONG64 get_expr(char *expr_fmt, ...);
