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

#define usym_sizeof(name) \
    ___usym_sizeof___##name
#define usym_addr(name) \
    name##___addr
#define usym_arr(name) \
    name##___arr

#define def_usym(name, field, field_offset) \
    const ULONG ___usym___##name##___##field = (field_offset)
#define def_usym_addr(name, field, field_offset) \
    const ULONG usym_addr(___usym___##name##___##field) = (field_offset)
#define def_usym_sizeof(name, size) \
    const ULONG usym_sizeof(name) = (size)

#define usym_fetch(name, size, fail_action)                                   \
    ExtRemoteData name##_r(usym_addr(name), size);                            \
    UCHAR name##_buf[size];                                                   \
    ULONG name##_ret_size;                                                    \
    name##_ret_size = name##_r.ReadBuffer(name##_buf, size, FALSE);           \
    if (size != name##_ret_size) {                                            \
        Out("!!! Failed to read 0x%x bytes @ 0x%p of [%s] from target (read:0x%x)\n", \
            size, usym_addr(name), #name, name##_ret_size);                   \
        fail_action;                                                          \
    }

#define usym_fetch_struct(name, fail_action) \
    usym_fetch(name, usym_sizeof(name), fail_action)

#define usym_fetch_array(name, num, type, fail_action)                        \
    ExtRemoteData name##_r(usym_addr(name), num * sizeof(type));              \
    type *usym_arr(name);                                                     \
    ULONG name##_ret_size;                                                    \
    usym_arr(name) = (type *)calloc(num, sizeof(type));                       \
    if (!usym_arr(name)) {                                                    \
        Out("!!! Failed to allocate 0x%x bytes for [%s]\n",                   \
            num * sizeof(type), #name);                                       \
        fail_action;                                                          \
    }                                                                         \
    name##_ret_size = name##_r.ReadBuffer(usym_arr(name), num * sizeof(type), FALSE); \
    if (num * sizeof(type) != name##_ret_size) {                              \
        Out("!!! Failed to read 0x%x bytes @ 0x%p of [%s] array from target (read:0x%x)\n", \
            num * sizeof(type), usym_addr(name), #name, name##_ret_size);     \
        fail_action;                                                          \
    }
#define usym_free_arr(name) do {                                              \
        if (usym_arr(name))                                                   \
            free(usym_arr(name));                                             \
    } while (0, 0)

#define usym_read_u64(name, field) \
    (*((ULONG64*)&name##_buf[___usym___##name##___##field]))
#define usym_read_u32(name, field) \
     (*((ULONG*)&name##_buf[___usym___##name##___##field]))
#define usym_read_u16(name, field) \
    (*((USHORT*)&name##_buf[___usym___##name##___##field]))
#define usym_read_u8(name, field) \
    (*((UCHAR*)&name##_buf[___usym___##name##___##field]))

#define usym_read_addr(name, field) \
    (*((VM_PTR_TYPE*)&name##_buf[___usym___##name##___##field##___addr]))

#define usym_def(name, field, type) \
    type name##_##field = (*((type*)&name##_buf[___usym___##name##___##field]))
#define usym_def_u8(name, field) \
    usym_def(name, field, UCHAR)
#define usym_def_u16(name, field) \
    usym_def(name, field, USHORT)
#define usym_def_u32(name, field) \
    usym_def(name, field, ULONG)
#define usym_def_u64(name, field) \
    usym_def(name, field, ULONG64)
#define usym_def_addr(name, field) \
    VM_PTR_TYPE name##_##field##___addr = \
        (*((VM_PTR_TYPE*)&name##_buf[___usym___##name##___##field##___addr]))

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
    EXT_COMMAND_METHOD(domain);
    EXT_COMMAND_METHOD(dumplog);
    EXT_COMMAND_METHOD(hostpages);
    EXT_COMMAND_METHOD(uxen);
    EXT_COMMAND_METHOD(ugdb);
    EXT_COMMAND_METHOD(udt);
private:
    void dump_page_list(ULONG64, ULONG64, bool, bool, ULONG64);
    ULONG64 get_domain_by_id(uint16_t id);
    char *uxen_logging_read(struct uxen_logging_buffer *,
                            uint64_t *, uint32_t *, uint64_t *log_size);
    void execute_gdb_cmd(const char *, const char *, const char *);
    void refresh_uxen_paths(const bool);
};

ULONG64 get_expr(char *expr_fmt, ...);
