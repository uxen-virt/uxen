/*
 * Copyright 2015-2016, Bromium, Inc.
 * Author: Phil Dennis-Jordan <phil@philjordan.eu>
 * SPDX-License-Identifier: ISC
 */

#ifndef _UXENHYPERCALL_H_
#define _UXENHYPERCALL_H_

#include <stdint.h>
#include <xen/version.h>
#include <xen/xen.h>

#ifdef __cplusplus
extern "C" {
#endif

extern uint16_t uxen_version_major, uxen_version_minor;
extern xen_extraversion_t uxen_extraversion;

int
uxen_hypercall_version(int cmd, void *arg);

int
uxen_hypercall_memory_op(int cmd, void *arg);

int
uxen_hypercall_hvm_op(int cmd, void *arg);

uintptr_t
uxen_hypercall0(unsigned hypercall_index);

uintptr_t
uxen_hypercall1(unsigned hypercall_index, uintptr_t arg1);

uintptr_t
uxen_hypercall2(
    unsigned hypercall_index, uintptr_t arg1, uintptr_t arg2);

uintptr_t
uxen_hypercall3(
    unsigned hypercall_index, uintptr_t arg1, uintptr_t arg2, uintptr_t arg3);

uintptr_t
uxen_hypercall4(
    unsigned hypercall_index, uintptr_t arg1, uintptr_t arg2, uintptr_t arg3,
    uintptr_t arg4);

uintptr_t
uxen_hypercall5(
    unsigned hypercall_index, uintptr_t arg1, uintptr_t arg2, uintptr_t arg3,
    uintptr_t arg4, uintptr_t arg5);

uintptr_t
uxen_hypercall6(
    unsigned hypercall_index, uintptr_t arg1, uintptr_t arg2, uintptr_t arg3,
    uintptr_t arg4, uintptr_t arg5, uintptr_t arg6);

#ifdef __cplusplus
}
#endif

#endif /* _UXENHYPERCALL_H_ s*/
