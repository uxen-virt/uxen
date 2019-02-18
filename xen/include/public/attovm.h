/******************************************************************************
 * attovm.h
 * 
 * AX protected vm interactions
 *
 * Copyright 2019, Bromium, Inc.
 * Author: Tomasz Wroblewski <tomasz.wroblewski@gmail.com>
 * SPDX-License-Identifier: ISC
 */
#ifndef __XEN_PUBLIC_ATTOVM_H__
#define __XEN_PUBLIC_ATTOVM_H__

#include "xen.h"
#include "attoxen-api/ax_structures.h"

/* seal hashed & signed memory contents */
#define ATTOVMOP_seal 1
struct attovm_op_seal {
    domid_t domain_id;
    struct attovm_definition_v1 definition;
};
typedef struct attovm_op_seal attovm_op_seal_t;
DEFINE_XEN_GUEST_HANDLE(attovm_op_seal_t);

/* read memory for debug-mode attovm */
#define ATTOVMOP_get_guest_pages 2
struct attovm_op_get_guest_pages {
    domid_t domain_id;
    uint64_t pfn;
    uint64_t count;
    XEN_GUEST_HANDLE(void) buffer;
};
typedef struct attovm_op_get_guest_pages attovm_op_get_guest_pages_t;
DEFINE_XEN_GUEST_HANDLE(attovm_op_get_guest_pages_t);

/* read cpu state for debug-mode attovm */
#define ATTOVMOP_get_guest_cpu_state 3
struct attovm_op_get_guest_cpu_state {
    domid_t domain_id;
    uint32_t vcpu_id;
    uint32_t buffer_size;
    XEN_GUEST_HANDLE(void) buffer;
};
typedef struct attovm_op_get_guest_cpu_state attovm_op_get_guest_cpu_state_t;
DEFINE_XEN_GUEST_HANDLE(attovm_op_get_guest_cpu_state_t);

#define ATTOVMOP_kbd_focus 4
struct attovm_op_kbd_focus {
    domid_t domain_id;
    uint32_t offer_focus;
};
typedef struct attovm_op_kbd_focus attovm_op_kbd_focus_t;
DEFINE_XEN_GUEST_HANDLE(attovm_op_kbd_focus_t);

#endif

