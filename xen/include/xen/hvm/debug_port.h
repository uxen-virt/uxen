/*
 * Copyright 2015, Bromium, Inc.
 * SPDX-License-Identifier: ISC
 */

#ifndef __XEN_HVM_DEBUG_PORT_H__
#define __XEN_HVM_DEBUG_PORT_H__

#include <xen/types.h>

#define DEBUG_PORT_BUFSZ 256
#define DEBUG_PORT_EOM_CHAR 0xa

struct debug_port_state
{
    unsigned char buf[DEBUG_PORT_BUFSZ + 1];
    size_t buf_ptr;
    int last_was_eom;
};

void hvm_init_debug_port(struct domain *d);

#endif /* __XEN_HVM_DEBUG_PORT_H__ */
