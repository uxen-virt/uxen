/*
 * Copyright 2016-2019, Bromium, Inc.
 * Author: Paulian Marinca <paulian@marinca.net>
 * SPDX-License-Identifier: ISC
 */

#ifndef _UXENL_HYPERCAL_H_
#define _UXENL_HYPERCAL_H_

int uxen_hypervisor(void);
int axen_hypervisor(void);
int whpx_hypervisor(void);
int uxen_hypercall_version(int cmd, void *arg);
int uxen_hypercall_memory_op(int cmd, void *arg);
int uxen_hypercall_hvm_op(int cmd, void *arg);
int uxen_hypercall_v4v_op(int cmd, void *arg1, void *arg2, void *arg3, void *arg4, void *arg5);

#endif
