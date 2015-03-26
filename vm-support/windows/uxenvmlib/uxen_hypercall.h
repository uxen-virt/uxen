/*
 * Copyright 2012-2015, Bromium, Inc.
 * Author: Christian Limpach <Christian.Limpach@gmail.com>
 * SPDX-License-Identifier: ISC
 */

#ifndef _UXEN_HYPERCALL_H_
#define _UXEN_HYPERCALL_H_

int
uxen_hypercall_init(void);

int
uxen_hypercall_version(int cmd, void *arg);

int
uxen_hypercall_memory_op(int cmd, void *arg);

int
uxen_hypercall_hvm_op(int cmd, void *arg);


uintptr_t uxen_hypercall1(unsigned int nr, uintptr_t arg1);
uintptr_t uxen_hypercall2(unsigned int nr, uintptr_t arg1, uintptr_t arg2);
uintptr_t uxen_hypercall3(unsigned int nr, uintptr_t arg1, uintptr_t arg2, uintptr_t arg3);
uintptr_t uxen_hypercall4(unsigned int nr, uintptr_t arg1, uintptr_t arg2, uintptr_t arg3, uintptr_t arg4);
uintptr_t uxen_hypercall5(unsigned int nr, uintptr_t arg1, uintptr_t arg2, uintptr_t arg3, uintptr_t arg4, uintptr_t arg5);
uintptr_t uxen_hypercall6(unsigned int nr, uintptr_t arg1, uintptr_t arg2, uintptr_t arg3, uintptr_t arg4, uintptr_t arg5, uintptr_t arg6);

#endif	/* _UXEN_HYPERCALL_H_ */
