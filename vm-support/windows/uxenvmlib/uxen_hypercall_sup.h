/*
 * Copyright 2012-2018, Bromium, Inc.
 * SPDX-License-Identifier: ISC
 */

#ifndef _UXEN_HYPERCALL_SUP_H_
#define _UXEN_HYPERCALL_SUP_H_

uintptr_t _hypercall1(uintptr_t addr, uintptr_t arg1);
uintptr_t _hypercall2(uintptr_t addr, uintptr_t arg1, uintptr_t arg2);
uintptr_t _hypercall3(uintptr_t addr, uintptr_t arg1, uintptr_t arg2, uintptr_t arg3);
uintptr_t _hypercall4(uintptr_t addr, uintptr_t arg1, uintptr_t arg2, uintptr_t arg3, uintptr_t arg4);
uintptr_t _hypercall5(uintptr_t addr, uintptr_t arg1, uintptr_t arg2, uintptr_t arg3, uintptr_t arg4, uintptr_t arg5);
uintptr_t _hypercall6(uintptr_t addr, uintptr_t arg1, uintptr_t arg2, uintptr_t arg3, uintptr_t arg4, uintptr_t arg5, uintptr_t arg6);

uintptr_t _whpx_hypercall1(uintptr_t addr, uintptr_t arg1);
uintptr_t _whpx_hypercall2(uintptr_t addr, uintptr_t arg1, uintptr_t arg2);
uintptr_t _whpx_hypercall3(uintptr_t addr, uintptr_t arg1, uintptr_t arg2, uintptr_t arg3);
uintptr_t _whpx_hypercall4(uintptr_t addr, uintptr_t arg1, uintptr_t arg2, uintptr_t arg3, uintptr_t arg4);
uintptr_t _whpx_hypercall5(uintptr_t addr, uintptr_t arg1, uintptr_t arg2, uintptr_t arg3, uintptr_t arg4, uintptr_t arg5);
uintptr_t _whpx_hypercall6(uintptr_t addr, uintptr_t arg1, uintptr_t arg2, uintptr_t arg3, uintptr_t arg4, uintptr_t arg5, uintptr_t arg6);

#endif	/* _UXEN_HYPERCALL_SUP_H_ */
