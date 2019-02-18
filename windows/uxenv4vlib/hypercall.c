/*
 * Copyright 2015-2019, Bromium, Inc.
 * SPDX-License-Identifier: ISC
 */

#include "uxenv4vlib_private.h"
#include <attoxen-api/ax_attovm.h>

#include <xen/errno.h>

uintptr_t _ax_v4v_hypercall(
    uintptr_t addr, uintptr_t arg1, uintptr_t arg2,
    uintptr_t arg3, uintptr_t arg4, uintptr_t arg5,
    uintptr_t arg6, uintptr_t ret1);


int
uxen_v4v_can_make_hypercall(void)
{
    return !!hypercall_func;
}

void *
uxen_v4v_hypercall_with_priv(int privileged, void *arg1, void *arg2, void *arg3,
                             void *arg4, void *arg5, void *arg6)
{

    if (!hypercall_func)
        return (void *)-ENOSYS;
    return (void *)hypercall_func((uintptr_t)privileged,
                                  (uintptr_t)arg1, (uintptr_t)arg2,
                                  (uintptr_t)arg3, (uintptr_t)arg4,
                                  (uintptr_t)arg5, (uintptr_t)arg6);
}

void *
uxen_v4v_hypercall(void *arg1, void *arg2, void *arg3,
                   void *arg4, void *arg5, void *arg6)
{

    return uxen_v4v_hypercall_with_priv(0, arg1, arg2, arg3, arg4, arg5, arg6);
}

void *
ax_v4v_hypercall(
    void *arg1, void *arg2, void *arg3,
    void *arg4, void *arg5, void *arg6,
    void *ret1)
{

  return (void*) _ax_v4v_hypercall(
    (uintptr_t)ATTOCALL_V4VOP,
    (uintptr_t)arg1, (uintptr_t)arg2, (uintptr_t)arg3,
    (uintptr_t)arg4, (uintptr_t)arg5, (uintptr_t)arg6,
    (uintptr_t)ret1);
}
