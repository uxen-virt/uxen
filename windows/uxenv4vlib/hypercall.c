/*
 * Copyright 2015, Bromium, Inc.
 * SPDX-License-Identifier: ISC
 */

#include "uxenv4vlib_private.h"


int uxen_v4v_can_make_hypercall(void)
{
    return !!hypercall_6_func;
}



void *
uxen_v4v_hypercall1 (void *arg1)
{
    if (!hypercall_6_func) return NULL;
    return (void *) hypercall_6_func((uintptr_t) arg1, (uintptr_t) NULL, (uintptr_t) NULL, (uintptr_t) NULL, (uintptr_t) NULL, (uintptr_t) NULL);
}

void *
uxen_v4v_hypercall2 (void *arg1, void *arg2)
{
    if (!hypercall_6_func) return NULL;
    return (void *) hypercall_6_func((uintptr_t) arg1, (uintptr_t) arg2, (uintptr_t) NULL, (uintptr_t) NULL, (uintptr_t) NULL, (uintptr_t) NULL);
}

void *
uxen_v4v_hypercall3 (void *arg1, void *arg2, void *arg3)
{
    if (!hypercall_6_func) return NULL;
    return (void *) hypercall_6_func((uintptr_t) arg1, (uintptr_t) arg2, (uintptr_t) arg3, (uintptr_t) NULL, (uintptr_t) NULL, (uintptr_t) NULL);
}

void *
uxen_v4v_hypercall6 (void *arg1, void *arg2, void *arg3, void *arg4,
                     void *arg5, void *arg6)
{
    if (!hypercall_6_func) return NULL;
    return (void *) hypercall_6_func((uintptr_t) arg1, (uintptr_t) arg2, (uintptr_t) arg3, (uintptr_t) arg4, (uintptr_t) arg5, (uintptr_t) arg6);
}

