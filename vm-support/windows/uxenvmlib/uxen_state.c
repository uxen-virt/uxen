/*
 * Copyright 2012-2015, Bromium, Inc.
 * Author: Christian Limpach <Christian.Limpach@gmail.com>
 * SPDX-License-Identifier: ISC
 */

#include <ntddk.h>

#include "uxen_types.h"


#include "uxen_state.h"

#include <xen/version.h>
#include <xen/xen.h>

extern struct uxp_state_bar *state_bar;

void uxen_set_state_bar(struct uxp_state_bar *a)
{
    state_bar = a;
}

struct uxp_state_bar **uxen_get_state_bar_ptr(void)
{
    return &state_bar;
}
