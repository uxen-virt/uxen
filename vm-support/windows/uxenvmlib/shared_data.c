/*
 * Copyright 2013-2015, Bromium, Inc.
 * Author: Christian Limpach <Christian.Limpach@gmail.com>
 * SPDX-License-Identifier: ISC
 */

#include <ntddk.h>

#pragma data_seg(".shared")
void *hypercall_page = NULL;
unsigned int *hypercall_page_mfn = NULL;
struct uxp_state_bar *state_bar;
#pragma data_seg()

