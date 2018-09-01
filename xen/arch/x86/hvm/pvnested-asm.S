/*
 * Copyright 2018-2019, Bromium, Inc.
 * Author: Christian Limpach <Christian.Limpach@gmail.com>
 * SPDX-License-Identifier: ISC
 */

#include <pvnested-api/pvnested-constants.h>

        .data
        .align 0x1000

        .globl pvnested_vmx_info
pvnested_vmx_info:
        .int PVNESTED_VMX_INFO_SIG_1
        .int PVNESTED_VMX_INFO_SIG_2
.rept 1020
        .int PVNESTED_VMX_INFO_SIG_f
.endr
        .int PVNESTED_VMX_INFO_SIG_1
        .int PVNESTED_VMX_INFO_SIG_2
