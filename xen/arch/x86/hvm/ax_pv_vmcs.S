/*
 * Copyright 2018, Bromium, Inc.
 * SPDX-License-Identifier: ISC
 */

#include <attoxen-api/ax_constants.h>

.text

.align 0x1000
.globl ax_pv_vmread
ax_pv_vmread:
	.int AX_PV_VMACCESS_SIG_1
	.int AX_PV_VMACCESS_SIG_2
.rept 4080
	nop
.endr
	.int AX_PV_VMACCESS_SIG_1
	.int AX_PV_VMACCESS_SIG_2


.align 0x1000
.globl ax_pv_vmwrite
ax_pv_vmwrite:
	.int AX_PV_VMACCESS_SIG_1
	.int AX_PV_VMACCESS_SIG_2
.rept 4080
	nop
.endr
	.int AX_PV_VMACCESS_SIG_1
	.int AX_PV_VMACCESS_SIG_2

