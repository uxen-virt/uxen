/*
 * Copyright 2018-2019, Bromium, Inc.
 * Author: Christian Limpach <Christian.Limpach@gmail.com>
 * SPDX-License-Identifier: ISC
 */

#ifndef __PVNESTED_STRUCTURES__
#define __PVNESTED_STRUCTURES__

struct pvnested_vmx_info {
    uint32_t pvi_sig;
    uint32_t pvi_version;

    uint64_t pvi_vmx_cr0_fixed0;
    uint64_t pvi_vmx_cr0_fixed1;

    uint64_t pvi_feature_control;

    uint64_t pvi_vmx_basic;
    uint64_t pvi_vmx_ept_vpid_cap;
    uint64_t pvi_vmx_pinbased_ctls;
    uint64_t pvi_vmx_procbased_ctls;
    uint64_t pvi_vmx_procbased_ctls2;
    uint64_t pvi_vmx_true_procbased_ctls;
    uint64_t pvi_vmx_exit_ctls;
    uint64_t pvi_vmx_entry_ctls;
};

#endif  /* __PVNESTED_STRUCTURES__ */
