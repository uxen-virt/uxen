/*
 * Copyright 2018-2019, Bromium, Inc.
 * Author: Christian Limpach <Christian.Limpach@gmail.com>
 * SPDX-License-Identifier: ISC
 */

#ifndef __PVNESTED_CONSTANTS__
#define __PVNESTED_CONSTANTS__

#define PVNESTED_CPUID_leafs 0x4e000000
#define PVNESTED_CPUID_mask 0xff000000

#define PVNESTED_CPUID_VMX_INFO 0x4e5f651a
/* fill vmx info page
 * RBX: va of page to be filled
 * =RAX: 1 on success
 */

#define PVNESTED_VMX_INFO_SIG_1 0xaf504979
#define PVNESTED_VMX_INFO_SIG_2 0x7015c28e
#define PVNESTED_VMX_INFO_SIG_f 0x46dc2141

#define PVNESTED_VMX_INFO_SIG_FILLED 0x12b622be

#define PVNESTED_VMX_INFO_REVISION_ID 0x59f4b250
/* NOTE: must be 31 bit */

#define PVNESTED_CPUID_VMXON 0x4efa861f
/* vmxon
 * RBX: maddr of vmxon region
 * =RAX: 1 on success
 */

#endif  /* __PVNESTED_CONSTANTS__ */
