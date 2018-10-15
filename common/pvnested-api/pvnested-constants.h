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

#define PVNESTED_CPUID_VMXOFF 0x4eb7e472
/* vmxoff
 */

#define PVNESTED_CPUID_VMPTRLD 0x4e45d0b9
/* vmptrld
 * RBX: maddr of vmcs
 * =RAX: 1 on success
 */

#define PVNESTED_CPUID_VMPCLEAR 0x4e1d0a0f
/* vmpclear
 * RBX: maddr of vmcs
 * =RAX: 1 on success
 */

#define PVNESTED_CPUID_INVEPT 0x4e32f567
/* invept
 * RBX: type (INVEPT_{SINGLE,ALL}_CONTEXT)
 * RCX: eptp
 * RDX: gpa
 */

#define PVNESTED_CPUID_PV_VMACCESS 0x4e455c58
/* setup pv vmread/vmwrite access
 * RBX: 1 enable, 0 disable
 * RCX: 0 or pv_vmread va (va to patch on 1st call)
 * RDX: 0 or pv_wmwrite va (va to patch on 1st call)
 * =RAX: 1
 * =RBX: per-pcpu context
 */

#define PVNESTED_PV_VMACCESS_SIG_1 0xa5420b0f
#define PVNESTED_PV_VMACCESS_SIG_2 0x6212bf65

#define PVNESTED_CPUID_VMREAD 0x4e54a5f3
/* vmread
 * RBX: field
 * =RAX: vmread return value
 * =RBX: value
 */

#define PVNESTED_CPUID_VMREAD_VALIDATE 0x4e9f4a92
/* vmread validation
 * RBX: field
 * RDX: value to validate
 * =RAX: vmread return value
 * =RBX: value
 */

#define PVNESTED_CPUID_VMWRITE 0x4e6cf7b2
/* vmwrite
 * RBX: field
 * RCX: value
 * =RAX: vmwrite return value
 */

#define PVNESTED_CPUID_VMWRITE_VALIDATE 0x4e1de5d1
/* vmwrite validation
 * RBX: field
 * RCX: value
 * =RAX: vmwrite return value
 */

#endif  /* __PVNESTED_CONSTANTS__ */
