/*
 * Copyright 2017-2019, Bromium, Inc.
 * SPDX-License-Identifier: ISC
 */

#ifndef __AX_CONSTANTS_H__
#define __AX_CONSTANTS_H__

//Probably need a better place to do Atto call documentation - but here will do for now


#define AX_CPUID_EFISTUB      0x35271645
// LEGACY -

#define AX_CPUID_LEVEL        0x351f9005
// DEPRECIATED - GET CURRENT LEVEL
// returns string in RBX,RDX,RCX giving some AX info including the current
// nesting level.

#define AX_CPUID_CONFIG       0x35655f10
// READ FROM CONFIG SPACE
// on entry RCX is offset into config space to read. on exit RBX and RDX
// contain 16 bytes of config space at that offset and RCX contains the
// config_space length

#define AX_CPUID_INFO         0x358a719a
// DEPRECIATED - READ FROM INFO SPACE
// on entry RCX contains offset into info space, RCX = 0 regenerates info.
// on exit RBX and RDX gives 16 bytes of info space and RCX gives
// the number of bytes read.


#define AX_CPUID_LOG          0x3509cfe1
// READ FROM LOG SPACE
// on entry RCX contains offset into log space.
// on exit RAX, RBX, RCX, RDX contain upto 32 bytes of log data

#define AX_CPUID_LOG_SIZE     0x3575d04f
// READ LOG SIZE
// on exit RBX contains the size of log space
// RCX the log read offset
// RDX the log write offset

#define AX_CPUID_PRESENCE     0x35f9e064
#define AX_CPUID_PRESENCE_RDX 0xfee1dead
// TEST FOR AX
// on exit RDX has the value AX_CPUID_PRESENCE_RDX

#define AX_CPUID_EBS          0x35ce0403
// the AX bootloader hooks EBS, and uses this CPUID to communicate
// to AX from L1 that L1 EBS has succesfully returned.
// AX then takes over the remaining cpus in the platform, and returns.

#define AX_CPUID_VMINVGPA     0x356d647a
// unknown - tomasz?
#define AX_CPUID_VMINVGPAS    0x35372de9
// unknown - tomasz?

#define AX_CPUID_GA_LOOKUP    0x352a4ca0
// Lookup guest accessable symbol information
// on entry RCX contains the symbol number
// on exit RAX contains type and flags information see ga_types.h
// RBX contains the offset in the GA section where the name of the symbol
// is stored.
// RCX contains the offset in the GA section were the data of the symbol
// is stored
// RDX contains the size of the symbol


#define AX_CPUID_GA_READ      0x35452ce1
// Reads upto 16 bytes of GA data into RBX, RDX
// on entry RCX is offset.

#define AX_CPUID_AX_FEATURES  0x351f9505
// reads 32 AX feature bits from [RCX<<5 + 31,RCX <<5] into RDX

#define AX_CPUID_LN_FEATURES  0x3583c6ea
// reads 32 LN feature bits from [RCX<<5 + 31,RCX <<5] into RDX

#define AX_CPUID_TREE_LOG     0x3527bbda
// READ TREE DATA
// on entry RCX is offset into tree data
// on exit RBX, RDX contain upto 16 bytes of tree data
// RCX contains the quantity of tree data available
// RAX is non zero to indicate the tree log has been truncated

#define AX_CPUID_PV_EPT_WRITE 0x35091554
#define AX_CPUID_PV_EPT_WRITE_LEVEL_MASK        0x07
#define AX_CPUID_PV_EPT_WRITE_VALID             0x10
#define AX_CPUID_PV_EPT_WRITE_INVEPT_ALL        0x20
// Update EPT entry. The guest can use this interface to avoid
// having to issue invept when it does certain modifications of L23
// EPT tables. After modifying the table the guest should call this
// function.
//
// on Entry
// RBX = L3 EPT_POINTER
// RCX = L3 GPA | flags | level
// RDX = EPTE that was written
//
// The valid flag must always be set
//
// AX will update the relevant L03 table (without necessarily consulting the L23 table)
// if the INVEPT_ALL bit is set in the flags, AX will then proceeed to ensure
// the L3 mapping is flushed on all cpus.
//
// NOTE this is the WRONG primitive to do this, a guest should:
// 1) write an invalid entry into L23
// 2) ask AX to:
// 3)   write an invalid entry into L03
// 4)   flush the L03 mappings on all cpus
// 5)   write the correct entry in L03
// 6) write the correct entry in L23
//
// uXen doesn't currently do 1) so we instead provide this primitive.
// the two are equivalent provided there are <3 guest cpus and updates
// are always RO->RW.

#define AX_CPUID_INVEPT_ALL   0x359ee514
// INVEPT ALL L3 CPUS
// when this call returns AX garuntees that all CPUs will flush
// their cached L03 EPT entries before executing any more L3 code.
// It does this by setting a flag on all cpus requring a flush before
// L3 entry, and then ensures that no cpus are in L3 (by issuing IPIs)

#define AX_CPUID_FLUSHTLB     0x35630ed1
// FLUSH TLB
// when this call returns AX garuntees that all CPUs (including this one)
// at this same level of virtualization will flush all cached VA->PA mappings
// before executing any more code at this level.

#define AX_CPUID_VMCLEAR      0x35ac6b48
// VMCLEAR on other CPU
// on entry RCX is the PA of the VMCS in question
// if the VMCS is not loaded on any CPU, AX will return 0 in RAX
// if it is in use AX will issue an IPI to cause it to be unloaded
// and return non-zero in RAX
// The guest should then pause and attempt the operation again until
// zero is returned or scheduling happens.
//
// NB IT IS THE GUEST'S RESPONSIBILITY NOT TO SHOOT ITSELF IN THE FOOT
// if a guest attempts a vmread/write/launch/resume with a vmcs that
// has been cleared from another cpu the operation will fail as if
// the vmcs had been loaded. Guests should use locks &c. to avoid misery.

//  printf 0x35%02x%02x%02x\\n $[ $RANDOM % 256 ] $[ $RANDOM % 256 ] $[ $RANDOM % 256 ]
//
//

#define AX_CPUID_CRASH_GUEST      0x35533fa3
// CRASH_GUEST
// on the next available L2 entry, inject an NMI into this cpu. Only in non-production builds.

#define AX_CPUID_PV_MEMORY    0x354ec2f6
// Hand memory to AX for use at this level
// RBX contains the VA of the base of
// RCX bytes of ram that AX may use as it sees fit
// NB: memory need not be PA contigugous
// memory must be filled completely with the string yam\0 repeated
//
#define AX_PV_MEMORY_TAG 0x79616d00
// The above is FOURCC 'yam\0'

#define AX_CPUID_PV_VMACCESS    0x35327f4e
// PV_VMACCESS
// Currently only supported for L2
// CPL 0 is required
// on entry RBX is zero to disable PV_VMACCESS, or one to enable.
// The effect is immediate and applies to all CPUs.
// RCX contains NULL or a pointer to PAGE of memory that starts and ends
// wih AX_PV_VMACCESS_SIG1, AX_PV_VMACCESS_SIG2 and will be replaced with
// the pv_vmread code.
// RDX contains NULL or a pointer to a similar PAGE of memory, and will
// be replaced with the pv_vmwrite code
// On exit RAX contains one if AX is configured to permit PV_VMACCESS
// RBX contains the context pointer for _this_ cpu or NULL
// RCX is unchanged or NULL
// RDX is unchanged or NULL
//
// You'd typically call it once to patch and then n or n-1 times
// to get the CTX pointers for all CPUs
// the vmread and vmwrite functions fall back if the ctx pointer
// is NULL.
//
#define AX_PV_VMACCESS_SIG_1    0xa5420b0f
#define AX_PV_VMACCESS_SIG_2    0x6212bf65


// FIXME: document these
#define AX_CPUID_INVEPT_BASE      0x359ff327
#define AX_CPUID_SVM_VMRUN      0x35404052
#define AX_CPUID_VMCB_CHECK_MY      0x355ea363
#define AX_CPUID_VMCB_CHECK_INTERCEPT_INVLPG  (1UL << 0)
#define AX_VMCB_OFFSET_V1     0x800
#define AX_SVM_FLAGS_VMSAVE_ROOT    0x1


#define AX_FEATURES_AX_L1_VMX      (1ULL << 0)
#define AX_FEATURES_AX_L2_VMX      (1ULL << 1)
#define AX_FEATURES_AX_SHADOW_EPT  (1ULL << 2)
#define AX_FEATURES_AX_L2_VMCLEAR  (1ULL << 3)
#define AX_FEATURES_AX_L2_FLUSHTLB (1ULL << 4)
#define AX_FEATURES_AX_PV_VMCS     (1ULL << 5)

#define AX_FEATURES_LN_VMCS_X_V1    (1ULL << 0)
#define AX_FEATURES_LN_VMCB_X_V1    (1ULL << 0)
#define AX_FEATURES_LN_NO_XCR0      (1ULL << 1)
#define AX_FEATURES_LN_NO_RESTORE_DT_LIMITS  (1ULL << 2)
#define AX_FEATURES_LN_ACCEPT_LAZY_EPT_FAULTS (1ULL << 3)

#define AX_VMCS_X_FLAGS_FLUSH_EPT        (1ULL << 0)

#define AX_VMCS_X_PV_EPT_WRITE_LEVEL_MASK       AX_CPUID_PV_EPT_WRITE_LEVEL_MASK
#define AX_VMCS_X_PV_EPT_WRITE_VALID            AX_CPUID_PV_EPT_WRITE_VALID
#define AX_VMCS_X_PV_EPT_WRITE_INVEPT_ALL       AX_CPUID_PV_EPT_WRITE_INVEPT_ALL

#define AX_INSTBITS_INSTALLED            (1UL << 0) /* system transitioned from ax uninstalled -> installed */
#define AX_INSTBITS_UNINSTALLED          (1UL << 1) /* system transitioned from ax installed -> uninstalled */
#define AX_INSTBITS_PROMOTED             (1UL << 2) /* test boot worked, and ax is now default boot */
#define AX_INSTBITS_CHANGED              (1UL << 3) /* a change was made */
#define AX_INSTBITS_DO_NOT_START         (1UL << 4) /* do not attempt to start uxen.sys */
#define AX_INSTBITS_NEED_REBOOT          (1UL << 5) /* state machine requires a reboot to progress */
#define AX_INSTBITS_BL_SUSPENDED         (1UL << 6) /* bitlocker was suspended */
#define AX_INSTBITS_BL_SUSPEND_NEEDED    (1UL << 7) /* promotion failed, and we weren't able to suspend bitlocker - HELP! */
#define AX_INSTBITS_NO_EFI               (1UL << 8) /* no EFI detected */
#define AX_INSTBITS_TEST_FAILED          (1UL << 9) /* A test install of this build has failed, so we're not trying again */
#define AX_INSTBITS_NOT_WIN10            (1UL <<10) /* Windows 10 or later not detected */
#define AX_INSTBITS_ERROR                (1UL <<11) /* an error occured */
#define AX_INSTBITS_AX_NEEDED_BUT_NO     (1UL <<12) /* AX is needed but install cannot proceed for whatever reason */
#define AX_INSTBITS_CPU_NOT_SUPP         (1UL <<13) /* unsupported CPU */
#define AX_INSTBITS_32_BIT               (1UL <<14) /* 32 bit windows */
#define AX_INSTBITS_RUN_INSTALLER        (1UL <<15) /* Pre-install says run installer at shutdown */
#define AX_INSTBITS_MS_UEFI_CA_MISSING   (1UL <<16) /* Secureboot is missing the Microsoft UEFI CA, you must enable it in setup before installation can proceed */
#define AX_INSTBITS_FASTBOOT_BUG         (1UL <<17) /* BIOS is not honoring BootNext */
#define AX_INSTBITS_NO_VMCS_SHADOW       (1UL <<18) /* CPU lacks VMCS shadowing */
#define AX_INSTBITS_RAN_BCDBOOT          (1UL <<19) /* The machine was booting by luck and we asked windows to fix that, potentially portending doom. */
#define AX_INSTBITS_BCDBOOT_FAILED       (1UL <<20) /* The machine was booting by luck and we asked windows to fix that, potentially portending doom. */
#define AX_INSTBITS_NX_MISSING           (1UL <<21) /* NX is disabled */
#define AX_INSTBITS_VT_NEEDED            (1UL <<22) /* VT is needed */
#define AX_INSTBITS_HV_UNHELPFUL         (1UL <<24) /* Hyper-V is unhelpful */


#define AX_INTEGRITY_PCR    9
#define AX_PCR_QUOTE_GUID   {0x2152b036, 0x5549, 0x412d, {0x27, 0xa4, 0xf6, 0xb4, 0x7b, 0xf7, 0xd4, 0x88}}

#define AX_PV_I_GA_VAR_NAME        "ax_pvi_sys"
#define AX_PV_I_IFACE_NAME         L"\\Callback\\AXPVI"
#define AX_PV_I_HASH_IDX     0
#define AX_PV_I_VMREAD_IDX     1
#define AX_PV_I_VMWRITE_IDX    2
#define AX_PV_I_MAX_IDX      3

// ATTOVM PV VMCS revisions:
#define PV_VMCS_ATTOVM_REV 0x4d565841

#endif /* __AX_CONSTANTS_H__ */
