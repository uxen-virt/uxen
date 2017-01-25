/*
 * Copyright 2017, Bromium, Inc.
 * SPDX-License-Identifier: ISC
 */

#ifndef __AX_CONSTANTS_H__
#define __AX_CONSTANTS_H__

#define AX_CPUID_EFISTUB      0x35271645
#define AX_CPUID_LEVEL        0x351f9005
#define AX_CPUID_CONFIG       0x35655f10
#define AX_CPUID_INFO         0x358a719a
#define AX_CPUID_LOG          0x3509cfe1
#define AX_CPUID_LOG_SIZE     0x3575d04f
#define AX_CPUID_PRESENCE     0x35f9e064
#define AX_CPUID_PRESENCE_RDX 0xfee1dead
#define AX_CPUID_EBS          0x35ce0403
#define AX_CPUID_VMINVGPA     0x356d647a
#define AX_CPUID_VMINVGPAS    0x35372de9
#define AX_CPUID_V4V          0x35dcd68c
#define AX_CPUID_GA_LOOKUP    0x352a4ca0
#define AX_CPUID_GA_READ      0x35452ce1
#define AX_CPUID_AX_FEATURES  0x351f9505
#define AX_CPUID_LN_FEATURES  0x3583c6ea
#define AX_CPUID_TREE_LOG     0x3527bbda
#define AX_CPUID_PV_EPT_WRITE 0x35091554
#define AX_CPUID_PV_EPT_WRITE_LEVEL_MASK        0x07
#define AX_CPUID_PV_EPT_WRITE_VALID             0x10
#define AX_CPUID_PV_EPT_WRITE_INVEPT_ALL        0x20
#define AX_CPUID_INVEPT_ALL   0x359ee514



#define AX_FEATURES_AX_L1_VMX     (1ULL << 0)
#define AX_FEATURES_AX_L2_VMX     (1ULL << 1)
#define AX_FEATURES_AX_SHADOW_EPT (1ULL << 2)

#define AX_FEATURES_LN_VMCS_X_V1    (1ULL << 0)
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


#define AX_INTEGRITY_PCR    9
#define AX_PCR_QUOTE_GUID   {0x2152b036, 0x5549, 0x412d, {0x27, 0xa4, 0xf6, 0xb4, 0x7b, 0xf7, 0xd4, 0x88}}

#endif /* __AX_CONSTANTS_H__ */
