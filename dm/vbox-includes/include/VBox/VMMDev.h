/** @file
 * Virtual Device for Guest <-> VMM/Host communication (ADD,DEV).
 */

/*
 * Copyright (C) 2006-2011 Oracle Corporation
 *
 * This file is part of VirtualBox Open Source Edition (OSE), as
 * available from http://www.virtualbox.org. This file is free software;
 * you can redistribute it and/or modify it under the terms of the GNU
 * General Public License (GPL) as published by the Free Software
 * Foundation, in version 2 as it comes in the "COPYING" file of the
 * VirtualBox OSE distribution. VirtualBox OSE is distributed in the
 * hope that it will be useful, but WITHOUT ANY WARRANTY of any kind.
 *
 * The contents of this file may alternatively be used under the terms
 * of the Common Development and Distribution License Version 1.0
 * (CDDL) only, as it comes in the "COPYING.CDDL" file of the
 * VirtualBox OSE distribution, in which case the provisions of the
 * CDDL are applicable instead of those of the GPL.
 *
 * You may elect to license modified versions of this file under the
 * terms and conditions of either the GPL or the CDDL or both.
 */

#ifndef ___VBox_VMMDev_h
#define ___VBox_VMMDev_h

#include <VBox/cdefs.h>
#include <VBox/param.h>                 /* for the PCI IDs. */
#include <VBox/types.h>
#include <VBox/err.h>
#include <VBox/ostypes.h>
#include <VBox/VMMDev2.h>
#include <iprt/assert.h>


RT_C_DECLS_BEGIN

#ifdef VBOX_WITH_64_BITS_GUESTS
/*
 * Constants and structures are redefined for the guest.
 *
 * Host code MUST always use either *32 or *64 variant explicitely.
 * Host source code will use VBOX_HGCM_HOST_CODE define to catch undefined
 * data types and constants.
 *
 * This redefinition means that the new additions builds will use
 * the *64 or *32 variants depending on the current architecture bit count (ARCH_BITS).
 */
# ifndef VBOX_HGCM_HOST_CODE
#  if ARCH_BITS == 64
#   define VMMDevReq_HGCMCall VMMDevReq_HGCMCall64
#  elif ARCH_BITS == 32
#   define VMMDevReq_HGCMCall VMMDevReq_HGCMCall32
#  else
#   error "Unsupported ARCH_BITS"
#  endif
# endif /* !VBOX_HGCM_HOST_CODE */
#endif /* VBOX_WITH_64_BITS_GUESTS */

/** Version of VMMDevRequestHeader structure. */
#define VMMDEV_REQUEST_HEADER_VERSION (0x10001)

#pragma pack(4) /* force structure dword packing here. */

/**
 * Generic VMMDev request header.
 */
typedef struct
{
    /** IN: Size of the structure in bytes (including body). */
    uint32_t size;
    /** IN: Version of the structure.  */
    uint32_t version;
    /** IN: Type of the request. */
    uint32_t requestType;
    /** OUT: Return code. */
    int32_t  rc;
    /** Reserved field no.1. MBZ. */
    uint32_t reserved1;
    /** Reserved field no.2. MBZ. */
    uint32_t reserved2;
} VMMDevRequestHeader;
AssertCompileSize(VMMDevRequestHeader, 24);


#pragma pack()


#ifdef VBOX_WITH_HGCM

/** @name HGCM flags.
 * @{
 */
# define VBOX_HGCM_REQ_DONE      RT_BIT_32(VBOX_HGCM_REQ_DONE_BIT)
# define VBOX_HGCM_REQ_DONE_BIT  0
# define VBOX_HGCM_REQ_CANCELLED (0x2)
/** @} */

# pragma pack(4)
/**
 * HGCM parameter type.
 */
typedef enum
{
    VMMDevHGCMParmType_Invalid            = 0,
    VMMDevHGCMParmType_32bit              = 1,
    VMMDevHGCMParmType_64bit              = 2,
    VMMDevHGCMParmType_PhysAddr           = 3,  /**< @deprecated Doesn't work, use PageList. */
    VMMDevHGCMParmType_LinAddr            = 4,  /**< In and Out */
    VMMDevHGCMParmType_LinAddr_In         = 5,  /**< In  (read;  host<-guest) */
    VMMDevHGCMParmType_LinAddr_Out        = 6,  /**< Out (write; host->guest) */
    VMMDevHGCMParmType_LinAddr_Locked     = 7,  /**< Locked In and Out */
    VMMDevHGCMParmType_LinAddr_Locked_In  = 8,  /**< Locked In  (read;  host<-guest) */
    VMMDevHGCMParmType_LinAddr_Locked_Out = 9,  /**< Locked Out (write; host->guest) */
    VMMDevHGCMParmType_PageList           = 10, /**< Physical addresses of locked pages for a buffer. */
    VMMDevHGCMParmType_SizeHack           = 0x7fffffff
} HGCMFunctionParameterType;
AssertCompileSize(HGCMFunctionParameterType, 4);

# ifdef VBOX_WITH_64_BITS_GUESTS
/**
 * HGCM function parameter, 32-bit client.
 */
typedef struct
{
    HGCMFunctionParameterType type;
    union
    {
        uint32_t   value32;
        uint64_t   value64;
        struct
        {
            uint32_t size;

            union
            {
                RTGCPHYS32 physAddr;
                RTGCPTR32  linearAddr;
            } u;
        } Pointer;
        struct
        {
            uint32_t size;   /**< Size of the buffer described by the page list. */
            uint32_t offset; /**< Relative to the request header, valid if size != 0. */
        } PageList;
    } u;
#  ifdef __cplusplus
    void SetUInt32(uint32_t u32)
    {
        type = VMMDevHGCMParmType_32bit;
        u.value64 = 0; /* init unused bits to 0 */
        u.value32 = u32;
    }

    int GetUInt32(uint32_t *pu32)
    {
        if (type == VMMDevHGCMParmType_32bit)
        {
            *pu32 = u.value32;
            return VINF_SUCCESS;
        }
        return VERR_INVALID_PARAMETER;
    }

    void SetUInt64(uint64_t u64)
    {
        type      = VMMDevHGCMParmType_64bit;
        u.value64 = u64;
    }

    int GetUInt64(uint64_t *pu64)
    {
        if (type == VMMDevHGCMParmType_64bit)
        {
            *pu64 = u.value64;
            return VINF_SUCCESS;
        }
        return VERR_INVALID_PARAMETER;
    }

    void SetPtr(void *pv, uint32_t cb)
    {
        type                    = VMMDevHGCMParmType_LinAddr;
        u.Pointer.size          = cb;
        u.Pointer.u.linearAddr  = (RTGCPTR32)(uintptr_t)pv;
    }
#  endif /* __cplusplus */
} HGCMFunctionParameter32;
AssertCompileSize(HGCMFunctionParameter32, 4+8);

/**
 * HGCM function parameter, 64-bit client.
 */
typedef struct
{
    HGCMFunctionParameterType type;
    union
    {
        uint32_t   value32;
        uint64_t   value64;
        struct
        {
            uint32_t size;

            union
            {
                RTGCPHYS64 physAddr;
                RTGCPTR64  linearAddr;
            } u;
        } Pointer;
        struct
        {
            uint32_t size;   /**< Size of the buffer described by the page list. */
            uint32_t offset; /**< Relative to the request header, valid if size != 0. */
        } PageList;
    } u;
#  ifdef __cplusplus
    void SetUInt32(uint32_t u32)
    {
        type = VMMDevHGCMParmType_32bit;
        u.value64 = 0; /* init unused bits to 0 */
        u.value32 = u32;
    }

    int GetUInt32(uint32_t *pu32)
    {
        if (type == VMMDevHGCMParmType_32bit)
        {
            *pu32 = u.value32;
            return VINF_SUCCESS;
        }
        return VERR_INVALID_PARAMETER;
    }

    void SetUInt64(uint64_t u64)
    {
        type      = VMMDevHGCMParmType_64bit;
        u.value64 = u64;
    }

    int GetUInt64(uint64_t *pu64)
    {
        if (type == VMMDevHGCMParmType_64bit)
        {
            *pu64 = u.value64;
            return VINF_SUCCESS;
        }
        return VERR_INVALID_PARAMETER;
    }

    void SetPtr(void *pv, uint32_t cb)
    {
        type                    = VMMDevHGCMParmType_LinAddr;
        u.Pointer.size          = cb;
        u.Pointer.u.linearAddr  = (uintptr_t)pv;
    }
#  endif /** __cplusplus */
} HGCMFunctionParameter64;
AssertCompileSize(HGCMFunctionParameter64, 4+12);

/* Redefine the structure type for the guest code. */
#  ifndef VBOX_HGCM_HOST_CODE
#   if ARCH_BITS == 64
#     define HGCMFunctionParameter  HGCMFunctionParameter64
#   elif ARCH_BITS == 32
#     define HGCMFunctionParameter  HGCMFunctionParameter32
#   else
#    error "Unsupported sizeof (void *)"
#   endif
#  endif /* !VBOX_HGCM_HOST_CODE */

# else /* !VBOX_WITH_64_BITS_GUESTS */
/**
 * HGCM function parameter, 32-bit client.
 *
 * @todo If this is the same as HGCMFunctionParameter32, why the duplication?
 */
typedef struct
{
    HGCMFunctionParameterType type;
    union
    {
        uint32_t   value32;
        uint64_t   value64;
        struct
        {
            uint32_t size;

            union
            {
                RTGCPHYS32 physAddr;
                RTGCPTR32  linearAddr;
            } u;
        } Pointer;
        struct
        {
            uint32_t size;   /**< Size of the buffer described by the page list. */
            uint32_t offset; /**< Relative to the request header, valid if size != 0. */
        } PageList;
    } u;
#  ifdef __cplusplus
    void SetUInt32(uint32_t u32)
    {
        type = VMMDevHGCMParmType_32bit;
        u.value64 = 0; /* init unused bits to 0 */
        u.value32 = u32;
    }

    int GetUInt32(uint32_t *pu32)
    {
        if (type == VMMDevHGCMParmType_32bit)
        {
            *pu32 = u.value32;
            return VINF_SUCCESS;
        }
        return VERR_INVALID_PARAMETER;
    }

    void SetUInt64(uint64_t u64)
    {
        type      = VMMDevHGCMParmType_64bit;
        u.value64 = u64;
    }

    int GetUInt64(uint64_t *pu64)
    {
        if (type == VMMDevHGCMParmType_64bit)
        {
            *pu64 = u.value64;
            return VINF_SUCCESS;
        }
        return VERR_INVALID_PARAMETER;
    }

    void SetPtr(void *pv, uint32_t cb)
    {
        type                    = VMMDevHGCMParmType_LinAddr;
        u.Pointer.size          = cb;
        u.Pointer.u.linearAddr  = (uintptr_t)pv;
    }
#  endif /* __cplusplus */
} HGCMFunctionParameter;
AssertCompileSize(HGCMFunctionParameter, 4+8);
# endif /* !VBOX_WITH_64_BITS_GUESTS */

/** @name Direction of data transfer (HGCMPageListInfo::flags). Bit flags.
 * @{ */
#define VBOX_HGCM_F_PARM_DIRECTION_NONE      UINT32_C(0x00000000)
#define VBOX_HGCM_F_PARM_DIRECTION_TO_HOST   UINT32_C(0x00000001)
#define VBOX_HGCM_F_PARM_DIRECTION_FROM_HOST UINT32_C(0x00000002)
#define VBOX_HGCM_F_PARM_DIRECTION_BOTH      UINT32_C(0x00000003)
/** Macro for validating that the specified flags are valid. */
#define VBOX_HGCM_F_PARM_ARE_VALID(fFlags) \
    (   (fFlags) > VBOX_HGCM_F_PARM_DIRECTION_NONE \
     && (fFlags) < VBOX_HGCM_F_PARM_DIRECTION_BOTH )
/** @} */

/**
 * VMMDevHGCMParmType_PageList points to this structure to actually describe the
 * buffer.
 */
typedef struct
{
    uint32_t flags;        /**< VBOX_HGCM_F_PARM_*. */
    uint16_t offFirstPage; /**< Offset in the first page where data begins. */
    uint16_t cPages;       /**< Number of pages. */
    RTGCPHYS64 aPages[1];  /**< Page addresses. */
} HGCMPageListInfo;
AssertCompileSize(HGCMPageListInfo, 4+2+2+8);

# pragma pack()

/** Get the pointer to the first parmater of a HGCM call request.  */
# define VMMDEV_HGCM_CALL_PARMS(a)   ((HGCMFunctionParameter *)((uint8_t *)(a) + sizeof (VMMDevHGCMCall)))
/** Get the pointer to the first parmater of a 32-bit HGCM call request.  */
# define VMMDEV_HGCM_CALL_PARMS32(a) ((HGCMFunctionParameter32 *)((uint8_t *)(a) + sizeof (VMMDevHGCMCall)))

# ifdef VBOX_WITH_64_BITS_GUESTS
/* Explicit defines for the host code. */
#  ifdef VBOX_HGCM_HOST_CODE
#   define VMMDEV_HGCM_CALL_PARMS32(a) ((HGCMFunctionParameter32 *)((uint8_t *)(a) + sizeof (VMMDevHGCMCall)))
#   define VMMDEV_HGCM_CALL_PARMS64(a) ((HGCMFunctionParameter64 *)((uint8_t *)(a) + sizeof (VMMDevHGCMCall)))
#  endif /* VBOX_HGCM_HOST_CODE */
# endif /* VBOX_WITH_64_BITS_GUESTS */

# define VBOX_HGCM_MAX_PARMS 32

#endif /* VBOX_WITH_HGCM */

typedef enum
{
    VBoxGuestFacilityType_Unknown         = 0,
    VBoxGuestFacilityType_VBoxGuestDriver = 20,
    VBoxGuestFacilityType_AutoLogon       = 90,  /* VBoxGINA / VBoxCredProv / pa
m_vbox. */
    VBoxGuestFacilityType_VBoxService     = 100,
    VBoxGuestFacilityType_VBoxTrayClient  = 101, /* VBoxTray (Windows), VBoxClie
nt (Linux, Unix). */
    VBoxGuestFacilityType_Seamless        = 1000,
    VBoxGuestFacilityType_Graphics        = 1100,
    VBoxGuestFacilityType_All             = 0x7ffffffe,
    VBoxGuestFacilityType_SizeHack        = 0x7fffffff
} VBoxGuestFacilityType;
AssertCompileSize(VBoxGuestFacilityType, 4);
RT_C_DECLS_END

#endif

