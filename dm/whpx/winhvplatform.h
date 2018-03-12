//
// WHP PLATFORM  HEADERS COMPTIBLE WITH WINDOWS INSIDER RS4 BUILD 17112
//

/*

Copyright (c) Microsoft Corporation.  All rights reserved.

Module Name:

    WinHvPlatform.ext

Abstract:

    ApiSet contract for the Windows Hypervisor User-Mode Platform APIs.

--*/

#ifndef _WINHVAPI_H_
#define _WINHVAPI_H_

#if defined(_MSC_VER) && (_MSC_VER >= 1200)
#pragma once
#endif

#if 0
#include <apiset.h>
#include <apisetcconv.h>
#include <minwindef.h>
#include <winapifamily.h>

#pragma region Desktop Family or OneCore Family
#endif
#if WINAPI_FAMILY_PARTITION(WINAPI_PARTITION_DESKTOP | WINAPI_PARTITION_SYSTEM)

#include "WinHvPlatformDefs.h"

#ifdef __cplusplus
extern "C" {
#endif

//
// Platform capabilities
//


WHP_API (WHvGetCapability,
    _In_ WHV_CAPABILITY_CODE CapabilityCode,
    _Out_writes_bytes_to_(CapabilityBufferSizeInBytes,*WrittenSizeInBytes) VOID* CapabilityBuffer,
    _In_ UINT32 CapabilityBufferSizeInBytes,
    _Out_opt_ UINT32* WrittenSizeInBytes
    );


WHP_API (WHvCreatePartition,
    _Out_ WHV_PARTITION_HANDLE* Partition
    );


WHP_API (WHvSetupPartition,
    _In_ WHV_PARTITION_HANDLE Partition
    );


WHP_API (WHvDeletePartition,
    _In_ WHV_PARTITION_HANDLE Partition
);


WHP_API (WHvGetPartitionProperty,
    _In_ WHV_PARTITION_HANDLE Partition,
    _In_ WHV_PARTITION_PROPERTY_CODE PropertyCode,
    _Out_writes_bytes_to_(PropertyBufferSizeInBytes,*WrittenSizeInBytes) VOID* PropertyBuffer,
    _In_ UINT32 PropertyBufferSizeInBytes,
    _Out_opt_ UINT32* WrittenSizeInBytes
    );


WHP_API (WHvSetPartitionProperty,
    _In_ WHV_PARTITION_HANDLE Partition,
    _In_ WHV_PARTITION_PROPERTY_CODE PropertyCode,
    _In_reads_bytes_(PropertyBufferSizeInBytes) const VOID* PropertyBuffer,
    _In_ UINT32 PropertyBufferSizeInBytes
    );


//
// Memory Management
//

WHP_API (WHvMapGpaRange,
    _In_ WHV_PARTITION_HANDLE Partition,
    _In_ VOID* SourceAddress,
    _In_ WHV_GUEST_PHYSICAL_ADDRESS GuestAddress,
    _In_ UINT64 SizeInBytes,
    _In_ WHV_MAP_GPA_RANGE_FLAGS Flags
    );


WHP_API (WHvUnmapGpaRange,
    _In_ WHV_PARTITION_HANDLE Partition,
    _In_ WHV_GUEST_PHYSICAL_ADDRESS GuestAddress,
    _In_ UINT64 SizeInBytes
    );


WHP_API (WHvTranslateGva,
    _In_ WHV_PARTITION_HANDLE Partition,
    _In_ UINT32 VpIndex,
    _In_ WHV_GUEST_VIRTUAL_ADDRESS Gva,
    _In_ WHV_TRANSLATE_GVA_FLAGS TranslateFlags,
    _Out_ WHV_TRANSLATE_GVA_RESULT* TranslationResult,
    _Out_ WHV_GUEST_PHYSICAL_ADDRESS* Gpa
    );


//
// Virtual Processors
//

WHP_API (WHvCreateVirtualProcessor,
    _In_ WHV_PARTITION_HANDLE Partition,
    _In_ UINT32 VpIndex,
    _In_ UINT32 Flags
    );


WHP_API (WHvDeleteVirtualProcessor,
    _In_ WHV_PARTITION_HANDLE Partition,
    _In_ UINT32 VpIndex
    );


WHP_API (WHvRunVirtualProcessor,
    _In_ WHV_PARTITION_HANDLE Partition,
    _In_ UINT32 VpIndex,
    _Out_writes_bytes_(ExitContextSizeInBytes) VOID* ExitContext,
    _In_ UINT32 ExitContextSizeInBytes
    );


WHP_API (WHvCancelRunVirtualProcessor,
    _In_ WHV_PARTITION_HANDLE Partition,
    _In_ UINT32 VpIndex,
    _In_ UINT32 Flags
    );


WHP_API (WHvGetVirtualProcessorRegisters,
    _In_ WHV_PARTITION_HANDLE Partition,
    _In_ UINT32 VpIndex,
    _In_reads_(RegisterCount) const WHV_REGISTER_NAME* RegisterNames,
    _In_ UINT32 RegisterCount,
    _Out_writes_(RegisterCount) WHV_REGISTER_VALUE* RegisterValues
    );


WHP_API (WHvSetVirtualProcessorRegisters,
    _In_ WHV_PARTITION_HANDLE Partition,
    _In_ UINT32 VpIndex,
    _In_reads_(RegisterCount) const WHV_REGISTER_NAME* RegisterNames,
    _In_ UINT32 RegisterCount,
    _In_reads_(RegisterCount) const WHV_REGISTER_VALUE* RegisterValues
    );


#ifdef __cplusplus
}
#endif

#endif // WINAPI_FAMILY_PARTITION(WINAPI_PARTITION_DESKTOP | WINAPI_PARTITION_SYSTEM)
#if 0
#pragma endregion
#endif

#endif // _WINHVAPI_H_





#ifndef ext_ms_win_hyperv_hvplatform_l1_1_0_query_routines
#define ext_ms_win_hyperv_hvplatform_l1_1_0_query_routines



//
//Private Extension API Query Routines
//

#ifdef __cplusplus
extern "C" {
#endif

BOOLEAN
__stdcall
IsWHvGetCapabilityPresent(
    VOID
    );

BOOLEAN
__stdcall
IsWHvCreatePartitionPresent(
    VOID
    );

BOOLEAN
__stdcall
IsWHvSetupPartitionPresent(
    VOID
    );

BOOLEAN
__stdcall
IsWHvDeletePartitionPresent(
    VOID
    );

BOOLEAN
__stdcall
IsWHvGetPartitionPropertyPresent(
    VOID
    );

BOOLEAN
__stdcall
IsWHvSetPartitionPropertyPresent(
    VOID
    );

BOOLEAN
__stdcall
IsWHvMapGpaRangePresent(
    VOID
    );

BOOLEAN
__stdcall
IsWHvUnmapGpaRangePresent(
    VOID
    );

BOOLEAN
__stdcall
IsWHvTranslateGvaPresent(
    VOID
    );

BOOLEAN
__stdcall
IsWHvCreateVirtualProcessorPresent(
    VOID
    );

BOOLEAN
__stdcall
IsWHvDeleteVirtualProcessorPresent(
    VOID
    );

BOOLEAN
__stdcall
IsWHvRunVirtualProcessorPresent(
    VOID
    );

BOOLEAN
__stdcall
IsWHvCancelRunVirtualProcessorPresent(
    VOID
    );

BOOLEAN
__stdcall
IsWHvGetVirtualProcessorRegistersPresent(
    VOID
    );

BOOLEAN
__stdcall
IsWHvSetVirtualProcessorRegistersPresent(
    VOID
    );

#ifdef __cplusplus
}
#endif

#endif // endof guard

