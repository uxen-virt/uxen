/*
 * Copyright 2013-2015, Bromium, Inc.
 * Author: Kris Uchronski <kuchronski@gmail.com>
 * SPDX-License-Identifier: ISC
 */

#include <ntddk.h>
#include <Aux_klib.h>

#include "uxenvmlib.h"

#include <dm/hw/dmpdev-prot.h>

extern "C" DRIVER_INITIALIZE DriverEntry;
static KBUGCHECK_REASON_CALLBACK_ROUTINE BugcheckDumpIoCallback;
                               
#define MEMTAG_DUMP_HEADER ((ULONG)'10dd')

const UCHAR bugCheckTag[] = "CrashDumpDriver";

KBUGCHECK_REASON_CALLBACK_RECORD g_bugCheckReasonCbRecord;

PHYSICAL_ADDRESS highestAcceptableAddress = {(ULONG)-1, -1};

// KeInitializeCrashDumpHeader is documented
// (http://msdn.microsoft.com/en-us/library/windows/hardware/ff552118(v=vs.85).aspx)
// but not declared in WDK headers.
const ULONG DUMP_TYPE_FULL = 1;

#ifdef _M_AMD64
extern "C" NTKERNELAPI NTSTATUS FASTCALL KeInitializeCrashDumpHeader(
    __in ULONG DumpType,
    __in ULONG Flags,
    __out PVOID Buffer,
    __in ULONG BufferSize,
    __out_opt PULONG BufferNeeded);
#else
extern "C" NTKERNELAPI NTSTATUS KeInitializeCrashDumpHeader(
    __in ULONG DumpType,
    __in ULONG Flags,
    __out PVOID Buffer,
    __in ULONG BufferSize,
    __out_opt PULONG BufferNeeded);
#endif

static PCHAR AnsiStringReverseFindChar(
    __in PCANSI_STRING pString,
    __in const CHAR ch)
{
    ASSERT(NULL != pString);
    for (USHORT i = pString->Length - 1; i >= 0; i--) {
        if (pString->Buffer[i] == ch) {
            return &pString->Buffer[i];
        }
    }
    return NULL;
}

static __inline VOID SendCommand(
    __in const DMPDEV_CTRL_CODE ctrl,
    __in_bcount(cbBufferSize) PVOID pBuffer,
    __in ULONG cbBufferSize)
{
    WRITE_PORT_UCHAR((PUCHAR)DMPDEV_CONTROL_PORT, (UCHAR)ctrl);
    for (ULONG i = 0; i < cbBufferSize; i++) {
        WRITE_PORT_UCHAR((PUCHAR)DMPDEV_DATA_PORT, ((PUCHAR)pBuffer)[i]);
    }
}

static __inline VOID ReportDmpDrvFailure(
    __in DMPDRV_FAILURE_TYPE type,
    __in ULONG code)
{
    DMPDRV_FAILURE_INFO info = {type, code};
    SendCommand(DMPDEV_CTRL_FAILURE, (PVOID)&info, sizeof(info));
}

static VOID ReportLoadedModules()
{
    NTSTATUS status = STATUS_UNSUCCESSFUL;
    AUX_MODULE_EXTENDED_INFO *pModules = NULL;
    ULONG cbModulesSize = 0;
    DMPDEV_MODULES_INFO modulesInfo;

    uxen_msg("begin");

    status = AuxKlibInitialize();
    if (!NT_SUCCESS(status)) {
        ReportDmpDrvFailure(DMPDRV_AUXK_INIT_FAILED, status);
        return;
    }

    status = AuxKlibQueryModuleInformation(&cbModulesSize,
                                            sizeof(*pModules),
                                            NULL);
    if ((!NT_SUCCESS(status)) || (0 == cbModulesSize)) {
        ReportDmpDrvFailure(DMPDRV_QMODULE_QSIZE_FAILED, status);
        return;
    }

    pModules = (AUX_MODULE_EXTENDED_INFO *)MmAllocateContiguousMemory(
        ROUND_TO_PAGES(cbModulesSize),
        highestAcceptableAddress);
    if (NULL == pModules) {
        ReportDmpDrvFailure(DMPDRV_QMODULE_ALLOC_FAILED,
                            (ULONG)STATUS_INSUFFICIENT_RESOURCES);
        return;
    }

    RtlZeroMemory(pModules, cbModulesSize);
    status = AuxKlibQueryModuleInformation(&cbModulesSize,
                                           sizeof(*pModules),
                                           pModules);
    if (!NT_SUCCESS(status)) {
        ReportDmpDrvFailure(DMPDRV_QMODULE_FAILED, status);
        goto out;
    }

    modulesInfo.phys_addr = MmGetPhysicalAddress(pModules).QuadPart;
    modulesInfo.size = cbModulesSize;
    modulesInfo.entry_size = sizeof(*pModules);
#if defined(_AMD64_)
    modulesInfo.flags = DMPDEV_MIF_X64;
#else
    modulesInfo.flags = 0;
#endif
    SendCommand(DMPDEV_CTRL_MODULE_INFO, &modulesInfo, sizeof(modulesInfo));

out:
    MmFreeContiguousMemory(pModules);

    uxen_msg("end");
}

static VOID ReportGlobals()
{
    DMPDEV_GLOBALS_INFO globalsInfo;
    ULONG cbDumpHeaderSize = 0;
    void *pDumpHeader = NULL;
    NTSTATUS status = STATUS_UNSUCCESSFUL;

    uxen_msg("begin");

    // Get dump header size.
    status = KeInitializeCrashDumpHeader(DUMP_TYPE_FULL,
                                         0,
                                         NULL,
                                         0,
                                         &cbDumpHeaderSize);
    if (0 == cbDumpHeaderSize) {
        ReportDmpDrvFailure(DMPDRV_DMP_HDR_INIT_1_FAILED, status);
        return;
    }

    // Allocate dump header buffer.
    pDumpHeader = ExAllocatePoolWithTag(NonPagedPool,
                                        cbDumpHeaderSize,
                                        MEMTAG_DUMP_HEADER);
    if (NULL == pDumpHeader) {
        ReportDmpDrvFailure(DMPDRV_DMP_HDR_ALLOC_FAILED,
                            (ULONG)STATUS_INSUFFICIENT_RESOURCES);
        return;
    }

    // Generate dump header.
    status = KeInitializeCrashDumpHeader(DUMP_TYPE_FULL,
                                         0,
                                         pDumpHeader,
                                         cbDumpHeaderSize,
                                         NULL);
    if (NT_SUCCESS(status)) {
#if defined(_AMD64_)
        uint64_t *pDumpHeaderTyped = (uint64_t *)pDumpHeader;
        const int PsLoadedModulesListOffset = 4;
        const int PsActiveProcessHeadOffset = 5;
#else
        uint32_t *pDumpHeaderTyped = (uint32_t *)pDumpHeader;
        const int PsLoadedModulesListOffset = 6;
        const int PsActiveProcessHeadOffset = 7;
#endif
        // Offsets (4-7) are undocumented, but seem stable for win7.
        globalsInfo.PsLoadedModulesList = pDumpHeaderTyped[PsLoadedModulesListOffset];
        globalsInfo.PsActiveProcessHead = pDumpHeaderTyped[PsActiveProcessHeadOffset];        
        SendCommand(DMPDEV_CTRL_GLOBALS_INFO, &globalsInfo, sizeof(globalsInfo));
    } else {
        ReportDmpDrvFailure(DMPDRV_DMP_HDR_INIT_2_FAILED, status);
    }

    ExFreePoolWithTag(pDumpHeader, MEMTAG_DUMP_HEADER);

    uxen_msg("end");
}

static VOID LoadImageNotifyRoutine(
    __in_opt PUNICODE_STRING pFullImageName,
    __in HANDLE processId,
    __in PIMAGE_INFO pImageInfo)
{
    UNICODE_STRING vgadllName = RTL_CONSTANT_STRING(L"\\systemroot\\system32\\vga.dll");

    PAUX_MODULE_EXTENDED_INFO pModule = NULL;
    DMPDEV_MODULES_INFO moduleInfo;
    ANSI_STRING fullImageName;
    NTSTATUS status = STATUS_UNSUCCESSFUL;
    PCHAR pImageName = NULL;
    USHORT cbImageNameLength = 0;

    // Only KM modules are reported.
    if ((NULL != processId) && (!pImageInfo->SystemModeImage)) {
        return;
    }

    // VGA.DLL is loaded on most mode changes.
    if (RtlEqualUnicodeString(&vgadllName, pFullImageName, TRUE)) {
        return;
    }

    pModule = (AUX_MODULE_EXTENDED_INFO *)MmAllocateContiguousMemory(
        ROUND_TO_PAGES(sizeof(*pModule)),
        highestAcceptableAddress);
    if (NULL == pModule) {
        ReportDmpDrvFailure(DMPDRV_QMODULE_ALLOC_FAILED,
                            (ULONG)STATUS_INSUFFICIENT_RESOURCES);
        return;
    }

    RtlZeroMemory(pModule, ROUND_TO_PAGES(sizeof(*pModule)));

    // Convert to ANSI string.
    status = RtlUnicodeStringToAnsiString(&fullImageName,
                                          pFullImageName,
                                          TRUE);
    if (!NT_SUCCESS(status)) {
        ReportDmpDrvFailure(DMPDRV_STR_CONVERTION_FAILED,
                            status);
        goto out;
    }

    // Locate image name (exclude path).
    pImageName = AnsiStringReverseFindChar(&fullImageName, '\\');
    if (NULL == pImageName) {
        cbImageNameLength = min(fullImageName.Length,
                                sizeof(pModule->FullPathName));
    } else {
        ASSERT(pImageName >= fullImageName.Buffer);
        cbImageNameLength = 
            (USHORT)min((fullImageName.Buffer + fullImageName.Length - pImageName),
                        sizeof(pModule->FullPathName));
    }
    pImageName = fullImageName.Buffer + fullImageName.Length
                 - cbImageNameLength;

    // Module details.
    pModule->BasicInfo.ImageBase = pImageInfo->ImageBase;
    pModule->ImageSize = (ULONG)pImageInfo->ImageSize;
    pModule->FileNameOffset = 0;
    RtlCopyMemory(pModule->FullPathName, pImageName, cbImageNameLength);

    // Module descriptor.
    moduleInfo.phys_addr = MmGetPhysicalAddress(pModule).QuadPart;
    moduleInfo.size = sizeof(*pModule);
    moduleInfo.entry_size = sizeof(*pModule);
#if defined(_AMD64_)
    moduleInfo.flags = DMPDEV_MIF_X64;
#else
    moduleInfo.flags = 0;
#endif
    SendCommand(DMPDEV_CTRL_MODULE_INFO,
                &moduleInfo,
                sizeof(moduleInfo));
    RtlFreeAnsiString(&fullImageName);

out:
    MmFreeContiguousMemory(pModule);
}

static VOID ReportBugcheckDetails()
{
    KBUGCHECK_DATA bugcheckData;
    DMPDEV_CRASH_INFO crashInfo;
    NTSTATUS status = STATUS_UNSUCCESSFUL;

    bugcheckData.BugCheckDataSize = sizeof(bugcheckData);
    status = AuxKlibGetBugCheckData(&bugcheckData);
    if (NT_SUCCESS(status)) {
        crashInfo.code   = (uint32_t)bugcheckData.BugCheckCode;
        crashInfo.param1 = (uint64_t)bugcheckData.Parameter1;
        crashInfo.param2 = (uint64_t)bugcheckData.Parameter2;
        crashInfo.param3 = (uint64_t)bugcheckData.Parameter3;
        crashInfo.param4 = (uint64_t)bugcheckData.Parameter4;
        SendCommand(DMPDEV_CTRL_CRASH_INFO, &crashInfo, sizeof(crashInfo));
    } else {
        ReportDmpDrvFailure(DMPDRV_QBUGCHECK_FAILED, status);
    }
}

static VOID BugcheckDumpIoCallback(
    __in KBUGCHECK_CALLBACK_REASON reason,
    __in PKBUGCHECK_REASON_CALLBACK_RECORD pRecord,
    __inout PVOID pReasonSpecificData,
    __in ULONG cbReasonSpecificDataLength)
{
    static BOOLEAN fBugcheckDetailsReported = FALSE;
    PKBUGCHECK_DUMP_IO pDumpIo = (PKBUGCHECK_DUMP_IO)pReasonSpecificData;
    DMPDEV_DUMP_DATA dumpData = {0};
    
    UNREFERENCED_PARAMETER(reason);
    UNREFERENCED_PARAMETER(pRecord);
    UNREFERENCED_PARAMETER(cbReasonSpecificDataLength);

    if (!fBugcheckDetailsReported) {
        ReportBugcheckDetails();
        fBugcheckDetailsReported = TRUE;
    }

    if (((ULONG64)-1) != pDumpIo->Offset) {
        // FIXME: No support out-of-order dumping.
        ReportDmpDrvFailure(DMPDRV_DUMPDATA_FAILED, 1);
    }

    if (pDumpIo->Buffer < MmSystemRangeStart) {
        dumpData.phys_addr = (uint64_t)pDumpIo->Buffer;
        dumpData.size = pDumpIo->BufferLength;
        dumpData.flags = (KbDumpIoComplete == pDumpIo->Type) ? 1 : 0;
        SendCommand(DMPDEV_CTRL_DUMP_DATA, (PVOID)&dumpData, sizeof(dumpData));
    } else {
        if (pDumpIo->BufferLength > PAGE_SIZE) {
            // FIXME: No support for buffers that exceeds page size.
            ReportDmpDrvFailure(DMPDRV_DUMPDATA_FAILED, 2);
        } else {
            dumpData.phys_addr = MmGetPhysicalAddress(pDumpIo->Buffer).QuadPart;
            dumpData.size = pDumpIo->BufferLength;
            dumpData.flags = (KbDumpIoComplete == pDumpIo->Type) ? 1 : 0;
            SendCommand(DMPDEV_CTRL_DUMP_DATA, (PVOID)&dumpData, sizeof(dumpData));
        }
    }
}

extern "C" NTSTATUS DriverEntry(
    __in DRIVER_OBJECT *pDriver,
    __in UNICODE_STRING *pServiceKey)
{
    BOOLEAN fBugCheckCbRegistered = FALSE;
    NTSTATUS status = STATUS_UNSUCCESSFUL;
    DMPDEV_VERSION version = {DMPDEV_PROTOCOL_VERSION};

    UNREFERENCED_PARAMETER(pDriver);
    UNREFERENCED_PARAMETER(pServiceKey);

    uxen_msg("begin");

    SendCommand(DMPDEV_CTRL_VERSION, (PVOID)&version, sizeof(version));

    KeInitializeCallbackRecord(&g_bugCheckReasonCbRecord);
    fBugCheckCbRegistered = KeRegisterBugCheckReasonCallback(
        &g_bugCheckReasonCbRecord,
        BugcheckDumpIoCallback,
        KbCallbackDumpIo,
        (PUCHAR)bugCheckTag);
    if (!fBugCheckCbRegistered) {
        // Fatal - no reason to hang around.
        ReportDmpDrvFailure(DMPDRV_REG_CRASH_CB_FAILED, 0);
        return STATUS_UNSUCCESSFUL;
    }

    ReportLoadedModules();
    ReportGlobals();

    status = PsSetLoadImageNotifyRoutine(&LoadImageNotifyRoutine);
    if (!NT_SUCCESS(status)) {
        // Non-fatal.
        ReportDmpDrvFailure(DMPDRV_IMAGE_LOAD_CB_REG_FAILED, status);
    }

    uxen_msg("end");

    return STATUS_SUCCESS;
}
