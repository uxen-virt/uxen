/*
 * Copyright 2013-2015, Bromium, Inc.
 * SPDX-License-Identifier: ISC
 */

//
//  uxenzeroshareconsole: uxenzeroshareconsole.c
//

#include <windows.h>
#include <winioctl.h>
#include <tchar.h>
#include <strsafe.h>
#pragma warning(disable: 4995)
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <crtdbg.h>
#include <assert.h>
#include <string.h>
#define _NO_CVCONST_H
#define DBGHELP_TRANSLATE_TCHAR
#include <dbghelp.h>
#pragma warning(default: 4995)

#include "uxenzeroshare.h"

int
init_internal_symbol(
    HANDLE                            Id,
    ULONG64                           Base,
    const wchar_t                   * SymbolExpression,
    UXENZEROSHARE_INTERNAL_SYMBOL   * SymbolInfo
    );

int
query_internals_info(
    ULONG64                           BaseOfKernel,
    UXENZEROSHARE_INTERNALS_INFO    * InternalsInfo
    );

const wchar_t                       * kMsftSymbolServerPath     = L"srv**http://msdl.microsoft.com/download/symbols";
const char                          * kNtoskrnlPath             = "%SystemRoot%\\system32\\ntoskrnl.exe";
const wchar_t                       * kUxenZeroshareDevicePath  = L"\\\\.\\" UXENZEROSHARE_DEVICE_NAME;

#define SIZE_OF_SYMBOL_INFO_BUFFER                                \
    (sizeof(SYMBOL_INFO) + MAX_SYM_NAME * sizeof(TCHAR) + sizeof(ULONG64) - 1) / sizeof(ULONG64)

int
__cdecl
main(int argc, char * * argv)
{
    DWORD                                       bytes;
    UXENZEROSHARE_CREATE_ZEROING_THREAD_INFO    createZeroingThreadInfo;
    HANDLE                                      device;
    BOOLEAN                                     hypercall          = 1;
    UXENZEROSHARE_INTERNALS_INFO                internals_info;
    UXENZEROSHARE_KERNEL_BASE_INFO              kernelBaseInfo;
    int                                         rc                 = -1;

    printf("uXen zeroshare console\n\n");
    printf(" Use --dryrun to disable uXen hypercall\n\n");

    if (argc == 2) {
        if (!strcmp("--dryrun", argv[2])) {
            printf("NOT activating uXen hypercall!\n");
            hypercall = 0;
        }
        else {
            printf("error: unrecognized option - %s\n", argv[2]);
            return -1;
        }
    }
    else if (argc != 1) {
        printf(" error: unrecognized options - %s\n", argv[1]);
        return -1;
    }

    device  =   CreateFileW(
        kUxenZeroshareDevicePath,
        GENERIC_READ | GENERIC_WRITE,
        0,                                              //  Exclusive
        0,                                              //  No sec attributes
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        0                                               //  No template file
        );
    
    if (device == INVALID_HANDLE_VALUE) {
        printf("ERROR: couldn't open device - %d\n", GetLastError());

        return rc;
    }

    if (! DeviceIoControl(
            device,
            (DWORD) UXENZEROSHARE_IOCTL_GET_KERNEL_BASE,
            0,                                          //  No input buffer
            0,                                          //  Buffer size==0
            (void *) & kernelBaseInfo,
            sizeof(kernelBaseInfo),
            & bytes,
            0                                           //  Not overlapped
            )) {
        printf("ERROR: couldn't get kernel base info: %d\n", GetLastError());

        goto out;
    }

    if (! query_internals_info(kernelBaseInfo.Base, & internals_info)) {
        printf("ERROR: couldn't query internals.\n");

        goto out;
    }

    int_dump_internals_info(& internals_info);
    int_validate_internals_info(& internals_info);

    if (! DeviceIoControl(
            device,
            (DWORD) UXENZEROSHARE_IOCTL_SET_INTERNALS_INFO,
            (void *) & internals_info,
            sizeof(internals_info),
            0,                                          //  No input buffer
            0,                                          //  Buffer size==0
            & bytes,
            0                                           //  Not overlapped
            )) {
        printf("ERROR: couldn't set internals info: %d\n", GetLastError());

        goto out;
    }

    createZeroingThreadInfo.Hypercall = hypercall;

    printf("creating zeroing thread (%u)...\n", createZeroingThreadInfo.Hypercall);

    if (! DeviceIoControl(
            device,
            (DWORD) UXENZEROSHARE_IOCTL_CREATE_ZEROING_THREAD,
            & createZeroingThreadInfo,
            sizeof(createZeroingThreadInfo),
            0,                                          //  No output buffer
            0,                                          //  Buffer size == 0
            & bytes,
            0                                           //  Not overlapped
            )) {
        printf("ERROR: couldn't create zeroing thread: %d\n", GetLastError());

        goto out;
    }

    rc = 0;
    
out:
    CloseHandle(device);

    return rc;
}

int
query_internals_info(ULONG64 BaseOfKernel, UXENZEROSHARE_INTERNALS_INFO * InternalsInfo)
{
    ULONG64             base = 0;
    ULONG64             buffer[SIZE_OF_SYMBOL_INFO_BUFFER];
    HANDLE              handle  = GetCurrentProcess();
    int                 i;
    IMAGEHLP_MODULE64   mod;
    DWORD               options;
    SYMBOL_INFO      *  sym = (SYMBOL_INFO *) & buffer;
    wchar_t             sympath[1024];

    /* warning about using a non-standard extension: anonymous structure... */
    #pragma warning(disable: 4204)
    struct { const wchar_t* symbol;
        UXENZEROSHARE_INTERNAL_SYMBOL * info;} internals[] = {
        { L"ntoskrnl!KeWaitForGate", & InternalsInfo->KeWaitForGate },
        { L"ntoskrnl!MiInsertPageInFreeOrZeroedList", & InternalsInfo->MiInsertPageInFreeOrZeroedList},
        { L"ntoskrnl!MiMapPageInHyperSpaceWorker", & InternalsInfo->MiMapPageInHyperSpaceWorker},
        { L"ntoskrnl!MiRemoveAnyPage", & InternalsInfo->MiRemoveAnyPage},
        { L"ntoskrnl!MiUnmapPageInHyperSpaceWorker", & InternalsInfo->MiUnmapPageInHyperSpaceWorker},
        { L"ntoskrnl!MiZeroingDisabled", & InternalsInfo->MiZeroingDisabled},
        { L"ntoskrnl!MmFreePageListHead", & InternalsInfo->MmFreePageListHead},
        { L"ntoskrnl!MmZeroingPageGate", & InternalsInfo->MmZeroingPageGate},

    };
    #pragma warning(default: 4204)

    memset(InternalsInfo, 0, sizeof(UXENZEROSHARE_INTERNALS_INFO));
    InternalsInfo->BaseOfNtoskrnl   =   BaseOfKernel;
    mod.SizeOfStruct                =   sizeof(mod);
    sym->SizeOfStruct               =   sizeof(SYMBOL_INFO);
    sym->MaxNameLen                 =   MAX_SYM_NAME;

    printf("BaseOfKernel: 0x%.016I64X\n", BaseOfKernel);

    if (! SymInitialize(handle, kMsftSymbolServerPath, FALSE)) {
        printf("\nERROR: SymInitialize() - %d\n\n", GetLastError());

        return 0;
    }

    options =   SymGetOptions();

    options &=  (~ SYMOPT_DEFERRED_LOADS);
    options |=  (SYMOPT_DEBUG);

    SymSetOptions(options);

    base    =   SymLoadModule64(handle, 0, kNtoskrnlPath, 0, InternalsInfo->BaseOfNtoskrnl, 0);
    if (! base) {
        printf("\nERROR: SymLoadModule64(nt): %d\n\n", GetLastError());
        SymCleanup(handle);

        return 0;
    }
    if (base != InternalsInfo->BaseOfNtoskrnl) {
        printf("\nERROR: base(0x%.016I64X) != BaseOfNtoskrnl(0x%.016I64X)\n\n", base, InternalsInfo->BaseOfNtoskrnl);
        SymCleanup(handle);
        
        return 0;
    }

    SymGetSearchPathW(handle, sympath, 1024);
    printf("base: 0x%.016I64X\n", base);
    printf("sympath: %S\n", sympath);

    SymRefreshModuleList(handle);

    if (! SymGetModuleInfo64(handle, base, & mod)) {
        printf("\nERROR: SymGetModuleInfo64(nt): %d\n\n", GetLastError());
        SymUnloadModule64(handle, base);
        SymCleanup(handle);

        return 0;
    }

    printf("module: %S\n", mod.ModuleName);
    printf("ImageSize: %d\n", mod.ImageSize);
    printf("SymType: %d\n", mod.SymType);
    printf("PdbSig: 0x%.08X\n", mod.PdbSig);
    printf("PdbSig70: %.08X-%.04X-%.04X\n", mod.PdbSig70.Data1, mod.PdbSig70.Data2, mod.PdbSig70.Data3);
    printf("PdbUnmatched: %d\n", mod.PdbUnmatched);
    printf("pdb: %S\n", mod.LoadedPdbName);

    if ((! mod.LoadedPdbName) || (! * mod.LoadedPdbName)) {
        printf("\nERROR: couldn't download/load matching pdb\n\n");
        SymUnloadModule64(handle, base);
        SymCleanup(handle);

        return 0;
    }

    for (i = 0; i < sizeof(internals) / sizeof(internals[0]); ++i) {
        if (! init_internal_symbol(handle, base, internals[i].symbol, internals[i].info)) {
            printf("error initializing internal symbol %s\n", internals[i].symbol);
            SymUnloadModule64(handle, base);
            SymCleanup(handle);

            return 0;
        }
    }

    if (! SymUnloadModule64(handle, base)) {
        printf("\nERROR: SymUnloadModule64(nt): %d\n\n", GetLastError());
        SymCleanup(handle);
        
        return 0;
    }

    if (! SymCleanup(handle)) {
        printf("\nERROR: SymCleanup() - %d\n\n", GetLastError());
        return 0;
    }

    return 1;
}

int
init_internal_symbol(
    HANDLE                            Id,
    ULONG64                           Base,
    const wchar_t                   * SymbolExpression,
    UXENZEROSHARE_INTERNAL_SYMBOL   * SymbolInfo
    )
{
    ULONG64             buf[SIZE_OF_SYMBOL_INFO_BUFFER];
    SYMBOL_INFOW    *   sym =   (SYMBOL_INFOW *) & buf[0];
    sym->SizeOfStruct       =   sizeof(SYMBOL_INFOW);

    SymbolInfo->Name    =   0;
    SymbolInfo->Rva     =   0;
    SymbolInfo->Va      =   0;

    if (! SymFromNameW(Id, SymbolExpression, sym)) {
        printf("\nERROR: SymFromName(%S): %d\n\n", SymbolExpression, GetLastError());
        
        return 0;
    }

    SymbolInfo->Name    =   SymbolExpression;
    SymbolInfo->Rva     =   (ULONG) (sym->Address - Base);
    SymbolInfo->Va      =   (ULONG_PTR) sym->Address;

    return 1;
}

//
//  uxenzeroshareconsole: uxenzeroshareconsole.c
//

