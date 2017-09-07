/*
 * Copyright 2016-2018, Bromium, Inc.
 * Author: Tomasz Wroblewski <tomasz.wroblewski@gmail.com>
 * SPDX-License-Identifier: ISC
 */

#include <stdbool.h>

#include "config.h"

#ifndef LIBIMG

/* Wrapper to call Win32 WerRegisterRuntimeExceptionModule. MinGW's werapi.h
   header doesn't define this function in the version currently shipped (and it
   suffers a number of other bugs), so call it dynamically */
typedef HRESULT (WINAPI* wer_register_module_function)(PCWSTR, PVOID);

static
HRESULT wer_register_rem(PCWSTR path, PVOID context)
{
    HMODULE kernel32;
    FARPROC api_addr;
    HRESULT result = E_FAIL;

    kernel32 = LoadLibraryA("kernel32.dll");
    if (kernel32 != NULL) {
        api_addr = GetProcAddress(kernel32, "WerRegisterRuntimeExceptionModule");
        if (api_addr != NULL) {
            result = ((wer_register_module_function)api_addr)(path, context);
            if (!SUCCEEDED(result))
                Wwarn("WerRegisterRuntimeExceptionModule(%ls) failed: %x",
                      path, result);
        } else
            Wwarn("Failed to get WerRegisterRuntimeExceptionModule() address");
        FreeLibrary(kernel32);
    } else
        Wwarn("Failed to load kernel32.dll");

    return result;
}

/* Check environment for WER option and if present register the given
   runtime exception module to be called back out-of-process if we crash.
   Otherwise assume running standalone and load the backtrace module if
   available */
static
bool init_dump_handling()
{
    wchar_t *s = _wgetenv(L"UXENDM_WER");

    if (s != NULL) {
        SetErrorMode(SEM_FAILCRITICALERRORS);
        _set_error_mode(_OUT_TO_STDERR);
        return SUCCEEDED(wer_register_rem(s, NULL));
    } else
        return LoadLibraryA("uxen-backtrace.dll") != NULL;
}

initcall(backtrace_init)
{
    if (!init_dump_handling())
        Wwarn("Failed to initialise dump handling (WER REM or backtrace DLL)");
}

#endif
