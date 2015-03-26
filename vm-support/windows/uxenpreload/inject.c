/*
 * Copyright 2014-2015, Bromium, Inc.
 * Author: Julian Pidancet <julian@pidancet.net>
 * SPDX-License-Identifier: ISC
 */

#include <windows.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <wchar.h>

int
main(void)
{
    wchar_t *cl = GetCommandLineW();
    wchar_t **argvw;
    int argc;
    wchar_t *dllname; size_t dllname_sz;
    PROCESS_INFORMATION pi;
    STARTUPINFOW si;
    BOOL rc;
    LPVOID remote_dllname;
    HANDLE remote_thread;
    void *loadlibrary_fn;

    argvw = CommandLineToArgvW(cl, &argc);

    if (argc < 3)
        return -1;

    dllname = argvw[1];
    cl = argvw[2];
    dllname_sz = (wcslen(dllname) + 1) * sizeof(wchar_t);

    wprintf(L"dll=%s\n", dllname);
    wprintf(L"commandline=%s\n", cl);

    memset(&pi, 0, sizeof(pi));
    memset(&si, 0, sizeof(si));
    si.cb = sizeof(si);

    rc = CreateProcessW(NULL, cl, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL,
                        NULL, &si, &pi);
    if (!rc) {
        wprintf(L"CreateProcess %lx\n", GetLastError());
        return -1;
    }

    remote_dllname = VirtualAllocEx(pi.hProcess, NULL, dllname_sz, MEM_COMMIT,
                                    PAGE_READWRITE);
    WriteProcessMemory(pi.hProcess, remote_dllname, dllname, dllname_sz, NULL);
    loadlibrary_fn = GetProcAddress(GetModuleHandleA("kernel32.dll"),
                                    "LoadLibraryW"),
    remote_thread = CreateRemoteThread(pi.hProcess, NULL, 0,
                                       loadlibrary_fn, remote_dllname, 0, NULL);
    WaitForSingleObject(remote_thread, INFINITE);
    VirtualFreeEx(pi.hProcess, remote_dllname, dllname_sz, MEM_RELEASE);
    ResumeThread(pi.hThread);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);

    return 0;
}
