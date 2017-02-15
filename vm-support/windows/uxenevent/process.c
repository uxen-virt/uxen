/*
 * Copyright 2017, Bromium, Inc.
 * Author: Tomasz Wroblewski <tomasz.wroblewski@gmail.com>
 * SPDX-License-Identifier: ISC
 */

#include "process.h"
#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>

typedef LONG (NTAPI *NtSuspendProcess)(IN HANDLE ProcessHandle);
typedef LONG (NTAPI *NtResumeProcess)(IN HANDLE ProcessHandle);

static NtSuspendProcess pfnNtSuspendProcess;
static NtResumeProcess pfnNtResumeProcess;
static HMODULE ntdll;

static void
load(void)
{
    if (!ntdll)
        ntdll = LoadLibrary("ntdll");
    if (ntdll) {
        if (!pfnNtSuspendProcess)
            pfnNtSuspendProcess = (NtSuspendProcess) GetProcAddress(
                ntdll, "NtSuspendProcess");
        if (!pfnNtResumeProcess)
            pfnNtResumeProcess = (NtResumeProcess) GetProcAddress(
                ntdll, "NtResumeProcess");
    }
}

DWORD
suspend_pid(DWORD pid)
{
    DWORD rv = 0;

    load();

    if (pfnNtSuspendProcess) {
        HANDLE h = OpenProcess(PROCESS_SUSPEND_RESUME, FALSE, pid);
        if (!h)
            return GetLastError();
        rv = pfnNtSuspendProcess(h);
        CloseHandle(h);
    }

    return rv;
}

DWORD
resume_pid(DWORD pid)
{
    DWORD rv = 0;

    load();

    if (pfnNtResumeProcess) {
        HANDLE h = OpenProcess(PROCESS_SUSPEND_RESUME, FALSE, pid);
        if (!h)
            return GetLastError();
        rv = pfnNtResumeProcess(h);
        CloseHandle(h);
    }

    return rv;
}

DWORD
find_pid(const char *name)
{
    HANDLE hsnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    PROCESSENTRY32 pe;
    DWORD pid = 0;

    if (!hsnap)
        return 0;

    pe.dwSize = sizeof(PROCESSENTRY32);
    Process32First(hsnap, &pe);

    do {
        if (!_stricmp(name, pe.szExeFile)) {
            pid = pe.th32ProcessID;
            break;
        }
    } while (Process32Next(hsnap, &pe));
    CloseHandle(hsnap);

    return pid;
}
