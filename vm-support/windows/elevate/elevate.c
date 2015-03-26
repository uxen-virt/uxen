/*
 * Copyright 2013-2015, Bromium, Inc.
 * Author: Julian Pidancet <julian@pidancet.net>
 * SPDX-License-Identifier: ISC
 */

#include <windows.h>
#include <winbase.h>
#include <tchar.h>
#include <stdio.h>

static void
report_pid(HANDLE f, DWORD pid)
{
    DWORD w;

    WriteFile(f, &pid, sizeof (pid), &w, NULL);
}

int WINAPI
WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance,
        LPSTR szCmdLine, int iCmdShow)
{
    BOOL rc;
    SHELLEXECUTEINFO sei;
    DWORD ret;
    HANDLE out;

    out = GetStdHandle(STD_OUTPUT_HANDLE);

    sei.cbSize = sizeof(sei);
    sei.fMask = SEE_MASK_NOCLOSEPROCESS;
    sei.hwnd = NULL;
    sei.lpVerb = _T("runas");
    sei.lpFile = szCmdLine;
    sei.lpParameters = NULL;
    sei.nShow = iCmdShow;
    sei.hInstApp = NULL;

    rc = ShellExecuteEx(&sei);
    if (!rc) {
        if (out != INVALID_HANDLE_VALUE)
            report_pid(out, (DWORD) -1);
        return GetLastError();
    }

    if (out != INVALID_HANDLE_VALUE)
        report_pid(out, GetProcessId(sei.hProcess));

    WaitForSingleObject(sei.hProcess, INFINITE);
    rc = GetExitCodeProcess(sei.hProcess, &ret);
    if (!rc)
        return GetLastError();
    CloseHandle(sei.hProcess);

    return ret;
}
