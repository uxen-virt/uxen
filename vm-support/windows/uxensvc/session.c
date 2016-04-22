/*
 * Copyright 2013-2016, Bromium, Inc.
 * Author: Julian Pidancet <julian@pidancet.net>
 * SPDX-License-Identifier: ISC
 */

#include <windows.h>
#include <wtsapi32.h>
#include <userenv.h>
#include <sddl.h>
#include <psapi.h>
#include <tchar.h>
#include <stdio.h>

#include "session.h"
#include "logging.h"

extern wchar_t *svc_path;

/* This struct seems to be missing from headers */
typedef struct _TOKEN_MANDATORY_LABEL {
      SID_AND_ATTRIBUTES Label;
} TOKEN_MANDATORY_LABEL, *PTOKEN_MANDATORY_LABEL;

static int
set_high_integrity(HANDLE token)
{
    BOOL rc;
    PSID sid;
    TOKEN_MANDATORY_LABEL label;

    rc = ConvertStringSidToSidW(L"S-1-16-12288", &sid);
    if (!rc) {
        svc_printf(SVC_ERROR, L"ConvertStringToSidW failed (%d)",
                   GetLastError());
        return -1;
    }

    label.Label.Attributes = SE_GROUP_INTEGRITY;
    label.Label.Sid = sid;

    rc = SetTokenInformation(token, TokenIntegrityLevel, &label,
                             sizeof (label) + GetLengthSid(sid));
    LocalFree(sid);
    if (!rc) {
        svc_printf(SVC_ERROR, L"SetTokenInformation failed (%d)",
                   GetLastError());
        return -1;
    }

    return 0;
}

static wchar_t *
get_uxenevent_path(void)
{
    wchar_t *path;

    path = calloc(MAX_PATH, sizeof (wchar_t));
    if (!path)
        return NULL;

    _wsplitpath(svc_path, path, path + 2, NULL, NULL);

    return path;
}

static wchar_t *
get_uxenevent_commandline(wchar_t *path)
{
    wchar_t *command_line;

    command_line = calloc(MAX_PATH, sizeof (wchar_t));
    if (!command_line)
        return NULL;

    _snwprintf(command_line, MAX_PATH, L"%suxenevent.exe", path);

    return command_line;
}

static wchar_t *
get_uxenclipboard_commandline(wchar_t *path)
{
    wchar_t *command_line;

    command_line = calloc(MAX_PATH, sizeof (wchar_t));
    if (!command_line)
        return NULL;

    _snwprintf(command_line, MAX_PATH, L"%suxenclipboard.exe", path);

    return command_line;
}

static int
create_process(HANDLE token, wchar_t *command_line, wchar_t *path)
{
    BOOL rc;
    STARTUPINFOW si;
    PROCESS_INFORMATION pi;
    void *env = NULL; /* Never EVER call your variable "environ" */

    rc = CreateEnvironmentBlock(&env, token, FALSE);
    if (!rc) {
        svc_printf(SVC_ERROR, L"CreateEnvironmentBlock failed (%d)",
                   GetLastError());
        return -1;
    }

    memset(&si, 0, sizeof (si));
    si.cb = sizeof (si);
    si.lpDesktop = L"WinSta0\\Default";
    memset(&pi, 0, sizeof (pi));

    rc = CreateProcessAsUserW(token, NULL, command_line,
                              NULL, /* Security Attr */
                              NULL, /* Thread Attr */
                              FALSE, /* Inherit handles */
                              NORMAL_PRIORITY_CLASS |
                              CREATE_UNICODE_ENVIRONMENT |
                              CREATE_NEW_CONSOLE,
                              env,
                              path,
                              &si, &pi);
    DestroyEnvironmentBlock(env);
    if (!rc) {
        svc_printf(SVC_ERROR, L"CreateProcessAsUserW failed (%d)",
                   GetLastError());
        return -1;
    }

    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    svc_printf(SVC_INFO, L"Created process with PID %d", pi.dwProcessId);

    return 0;
}

int
create_user_process(DWORD session_id, wchar_t *command_line, wchar_t *path)
{
    int ret;
    BOOL rc;
    HANDLE token, primary_token;

    rc = WTSQueryUserToken(session_id, &token);
    if (!rc) {
        svc_printf(SVC_ERROR, L"WTSQueryUserToken failed (%d)",
                   GetLastError());
        return -1;
    }

    rc = DuplicateTokenEx(token,
                          MAXIMUM_ALLOWED,
                          NULL,
                          SecurityImpersonation,
                          TokenPrimary, &primary_token);
    CloseHandle(token);
    if (!rc) {
        svc_printf(SVC_ERROR, L"DuplicateTokenEx failed (%d)", GetLastError());
        return -1;
    }

    ret = create_process(primary_token, command_line, path);
    CloseHandle(primary_token);
    if (ret) {
        svc_printf(SVC_ERROR, L"Failed to create uxenevent process");
        return ret;
    }

    return ret;
}

int
create_admin_process(DWORD session_id, wchar_t *command_line, wchar_t *path)
{
    int ret;
    HANDLE proc;
    HANDLE token, primary_token;
    BOOL rc;

    proc = GetCurrentProcess();
    rc = OpenProcessToken(proc, MAXIMUM_ALLOWED, &token);
    CloseHandle(proc);
    if (!rc) {
        svc_printf(SVC_ERROR, L"OpenProcessToken failed (%d)", GetLastError());
        return -1;
    }

    rc = DuplicateTokenEx(token,
                          MAXIMUM_ALLOWED,
                          NULL,
                          SecurityImpersonation,
                          TokenPrimary, &primary_token);
    CloseHandle(token);
    if (!rc) {
        svc_printf(SVC_ERROR, L"DuplicateTokenEx failed (%d)", GetLastError());
        return -1;
    }

    rc = SetTokenInformation(primary_token, TokenSessionId, &session_id,
                             sizeof (session_id));
    if (!rc) {
        svc_printf(SVC_ERROR, L"SetTokenInformation failed (%d)",
                   GetLastError());
        return -1;
    }

    ret = set_high_integrity(primary_token);
    if (ret) {
        svc_printf(SVC_ERROR, L"Failed to set process integrity level");
        return ret;
    }

    svc_printf(SVC_INFO, L"Starting \"%s\" in session %lx", command_line,
               session_id);

    ret = create_process(primary_token, command_line, path);
    CloseHandle(primary_token);
    if (ret) {
        svc_printf(SVC_ERROR, L"Failed to create uxenevent process");
        return ret;
    }

    return ret;
}


void
session_connect(DWORD session_id)
{
    BOOL rc;
    USHORT *session_type;
    DWORD len = sizeof (session_type);
    wchar_t *path;
    wchar_t *command_line;

    rc = WTSQuerySessionInformation(WTS_CURRENT_SERVER_HANDLE,
                                    session_id,
                                    WTSClientProtocolType,
                                    (char **)&session_type,
                                    &len);
    if (!rc) {
        svc_printf(SVC_ERROR, L"WTSQuerySessionInformation(%d) failed (%d)",
                   session_id, GetLastError());
        return;
    }

    if (*session_type != 0) /* not console */
        return;

    path = get_uxenevent_path();
    command_line = get_uxenevent_commandline(path);
    create_admin_process(session_id, command_line, path);
    free(command_line);
    command_line = get_uxenclipboard_commandline(path);
    create_user_process(session_id, command_line, path);
    free(command_line);
    free(path);
}

static HANDLE
process_lookup(DWORD session_id, wchar_t *basename)
{
    DWORD *procs = NULL;
    DWORD buf_len = 0;
    DWORD len = 0;
    DWORD i;
    BOOL rc;
    HANDLE ret = NULL;

    while (len == buf_len) {
        buf_len += 1024;
        procs = realloc(procs, buf_len);
        if (!procs) {
            svc_printf(SVC_ERROR, L"Allocation failure (%d)",
                       GetLastError());
            return NULL;
        }

        rc = EnumProcesses(procs, buf_len, &len);
        if (!rc) {
            svc_printf(SVC_ERROR, L"EnumProcesses failed (%d)",
                       GetLastError());
            return NULL;
        }
    }

    for (i = 0; i < (len / sizeof (DWORD)); i++) {
        wchar_t name[64];
        DWORD l;
        HANDLE proc;
        DWORD sess_id;

        rc = ProcessIdToSessionId(procs[i], &sess_id);
        if (!rc || (sess_id != session_id))
            continue;

        proc = OpenProcess(PROCESS_QUERY_INFORMATION |
                           PROCESS_VM_READ, FALSE, procs[i]);
        if (!proc)
            continue;

        l = GetModuleBaseNameW(proc, NULL, name, 64);
        if (!l) {
            svc_printf(SVC_ERROR, L"GetModuleBaseNameW failed (%d)",
                       GetLastError());
            break;
        }

        if (!wcsncmp(name, basename, l)) {
            CloseHandle(proc);
            ret = OpenProcess(MAXIMUM_ALLOWED, FALSE, procs[i]);
            break;
        }

        CloseHandle(proc);
    }

    return ret;
}

void session_disconnect(DWORD session_id)
{
    HANDLE proc;

    proc = process_lookup(session_id, L"uxenevent.exe");
    if (proc) {
        TerminateProcess(proc, 1);
        CloseHandle(proc);
    }
    proc = process_lookup(session_id, L"uxenclipboard.exe");
    if (proc) {
        TerminateProcess(proc, 1);
        CloseHandle(proc);
    }
}

