/*
 * Copyright 2014-2015, Bromium, Inc.
 * Author: Kris Uchronski <kuchronski@gmail.com>
 * SPDX-License-Identifier: ISC
 */

#include "kdx.h"

/* these can be override by creating environment variables with the same names */
static char uxen_gdb_path[] = 
    "c:\\uxen\\tools\\install\\bin\\x86_64-w64-mingw32-gdb";
static char uxen_obj_path[] =
    "c:\\uxen\\build\\uxen.windows\\uxen.obj";

void 
EXT_CLASS::execute_gdb_cmd(const char *gdb_path,
                           const char *uxen_obj_path,
                           const char *gdb_cmd)
{ 
    char cmd[2 << 12];
    char gdb_stdout_buf[2 << 12];
    PROCESS_INFORMATION proc_info;
    STARTUPINFOA start_info;
    SECURITY_ATTRIBUTES sec_attrs;
    HANDLE child_stdout_read, child_stdout_write;
    DWORD bytes_avail;

    ZeroMemory(&proc_info, sizeof(proc_info));
  
    sec_attrs.nLength = sizeof(SECURITY_ATTRIBUTES); 
    sec_attrs.bInheritHandle = TRUE; 
    sec_attrs.lpSecurityDescriptor = NULL; 
    if (!CreatePipe(&child_stdout_read, &child_stdout_write, &sec_attrs, 0)) {
        Out("CreatePipe() failed: %d\n", GetLastError());
        child_stdout_read = NULL;
        child_stdout_write = NULL;
        goto out;
    }
    if (!SetHandleInformation(child_stdout_read, HANDLE_FLAG_INHERIT, 0)) {
        Out("SetHandleInformation() failed: %d\n", GetLastError());
        goto out;
    }

    ZeroMemory(&start_info, sizeof(start_info));
    start_info.cb = sizeof(STARTUPINFO); 
    start_info.hStdOutput = child_stdout_write;
    start_info.wShowWindow = SW_HIDE;
    start_info.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
    
    sprintf_s(cmd, sizeof(cmd),
              "%s %s --batch -ex \"%s\"",
              gdb_path, uxen_obj_path, gdb_cmd);
    if (!CreateProcessA(NULL, cmd,
                        NULL, NULL, TRUE, 0, NULL, NULL, 
                        &start_info, &proc_info))
    {
        Out("CreateProcess() failed: %d\n", GetLastError());
        goto out;
    }

    for (;;) { 
        if (!PeekNamedPipe(child_stdout_read, NULL, 0,
                           NULL, &bytes_avail, NULL))
        {
            Out("PeekNamedPipe() failed: %d\n", GetLastError());
            goto out;
        }

        if (bytes_avail) {
            if (!ReadFile(child_stdout_read,
                          gdb_stdout_buf, sizeof(gdb_stdout_buf),
                          &bytes_avail, NULL)
                || 0 == bytes_avail)
            {
                Out("ReadFile() failed: %d\n", GetLastError());
                break;
            }
            gdb_stdout_buf[bytes_avail] = 0;
            Out(gdb_stdout_buf);
        } else {
            if (WAIT_OBJECT_0 == WaitForSingleObject(proc_info.hProcess, 0)) {
                break;
            }
        }
    } 

out:
    if (proc_info.hProcess) {
        CloseHandle(proc_info.hProcess);
    }
    if (proc_info.hThread) {
        CloseHandle(proc_info.hThread);
    }
    if (child_stdout_read) {
        CloseHandle(child_stdout_read);
    }
    if (child_stdout_write) {
        CloseHandle(child_stdout_read);
    }
}

void
EXT_CLASS::refresh_uxen_paths(bool print_paths)
{
    GetEnvironmentVariableA("uxen_gdb_path",
                            uxen_gdb_path, sizeof(uxen_gdb_path));
    GetEnvironmentVariableA("uxen_obj_path",
                            uxen_obj_path, sizeof(uxen_obj_path));

    if (print_paths) {
        Out("uxen_obj_path = %s\n", uxen_obj_path);
        Out("uxen_gdb_path = %s\n", uxen_gdb_path);
        Out("\n");
    }
}

EXT_COMMAND(
    udt,
    "show uxen structure",
    "{;x,o;expr;struct name}")
{
    char cmd[1 << 12];

    RequireKernelMode();
    refresh_uxen_paths(!HasUnnamedArg(0));

    if (HasUnnamedArg(0)) {
        sprintf_s(cmd, sizeof(cmd), "ptype struct %s", GetUnnamedArgStr(0));
        execute_gdb_cmd(uxen_gdb_path, uxen_obj_path, cmd);
    } else {
        Out("Usage: !udt <uxen-struct-name>\n");
    }
}

EXT_COMMAND(
    ugdb,
    "executes gdb command on uxen.obj",
    "{;x,o;expr;gdb command}")
{

    RequireKernelMode();
    refresh_uxen_paths(!HasUnnamedArg(0));

    if (HasUnnamedArg(0)) {
        execute_gdb_cmd(uxen_gdb_path, uxen_obj_path, GetUnnamedArgStr(0));
    } else {
        Out("Usage: !ugdb <gdb-cmd>\n");
    }
}
