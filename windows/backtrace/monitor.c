/*
 * Copyright 2014-2015, Bromium, Inc.
 * Author: Julian Pidancet <julian@pidancet.net>
 * SPDX-License-Identifier: ISC
 */

#include <windows.h>
#include <dbghelp.h>
#include <psapi.h>
#include <stdio.h>
#include <stdlib.h>

#include "monitor.h"

static volatile struct except_info *except_info = NULL;

int main(int argc, char **argv)
{
    HANDLE except_shm_handle;
    HANDLE except_notify_event;
    HANDLE except_cont_event;
    HANDLE except_monitor_mutex;
    int ret;
    DWORD rc;

    ret = 1;
    except_shm_handle = CreateFileMapping(INVALID_HANDLE_VALUE, NULL,
                                          PAGE_READWRITE | SEC_COMMIT, 0,
                                          sizeof (*except_info),
                                          EXCEPTION_SHM_FILE_NAME);
    if (!except_shm_handle) {
        fprintf(stderr, "CreateFileMapping failed: %08x\n",
                (int)GetLastError());
        goto file_fail;
    }
    except_info = MapViewOfFile(except_shm_handle, FILE_MAP_WRITE, 0, 0,
                                sizeof (*except_info));
    if (!except_info) {
        fprintf(stderr, "MapViewOfFile failed: %08x\n",
                (int)GetLastError());
        goto map_fail;
    }

    except_monitor_mutex = CreateMutex(NULL, FALSE,
                                       EXCEPTION_MONITOR_MUTEX_NAME);
    if (!except_monitor_mutex) {
        fprintf(stderr, "CreateMutex failed: %08x\n",
                (int)GetLastError());
        goto mutex_fail;
    }

    except_notify_event = CreateEvent(NULL, FALSE, FALSE,
                                      EXCEPTION_NOTIFY_EVENT_NAME);
    if (!except_notify_event) {
        fprintf(stderr, "CreateEvent failed: %08x\n",
                (int)GetLastError());
        goto event1_fail;
    }

    except_cont_event = CreateEvent(NULL, FALSE, FALSE,
                                    EXCEPTION_CONTINUE_EVENT_NAME);
    if (!except_cont_event) {
        fprintf(stderr, "CreateEvent failed: %08x\n",
                (int)GetLastError());
        goto event2_fail;
    }

    rc = WaitForSingleObject(except_monitor_mutex, INFINITE);
    if (rc != WAIT_OBJECT_0) {
        fprintf(stderr, "Fail to acquire monitor mutex: %08x(%08x)\n",
                (int)rc, (int)GetLastError());
        goto lock_fail;
    }

    do {
        HANDLE proc_handle;
        BOOL r;
        char basename[256];
        char dumpname[MAX_PATH];
        HANDLE dump_handle;
        MINIDUMP_EXCEPTION_INFORMATION minidump_except_info;

        rc = WaitForSingleObject(except_notify_event, INFINITE);
        if (rc != WAIT_OBJECT_0) {
            fprintf(stderr, "WaitForSingleObject failed: %08x\n",
                    (int)GetLastError());
            goto wait_fail;
        }

        proc_handle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
                                  FALSE, except_info->process_id);
        if (!proc_handle) {
            fprintf(stderr, "OpenProcess failed: %08x\n",
                    (int)GetLastError());
            goto signal_cont_event;
        }

        rc = GetModuleBaseNameA(proc_handle, NULL, basename, sizeof (basename) - 1);
        if (!rc) {
            fprintf(stderr, "GetModuleBaseName failed: %08x\n",
                    (int)GetLastError());
            goto close_proc_handle;
        }
        basename[rc] = '\0';
        ret = snprintf(dumpname, sizeof (dumpname) - 1, "%s%s-%d.dmp",
                       "", basename, (int)except_info->process_id);
        if (ret < 0) {
            fprintf(stderr, "Filename too long\n");
            goto close_proc_handle;
        }
        dumpname[ret] = '\0';

        fprintf(stdout, "Exception event from PID: %d, creating dump file %s...\n",
                (int)except_info->process_id, dumpname);

        dump_handle = CreateFileA(dumpname, GENERIC_READ | GENERIC_WRITE,
                                  0, NULL, CREATE_NEW, FILE_ATTRIBUTE_NORMAL,
                                  NULL);
        if (!dump_handle) {
            fprintf(stderr, "CreateFile failed: %08x\n",
                    (int)GetLastError());
            goto close_proc_handle;
        }

        minidump_except_info.ThreadId = except_info->thread_id;
        minidump_except_info.ExceptionPointers = except_info->exception_pointers;
        minidump_except_info.ClientPointers = TRUE;

        r = MiniDumpWriteDump(proc_handle, except_info->process_id,
                              dump_handle, MiniDumpWithFullMemory |
                                           MiniDumpWithHandleData |
                                           MiniDumpWithUnloadedModules |
                                           MiniDumpWithProcessThreadData |
                                           MiniDumpIgnoreInaccessibleMemory,
                              &minidump_except_info, NULL, NULL);
        if (!r)
            fprintf(stderr, "MiniDumpWriteDump failed: %08x\n",
                    (int)GetLastError());

        CloseHandle(dump_handle);
close_proc_handle:
        CloseHandle(proc_handle);
signal_cont_event:
        SetEvent(except_cont_event);
    } while (1);

    ret = 0;

wait_fail:
    ReleaseMutex(except_monitor_mutex);
lock_fail:
    CloseHandle(except_cont_event);
event2_fail:
    CloseHandle(except_notify_event);
event1_fail:
    CloseHandle(except_monitor_mutex);
mutex_fail:
    UnmapViewOfFile((void *)except_info);
map_fail:
    CloseHandle(except_shm_handle);
file_fail:

    return ret;
}
