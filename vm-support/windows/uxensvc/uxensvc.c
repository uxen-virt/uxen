/*
 * Copyright 2013-2019, Bromium, Inc.
 * Author: Julian Pidancet <julian@pidancet.net>
 * SPDX-License-Identifier: ISC
 */

#include <windows.h>
#include <tchar.h>
#include <stdio.h>
#include <inttypes.h>
#include <winioctl.h>
#define V4V_USE_INLINE_API
#include <windows/uxenv4vlib/gh_v4vapi.h>
#include <echo-common.h>

errno_t rand_s(   unsigned int* randomValue);
#include "platform.h"
#include "session.h"
#include "../common/debug-user.h"

wchar_t                         *svc_name = L"uxensvc";
wchar_t                         *svc_path;

static SERVICE_STATUS           svc_status;
static SERVICE_STATUS_HANDLE    svc_status_handle;
static HANDLE                   svc_stop_event = NULL;

struct echo_msg {
    v4v_datagram_t dg;
    struct uxenecho_msg msg;
};

static v4v_channel_t v4v;
static int echo_initialized;
static HANDLE echo_event, echo_write_event;
static OVERLAPPED echo_ov, echo_write_ov;
static struct echo_msg echo_msg;


static int
svc_set_privilege(const char *priv_name)
{
    BOOL rc;
    TOKEN_PRIVILEGES tok_priv;
    HANDLE token;

    rc = LookupPrivilegeValue(NULL, priv_name, &tok_priv.Privileges[0].Luid);
    if (!rc) {
        uxen_err("LookupPrivilegeValue failed (%d)",
            (int)GetLastError());
        return -1;
    }

    rc = OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES,
                          &token);
    if (!rc) {
        uxen_err("OpenProcessToken failed (%d)", (int)GetLastError());
        return -1;
    }

    tok_priv.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    tok_priv.PrivilegeCount = 1;

    rc = AdjustTokenPrivileges(token, FALSE, &tok_priv, 0, NULL, NULL);
    CloseHandle(token);
    if (!rc) {
        uxen_err("AdjustTokenPrivileges failed (%d)", (int)GetLastError());
        return -1;
    }

    return 0;
}

static void
svc_report_status(DWORD dwCurrentState,
                  DWORD dwWin32ExitCode,
                  DWORD dwWaitHint)
{
    static DWORD checkpoint = 1;

    svc_status.dwCurrentState = dwCurrentState;
    svc_status.dwWin32ExitCode = dwWin32ExitCode;
    svc_status.dwWaitHint = dwWaitHint;

    if (dwCurrentState == SERVICE_START_PENDING)
        svc_status.dwControlsAccepted = 0;
    else
        svc_status.dwControlsAccepted = SERVICE_ACCEPT_STOP |
                                        SERVICE_ACCEPT_SESSIONCHANGE;

    if ((dwCurrentState == SERVICE_RUNNING) ||
        (dwCurrentState == SERVICE_STOPPED))
        svc_status.dwCheckPoint = 0;
    else
        svc_status.dwCheckPoint = checkpoint++;

    SetServiceStatus(svc_status_handle, &svc_status);
}

static DWORD CALLBACK
svc_ctl_handler(DWORD control, DWORD event_type, void *event_data,
                void *context)
{
    switch (control) {
    case SERVICE_CONTROL_STOP:
        svc_report_status(SERVICE_STOP_PENDING, NO_ERROR, 0);
        SetEvent(svc_stop_event);
        svc_report_status(svc_status.dwCurrentState, NO_ERROR, 0);
        break;

    case SERVICE_CONTROL_INTERROGATE:
        break;

    case SERVICE_CONTROL_SESSIONCHANGE:
        {
            WTSSESSION_NOTIFICATION *s = event_data;

            if (event_type == WTS_SESSION_LOGON)
                session_connect(s->dwSessionId);
            else if (event_type == WTS_SESSION_LOGOFF)
                session_disconnect(s->dwSessionId);
        }
        break;

    default:
        break;
   }

    return NO_ERROR;
}

static void
echo_read(void)
{
    memset(&echo_ov, 0, sizeof(echo_ov));
    echo_ov.hEvent = echo_event;

    if (!ReadFile(v4v.v4v_handle, &echo_msg, sizeof(echo_msg), NULL, &echo_ov)) {
        switch (GetLastError()) {
        case ERROR_IO_PENDING:
            break;
        default:
            uxen_err("echo ReadFile failed: %d", GetLastError());
            break;
        }
    }
}

static void
echo_dispatch(void)
{
    DWORD bytes;

    if (!GetOverlappedResult(v4v.v4v_handle, &echo_ov, &bytes, FALSE)) {
        switch (GetLastError()) {
        case ERROR_IO_INCOMPLETE:
            return;
        }
        uxen_err("echo GetOverlappedResult failed err=%d", GetLastError());
    } else {
        /* send echo response */
        memset(&echo_write_ov, 0, sizeof(echo_write_ov));
        echo_write_ov.hEvent = echo_write_event;
        if (!WriteFile(v4v.v4v_handle, &echo_msg, sizeof(echo_msg), NULL, &echo_write_ov)) {
            switch (GetLastError()) {
            case ERROR_IO_PENDING:
                break;
            default:
                uxen_err("echo WriteFile failed: %d", GetLastError());
                break;
            }
        }
    }
    /* read next */
    echo_read();
}

static int
echo_init(void)
{
    v4v_bind_values_t bind = { };

    if (!v4v_open(&v4v, UXEN_ECHO_RING_SIZE, V4V_FLAG_ASYNC)) {
        uxen_err("v4v_open failed");
        return -1;
    }

    bind.ring_id.addr.port = UXEN_ECHO_US_PORT;
    bind.ring_id.addr.domain = V4V_DOMID_ANY;
    bind.ring_id.partner = V4V_DOMID_DM;

    if (!v4v_bind(&v4v, &bind)) {
        uxen_err("v4v_bind failed");
        v4v_close(&v4v);
        return -1;
    }

    echo_event = CreateEvent(NULL, FALSE, FALSE, NULL);
    echo_write_event = CreateEvent(NULL, FALSE, FALSE, NULL);
    echo_initialized = 1;

    uxen_msg("hbmon us echo service started");

    return 0;
}

static void
echo_cleanup(void)
{
    if (echo_initialized) {
        CloseHandle(echo_event);
        CloseHandle(echo_write_event);
        v4v_close(&v4v);
        echo_initialized = 0;
    }
}

static void
svc_init(DWORD argc, wchar_t **argv)
{
    DWORD err = NO_ERROR;
    DWORD active_session;
    HANDLE events[4] = { NULL, NULL, NULL, NULL };
    unsigned int random_wait;
    int rc;
    int i;

    svc_stop_event = CreateEvent(NULL, TRUE, FALSE, NULL);
    if (!svc_stop_event) {
        svc_report_status(SERVICE_STOPPED, NO_ERROR, 0);
        return;
    }
    events[0] = svc_stop_event;

    rc = svc_set_privilege(SE_INCREASE_QUOTA_NAME);
    if (rc){
        uxen_err("Failed to set SE_INCREASE_QUOTA_NAME privilege");
        err = GetLastError();
        goto stop;
    }

    rc = svc_set_privilege(SE_ASSIGNPRIMARYTOKEN_NAME);
    if (rc){
        uxen_err("Failed to set SE_ASSIGNPRIMARYTOKEN_NAME privilege");
        err = GetLastError();
        goto stop;
    }

    rc = platform_open();
    if (rc) {
        uxen_err("platform_open() failed (%d)", rc);
        err = rc;
        goto stop;
    }

    events[1] = CreateEvent(NULL, FALSE, FALSE, NULL);

    rc = platform_set_time_update_event(events[1]);
    if (rc) {
        uxen_err("platform_set_time_update_event() failed (%d)", rc);
        err = rc;
        goto stop;
    }

    events[2] = CreateEvent(NULL, FALSE, FALSE, NULL);

    rc = platform_service_balloon_update_event(events[2]);
    if (rc) {
        uxen_err("platform_set_balloon_update_event() failed (%d)", rc);
        err = rc;
        goto stop;
    }

    rc = echo_init();
    if (rc) {
        uxen_err("echo_init failed (%d)", rc);
        err = rc;
        goto stop;
    }

    events[3] = echo_event;

    /* Service balloon driver once on startup. */
    platform_service_balloon();
    /* initial time alignment with the platform */
    platform_update_system_time();

    active_session = WTSGetActiveConsoleSessionId();
    if (active_session && active_session != (DWORD)-1) {
        uxen_msg("Active session %d already present", active_session);
        session_connect(active_session);
    }

    echo_read();

    svc_report_status(SERVICE_RUNNING, NO_ERROR, 0);

    while (1) {
        rand_s(&random_wait);
        random_wait &= 0x1f;
        /* Use timeout to adjust balloon periodically. We make the timeout
         * slightly random to avoid all VMs adjusting their balloons at the
         * same time. */
        rc = WaitForMultipleObjectsEx(4, events, FALSE, 111 + random_wait,
                TRUE);
        switch (rc) {
        case WAIT_OBJECT_0:
            /* stop event */
            goto stop;
        case WAIT_OBJECT_0 + 1:
            /* platform event */
            ResetEvent(events[1]);
            platform_update_system_time();
            break;
        case WAIT_OBJECT_0 + 3:
            /* echo event */
            echo_dispatch();
            break;
        case WAIT_OBJECT_0 + 2:
            /* balloon event */
            ResetEvent(events[2]);
        case WAIT_TIMEOUT:
            platform_service_balloon();
            break;
        case WAIT_IO_COMPLETION:
            break;
        default:
            uxen_err("WaitForMultipleObjectEx failed (%d)", (int)GetLastError());
            goto stop;
        }
    }

stop:
    echo_cleanup();

    active_session = WTSGetActiveConsoleSessionId();
    if (active_session && active_session != (DWORD)-1)
        session_disconnect(active_session);

    for (i = 0; i < 3; ++i) {
        if (events[i])
            CloseHandle(events[i]);
    }

    svc_report_status(SERVICE_STOPPED, err, 0);
}

static void WINAPI
svc_main(DWORD argc, wchar_t **argv)
{
    InitializeCriticalSection(&session_lock);

    svc_status_handle = RegisterServiceCtrlHandlerExW(svc_name,
                                                      svc_ctl_handler,
                                                      NULL);
    if (!svc_status_handle) {
        uxen_err("RegisterServiceCtrlHandler failed (%d)", (int)GetLastError());
        return;
    }

    svc_status.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    svc_status.dwServiceSpecificExitCode = 0;

    svc_report_status(SERVICE_START_PENDING, NO_ERROR, 3000);

    svc_init(argc, argv);
}

static int
svc_install(void)
{
    SC_HANDLE scm;
    SC_HANDLE service;

    scm = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);

    if (!scm) {
        uxen_err("OpenSCManager failed (%d)\n", (int)GetLastError());
        return -1;
    }


    service = CreateServiceW(scm,
                             svc_name,
                             svc_name,
                             SERVICE_ALL_ACCESS,
                             SERVICE_WIN32_OWN_PROCESS,
                             SERVICE_AUTO_START,
                             SERVICE_ERROR_NORMAL,
                             svc_path,
                             NULL,
                             NULL,
                             NULL,
                             NULL,
                             NULL);

    if (!service) {
        uxen_err("CreateService failed (%d)\n", (int)GetLastError());
        CloseServiceHandle(scm);
        return -1;
    }

    uxen_msg("Service installed successfully\n");

    CloseServiceHandle(service);
    CloseServiceHandle(scm);

    return 0;
}

static int
svc_delete(void)
{
    SC_HANDLE scm;
    SC_HANDLE service;
    BOOL rc;

    scm = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);

    if (!scm) {
        uxen_err("OpenSCManager failed (%d)\n", (int)GetLastError());
        return -1;
    }


    service = OpenServiceW(scm, svc_name, DELETE);
    if (!service) {
        uxen_err("OpenService failed (%d)\n", (int)GetLastError());
        CloseServiceHandle(scm);
        return -1;
    }

    rc = DeleteService(service);
    if (!rc) {
        uxen_err("DeleteService failed (%d)\n", (int)GetLastError());
        CloseServiceHandle(service);
        CloseServiceHandle(scm);
        return -1;
    }

    uxen_msg("Service deleted successfully\n");

    CloseServiceHandle(service);
    CloseServiceHandle(scm);

    return 0;
}

static int
svc_start(int argc, const wchar_t **argv)
{
    SC_HANDLE scm;
    SC_HANDLE service;
    BOOL rc;

    scm = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);

    if (!scm) {
        uxen_err("OpenSCManager failed (%d)\n", (int)GetLastError());
        return -1;
    }


    service = OpenServiceW(scm, svc_name, SERVICE_ALL_ACCESS);
    if (!service) {
        uxen_err("OpenService failed (%d)\n", (int)GetLastError());
        CloseServiceHandle(scm);
        return -1;
    }

    rc = StartServiceW(service, argc, argv);
    if (!rc) {
        uxen_err("StartService failed (%d)\n", (int)GetLastError());
        CloseServiceHandle(service);
        CloseServiceHandle(scm);
        return -1;
    }

    uxen_msg("Service started successfully\n");

    CloseServiceHandle(service);
    CloseServiceHandle(scm);

    return 0;
}

static const wchar_t *status_str[] = {
    [SERVICE_CONTINUE_PENDING] = L"continue pending",
    [SERVICE_PAUSE_PENDING] = L"pause pending",
    [SERVICE_PAUSED] = L"paused",
    [SERVICE_RUNNING] = L"running",
    [SERVICE_START_PENDING] = L"start pending",
    [SERVICE_STOP_PENDING] = L"stop pending",
    [SERVICE_STOPPED] = L"stopped",
};

static int
svc_stop(void)
{
    SC_HANDLE scm;
    SC_HANDLE service;
    BOOL rc;
    SERVICE_STATUS status;

    scm = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);

    if (!scm) {
        uxen_err("OpenSCManager failed (%d)\n", (int)GetLastError());
        return -1;
    }


    service = OpenServiceW(scm, svc_name, SERVICE_STOP);
    if (!service) {
        uxen_err("OpenService failed (%d)\n", (int)GetLastError());
        CloseServiceHandle(scm);
        return -1;
    }

    rc = ControlService(service, SERVICE_CONTROL_STOP, &status);
    if (!rc) {
        uxen_err("ControlService failed (%d)\n", (int)GetLastError());
        CloseServiceHandle(service);
        CloseServiceHandle(scm);
        return -1;
    }

    uxen_msg("Service status: %s\n", status_str[status.dwCurrentState]);

    CloseServiceHandle(service);
    CloseServiceHandle(scm);

    return 0;
}

static int
svc_query(void)
{
    SC_HANDLE scm;
    SC_HANDLE service;
    BOOL rc;
    SERVICE_STATUS_PROCESS status;
    DWORD len;

    scm = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);

    if (!scm) {
        uxen_err("OpenSCManager failed (%d)\n", (int)GetLastError());
        return -1;
    }


    service = OpenServiceW(scm, svc_name, SERVICE_ALL_ACCESS);
    if (!service) {
        uxen_err("OpenService failed (%d)\n", (int)GetLastError());
        CloseServiceHandle(scm);
        return -1;
    }

    rc = QueryServiceStatusEx(service, SC_STATUS_PROCESS_INFO, (void *)&status,
                              sizeof (status), &len);
    if (!rc) {
        uxen_err("QueryServiceStatusEx failed (%d)\n", (int)GetLastError());
        CloseServiceHandle(service);
        CloseServiceHandle(scm);
        return -1;
    }

    uxen_msg("Service status: %s\n", status_str[status.dwCurrentState]);

    CloseServiceHandle(service);
    CloseServiceHandle(scm);

    return 0;
}

static void
usage(wchar_t *progname)
{
    wprintf(L"usage:\n");
    wprintf(L"%s [install|delete|start|stop|query|help]\n", progname);
    wprintf(L"\n");
    wprintf(L"%s install\n", progname);
    wprintf(L"    Install service.\n");
    wprintf(L"%s delete\n", progname);
    wprintf(L"    Delete service.\n");
    wprintf(L"%s start <args>\n", progname);
    wprintf(L"    Start service.\n");
    wprintf(L"%s stop\n", progname);
    wprintf(L"    Stop service.\n");
    wprintf(L"%s query\n", progname);
    wprintf(L"    Query service.\n");
    wprintf(L"%s help\n", progname);
    wprintf(L"    Show this help.\n");
}

int WINAPI
WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance,
        LPSTR szCmdLine, int iCmdShow)
{
    int argc;
    wchar_t **argv;
    BOOL rc;
    SERVICE_TABLE_ENTRYW dispatch[] = {
        { svc_name, svc_main },
        { NULL, NULL }
    };

    uxen_ud_set_progname("uxensvc");

    argv = CommandLineToArgvW(GetCommandLineW(), &argc);
    if (!argv) {
        uxen_err("CommandLineToArgvW failed (%d)\n", (int)GetLastError());
        return -1;
    }

    svc_path = calloc(PATH_MAX, sizeof (wchar_t));

    if (!GetModuleFileNameW(NULL, svc_path, MAX_PATH)) {
        uxen_err("GetModuleFileNameW failed (%d)\n",  (int)GetLastError());
        return -1;
    }

    if (argc >= 2) {
        if (!wcscmp(argv[1], L"install"))
            return svc_install();
        else if (!wcscmp(argv[1], L"delete"))
            return svc_delete();
        else if (!wcscmp(argv[1], L"start"))
            return svc_start(argc - 2, (const wchar_t **)(argv + 2));
        else if (!wcscmp(argv[1], L"stop"))
            return svc_stop();
        else if (!wcscmp(argv[1], L"query"))
            return svc_query();
        else if (!wcscmp(argv[1], L"help")) {
            usage(argv[0]);
            return 0;
        }

        wprintf(L"Unrecognized parameter: %s\n", argv[1]);
        usage(argv[0]);
        return -1;
    }

    rc = StartServiceCtrlDispatcherW(dispatch);
    if (!rc) {
        int err = GetLastError();

        if (err == ERROR_FAILED_SERVICE_CONTROLLER_CONNECT)
            usage(argv[0]);
        else
            uxen_err("StartServiceCtrlDispatcher failed (%d)", err);

        return -1;
    }

    return 0;
}

