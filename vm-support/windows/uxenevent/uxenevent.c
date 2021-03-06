/*
 *  uxenevent.c
 *  uxen
 *
 * Copyright 2012-2017, Bromium, Inc.
 * Author: Christian Limpach <Christian.Limpach@gmail.com>
 * SPDX-License-Identifier: ISC
 *
 */

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#ifndef WINVER
#define WINVER 0x0601
#endif
#define _WIN32_WINNT 0x0601
#include <windows.h>
#include <winsock2.h>
#endif

#include <assert.h>
#define ERR_WINDOWS
#define ERR_AUTO_CONSOLE
#include <err.h>
#include <getopt.h>
#include <inttypes.h>
#include <pdh.h>
#include <pdhmsg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <tchar.h>
#include <wtsapi32.h>
#include <userenv.h>
#include <conio.h>

#ifdef __APPLE__
#include <sys/types.h>
#include <sys/socket.h>
#endif

#include <guest-agent-proto.h>

#include <inttypes.h>

#include <winioctl.h>
#define V4V_USE_INLINE_API
#include <windows/uxenv4vlib/gh_v4vapi.h>

#ifndef WAIT_OBJECT_1
#define WAIT_OBJECT_1 ((WAIT_OBJECT_0)+1)
#endif

#ifndef WAIT_OBJECT_2
#define WAIT_OBJECT_2 ((WAIT_OBJECT_0)+2)
#endif

#include "input.h"
#include "perf_counters.h"
#include "display.h"
#include "uxenevent.h"
#include "window.h"
#include "process.h"

DECLARE_PROGNAME;

#define DEFAULT_PORT 44448
#define RING_SIZE 262144
#define PACKET_SIZE 16384
struct pkt {
    v4v_datagram_t dgram;
    union {
        struct ns_event_msg_header hdr;
        unsigned char data[NS_EVENT_MSG_MAX_LEN];
    };
};


static struct send_item {
    OVERLAPPED o;
    struct pkt pkt;
    struct send_item *next;
} *send_list = NULL;

static OVERLAPPED recv_overlapped;
static BOOLEAN recv_pending;
static struct pkt recv_pkt;
static HANDLE recv_event;
static HANDLE send_event;


int verbose = 0;

static HANDLE resize_event;
static int resize_timer_set = 0;
static int requested_w, requested_h;
static unsigned int requested_flags;

static void
usage(const char *progname)
{

    errx(1, "usage: %s [-h] [-i ip] [-p port] [-v]", progname);
}

static void
socket_cleanup(void)
{
    WSACleanup();
}


static void
send_collect(v4v_channel_t * c)
{
    struct send_item **ip, *i;

    DWORD bytes;

    ResetEvent(&send_event);

    ip = &send_list;
    while ((i = *ip)) {

        if (!GetOverlappedResult (c->v4v_handle, &i->o, &bytes, FALSE)) {
            if (GetLastError () == ERROR_IO_INCOMPLETE) {
                ip = &i->next;
                continue;
            }

            uxen_err("WriteFile failed: %d", GetLastError ());
        }


        /* Either success or failure here so delete the item */
        *ip = i->next;
        free (i);
    }
}


static int
send_enqueue(v4v_channel_t *c, struct pkt *pkt)
{
    struct send_item *i;
    DWORD bytes,len;

    send_collect(c);

    i=malloc(sizeof(*i));
    if (!i) return -1;

    memset(&i->o,0,sizeof(i->o));

    len=pkt->hdr.len + sizeof (pkt->dgram);

    if (len>sizeof(*pkt)) return -1;

    memcpy(&i->pkt,pkt,len);
    pkt->dgram.flags = 0;

    i->o.hEvent=send_event;

    if (WriteFile(c->v4v_handle, &i->pkt, len, &bytes, &i->o)) {
        free(i);
        return 0;
    }

    switch(GetLastError()) {
        case ERROR_IO_PENDING:
            break;
        default:
            uxen_err("WriteFile failed: %d", GetLastError());

            free(i);
            return -1;
    }

    i->next=send_list;
    send_list=i;

    return 0;
}

static void
process_resize(void)
{
    if ((requested_w > 0) && (requested_h > 0)) {
        LARGE_INTEGER timeout;

        uxen_msg("%dx%d flags 0x%x", requested_w, requested_h, requested_flags);

        display_resize(requested_w, requested_h, requested_flags);
        requested_w = 0;
        requested_h = 0;
        requested_flags = 0;

        timeout.QuadPart = -2500000; /* 250ms */
        SetWaitableTimer(resize_event, &timeout, 0, NULL, NULL, 0);
        resize_timer_set = 1;
    }
}

static void
schedule_resize(int w, int h, unsigned int flags)
{
    requested_w = w;
    requested_h = h;
    requested_flags = flags;

    uxen_msg("%dx%d flags 0x%x", w, h, flags);

    if (!resize_timer_set)
        process_resize();
}

static int
process_windows_window_proc(struct ns_event_msg_windows_window_proc *msg)
{
    int rc = -1;

    switch (msg->message) {
    case WM_SIZE:
        schedule_resize(msg->lParam & 0xffff, (msg->lParam >> 16) & 0xffff, msg->wParam);
        rc = 0;
        break;

    case WM_LBUTTONDOWN:
    case WM_RBUTTONDOWN:
    case WM_MBUTTONDOWN:
    case WM_LBUTTONUP:
    case WM_RBUTTONUP:
    case WM_MBUTTONUP:
    case WM_MOUSEMOVE:
    case WM_MOUSEWHEEL:
    case WM_MOUSEHWHEEL:
    case WM_MOUSELEAVE:
    case WM_XBUTTONUP:
    case WM_XBUTTONDOWN:
        rc = input_wm_mouse_event(msg->message, msg->wParam, msg->lParam);
        break;

    case WM_ACTIVATE:
    case WM_KILLFOCUS:
    case WM_SETFOCUS:
        rc = window_event(msg->message, msg->wParam, msg->lParam);
        break;

    default:
        break;
    }

    return rc;
}

#define COMMAND_PROMPT_PATH _T("C:\\Windows\\System32\\cmd.exe")

static HANDLE cmd_hwnd = NULL;
static DWORD cmd_watch = (DWORD)-1;

static BOOL CALLBACK
enum_hwnd_cb(HWND hwnd, LPARAM lParam)
{
    DWORD pid;

    GetWindowThreadProcessId(hwnd, &pid);
    if ((DWORD)lParam == pid) {
        cmd_hwnd = hwnd;
        return FALSE;
    }

    return TRUE;
}

static int
execute_as_user(TCHAR *command_line, TCHAR *path,
                HANDLE std_out, PROCESS_INFORMATION *pi)
{
    BOOL rc;
    DWORD session_id;
    HANDLE token, primary_token;
    STARTUPINFO si;
    void *env = NULL; /* Never EVER call your variable "environ" */

//    debug_log("%s: command line: \"%s\", path: \"%s\"", __FUNCTION__,
//              command_line, path);
    ProcessIdToSessionId(GetCurrentProcessId(), &session_id);
    uxen_msg("session ID %ld", session_id);
    rc = WTSQueryUserToken(session_id, &token);
    if (!rc) {
        uxen_err("WTSQueryUserToken failed (%ld)", GetLastError());
        return -1;
    }
    rc = DuplicateTokenEx(token,
                          MAXIMUM_ALLOWED,
                          NULL,
                          SecurityImpersonation,
                          TokenPrimary, &primary_token);
    CloseHandle(token);
    if (!rc) {
        uxen_err("DuplicateTokenEx failed (%ld)", GetLastError());
        return -1;
    }
    rc = CreateEnvironmentBlock(&env, primary_token, FALSE);
    if (!rc) {
        uxen_err("CreateEnvironmentBlock failed (%ld)", GetLastError());
        CloseHandle(primary_token);
        return -1;
    }

    memset(&si, 0, sizeof (si));
    si.cb = sizeof (si);
    si.lpDesktop = _T("WinSta0\\Default");
    if (std_out) {
        si.hStdOutput = std_out;
        si.dwFlags = STARTF_USESTDHANDLES;
    }
    memset(pi, 0, sizeof (*pi));

    rc = CreateProcessAsUser(primary_token, NULL,
                             command_line,
                             NULL, /* Security Attr */
                             NULL, /* Thread Attr */
                             TRUE, /* Inherit handles */
                             NORMAL_PRIORITY_CLASS |
                             CREATE_UNICODE_ENVIRONMENT |
                             CREATE_NEW_CONSOLE,
                             env,
                             path,
                             &si, pi);
    CloseHandle(primary_token);
    DestroyEnvironmentBlock(env);

    if (!rc) {
        uxen_err("CreateProcessAsUser failed (%ld)", GetLastError());
        return -1;
    }

    return 0;
}

static DWORD WINAPI
cmd_watch_thread(void *param)
{
    BOOL rc;
    PROCESS_INFORMATION pi;
    TCHAR drive[_MAX_DRIVE], dir[_MAX_DIR];
    TCHAR *command_line;
    HANDLE pw, pr;
    SECURITY_ATTRIBUTES sattr;
    DWORD pid, r;
    int ret = -1;

    command_line = calloc(PATH_MAX, sizeof (TCHAR));
    if (!command_line) {
        uxen_err("Allocation error");
        goto out;
    }

    rc = GetModuleFileName(NULL, command_line, MAX_PATH);
    if (!rc) {
        free(command_line);
        uxen_err("GetModuleFileName failed (%ld)", GetLastError());
        goto out;
    }

    _tsplitpath(command_line, drive, dir, NULL, NULL);
    _sntprintf(command_line, MAX_PATH,
               _T("%s%selevate.exe ") COMMAND_PROMPT_PATH,
               drive, dir);

    sattr.nLength = sizeof (sattr);
    sattr.bInheritHandle = TRUE;
    sattr.lpSecurityDescriptor = NULL;
    rc = CreatePipe(&pr, &pw, &sattr, 0);
    if (!rc) {
        free(command_line);
        uxen_err("CreatePipe failed");
        goto out;
    }
    SetHandleInformation(pr, HANDLE_FLAG_INHERIT, 0);

    ret = execute_as_user(command_line, _T("C:\\"), pw, &pi);
    free(command_line);
    if (ret) {
        uxen_err("execute_as_user failed");
        goto out;
    }

    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);

    rc = ReadFile(pr, &pid, sizeof (pid), &r, NULL);
    if (!rc || !r) {
        CloseHandle(pw);
        CloseHandle(pr);
        uxen_err("ReadFile failed (%ld)", GetLastError());
        goto out;
    }

    uxen_msg("Created elevated process %ld", pid);

    CloseHandle(pw);
    CloseHandle(pr);

    if (pid != (DWORD)-1) {
        HANDLE proc;
        DWORD exit_code;

        Sleep(200);
        EnumWindows(enum_hwnd_cb, (LPARAM)pid);
        if (cmd_hwnd)
            SetWindowPos(cmd_hwnd, HWND_TOPMOST, 0, 0, 0, 0,
                         SWP_NOMOVE | SWP_NOSIZE);

        proc = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid);
        if (!proc) {
            uxen_err("OpenProcess failed (%ld)", GetLastError());
            goto out;
        }

        do {
            Sleep(1000);

            rc = GetExitCodeProcess(proc, &exit_code);
            if (!rc) {
                CloseHandle(proc);
                uxen_err("GetExitCodeProcess failed (%ld)", GetLastError());
                goto out;
            }
        } while (exit_code == STILL_ACTIVE);

        CloseHandle(proc);
        uxen_msg("Process terminated with exit code %ld", exit_code);
    }
    ret = 0;

out:
    cmd_hwnd = NULL;
    cmd_watch = (DWORD)-1;
    return ret;
}

static int
process_start_command_prompt(struct ns_event_msg_start_command_prompt *msg)
{
    HANDLE thread;

    /* Process is already running */
    if (cmd_watch != (DWORD)-1) {
        if (cmd_hwnd) {
            if (IsIconic(cmd_hwnd))
                ShowWindow(cmd_hwnd, SW_RESTORE);

            SetWindowPos(cmd_hwnd, HWND_TOPMOST, 0, 0, 0, 0,
                         SWP_NOMOVE | SWP_NOSIZE);
        }

        return 0;
    }

    thread = CreateThread(NULL, 0, cmd_watch_thread, NULL, 0, &cmd_watch);
    if (thread)
        CloseHandle(thread);

    return 0;
}

static int
process_windows_set_time_zone_information(
    struct ns_event_msg_windows_set_time_zone_information *msg)
{
    TIME_ZONE_INFORMATION *tzi =
        (TIME_ZONE_INFORMATION *)msg->time_zone_information;
    HANDLE hToken;
    TOKEN_PRIVILEGES tkp;
    int rc = 0;

    OpenProcessToken(GetCurrentProcess(),
                     TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken);
    LookupPrivilegeValue(NULL, SE_TIME_ZONE_NAME, &tkp.Privileges[0].Luid);
    tkp.PrivilegeCount = 1;
    tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    AdjustTokenPrivileges(hToken, FALSE, &tkp, 0, (PTOKEN_PRIVILEGES)NULL, 0);
    if (!SetTimeZoneInformation(tzi))
        uxen_err("SetTimeZoneInformation failed");
    tkp.Privileges[0].Attributes = 0;
    AdjustTokenPrivileges(hToken, FALSE, &tkp, 0, (PTOKEN_PRIVILEGES)NULL, 0);

    return rc;
}

static int
process_windows_set_dynamic_time_zone_information(
    struct ns_event_msg_windows_set_dynamic_time_zone_information *msg)
{
    DYNAMIC_TIME_ZONE_INFORMATION *dtzi =
        (DYNAMIC_TIME_ZONE_INFORMATION *)msg->dynamic_time_zone_information;
    HANDLE hToken;
    TOKEN_PRIVILEGES tkp;
    int rc = 0;

    OpenProcessToken(GetCurrentProcess(),
                     TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken);
    LookupPrivilegeValue(NULL, SE_TIME_ZONE_NAME, &tkp.Privileges[0].Luid);
    tkp.PrivilegeCount = 1;
    tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    AdjustTokenPrivileges(hToken, FALSE, &tkp, 0, (PTOKEN_PRIVILEGES)NULL, 0);
    if (!SetDynamicTimeZoneInformation(dtzi))
        uxen_err("SetDynamicTimeZoneInformation failed");
    tkp.Privileges[0].Attributes = 0;
    AdjustTokenPrivileges(hToken, FALSE, &tkp, 0, (PTOKEN_PRIVILEGES)NULL, 0);

    return rc;
}

static int
process_user_draw_enable(
    struct ns_event_msg_user_draw_enable *msg)
{
    DWORD pid = find_pid("dwm.exe");
    DWORD err;

    if (pid) {
        /* if enabling user draw, replace framebuffer mapping in dwm.exe with
         * scratch framebuffer mapping; needs to be done on suspended process */

        err = suspend_pid(pid);
        if (err) {
            uxen_err("suspend of dwm.exe failed: %x\n", err);
            goto out;
        }

        /* replace any user fb mappings in the dwm process with scratch mappings */
        display_scratchify_process(pid, msg->enable);

        err = resume_pid(pid);
        if (err)
            uxen_err("resume of dwm.exe failed: %x\n", err);
    }

out:
    return 0;
}

static int
process_remote_execute(struct ns_event_msg_remote_execute *msg)
{
    int cmd_len;
    int rc;
    PROCESS_INFORMATION pi;
#ifdef _UNICODE
    wchar_t command_line[1024];
#else
    char *command_line;
#endif

    cmd_len = msg->msg.len - sizeof(*msg);
    if (cmd_len <= 0 || msg->command[cmd_len - 1]) {
        uxen_err("bad command");
        return -1;
    }

#ifdef _UNICODE
    rc = MultiByteToWideChar(CP_ACP, 0, msg->command, -1, &command_line,
                             sizeof(command_line));
    if (!rc) {
        uxen_err("WideChar conversion failed (%d)", GetLastError());
        return -1;
    }
#else
    command_line = msg->command;
#endif

    uxen_msg("exec %s", msg->command);
    rc = execute_as_user(command_line, NULL, NULL, &pi);
    if (rc) {
        uxen_err("exec failed");
        return rc;
    }

    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);

    return rc;
}

static int
process_start_perf_data_collection(
    struct ns_event_msg_start_perf_data_collection *msg)
{
    perf_start_sampling(msg->counters_mask,
                        msg->sampling_interval, msg->number_of_samples);

    return 0;
}

static int
process_blank_display(struct ns_event_msg_blank_display *msg)
{
    display_blank(msg->enable);
    return 0;
}

static int
process_kbd_input(struct ns_event_msg_kbd_input *msg)
{
    return input_key_event(msg->keycode, msg->repeat, msg->scancode,
                           msg->flags, msg->nchars, (wchar_t *)msg->chars,
                           msg->nchars_bare, (wchar_t *)msg->chars_bare);
}

static int
process_mouse_input(struct ns_event_msg_mouse_input *msg)
{
    return input_mouse_event(msg->x, msg->y, msg->dv, msg->dh, msg->flags);
}

#ifdef TOUCH_INJECTION
static int
process_touch_input(struct ns_event_msg_touch_input *msg)
{
    if (msg->msg.len < sizeof (*msg) + msg->count * sizeof (msg->contacts[0]))
        return -1;

    return input_touch_event(msg->count, msg->contacts);
}
#endif

void set_high_priority(void)
{
    if (!SetPriorityClass(GetCurrentProcess(), HIGH_PRIORITY_CLASS)) {
        uxen_err("INFO: Unable to enter high prio mode for process, error=%u\n",
                (uint32_t)GetLastError());
    }
    if (!SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_HIGHEST)) {
        uxen_err("INFO: Unable to enter high prio mode for thread, error=%u\n",
                (uint32_t)GetLastError());
    }
}



void recv_dispatch(v4v_channel_t *c,struct pkt *pkt,DWORD bytes)
{
    int rc;

    if ((bytes < sizeof (pkt->dgram) + sizeof (pkt->hdr)) ||
        (bytes < sizeof (pkt->dgram) + pkt->hdr.len)) {
        uxen_err("incomplete read, bytes=%d", bytes);
        return;
    }

#define CHECKBUFSZ(type) \
        if (bytes < sizeof (pkt->dgram) + sizeof(struct type)) { \
            uxen_err("invalid message size for proto %d (%d)",  \
                      pkt->hdr.proto, bytes); \
            return; \
        }

    switch (pkt->hdr.proto) {
    case NS_EVENT_MSG_PROTO_WINDOWS_WINDOW_PROC:
        CHECKBUFSZ(ns_event_msg_windows_window_proc);
        rc = process_windows_window_proc((void *)pkt->data);
        break;
    case NS_EVENT_MSG_PROTO_START_COMMAND_PROMPT:
        CHECKBUFSZ(ns_event_msg_start_command_prompt);
        rc = process_start_command_prompt((void *)pkt->data);
        break;
    case NS_EVENT_MSG_PROTO_WINDOWS_SET_TIME_ZONE_INFORMATION:
        CHECKBUFSZ(ns_event_msg_windows_set_time_zone_information);
        rc = process_windows_set_time_zone_information((void *)pkt->data);
        break;
    case NS_EVENT_MSG_PROTO_REMOTE_EXECUTE:
        CHECKBUFSZ(ns_event_msg_remote_execute);
        rc = process_remote_execute((void *)pkt->data);
        break;
    case NS_EVENT_MSG_PROTO_START_PERF_DATA_COLLECTION:
        CHECKBUFSZ(ns_event_msg_start_perf_data_collection);
        rc = process_start_perf_data_collection((void *)pkt->data);
        break;
    case NS_EVENT_MSG_PROTO_BLANK_DISPLAY:
        CHECKBUFSZ(ns_event_msg_blank_display);
        rc = process_blank_display((void *)pkt->data);
        break;
    case NS_EVENT_MSG_KBD_INPUT:
        CHECKBUFSZ(ns_event_msg_kbd_input);
        rc = process_kbd_input((void *)pkt->data);
        break;
    case NS_EVENT_MSG_MOUSE_INPUT:
        CHECKBUFSZ(ns_event_msg_mouse_input);
        rc = process_mouse_input((void *)pkt->data);
        break;
#ifdef TOUCH_INJECTION
    case NS_EVENT_MSG_TOUCH_INPUT:
        CHECKBUFSZ(ns_event_msg_touch_input);
        rc = process_touch_input((void *)pkt->data);
        break;
#endif
    case NS_EVENT_MSG_NOP:
        rc = 0;
        break;
    case NS_EVENT_MSG_PROTO_WINDOWS_SET_DYNAMIC_TIME_ZONE_INFORMATION:
        CHECKBUFSZ(ns_event_msg_windows_set_dynamic_time_zone_information);
        rc = process_windows_set_dynamic_time_zone_information((void *)pkt->data);
        break;
    case NS_EVENT_MSG_PROTO_USER_DRAW_ENABLE:
        CHECKBUFSZ(ns_event_msg_user_draw_enable);
        rc = process_user_draw_enable((void *)pkt->data);
        break;
    default:
        uxen_err("unknown message proto %d", pkt->hdr.proto);
        return;
    }

    /* Send back packet to RMA */
    if (rc)
        send_enqueue(c, pkt);
}

static int recv_setup(v4v_channel_t *c);

static void recv_collect(v4v_channel_t *c)
{
    DWORD bytes;

    ResetEvent(recv_event);

    if (!recv_pending) return;

    if (!GetOverlappedResult(c->v4v_handle,&recv_overlapped,&bytes,FALSE)) {
        switch(GetLastError()) {
            case ERROR_IO_INCOMPLETE:
                return;
        }

        uxen_err("GetOverLappedResult err=%d\n", GetLastError());
    } else {
      recv_dispatch(c,&recv_pkt,bytes);
    }

    recv_pending=0;
    recv_setup(c);
}




static int recv_setup(v4v_channel_t *c)
{
    DWORD bytes;
    if (recv_pending) recv_collect(c);
    if (recv_pending) return -1;

    ResetEvent(recv_event);

    memset(&recv_overlapped,0,sizeof(recv_overlapped));
    recv_overlapped.hEvent=recv_event;

    while (ReadFile(c->v4v_handle, &recv_pkt, sizeof (recv_pkt), &bytes, &recv_overlapped))  {
        recv_dispatch(c,&recv_pkt,bytes);

        ResetEvent(recv_event);
        memset(&recv_overlapped,0,sizeof(recv_overlapped));
        recv_overlapped.hEvent=recv_event;
    }


    switch(GetLastError()) {
        case ERROR_IO_PENDING:
            break;
        default:
            uxen_err("ReadFile failed: %d", GetLastError());
            return -1;
    }

    recv_pending=1;
    return 0;
}


static void v4v_init(v4v_channel_t *c)
{
    v4v_bind_values_t bind;

    if (!v4v_open(c, RING_SIZE, V4V_FLAG_ASYNC)) {
        uxen_err("v4v_open failed");
        err(1, "v4v_open");
    }

    bind.ring_id.addr.port = DEFAULT_PORT;
    bind.ring_id.addr.domain = V4V_DOMID_ANY;
    bind.ring_id.partner = V4V_DOMID_DM;

    if (!v4v_bind(c, &bind)) {
        uxen_err("v4v_bind failed");
        err(1, "v4v_bind");
    }
}


#define NR_EVENTS 3

int
main(int argc, char **argv)
{
    WSADATA Data;
    HANDLE events[NR_EVENTS];
    v4v_channel_t v4v;
    int ierr;

    setprogname(argv[0]);
    uxen_ud_set_progname("uxenevent");
    uxen_ud_mask = UXEN_UD_ERR | UXEN_UD_MSG;

    while (1) {
        int c, index = 0;
        static struct option long_options[] = {
            {"help",          no_argument,       NULL, 'h'},
            {"verbose",       no_argument,       NULL, 'v'},
            {NULL,   0,                 NULL, 0}
        };

        c = getopt_long(argc, argv, "hi:p:v", long_options, &index);
        if (c == -1)
            break;

        switch (c) {
        case 'h':
            usage(argv[0]);
            /* NOTREACHED */
        case 'v':
            verbose = 1;
            open_stderr_console();
            break;
        }
    }

    if ((ierr=WSAStartup(MAKEWORD(2,2), &Data)))
        JPWerr(1, "WSAStartup: %d, WSAGetLastError=%x \n",ierr,WSAGetLastError());

    set_high_priority();

    display_init();
#ifdef TOUCH_INJECTION
    input_touch_init();
#endif
    perf_counters_init();

    atexit(socket_cleanup);

    v4v_init(&v4v);

    recv_event=CreateEvent(NULL,FALSE,FALSE,NULL);

    if (!recv_event)
        JPWerr(1, "CreateEvent\n");

    send_event=CreateEvent(NULL,FALSE,FALSE,NULL);

    if (!send_event)
        JPWerr(1, "CreateEvent\n");

    recv_setup(&v4v);

    resize_event = CreateWaitableTimer(NULL, FALSE, NULL);
    assert(resize_event);

    events[0] = recv_event;
    events[1] = send_event;
    events[2] = resize_event;

    while (1) {
	DWORD err;
        err = WaitForMultipleObjectsEx(NR_EVENTS, events, FALSE, INFINITE,
                                       TRUE);

        if (err == WAIT_OBJECT_0) {
            recv_collect(&v4v);
        } else if (err == WAIT_OBJECT_1) {
            send_collect(&v4v);
        } else if (err == WAIT_OBJECT_2) {
            resize_timer_set = 0;
            process_resize();
        } else if (err == WAIT_IO_COMPLETION)
            /* nothing */ ;
        else {
            uxen_err("WaitForMultipleObjectsEx error %ld %ld", err, GetLastError());
        }
        display_border_windows_on_top();
    }

    return 0;
}
