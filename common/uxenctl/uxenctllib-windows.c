/*
 *  uxenctllib-windows.c
 *  uxen
 *
 * Copyright 2012-2015, Bromium, Inc.
 * Author: Christian Limpach <Christian.Limpach@gmail.com>
 * SPDX-License-Identifier: ISC
 *
 */

#define ERR_WINDOWS
#define ERR_NO_PROGNAME
#define ERR_STDERR _uxenctllib_stderr
#include <err.h>
#include <inttypes.h>
#include <stdint.h>

#include <winioctl.h>
#include <uxen_ioctl.h>

#include <uxen_def.h>

#include "uxenctllib.h"

int uxen_ioctl(UXEN_HANDLE_T h, uint64_t ctl, ...);

static int
stop_delete_service(SC_HANDLE scm_handle, SC_HANDLE *scs_handle,
                    BOOLEAN fail_ok)
{
    SERVICE_STATUS service_status;
    int ret;

    *scs_handle = OpenService(scm_handle, UXEN_DRIVER_NAME,
                              SERVICE_ALL_ACCESS);
    if (*scs_handle == NULL) {
        if (fail_ok) {
            ret = 0;
            goto out;
        }
        Wwarn("OpenService");
        ret = -1;
        goto out;
    }
    ret = !ControlService(*scs_handle, SERVICE_CONTROL_STOP,
                          &service_status);
    if (ret && GetLastError() != ERROR_SERVICE_NOT_ACTIVE) {
        if (fail_ok) {
            ret = 0;
            goto out;
        }
        Wwarn("ControlService");
        ret = -1;
        goto out;
    }

    ret = !DeleteService(*scs_handle);
    if (ret && GetLastError() != ERROR_SERVICE_MARKED_FOR_DELETE)
        Wwarn("DeleteService");

    ret = 0;
  out:
    return ret;
}

int
uxen_manage_driver(BOOLEAN install, BOOLEAN fail_ok, const char *path)
{
    SC_HANDLE scm_handle = NULL;
    SC_HANDLE scs_handle = NULL;
    int create_retry = 1;
    int ret = -1;
    wchar_t pathbuf[MAX_PATH];

    scm_handle = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (!scm_handle) {
	Wwarn("OpenSCManager");
	return ret;
    }

    if (install) {
        if (path && strcmp(path, ".")) {
            if (!MultiByteToWideChar(CP_UTF8, 0, path, -1, pathbuf, MAX_PATH)) {
                Wwarn("MultiByteToWideChar");
                ret = -1;
                goto out;
            }
        } else {
            ret = GetCurrentDirectoryW(sizeof(pathbuf), pathbuf);
            if (ret == 0) {
                Wwarn("GetCurrentDirectory");
                ret = -1;
                goto out;
            }
        }
	(void)wcsncat(pathbuf, L"\\" UXEN_DRIVER_NAME L".sys", sizeof(pathbuf));

      create_again:
	scs_handle = CreateServiceW(scm_handle, L"" UXEN_DRIVER_NAME,
				   L"" UXEN_DRIVER_NAME, SERVICE_ALL_ACCESS,
				   SERVICE_KERNEL_DRIVER, SERVICE_DEMAND_START,
				   SERVICE_ERROR_NORMAL,
				   pathbuf, NULL, NULL, NULL, NULL, NULL);
        if (scs_handle == NULL && GetLastError() ==
            ERROR_SERVICE_MARKED_FOR_DELETE && create_retry) {
            ret = stop_delete_service(scm_handle, &scs_handle, fail_ok);
            if (ret)
                goto out;
            CloseServiceHandle(scs_handle);
            scs_handle = NULL;
            create_retry = 0;
            goto create_again;
        }
	if (scs_handle) {
	    CloseServiceHandle(scs_handle);
	    scs_handle = OpenService(scm_handle, UXEN_DRIVER_NAME,
				     SERVICE_ALL_ACCESS);
	}
	if (scs_handle == NULL && GetLastError() == ERROR_SERVICE_EXISTS)
	    scs_handle = OpenService(scm_handle, UXEN_DRIVER_NAME,
				     SERVICE_ALL_ACCESS);
	if (scs_handle == NULL) {
	    if (fail_ok) {
		ret = 0;
		goto out;
	    }
	    Wwarn("CreateService");
            ret = -1;
            goto out;
	}
	ret = !StartService(scs_handle, 0, NULL);
	if (ret && GetLastError() != ERROR_SERVICE_ALREADY_RUNNING) {
	    if (fail_ok) {
		ret = 0;
		goto out;
	    }
	    Wwarn("StartService %s", pathbuf);
            ret = -1;
            goto out;
	}
        ret = 0;
    } else
        ret = stop_delete_service(scm_handle, &scs_handle, fail_ok);

  out:
    if (scs_handle) {
	if (ret)
	    DeleteService(scs_handle);
	CloseServiceHandle(scs_handle);
    }
    if (scm_handle)
	CloseServiceHandle(scm_handle);
    return ret;
}

UXEN_HANDLE_T
uxen_open(int index, BOOLEAN install_driver, const char *path)
{
    HANDLE h;
    int ret;

    /* FILE_FLAG_OVERLAPPED for speed */
    h = CreateFile("\\\\.\\" UXEN_DEVICE_NAME, GENERIC_READ, 0, NULL,
		   OPEN_EXISTING, FILE_FLAG_OVERLAPPED, NULL);
    if (h != INVALID_HANDLE_VALUE)
	return h;
    if (!install_driver || index != 0) {
	Wwarn("CreateFile \\\\.\\" UXEN_DEVICE_NAME);
	return INVALID_HANDLE_VALUE;
    }

    ret = uxen_manage_driver(TRUE, FALSE, path);
    if (ret)
	return INVALID_HANDLE_VALUE;

    /* try again */
    return uxen_open(index, FALSE, path);
}

void
uxen_close(UXEN_HANDLE_T h)
{
    int ret;

    if (h != INVALID_HANDLE_VALUE) {
        ret = !CloseHandle(h);
        if (ret)
            Wwarn("CloseHandle");
    }
}

static DWORD WINAPI
uxen_processexit_helper_threadfn(LPVOID arg)
{
    UXEN_HANDLE_T h = arg;
    uint32_t dummy;

    uxen_ioctl(h, UXENPROCESSEXITHELPER, &dummy);
    Wwarn("%s: continued", __FUNCTION__);
    warn("%s: continued", __FUNCTION__);

    return 0;
}

int
uxen_processexit_helper(UXEN_HANDLE_T h)
{
    HANDLE t;

    t = CreateThread(NULL, 0, uxen_processexit_helper_threadfn, h, 0, NULL);
    if (!t) {
        Wwarn("%s: CreateThread(processexit_helper)");
        _set_errno(EINVAL);
        return -1;
    }
    CloseHandle(t);

    return 0;
}

int
uxen_ioctl(UXEN_HANDLE_T h, uint64_t ctl, ...)
{
    va_list ap;
    int func;
    void *Buffer = NULL;
    unsigned long BufferLength = 0;
    OVERLAPPED ov;              /* XXX use tls to avoid create/destroy event? */
    unsigned long outlen;
    int ret;

    va_start(ap, ctl);

    func = FUNCTION_FROM_CTL_CODE(ctl);

    if (func & UXEN_FLAG_INBUFFER || func & UXEN_FLAG_OUTBUFFER) {
        Buffer = va_arg(ap, void *);
        BufferLength = ctl >> UXEN_IOCTL_SIZE_SHIFT;
        ctl &= ((1ULL << UXEN_IOCTL_SIZE_SHIFT) - 1);
    }

    memset(&ov, 0, sizeof(ov));
    ov.hEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
    ret = !DeviceIoControl(h, (DWORD)ctl,
                           (func & UXEN_FLAG_INBUFFER) ? Buffer : NULL,
                           (func & UXEN_FLAG_INBUFFER) ? BufferLength : 0,
			   (func & UXEN_FLAG_OUTBUFFER) ? Buffer : NULL,
                           (func & UXEN_FLAG_OUTBUFFER) ? BufferLength : 0,
                           &outlen, &ov);
    if (ret && GetLastError() == ERROR_IO_PENDING)
        ret = !GetOverlappedResult(h, &ov, &outlen, TRUE);
    if (!ret && (func & UXEN_FLAG_OUTBUFFER) && outlen != BufferLength) {
        _set_errno(EINVAL);
        warn("DeviceIoControl %"PRIx64" invalid OutputBuffer", ctl);
        ret = -1;
        goto out;
    }
    if (ret) {
	ret = GetLastError();
	if (UXEN_IS_ERRNO_NTSTATUS(ret)) {
	    _set_errno(UXEN_ERRNO_FROM_NTSTATUS(ret));
	    warn("DeviceIoControl %"PRIx64, ctl);
	    ret = -1;
	} else {
	    Wwarn("DeviceIoControl %"PRIx64, ctl);
	    _set_errno(EINVAL);
	    ret = -1;
	}
    }

  out:
    CloseHandle(ov.hEvent);
    va_end(ap);

    return ret;
}

int
uxen_event_init(UXEN_EVENT_HANDLE_T *ev)
{

    *ev = CreateEvent(NULL, TRUE, FALSE, NULL);
    return *ev ? 0 : EINVAL;
}

int
uxen_event_wait(UXEN_HANDLE_T h, UXEN_EVENT_HANDLE_T ev, int timeout_ms)
{
    int ret;

    ret = WaitForSingleObject(ev, timeout_ms < 0 ? INFINITE : timeout_ms);
    switch (ret) {
    case WAIT_OBJECT_0:
        ResetEvent(ev);
        return 1;
    case WAIT_ABANDONED:
        return EINTR;
    case WAIT_TIMEOUT:
        return 0;
    case WAIT_FAILED:
    default:
        return EINVAL;
    }
}
