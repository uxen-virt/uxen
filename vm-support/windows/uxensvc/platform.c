/*
 * Copyright 2013-2019, Bromium, Inc.
 * Author: Christian Limpach <Christian.Limpach@gmail.com>
 * SPDX-License-Identifier: ISC
 */

#include <windows.h>
#include <setupapi.h>
#include <stdint.h>
#include <initguid.h>
#include <errno.h>

#include "platform.h"
#include "platform_public.h"

#include "../common/debug-user.h"

#include <xen/xen.h>

static int verbose = 1;
static HANDLE platform_device = INVALID_HANDLE_VALUE;

int
platform_open(void)
{
    HDEVINFO hardware_deviceinfo;
    SP_DEVICE_INTERFACE_DATA device_interface_data;
    PSP_DEVICE_INTERFACE_DETAIL_DATA device_interface_detail_data = NULL;
    DWORD required_length;
    int ret;

    hardware_deviceinfo = SetupDiGetClassDevs(
        (LPGUID)&GUID_DEVINTERFACE_UXENPLATFORM,
        NULL, NULL, (DIGCF_PRESENT | DIGCF_DEVICEINTERFACE));
    if (hardware_deviceinfo == INVALID_HANDLE_VALUE)
        return -1;

    device_interface_data.cbSize = sizeof(device_interface_data);

    ret = !SetupDiEnumDeviceInterfaces(hardware_deviceinfo,
                                       0,
                                       (LPGUID)&GUID_DEVINTERFACE_UXENPLATFORM,
                                       0,
                                       &device_interface_data);
    if (ret) {
        /* uxen_err("SetupDiEnumDeviceInterfaces failed"); */
        goto out;
    }

    ret = !SetupDiGetDeviceInterfaceDetail(hardware_deviceinfo,
                                           &device_interface_data,
                                           NULL, 0,
                                           &required_length, NULL);
    if (ret && GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
        uxen_err("SetupDiGetDeviceInterfaceDetail probe failed");
        goto out;
    }

    device_interface_detail_data = calloc(1, required_length);
    if (!device_interface_detail_data) {
        uxen_err("calloc failed");
        ret = -1;
        goto out;
    }

    device_interface_detail_data->cbSize =
        sizeof(SP_DEVICE_INTERFACE_DETAIL_DATA);

    ret = !SetupDiGetDeviceInterfaceDetail(hardware_deviceinfo,
                                           &device_interface_data,
                                           device_interface_detail_data,
                                           required_length, &required_length,
                                           NULL);
    if (ret) {
        uxen_err("SetupDiGetDeviceInterfaceDetail failed");
        goto out;
    }

    platform_device = CreateFile(device_interface_detail_data->DevicePath,
                                 GENERIC_READ | GENERIC_WRITE, 0, NULL,
                                 OPEN_EXISTING, FILE_FLAG_OVERLAPPED, NULL);
    if (platform_device == INVALID_HANDLE_VALUE) {
        uxen_err("CreateFile failed");
        ret = -1;
        goto out;
    }

    ret = 0;
  out:
    free(device_interface_detail_data);
    SetupDiDestroyDeviceInfoList(hardware_deviceinfo);
    return ret;
}

int
uxen_ioctl(HANDLE h, uint64_t ctl, ...)
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
        BufferLength = ctl >> 32;
        ctl &= ((1ULL << 32) - 1);
    }

    memset(&ov, 0, sizeof(ov));
    ov.hEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
    ret = !DeviceIoControl(h, ctl, (func & UXEN_FLAG_INBUFFER) ? Buffer : NULL,
                           (func & UXEN_FLAG_INBUFFER) ? BufferLength : 0,
			   (func & UXEN_FLAG_OUTBUFFER) ? Buffer : NULL,
                           (func & UXEN_FLAG_OUTBUFFER) ? BufferLength : 0,
                           &outlen, &ov);
    if (ret && GetLastError() == ERROR_IO_PENDING)
        ret = !GetOverlappedResult(h, &ov, &outlen, TRUE);
    if (!ret && (func & UXEN_FLAG_OUTBUFFER) && outlen != BufferLength) {
        _set_errno(EINVAL);
        uxen_err("DeviceIoControl %llx invalid OutputBuffer", ctl);
        ret = -1;
        goto out;
    }
    if (ret) {
	ret = GetLastError();
	if (UXEN_IS_ERRNO_NTSTATUS(ret)) {
	    _set_errno(UXEN_ERRNO_FROM_NTSTATUS(ret));
	    uxen_err("DeviceIoControl %llx", ctl);
	    ret = -1;
	} else {
	    uxen_err("DeviceIoControl %llx", ctl);
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
platform_set_time_update_event(HANDLE event)
{
    struct uxen_platform_set_time_update_event d;
    int ret;

    d.time_update_event = event;
    ret = uxen_ioctl(platform_device, IOCTL_UXEN_PLATFORM_SET_TIME_UPDATE_EVENT,
                     &d);
    if (ret)
        uxen_err("ioctl(IOCTL_UXEN_PLATFORM_SET_TIME_UPDATE_EVENT)");

    return ret;
}

int
platform_service_balloon_update_event(HANDLE event)
{
    struct uxen_platform_set_balloon_update_event d;
    int ret;

    d.balloon_update_event = event;
    ret = uxen_ioctl(platform_device, IOCTL_UXEN_PLATFORM_SET_BALLOON_UPDATE_EVENT,
                     &d);
    if (ret)
        uxen_err("ioctl(IOCTL_UXEN_PLATFORM_SET_BALLOON_UPDATE_EVENT)");

    return ret;
}

struct shared_info *
platform_map_shared_info(void)
{
    struct uxen_platform_map_shared_info d;
    int ret;

    ret = uxen_ioctl(platform_device, IOCTL_UXEN_PLATFORM_MAP_SHARED_INFO, &d);
    if (ret) {
        uxen_err("ioctl(IOCTL_UXEN_PLATFORM_MAP_SHARED_INFO)");
        d.shared_info = NULL;
        goto out;
    }

  out:
    return d.shared_info;
}

int
platform_service_balloon(void)
{
    /* Settings: 100 retries, 10ms between, actual balloon size in mb
     * set later on. */
    MEMORYSTATUSEX statex;
    struct uxen_platform_balloon_statistics stats;
    struct uxen_platform_balloon_configuration cfg = {100, 10, 0};
    int ret = 0;
    int load;
    /* Statics to suppress balloon growth right the max gets adjusted.
     * Purpose is to avoid evicting cache state state right as we may be
     * starting to need it. */
    static int last_max = -1;
    static int suppress_growth = 0;

    /* Get current balloon setting. */
    ret = uxen_ioctl(platform_device,
            IOCTL_UXEN_PLATFORM_BALLOON_GET_STATISTICS, &stats);
    if (ret) {
        return ret;
    }

    /* Get Windows memory stats. */
    statex.dwLength = sizeof(statex);
    if (!GlobalMemoryStatusEx(&statex)) {
        return -1;
    }
    /* Convert to percentage load. */
    load = (100ULL - (100ULL*statex.ullAvailPhys) / statex.ullTotalPhys);
    /* Set maximum possible balloon size to be total memory size, but. */
    int min_balloon_mb = stats.min_size_mb;
    int max_balloon_mb = stats.max_size_mb;
    int balloon_mb = stats.current_size_mb;

    if (last_max != max_balloon_mb) {
        /* Wait a bit before actually starting to grow. */
        suppress_growth = 10;
        last_max = max_balloon_mb;
    }

    /* Our balloon adjustment policy. If low on memory we rapidly try to
     * deflate the balloon. If high on memory we inflate it less rapidly. */
    if (load > 95) {
        balloon_mb -= 32;
    } else if (load < 90) {
        if (suppress_growth > 0) {
            --suppress_growth;
        } else {
            if (load < 80) {
                balloon_mb += 2;
            } else {
                balloon_mb += 1;
            }
        }
    }

    /* Keep within bounds. */
    if (balloon_mb < min_balloon_mb) {
        balloon_mb = min_balloon_mb;
    } else if (balloon_mb > max_balloon_mb) {
        balloon_mb = max_balloon_mb;
    }

    if (balloon_mb != stats.current_size_mb) {
        /* Send ioctl to kernel driver to make it adjust balloon. If kernel
         * driver has been configured by host to use a larger balloon, that is
         * the size it will actually be set to. */
        cfg.target_size_mb = balloon_mb;
        ret = uxen_ioctl(platform_device,
                IOCTL_UXEN_PLATFORM_BALLOON_SET_CONFIGURATION, &cfg);
        if (ret) {
            uxen_err("ioctl(IOCTL_UXEN_PLATFORM_BALLOON_SET_CONFIGURATION)");
        }
    }
    return ret;
}

int
platform_update_system_time(void)
{
    int ret;
    uint64_t ft, tmp;
    FILETIME filetime;
    SYSTEMTIME st;

    ret = uxen_ioctl(platform_device, IOCTL_UXEN_PLATFORM_GET_FTIME, &ft);
    if (ret) {
        return ret;
    }

    do {
        tmp = ft;
        ret = uxen_ioctl(platform_device, IOCTL_UXEN_PLATFORM_GET_FTIME, &ft);
        if (ret) {
            return ret;
        }
    } while ((ft - tmp) >= 10000000ULL /* 1s */);

    filetime.dwLowDateTime = ft & 0xFFFFFFFF;
    filetime.dwHighDateTime = ft >> 32;

    FileTimeToSystemTime(&filetime, &st);
    ret = !SetSystemTime(&st);
    if (ret) {
        uxen_err("%s: SetSystemTime failed", __FUNCTION__);
        return ret;
    }

    if (verbose) {
        DWORD adj = 0, incr = 0;
        BOOL adj_dis = FALSE;

        uxen_msg("updated system time %04d-%02d-%02d %02d:%02d:%02d.%03d %d",
                   st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute,
                   st.wSecond, st.wMilliseconds, st.wDayOfWeek);
        memset(&st, 0, sizeof(st));
        GetSystemTime(&st);
        GetSystemTimeAdjustment(&adj, &incr, &adj_dis);
        uxen_msg("verified system time after update: %04d-%02d-%02d %02d:%02d:%02d.%03d %d",
                   st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute,
                   st.wSecond, st.wMilliseconds, st.wDayOfWeek);
        uxen_msg("time adjustment settings adj=%d incr=%d dis=%d", adj, incr, adj_dis);
    }

    return 0;
}
