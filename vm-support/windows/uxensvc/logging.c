/*
 * Copyright 2013-2015, Bromium, Inc.
 * Author: Julian Pidancet <julian@pidancet.net>
 * SPDX-License-Identifier: ISC
 */

#include <windows.h>
#include <stdio.h>

#include "logging.h"

extern wchar_t *svc_name;

void
svc_vprintf(DWORD lvl, const wchar_t *fmt, va_list ap)
{
    HANDLE h;
    wchar_t buf[512];
    const wchar_t *str[2];
    WORD type;

    switch (lvl) {
    case SVC_INFO:
        type = EVENTLOG_INFORMATION_TYPE;
        break;
    case SVC_WARN:
        type = EVENTLOG_WARNING_TYPE;
        break;
    case SVC_ERROR:
    default:
        type = EVENTLOG_ERROR_TYPE;
        break;
    }

    h = RegisterEventSourceW(NULL, svc_name);
    if (!h)
        return;

    _vsnwprintf(buf, sizeof (buf), fmt, ap);
    str[0] = svc_name;
    str[1] = buf;

    ReportEventW(h, type, 0, lvl, NULL, 2, 0, str, NULL);

    DeregisterEventSource(h);
}

void
svc_printf(DWORD lvl, const wchar_t *fmt, ...)
{
    va_list ap;

    va_start(ap, fmt);
    svc_vprintf(lvl, fmt, ap);
    va_end(ap);
}

