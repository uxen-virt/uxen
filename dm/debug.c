/*
 * Copyright 2013-2015, Bromium, Inc.
 * Author: Christian Limpach <Christian.Limpach@gmail.com>
 * SPDX-License-Identifier: ISC
 */

#include "config.h"
#ifdef MONITOR
#include "monitor.h"
#endif

#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#if defined(_WIN32)
#define _POSIX
#endif
#include <time.h>
#include <sys/time.h>

int
verbose_logging(void)
{
    return 1;
}

void
debug_vprintf(const char *fmt, va_list ap)
{
    struct tm _tm, *tm;
    time_t ltime;
    struct timeval tv;
    char prefix[3 + 1 + 2 + 1 + 2 + 1 + 2 + 1 + 3 + 1 + 1];
    char *buf;
    static int had_newline = 1;
    static int last_sec = -1;
    int flush = 0;
    va_list ap2;
#ifdef MONITOR
    va_list ap_mon;
#endif

    va_copy(ap2, ap);
#ifdef MONITOR
    va_copy(ap_mon, ap);
#endif

    if (had_newline) {
        gettimeofday(&tv, NULL);
        ltime = (time_t)tv.tv_sec;
        tm = localtime_r(&ltime, &_tm);
        flush = (last_sec != (int)tv.tv_sec);
        last_sec = (int)tv.tv_sec;
	if (tm) {
            snprintf(prefix, sizeof(prefix), "%03d-%02d:%02d:%02d.%03d ",
                     tm->tm_yday, tm->tm_hour, tm->tm_min, tm->tm_sec,
                     (int)(tv.tv_usec / 1000));
	    fputs(prefix, stderr);
	}
	had_newline = 0;
    }

    vasprintf(&buf, fmt, ap);
    if (buf) {
        fwrite(buf, strlen(buf), 1, stderr);
        free(buf);
    } else {
        vfprintf(stderr, fmt, ap2); /* slowpath on malloc failure. */
    }

    if (fmt[strlen(fmt) - 1] == '\n')
	had_newline = 1;

#ifdef MONITOR
    monitor_vprintf(NULL, fmt, ap_mon);
    va_end(ap_mon);
#endif
    va_end(ap2);

    if (flush)
        fflush(stderr);
}

void
debug_printf(const char *fmt, ...)
{
    va_list ap;

    va_start(ap, fmt);
    debug_vprintf(fmt, ap);
    va_end(ap);
}

void
error_printf(const char *fmt, ...)
{
    va_list ap;

    va_start(ap, fmt);
    debug_vprintf(fmt, ap);
    va_end(ap);
}
