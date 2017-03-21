/*
 * Copyright 2013-2017, Bromium, Inc.
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

static void (*log_prefix_fn)(char *target,
                             size_t len,
                             struct tm *tm,
                             struct timeval *tv) = NULL;

int
verbose_logging(void)
{
    return 1;
}

static void
log_prefix_default(char *target, size_t len, struct tm *tm, struct timeval *tv)
{
    snprintf(target, len, "%03d-%02d:%02d:%02d.%03d ",
             tm->tm_yday, tm->tm_hour, tm->tm_min, tm->tm_sec,
             (int)(tv->tv_usec / 1000));
}

static void
log_prefix_iso_8601(char *target, size_t len, struct tm *tm, struct timeval *tv)
{
    unsigned long tz_abs_hour_off;
    unsigned long tz_abs_minute_off;
    char tz_sign;

#ifdef _WIN32
    LONG log_timezone_bias = 0;
    int is_behind_utc;
    int abs_bias;

    TIME_ZONE_INFORMATION timezone_info;
    switch (GetTimeZoneInformation(&timezone_info)) {
        case TIME_ZONE_ID_UNKNOWN:
            log_timezone_bias = timezone_info.Bias;
            break;
        case TIME_ZONE_ID_STANDARD:
            log_timezone_bias = timezone_info.Bias + timezone_info.StandardBias;
            break;
        case TIME_ZONE_ID_DAYLIGHT:
            log_timezone_bias = timezone_info.Bias + timezone_info.DaylightBias;
            break;
        default:
            log_timezone_bias = 0;
            break;
    }
    is_behind_utc = log_timezone_bias > 0;
    abs_bias = log_timezone_bias < 0 ? -log_timezone_bias : log_timezone_bias;

    tz_abs_hour_off = abs_bias / 60;
    tz_abs_minute_off = abs_bias % 60;
    tz_sign = is_behind_utc ? '-' : '+';
#else
    tz_abs_hour_off = labs(tm->tm_gmtoff) / 3600L;
    tz_abs_minute_off = (labs(tm->tm_gmtoff) % 3600L) / 60L;
    tz_sign = tm->tm_gmtoff >= 0L ? '+' : '-';
#endif

    snprintf(target, len,
             "%04d-%02d-%02d %02d:%02d:%02d.%03d%c%02lu:%02lu ",
             tm->tm_year+1900, tm->tm_mon+1, tm->tm_mday, tm->tm_hour,
             tm->tm_min, tm->tm_sec, (int)(tv->tv_usec / 1000),
             tz_sign,
             tz_abs_hour_off,
             tz_abs_minute_off);
}

void
logstyle_set(const char *log_timestamp_style)
{
    if (!log_timestamp_style || !strcmp(log_timestamp_style, "default")) {

        log_prefix_fn = log_prefix_default;
    } else if (!strcmp(log_timestamp_style, "iso-8601")) {

        log_prefix_fn = log_prefix_iso_8601;
    } else {

        fprintf(stderr, "log timestamp style '%s' unknown, "
                "falling back to default\n", log_timestamp_style);
        log_prefix_fn = log_prefix_default;
    }
}

void
debug_vprintf(const char *fmt, va_list ap)
{
    struct tm _tm, *tm;
    time_t ltime;
    struct timeval tv;
    char prefix[32];
    int print_prefix = 0;
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
	    log_prefix_fn(prefix, sizeof(prefix), tm, &tv);
            print_prefix = 1;
	}
    }

    had_newline = fmt[strlen(fmt) - 1] == '\n';

    vasprintf(&buf, fmt, ap);

    if (buf && print_prefix) {
        char *prefixed_buf = NULL;

        asprintf(&prefixed_buf, "%s%s", prefix, buf);
        free(buf);
        buf = prefixed_buf;
    }

    if (buf) {
        fwrite(buf, strlen(buf), 1, stderr);
        free(buf);
    } else {
        if (print_prefix)
            fputs(prefix, stderr);
        vfprintf(stderr, fmt, ap2); /* slowpath on malloc failure. */
    }

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
