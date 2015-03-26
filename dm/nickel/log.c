/*
 * Copyright 2014-2015, Bromium, Inc.
 * Author: Paulian Marinca <paulian@marinca.net>
 * SPDX-License-Identifier: ISC
 */

#if defined(_WIN32)
#define _POSIX
#endif

#include <dm/config.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <sys/time.h>

#include <stdbool.h>

#include <dm/debug.h>
#include "nickel.h"
#include "log.h"
#include "buff.h"

/* 1 MB */
#define LOG_RING_SIZE   (1*1024L*1024L)

static char *ring_buf = NULL;
static size_t ring_idx = 0;
static bool ring_log = false;

static void ring_write(const char *buf, size_t len)
{
    size_t lenw;

    if (!ring_buf)
        return;

    if (ring_idx + len <= LOG_RING_SIZE) {
        memcpy(ring_buf + ring_idx, buf, len);
        ring_idx += len;
    } else {
        lenw = LOG_RING_SIZE - ring_idx;
        memcpy(ring_buf + ring_idx, buf, lenw);
        len = (len - lenw) % LOG_RING_SIZE;
        memcpy(ring_buf, buf + lenw, len);
        ring_idx = len;
    }
    ring_idx = ring_idx % LOG_RING_SIZE;
    ring_buf[(ring_idx + 1) % LOG_RING_SIZE] = 0;
}

static void ring_vprintf(const char *fmt, va_list ap)
{
    struct tm _tm, *tm;
    time_t ltime;
    struct timeval tv;
    char prefix[3 + 1 + 2 + 1 + 2 + 1 + 2 + 1 + 3 + 1 + 1];
    int len;
    char *buf = NULL;
    static int had_newline = 1;

    if (!ring_buf)
        return;

    if (had_newline) {
        gettimeofday(&tv, NULL);
        ltime = (time_t)tv.tv_sec;
        tm = localtime_r(&ltime, &_tm);
	if (tm) {
            snprintf(prefix, sizeof(prefix), "%03d-%02d:%02d:%02d.%03d ",
                     tm->tm_yday, tm->tm_hour, tm->tm_min, tm->tm_sec,
                     (int)(tv.tv_usec / 1000));
            ring_write(prefix, sizeof(prefix) - 1);
	}
	had_newline = 0;
    }

    len = vasprintf(&buf, fmt, ap);
    if (len < 1)
        goto out;
    ring_write(buf, len);

    if (fmt[strlen(fmt) - 1] == '\n')
	had_newline = 1;
out:
    if (len > 0 && buf)
        free(buf);
}

static void
ring_printf(const char *fmt, ...)
{
    va_list ap;

    va_start(ap, fmt);
    ring_vprintf(fmt, ap);
    va_end(ap);
}

#if 0
static int get_current_time()
{
    struct _timeb tb = {0};
    int cur = 0;

    _ftime(&tb);
    cur  = (u_int)tb.time * (u_int)1000;
    cur += (u_int)tb.millitm;
    return cur;
}
#endif

void netlog(const char *fmt, ...)
{
    va_list ap;

#if 0
    if (slirp_log_level >= 4) {
        ring_log = false;
        goto go_ahead;
    }

    if (!ring_log)
        goto out;

    if (!ring_buf) {
        ring_buf = calloc(1, LOG_RING_SIZE + 1);
        if (!ring_buf)
           goto out;
    }

go_ahead:
#endif
    if (!fmt)
        goto out;

    va_start(ap, fmt);
    if (ring_log)
        ring_vprintf(fmt, ap);
    else
        debug_vprintf(fmt, ap);
    va_end(ap);

out:
    return;
}

void netlog_buf(const char *msg, const char *buf, size_t len)
{
    const int char_per_line = 16;
    char tmp[3*char_per_line + 4];
    size_t i = 0, j;

    if (ring_log)
        ring_printf("%s\n", msg);
    else
        debug_printf("%s\n", msg);
    while (i < len) {
        int n = len - i;

        if (n > char_per_line)
            n = char_per_line;
        for (j = 0; j < n; j++)
            snprintf(tmp + j * 3, 4, " %02x", (unsigned char) (buf[i + j]));
        if (ring_log)
            ring_printf("\t<%03"PRIdSIZE":%03"PRIdSIZE"-%03"PRIdSIZE">:%s\n",
                        len, i, i + j - 1, tmp);
        else
            debug_printf("\t<%03"PRIdSIZE":%03"PRIdSIZE"-%03"PRIdSIZE">:%s\n",
                         len, i, i + j - 1, tmp);
        i += n;
    }
}

void netlog_flush(void)
{
    fflush(stderr);
    if (!ring_buf)
        return;

    if (!ring_idx && !ring_buf[ring_idx + 2])
        return;

    debug_printf("--- dumping proxy log ---\n");
    if (ring_idx + 2 < LOG_RING_SIZE && ring_buf[ring_idx + 2])
        fwrite(ring_buf + ring_idx + 2, LOG_RING_SIZE - ring_idx - 2, 1, stderr);

    if (ring_idx > 0)
        fwrite(ring_buf, ring_idx, 1, stderr);
    debug_printf("--- end of dump ---\n");
    memset(ring_buf, 0, LOG_RING_SIZE);
    ring_idx = 0;
    fflush(stderr);
}

#define HB_TO_ASCII(c)  ((c) > 9 ? (c) - 10  + 'a' : (c) + '0')
static void _netlog_print_esc(bool bin_always, const char *msg, const char *str, size_t len)
{
    bool binary = false, b_bsg = msg != NULL;
    size_t i = 0, olen = len;
    unsigned char c;

    if (bin_always)
        binary = true;

    fprintf(stderr, " --- DMP %s%s%s --- \n", b_bsg ? "[" : "",
            b_bsg ? msg : "", b_bsg ? "]" : "");
    while (i < len) {
        if (!bin_always && (*(str + i) == '\\' || *(str + i) == '~')) {
            if (i > 0) {
                fwrite(str, i, 1, stderr);
                str += i;
                len -= i;
                i = 0;
            }
            fputc('\\', stderr);
            fputc(*str, stderr);
            str += 1;
            len -= 1;
            continue;
        }

        c = *(str + i);
        if (bin_always || ((c < 32 || c >= 127) &&
            (binary || (c != '\n' && c != '\r' && c != 0x09)))) {

            if (i > 0) {
                fwrite(str, i, 1, stderr);
                str += i;
                len -= i;
                i = 0;
            }
            binary = true;
            fputc('~', stderr);
            c = ((unsigned char)*str) >> 4;
            fputc(HB_TO_ASCII(c), stderr);
            c = ((unsigned char)*str) & 0x0f;
            fputc(HB_TO_ASCII(c), stderr);
            str += 1;
            len -= 1;
            continue;
        }

        i++;
    }

    if (i > 0)
        fwrite(str, i, 1, stderr);

    fprintf(stderr, "\n --- END %lu bytes --- \n", (unsigned long) olen);
}

void netlog_print_esc(const char *msg, const char *str, size_t len)
{
    _netlog_print_esc(false, msg, str, len);
}

void netlog_print_bin(const char *msg, const char *str, size_t len)
{
    _netlog_print_esc(true, msg, str, len);
}

void netlog_prefix(int log_level, struct buff *bf)
{
    if (bf)
        buff_appendf(bf, "(nickel) ");
}
