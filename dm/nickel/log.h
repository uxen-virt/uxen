/*
 * Copyright 2014-2015, Bromium, Inc.
 * Author: Paulian Marinca <paulian@marinca.net>
 * SPDX-License-Identifier: ISC
 */

#ifndef _NICKEL_NETLOG_H_
#define _NICKEL_NETLOG_H_

struct buff;
extern int ni_log_level;
#define NLOG_LEVEL    ni_log_level
#define NETLOG_LEVEL(level, fmt, ...) do {                        \
        if (NLOG_LEVEL < (level))                              \
            break;                                                  \
        netlog("(nickel) " fmt "\n", ## __VA_ARGS__);  \
    } while (0)
#define NETLOG(fmt, ...)  NETLOG_LEVEL(1, fmt,  ## __VA_ARGS__)
#define NETLOG2(fmt, ...) NETLOG_LEVEL(2, fmt,  ## __VA_ARGS__)
#define NETLOG3(fmt, ...) NETLOG_LEVEL(3, fmt,  ## __VA_ARGS__)
#define NETLOG4(fmt, ...) NETLOG_LEVEL(4, fmt,  ## __VA_ARGS__)
#define NETLOG5(fmt, ...) NETLOG_LEVEL(5, fmt,  ## __VA_ARGS__)

#define NETLOGBUF(buf, len) do {                          \
        netlog_buf(buf, len);                            \
    } while(0)

void __attribute__ ((__format__ (printf, 1, 2)))
netlog(const char *fmt, ...);
void netlog_prefix(int log_level, struct buff *bf);
void netlog_buf(const char *msg, const char *buf, size_t len);
void netlog_flush(void);
void netlog_print_esc(const char *msg, const char *str, size_t len);
void netlog_print_bin(const char *msg, const char *str, size_t len);
#endif
