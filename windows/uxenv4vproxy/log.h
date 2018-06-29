/*
 * Copyright 2018, Bromium, Inc.
 * Author: Tomasz Wroblewski <tomasz.wroblewski@gmail.com>
 * SPDX-License-Identifier: ISC
 */

#ifndef LOG_H_
#define LOG_H_

#define LOG_ERROR 0
#define LOG_WARNING 1
#define LOG_INFO 2
#define LOG_NOTICE 3
#define LOG_VERBOSE 4

extern void (*proxy_logger)(int lvl, const char *);

#define proxy_KdPrintEx(id, l, fmt, ...) do {                        \
        DbgPrintEx(id, (l) >= LOG_VERBOSE ? DPFLTR_INFO_LEVEL :      \
                   ((l) >= LOG_INFO ? DPFLTR_TRACE_LEVEL :           \
                    ((l) >= LOG_WARNING ? DPFLTR_WARNING_LEVEL :     \
                     DPFLTR_ERROR_LEVEL)), fmt, ##__VA_ARGS__);         \
    } while (0)

#define _proxy_log(lvl, fmt, ...) {                                     \
        if (proxy_logger) {                                             \
            char buf[320];                                              \
            RtlStringCbPrintfA(buf, sizeof(buf), fmt, ##__VA_ARGS__);   \
            proxy_logger(lvl, buf);                                     \
        } else                                                          \
            proxy_KdPrintEx(DPFLTR_DEFAULT_ID, lvl, fmt, ##__VA_ARGS__); \
    }                                                                   \

#define proxy_log(lvl, fmt, ...)                                  \
    _proxy_log(lvl, "uxenv4vproxy: %s:%d: " fmt "\n",             \
        __FUNCTION__, __LINE__, ##__VA_ARGS__)

// ---------------
//#define DBG
// ---------------

#ifdef DBG
#define VERBOSE(fmt, ...) proxy_log(LOG_ERROR, fmt, ##__VA_ARGS__)
#else
#define VERBOSE(...)
#endif

#define INFO(fmt, ...) proxy_log(LOG_INFO, fmt, ##__VA_ARGS__)
#define ERROR(fmt, ...) proxy_log(LOG_ERROR, fmt, ##__VA_ARGS__)

#endif
