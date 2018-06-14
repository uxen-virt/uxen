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

#define proxy_KdPrintEx(id, l, fmt, ...) do {                        \
        DbgPrintEx(id, (l) >= LOG_VERBOSE ? DPFLTR_INFO_LEVEL :      \
                   ((l) >= LOG_INFO ? DPFLTR_TRACE_LEVEL :           \
                    ((l) >= LOG_WARNING ? DPFLTR_WARNING_LEVEL :     \
                     DPFLTR_ERROR_LEVEL)), fmt, ##__VA_ARGS__);         \
    } while (0)

#define proxy_log(lvl, fmt, ...)                                        \
    proxy_KdPrintEx(DPFLTR_DEFAULT_ID, lvl, "uxenv4vproxy: %s:%d: " fmt "\n", \
        __FUNCTION__, __LINE__, ##__VA_ARGS__)


// ---------------
//#define DBG
// ---------------

#ifdef DBG
#define VERBOSE(fmt, ...) proxy_log(LOG_ERROR, fmt, ##__VA_ARGS__)
#define INFO(fmt, ...) proxy_log(LOG_ERROR, fmt, ##__VA_ARGS__)
#else
#define VERBOSE(...)
#define INFO(...)
#endif

#define ERROR(fmt, ...) proxy_log(LOG_ERROR, fmt, ##__VA_ARGS__)

#endif
