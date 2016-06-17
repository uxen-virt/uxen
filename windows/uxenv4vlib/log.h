/*
 * Copyright 2016, Bromium, Inc.
 * SPDX-License-Identifier: ISC
 */

#ifndef __UXENV4VLIB_LOG_H__
#define __UXENV4VLIB_LOG_H__

extern uxen_v4v_logger_t uxen_v4v_logger;

#if DBG
/* KdPrint((fmt, ##__VA_ARGS__)) doesn't work if __VA_ARGS__ is empty,
 * also translate verbosity levels */
#define uxen_v4v_KdPrintEx(id, l, fmt, ...) do {                        \
        DbgPrintEx(id, (l) >= V4VLOG_VERBOSE ? DPFLTR_INFO_LEVEL :      \
                   ((l) >= V4VLOG_INFO ? DPFLTR_TRACE_LEVEL :           \
                    ((l) >= V4VLOG_WARNING ? DPFLTR_WARNING_LEVEL :     \
                     DPFLTR_ERROR_LEVEL)), fmt, ##__VA_ARGS__);         \
    } while (0)
#else
#define uxen_v4v_KdPrintEx(id, l, fmt, ...)
#endif

#define uxen_v4v_log(lvl, fmt, ...) {                                   \
        if (uxen_v4v_logger) {                                          \
            char buf[320];                                              \
            RtlStringCbPrintfA(buf, sizeof(buf), fmt, ##__VA_ARGS__);   \
            uxen_v4v_logger(lvl, buf);                                  \
        } else                                                          \
            uxen_v4v_KdPrintEx(DPFLTR_DEFAULT_ID, lvl, fmt, ##__VA_ARGS__); \
    }                                                                   \

#define _Trace(lvl, fmt, ...)                           \
    uxen_v4v_log(lvl, "uxenv4vlib: %s:%d: " fmt,        \
                 __FUNCTION__, __LINE__, ##__VA_ARGS__)

#define _TraceVerbose(fmt, ...) _Trace(V4VLOG_VERBOSE, fmt, ##__VA_ARGS__)
#define _TraceNotice(fmt, ...)  _Trace(V4VLOG_NOTICE, fmt, ##__VA_ARGS__)
#define _TraceInfo(fmt, ...)    _Trace(V4VLOG_INFO, fmt, ##__VA_ARGS__)
#define _TraceWarning(fmt, ...) _Trace(V4VLOG_WARNING, fmt, ##__VA_ARGS__)
#define _TraceError(fmt, ...)   _Trace(V4VLOG_ERROR, fmt, ##__VA_ARGS__)

//#define TraceVerbose(a) do { _TraceVerbose a; } while (0)
//#define TraceNotice(a) do { _TraceNotice a; } while (0)
//#define TraceInfo(a) do { _TraceInfo a; } while (0)
#define TraceVerbose(a)
#define TraceNotice(a)
#define TraceInfo(a)
#define TraceWarning(a) do { _TraceWarning a; } while (0)
#define TraceError(a) do { _TraceError a; } while (0)

#endif  /* __UXENV4VLIB_LOG_H__ */
