/*
 * Copyright 2014-2016, Bromium, Inc.
 * Author: Kris Uchronski <kuchronski@gmail.com>
 * SPDX-License-Identifier: ISC
 */

#ifndef _COMMON_DEBUG_H_
#define _COMMON_DEBUG_H_

#include <ntddk.h>
#include <ntstrsafe.h>

#define UXEN_KD_ERR             (1UL << 0)
#define UXEN_KD_MSG             (1UL << 1)
#define UXEN_KD_DBG             (1UL << 2)

#define UXEN_KD_ASSERT          (1UL << 27)
#define UXEN_KD_ASSERT_BREAK    (1UL << 28)
#define UXEN_KD_BREAK_ON_ERR    (1UL << 29)
#define UXEN_KD_USE_IOPORT      (1UL << 30)
#define UXEN_KD_USE_OSPRINTK    (1UL << 31)

extern __declspec(selectany)
ULONG uxen_kd_mask = DEF_UXEN_KD_MASK;

#define UXEN_DEBUG_PORT 0x54

__inline void
_printk(const char *fmt, ...)
{
    size_t n, r;
    char buf[1024], *p;
    va_list args;

    va_start(args, fmt);
    NT_VERIFY(NT_SUCCESS(RtlStringCchVPrintfExA(&buf[0], sizeof(buf),
                                                NULL, &r, 0,
                                                fmt, args)));
    va_end(args);

    p = buf;
    n = sizeof(buf) - r;
    while (n && ((ULONG_PTR)p & 3)) {
        WRITE_PORT_UCHAR((PUCHAR)UXEN_DEBUG_PORT, *p);
        p++;
        n--;
    }
    if (n) {
        while (n > 3) {
            WRITE_PORT_ULONG((PULONG)UXEN_DEBUG_PORT, *(PULONG)p);
            p += 4;
            n -= 4;
        }
        while (n) {
            WRITE_PORT_UCHAR((PUCHAR)UXEN_DEBUG_PORT, *p);
            p++;
            n--;
        }
    }
}

void _printk(const char *fmt, ...);
#define printk(fmt, ...)                                                      \
    _printk("%s!%s:%d: " fmt "\n",                                            \
            __DRV_NAME__, __FUNCTION__, __LINE__, __VA_ARGS__)

#define uxen_err(fmt, ...) do {                                               \
    if (!(uxen_kd_mask & UXEN_KD_ERR))                                        \
        break;                                                                \
    if (uxen_kd_mask & UXEN_KD_USE_IOPORT)                                    \
        printk("error: " fmt, __VA_ARGS__);                                   \
    if (*KdDebuggerEnabled && (uxen_kd_mask & UXEN_KD_USE_OSPRINTK))          \
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,                   \
                   "%s!%s:%d error: " fmt "\n",                               \
                   __DRV_NAME__, __FUNCTION__, __LINE__, __VA_ARGS__);        \
    if (uxen_kd_mask & UXEN_KD_BREAK_ON_ERR)                                  \
        __debugbreak();                                                       \
} while (0, 0)

#define uxen_msg(fmt, ...) do {                                               \
    if (!(uxen_kd_mask & UXEN_KD_MSG))                                        \
        break;                                                                \
    if (uxen_kd_mask & UXEN_KD_USE_IOPORT)                                    \
        printk(fmt, __VA_ARGS__);                                             \
    if (*KdDebuggerEnabled && (uxen_kd_mask & UXEN_KD_USE_OSPRINTK))          \
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,                   \
                   "%s!%s:%d: " fmt "\n",                                     \
                   __DRV_NAME__, __FUNCTION__, __LINE__, __VA_ARGS__);        \
} while (0, 0)

#define uxen_debug(fmt, ...) do {                                             \
    if (!(uxen_kd_mask & UXEN_KD_DBG))                                        \
        break;                                                                \
    if (uxen_kd_mask & UXEN_KD_USE_IOPORT)                                    \
        printk(fmt, __VA_ARGS__);                                             \
    if (*KdDebuggerEnabled && (uxen_kd_mask & UXEN_KD_USE_OSPRINTK))          \
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,                   \
                   "%s!%s:%d: " fmt "\n",                                     \
                   __DRV_NAME__, __FUNCTION__, __LINE__, __VA_ARGS__);        \
} while (0, 0)

#define uxen_printk(lvl, fmt, ...) do {                                       \
    if (!(uxen_kd_mask & lvl))                                                \
        break;                                                                \
    if (uxen_kd_mask & UXEN_KD_USE_IOPORT)                                    \
        _printk(fmt, __VA_ARGS__);                                            \
    if (*KdDebuggerEnabled && (uxen_kd_mask & UXEN_KD_USE_OSPRINTK))          \
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,                   \
                   fmt "\n", __VA_ARGS__);                                    \
} while (0, 0)

#define BUG_ON(condition) do {                                                \
    if (condition) {                                                          \
        uxen_err("BUG_ON(%s)", # condition);                                  \
        KeBugCheckEx(DRIVER_VIOLATION, 0, 0, 0, __LINE__);                    \
    }                                                                         \
} while (0, 0)

#undef ASSERT
#define ASSERT(expr) do {                                                     \
    if (!(uxen_kd_mask & UXEN_KD_ASSERT))                                     \
        break;                                                                \
    if (!(expr)) {                                                            \
        uxen_err("ASSERT(%s) failed", # expr);                                \
        if (uxen_kd_mask & UXEN_KD_ASSERT_BREAK &&                            \
            !(uxen_kd_mask & UXEN_KD_BREAK_ON_ERR))                           \
            __debugbreak();                                                   \
    }                                                                         \
} while (0, 0)

#define ASSERT_FAIL(fmt, ...) do {                                            \
    if (!(uxen_kd_mask & UXEN_KD_ASSERT))                                     \
        break;                                                                \
    uxen_err("ASSERT_FAIL: " fmt, __VA_ARGS__);                               \
    if (uxen_kd_mask & UXEN_KD_ASSERT_BREAK &&                                \
        !(uxen_kd_mask & UXEN_KD_BREAK_ON_ERR))                               \
        __debugbreak();                                                       \
} while (0, 0)

#define ASSERT_IRQL_BE(irql) do {                                             \
    if (uxen_kd_mask & UXEN_KD_ASSERT) {                                      \
        KIRQL curr_irql = KeGetCurrentIrql();                                 \
        if (curr_irql > (irql))                                               \
            ASSERT_FAIL("current IRQL (%d) higher than expected (%d)",        \
                        curr_irql, (irql));                                   \
    }                                                                         \
} while (0, 0)

#define ASSERT_IRQL_E(irql) do {                                              \
    if (uxen_kd_mask & UXEN_KD_ASSERT) {                                      \
        KIRQL curr_irql = KeGetCurrentIrql();                                 \
        if (curr_irql != (irql))                                              \
            ASSERT_FAIL("current IRQL (%d) higher than expected (%d)",        \
                        curr_irql, (irql));                                   \
    }                                                                         \
} while (0, 0)

#define ASSERT_IRQL_GE(irql) do {                                             \
    if (uxen_kd_mask & UXEN_KD_ASSERT) {                                      \
        KIRQL curr_irql = KeGetCurrentIrql();                                 \
        if (curr_irql < (irql))                                               \
            ASSERT_FAIL("current IRQL (%d) higher than expected (%d)",        \
                        curr_irql, (irql));                                   \
    }                                                                         \
} while (0, 0)

#endif 	/* _COMMON_DEBUG_H_ */
