/*
 *  uxen_debug.c
 *  uxen
 *
 * Copyright 2011-2017, Bromium, Inc.
 * Author: Christian Limpach <Christian.Limpach@gmail.com>
 * SPDX-License-Identifier: ISC
 * 
 */

#include <stdarg.h>

#include "uxen.h"

#include <ntstrsafe.h>
#include <winerror.h>

#ifdef DBG
int kdbgprint = 1;
#else
int kdbgprint = 0;
#endif
int kdbgprintvm = 0;

uint32_t crash_on = 0;

int
uxen_vprintk(struct vm_info_shared *vmi, const char *fmt, va_list ap)
{
    int ret;

    ret = uxen_op_logging_vprintk(vmi, fmt, ap);

    if (!kdbgprint)
	return 0;
    if (!kdbgprintvm && ret)
        return 0;
    return vDbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, fmt, ap);
}

#ifdef UXEN_DPRINTK
uint64_t __cdecl
uxen_dprintk(struct vm_info_shared *vmi, const char *fmt, ...)
{
    va_list ap;
    int ret;

    va_start(ap, fmt);
    ret = uxen_vprintk(vmi, fmt, ap);
    va_end(ap);

    return ret;
}
#else
uint64_t __cdecl
uxen_dprintk(struct vm_info_shared *vmi, const char *fmt, ...)
{
    return 0;
}
#endif

uint64_t __cdecl
uxen_printk(struct vm_info_shared *vmi, const char *fmt, ...)
{
    va_list ap;
    int ret;

    va_start(ap, fmt);
    ret = uxen_vprintk(vmi, fmt, ap);
    va_end(ap);

    return ret;
}

#define TIMESTAMP_FMT "%04d/%02d/%02d-%02d:%02d:%02d: %s"
#define TIMESTAMP_size (4 + 1 + 2 + 1 + 2 + 1 + 2 + 1 + 2 + 1 + 2 + 2)

uint64_t __cdecl
uxen_printk_with_timestamp(struct vm_info_shared *vmi, const char *_fmt, ...)
{
    char *fmt = _alloca(TIMESTAMP_size + strlen(_fmt) + 1);
    TIME_FIELDS tf;
    LARGE_INTEGER now, now_local;
    NTSTATUS res;
    va_list ap;
    int ret;

    KeQuerySystemTime(&now);
    ExSystemTimeToLocalTime(&now, &now_local);
    RtlTimeToTimeFields(&now_local, &tf);

    res = RtlStringCbPrintfA(fmt, TIMESTAMP_size + strlen(_fmt) + 1,
                             TIMESTAMP_FMT, tf.Year, tf.Month, tf.Day,
                             tf.Hour, tf.Minute, tf.Second, _fmt);
    if (!SUCCEEDED(res))
        memcpy(fmt, _fmt, strlen(_fmt) + 1);

    va_start(ap, _fmt);
    ret = uxen_vprintk(vmi, fmt, ap);
    va_end(ap);

    return ret;
}

#if defined(__x86_64__)
void kdbgrebootsup(void);
#else
void
_ud2(void)
{
    __asm {
	ud2;
    }
}
#endif

int kdbgdoreboot = 0;
void
kdbgreboot(void)
{
    KeSetSystemAffinityThread(1 << 0);
#if defined(__x86_64__)
    kdbgrebootsup();
#else
    __asm {
	/* VMXOFF */
	_emit 0x0f;
	_emit 0x01;
	_emit 0xc4;
	push 0xffffffff;
	push 0xffff0000;
	lidt [esp];
	ud2;
    }
    _ud2();
#endif
}
