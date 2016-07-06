/*
 * Copyright 2012-2016, Bromium, Inc.
 * SPDX-License-Identifier: ISC
 */

#include <dm/config.h>
#include <os.h>
#include <iprt/alloc.h>
#include <iprt/err.h>
#include <iprt/log.h>
#include <stdio.h>

#include <config.h>
#include <dm.h>
#include <dm/vbox-drivers/heap.h>
#include "../../debug.h"

heap_t hgcm_heap;

wchar_t* RTwcsdup(wchar_t* s)
{
    wchar_t* buf = RTMemAlloc(wcslen(s) * 2 + 2);
    if (!buf)
        return NULL;
    wcscpy(buf, s);
    return buf;
}

RTDECL(void) RTLogLoggerEx(PRTLOGGER pLogger, unsigned fFlags, unsigned iGroup,
const char *pszFormat, ...)
{
    va_list args;
    if (!(guest_drivers_logmask&fFlags))
        return;
    va_start(args, pszFormat);
    debug_vprintf(pszFormat, args);
    va_end(args);
}

RTDECL(PRTLOGGER)   RTLogRelDefaultInstance(void)
{
    return NULL;
}

RTDECL(void *) RTMemAllocTag(size_t cb, const char *pszTag)
{
    return hgcm_malloc(cb);
}
RTDECL(void) RTMemFree(void *pv)
{
    return hgcm_free(pv);
}
RTDECL(void *) RTMemAllocZTag(size_t cb, const char *pszTag)
{
    return hgcm_calloc(1, cb);
}

/* I am not sure why these do not get ifdef-ed out. Somehow RT_STRICT seems
to be defined - perhaps one of DM defines set it.
Perhaps make them really log ? */
RTDECL(void)    RTAssertMsg2Weak(const char *pszFormat, ...)
{
}

RTDECL(void)    RTAssertMsg1Weak(const char *pszExpr, unsigned uLine, const char
    *pszFile, const char *pszFunction)
{
}

RTDECL(bool)    RTAssertShouldPanic(void)
{
    return false;
}

initcall(hgcm_heap_init)
{
    priv_heap_create(&hgcm_heap);
}
