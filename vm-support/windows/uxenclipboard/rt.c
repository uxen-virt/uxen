/*
 * Copyright 2013-2015, Bromium, Inc.
 * SPDX-License-Identifier: ISC
 */

#include <iprt/log.h>
#include <malloc.h>
#include <stdio.h>
#include <windows.h>

void RTLogLoggerEx(PRTLOGGER pLogger, unsigned fFlags, unsigned iGroup,
    const char *pszFormat, ...)
{
        va_list args;
        char buf[2048];
        va_start(args, pszFormat);
        _vsnprintf(buf, sizeof(buf), pszFormat, args);
        buf[sizeof(buf) - 1] = 0;
        OutputDebugString(buf);
        va_end(args);
}

PRTLOGGER RTLogRelDefaultInstance(void)
{
        return NULL;
}

void * RTMemAllocTag(size_t cb, const char *pszTag)
{
    return malloc(cb);
}

void * RTMemAllocZTag(size_t cb, const char *pszTag)
{
    return calloc(1, cb);
}

