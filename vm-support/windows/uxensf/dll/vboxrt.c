/*
 * Copyright 2013-2015, Bromium, Inc.
 * SPDX-License-Identifier: ISC
 */

#include <windows.h>
#include <iprt/err.h>
#include <iprt/log.h>
#include <stdio.h>
#include <stdarg.h>

void RTLogLoggerEx(PRTLOGGER pLogger, unsigned fFlags, unsigned iGroup,
const char *pszFormat, ...)
{
    char buf[2048];
    va_list args;
    va_start(args, pszFormat);
    _vsnprintf(buf, sizeof(buf), pszFormat, args);
    buf[sizeof(buf)-1] = 0;
    OutputDebugStringA(buf);
    va_end(args);
}

PRTLOGGER   RTLogRelDefaultInstance(void)
{
    return NULL;
}

void RTR3InitDll(void)
{
}

