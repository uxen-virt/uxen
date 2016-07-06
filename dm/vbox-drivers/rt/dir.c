/* $Id: dir.cpp $ */
/** @file
 * IPRT - Directory Manipulation, Part 1.
 */

/*
 * Copyright (C) 2006-2010 Oracle Corporation
 *
 * This file is part of VirtualBox Open Source Edition (OSE), as
 * available from http://www.virtualbox.org. This file is free software;
 * you can redistribute it and/or modify it under the terms of the GNU
 * General Public License (GPL) as published by the Free Software
 * Foundation, in version 2 as it comes in the "COPYING" file of the
 * VirtualBox OSE distribution. VirtualBox OSE is distributed in the
 * hope that it will be useful, but WITHOUT ANY WARRANTY of any kind.
 *
 * The contents of this file may alternatively be used under the terms
 * of the Common Development and Distribution License Version 1.0
 * (CDDL) only, as it comes in the "COPYING.CDDL" file of the
 * VirtualBox OSE distribution, in which case the provisions of the
 * CDDL are applicable instead of those of the GPL.
 *
 * You may elect to license modified versions of this file under the
 * terms and conditions of either the GPL or the CDDL or both.
 */


/*******************************************************************************
*   Header Files                                                               *
*******************************************************************************/
#include <dm/config.h>
#define LOG_GROUP RTLOGGROUP_DIR
#ifdef RT_OS_WINDOWS /* PORTME: Assumes everyone else is using dir-posix.cpp */
# include <windows.h>
#else
# include <dirent.h>
# include <unistd.h>
# include <limits.h>
#endif

#include <iprt/dir.h>
#include "internal/iprt.h"

#include <iprt/assert.h>
#include <iprt/file.h>
#include <iprt/err.h>
#include <iprt/log.h>
#include <iprt/mem.h>
#include <iprt/param.h>
#include <iprt/path.h>
#include <iprt/string.h>
#include "internal/dir.h"
#include "internal/path.h"
#include "rt/rt.h"

/**
 * Common worker for opening a directory.
 *
 * @returns IPRT status code.
 * @param   ppDir       Where to store the directory handle.
 * @param   pszPath     The specified path.
 * @param   pszFilter   Pointer to where the filter start in the path. NULL if no filter.
 * @param   enmFilter   The type of filter to apply.
 */
static int rtDirOpenCommonUcs(PRTDIR *ppDir, const wchar_t *pszPath, const char *pszFilter, RTDIRFILTER enmFilter)
{
    int rc;
    PRTDIR pDir = (PRTDIR)RTMemAllocZ(sizeof(RTDIR));
    pDir->u32Magic = RTDIR_MAGIC;
    pDir->enmFilter = RTDIRFILTER_NONE;
    rc = rtDirNativeOpenUcs(pDir, (wchar_t *)pszPath);

    if (RT_SUCCESS(rc)) {
        pDir->pwszPath = RTwcsdup((wchar_t *)pszPath);
        *ppDir = pDir;
    }
    else
        RTMemFree(pDir);

    return rc;
}


RTDECL(int) RTDirOpenUcs(PRTDIR *ppDir, const wchar_t *pszPath)
{
    /*
     * Validate input.
     */
    AssertMsgReturn(VALID_PTR(ppDir), ("%p\n", ppDir), VERR_INVALID_POINTER);
    AssertMsgReturn(VALID_PTR(pszPath), ("%p\n", pszPath), VERR_INVALID_POINTER);

    /*
     * Take common cause with RTDirOpenFiltered().
     */
    int rc = rtDirOpenCommonUcs(ppDir, pszPath, NULL,  RTDIRFILTER_NONE);
    LogFlow(("RTDirOpen(%p:{%p}, %p:{%ls}): return 0x%x\n", ppDir, *ppDir, pszPath, pszPath, rc));
    return rc;
}


RTDECL(int) RTDirOpenFilteredUcs(PRTDIR *ppDir, const wchar_t *pszPath, RTDIRFILTER enmFilter, uint32_t fOpen)
{
    /*
     * Validate input.
     */
    AssertMsgReturn(VALID_PTR(ppDir), ("%p\n", ppDir), VERR_INVALID_POINTER);
    AssertMsgReturn(VALID_PTR(pszPath), ("%p\n", pszPath), VERR_INVALID_POINTER);
    switch (enmFilter)
    {
        case RTDIRFILTER_UNIX:
        case RTDIRFILTER_UNIX_UPCASED:
            AssertMsgFailed(("%d is not implemented!\n", enmFilter));
            return VERR_NOT_IMPLEMENTED;
        case RTDIRFILTER_NONE:
        case RTDIRFILTER_WINNT:
            break;
        default:
            AssertMsgFailedReturn(("%d\n", enmFilter), VERR_INVALID_PARAMETER);
    }

    /*
     * Call worker common with RTDirOpen which will verify the path, allocate
     * and initialize the handle, and finally call the backend.
     */
    int rc = rtDirOpenCommonUcs(ppDir, pszPath, NULL, enmFilter);

//    LogFlow(("RTDirOpenFiltered(%p:{%p}, %p:{%ls}, %d): return 0x%x\n",
//             ppDir, *ppDir, pszPath, pszPath, enmFilter, rc));
    return rc;
}



