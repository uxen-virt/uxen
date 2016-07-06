/* $Id: dir-win.cpp $ */
/** @file
 * IPRT - Directory, win32.
 */

/*
 * Copyright (C) 2006-2007 Oracle Corporation
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
#include <windows.h>
#include <io.h>

#include <iprt/dir.h>
#include <iprt/path.h>
#include <iprt/alloc.h>
#include <iprt/string.h>
#include <iprt/assert.h>
#include <iprt/param.h>
#include <iprt/err.h>
#include <iprt/file.h>
#include <iprt/log.h>
#include "internal/fs.h"
#include "internal/path.h"
#include "internal/dir.h"
#include "rt/rt.h"


RTDECL(int) RTDirCreateUcs(const wchar_t *pszPath, RTFMODE fMode, uint32_t fCreate)
{
    /*
     * Validate the file mode.
     */
    int rc = VINF_SUCCESS;
    // FIXME - is pszpath really needed
    fMode = rtFsModeNormalize(fMode, "", 0);
    if (rtFsModeIsValidPermissions(fMode))
    {
        if (RT_SUCCESS(rc))
        {
            /*
             * Create the directory.
             */
            if (CreateDirectoryW((LPCWSTR)pszPath, NULL))
                rc = VINF_SUCCESS;
            else
                rc = RTErrConvertFromWin32(GetLastError());

            /*
             * Turn off indexing of directory through Windows Indexing Service
             */
            if (RT_SUCCESS(rc))
            {
                if (SetFileAttributesW((LPCWSTR)pszPath, FILE_ATTRIBUTE_NOT_CONTENT_INDEXED))
                    rc = VINF_SUCCESS;
                else
                    rc = RTErrConvertFromWin32(GetLastError());
            }

        }
    }
    else
    {
        AssertMsgFailed(("Invalid file mode! %RTfmode\n", fMode));
        rc = VERR_INVALID_FMODE;
    }

    LogFlow(("RTDirCreate(%p:{%ls}, %RTfmode): returns 0x%x\n", pszPath, pszPath, fMode, rc));
    return rc;
}


RTDECL(int) RTDirRemoveUcs(const wchar_t *pszPath)
{
    int rc;
    if (RemoveDirectoryW((LPCWSTR)pszPath))
        rc = VINF_SUCCESS;
    else
        rc = RTErrConvertFromWin32(GetLastError());
    LogFlow(("RTDirRemove(%p:{%ls}): returns 0x%x\n", pszPath, pszPath, rc));
    return rc;
}


RTDECL(int) RTDirFlush(const char *pszPath)
{
    return VERR_NOT_SUPPORTED;
}


int rtDirNativeOpenUcs(PRTDIR pDir, wchar_t *pszPathBuf)
{
    wchar_t tmpbuf[RTPATH_MAX];
    int i;
    int rc = VINF_SUCCESS;
    int len;

    if (wcslen(pszPathBuf) + 2 >= RTPATH_MAX)
        return VERR_NO_MEMORY;
    wcscpy(tmpbuf, pszPathBuf);
    for (i = wcslen(tmpbuf) - 1; i >= 0; i--) {
        if (tmpbuf[i] == '/' || tmpbuf[i] == '\\')
            tmpbuf[i] = 0;
        else
            break;
    }

    /* FindFirstFileW(rootdir/.) returns the real rootdir name.
    Disallow it. */
    len = wcslen(tmpbuf);
    if (tmpbuf[len - 1] == '.' && (tmpbuf[len - 2] == '\\' || tmpbuf[len - 2] == '/'))
        return VERR_INVALID_PARAMETER;

    /*
     * Attempt opening the search.
     */
    {
        pDir->hDir    = FindFirstFileW(tmpbuf, &pDir->Data);
        if (pDir->hDir != INVALID_HANDLE_VALUE)
            pDir->fDataUnread = true;
        /* theoretical case of an empty directory. */
        else if (GetLastError() == ERROR_NO_MORE_FILES)
            pDir->fDataUnread = false;
        else
            rc = RTErrConvertFromWin32(GetLastError());
    }

    return rc;
}


RTDECL(int) RTDirClose(PRTDIR pDir)
{
    /*
     * Validate input.
     */
    if (!pDir)
        return VERR_INVALID_PARAMETER;
    if (pDir->u32Magic != RTDIR_MAGIC)
    {
        AssertMsgFailed(("Invalid pDir=%p\n", pDir));
        return VERR_INVALID_PARAMETER;
    }

    /*
     * Close the handle.
     */
    pDir->u32Magic++;
    if (pDir->hDir != INVALID_HANDLE_VALUE)
    {
        BOOL fRc = FindClose(pDir->hDir);
        Assert(fRc);
        pDir->hDir = INVALID_HANDLE_VALUE;
    }
    if (pDir->pwszName)
        RTMemFree(pDir->pwszName);
    pDir->pwszName = NULL;
    if (pDir->pwszPath)
        RTMemFree(pDir->pwszPath);
    pDir->pwszPath = NULL;
    RTMemFree(pDir);

    return VINF_SUCCESS;
}

RTDECL(int) RTDirReadExUcs(PRTDIR pDir, PRTDIRENTRYEX pDirEntry, size_t *pcbDirEntry, RTFSOBJATTRADD enmAdditionalAttribs, uint32_t fFlags)
{
    /** @todo Symlinks: Find[First|Next]FileW will return info about
        the link, so RTPATH_F_FOLLOW_LINK is not handled correctly. */
    /*
     * Validate input.
     */
    if (!pDir || pDir->u32Magic != RTDIR_MAGIC)
    {
        AssertMsgFailed(("Invalid pDir=%p\n", pDir));
        return VERR_INVALID_PARAMETER;
    }
    if (!pDirEntry)
    {
        AssertMsgFailed(("Invalid pDirEntry=%p\n", pDirEntry));
        return VERR_INVALID_PARAMETER;
    }
    if (    enmAdditionalAttribs < RTFSOBJATTRADD_NOTHING
        ||  enmAdditionalAttribs > RTFSOBJATTRADD_LAST)
    {
        AssertMsgFailed(("Invalid enmAdditionalAttribs=%p\n", enmAdditionalAttribs));
        return VERR_INVALID_PARAMETER;
    }
    AssertMsgReturn(RTPATH_F_IS_VALID(fFlags, 0), ("%#x\n", fFlags), VERR_INVALID_PARAMETER);
    size_t cbDirEntry = sizeof(*pDirEntry);
    if (pcbDirEntry)
    {
        cbDirEntry = *pcbDirEntry;
        if (cbDirEntry < RT_UOFFSETOF(RTDIRENTRYEX, szName[2]))
        {
            AssertMsgFailed(("Invalid *pcbDirEntry=%d (min %d)\n", *pcbDirEntry, RT_OFFSETOF(RTDIRENTRYEX, szName[2])));
            return VERR_INVALID_PARAMETER;
        }
    }

    /*
     * Fetch data?
     */
    if (!pDir->fDataUnread)
    {
        if (pDir->pwszName)
            RTMemFree(pDir->pwszName);
        pDir->pwszName = NULL;

        BOOL fRc = FindNextFileW(pDir->hDir, &pDir->Data);
        if (!fRc)
        {
            int iErr = GetLastError();
            if (pDir->hDir == INVALID_HANDLE_VALUE || iErr == ERROR_NO_MORE_FILES)
                return VERR_NO_MORE_FILES;
            return RTErrConvertFromWin32(iErr);
        }
    }

    /*
     * Convert the filename to UTF-8.
     */
    if (!pDir->pwszName)
    {
        pDir->pwszName = RTwcsdup(pDir->Data.cFileName);
        if (!pDir->pwszName) {
            return VERR_NO_MEMORY;
        }
        pDir->cchName = wcslen(pDir->pwszName);
    }

    /*
     * Check if we've got enough space to return the data.
     */
    const wchar_t  *pszName    = pDir->pwszName;
    const size_t cchName    = 2 * pDir->cchName;
    const size_t cbRequired = RT_OFFSETOF(RTDIRENTRYEX, szName[1]) + cchName;
    if (pcbDirEntry)
        *pcbDirEntry = cbRequired;
    if (cbRequired > cbDirEntry)
        return VERR_BUFFER_OVERFLOW;

    /*
     * Setup the returned data.
     */
    pDir->fDataUnread  = false;
    pDirEntry->cbName  = (uint16_t)cchName;
    Assert(pDirEntry->cbName == cchName);
    memcpy(pDirEntry->szName, pszName, cchName + 2);
    if (pDir->Data.cAlternateFileName[0])
    {
        /* copy and calc length */
        PCRTUTF16 pwszSrc = (PCRTUTF16)pDir->Data.cAlternateFileName;
        PRTUTF16  pwszDst = pDirEntry->wszShortName;
        uint32_t  off = 0;
        while (pwszSrc[off] && off < RT_ELEMENTS(pDirEntry->wszShortName) - 1U)
        {
            pwszDst[off] = pwszSrc[off];
            off++;
        }
        pDirEntry->cwcShortName = (uint16_t)off;

        /* zero the rest */
        do
            pwszDst[off++] = '\0';
        while (off < RT_ELEMENTS(pDirEntry->wszShortName));
    }
    else
    {
        memset(pDirEntry->wszShortName, 0, sizeof(pDirEntry->wszShortName));
        pDirEntry->cwcShortName = 0;
    }

    pDirEntry->Info.cbObject    = ((uint64_t)pDir->Data.nFileSizeHigh << 32)
                                |  (uint64_t)pDir->Data.nFileSizeLow;
    pDirEntry->Info.cbAllocated = pDirEntry->Info.cbObject;

    Assert(sizeof(uint64_t) == sizeof(pDir->Data.ftCreationTime));
    RTTimeSpecSetNtTime(&pDirEntry->Info.BirthTime,         *(uint64_t *)&pDir->Data.ftCreationTime);
    RTTimeSpecSetNtTime(&pDirEntry->Info.AccessTime,        *(uint64_t *)&pDir->Data.ftLastAccessTime);
    RTTimeSpecSetNtTime(&pDirEntry->Info.ModificationTime,  *(uint64_t *)&pDir->Data.ftLastWriteTime);
    pDirEntry->Info.ChangeTime  = pDirEntry->Info.ModificationTime;

    pDirEntry->Info.Attr.fMode  = rtFsModeFromDos((pDir->Data.dwFileAttributes << RTFS_DOS_SHIFT) & RTFS_DOS_MASK_NT,
                                                   "", 0);
// usual rtFsModeFromDos warning

    /*
     * Requested attributes (we cannot provide anything actually).
     */
    switch (enmAdditionalAttribs)
    {
        case RTFSOBJATTRADD_EASIZE:
            pDirEntry->Info.Attr.enmAdditional          = RTFSOBJATTRADD_EASIZE;
            pDirEntry->Info.Attr.u.EASize.cb            = 0;
            break;

        case RTFSOBJATTRADD_UNIX:
            pDirEntry->Info.Attr.enmAdditional          = RTFSOBJATTRADD_UNIX;
            pDirEntry->Info.Attr.u.Unix.uid             = ~0U;
            pDirEntry->Info.Attr.u.Unix.gid             = ~0U;
            pDirEntry->Info.Attr.u.Unix.cHardlinks      = 1;
            pDirEntry->Info.Attr.u.Unix.INodeIdDevice   = 0; /** @todo Use the volume serial number (see GetFileInformationByHandle). */
            pDirEntry->Info.Attr.u.Unix.INodeId         = 0; /** @todo Use the fileid (see GetFileInformationByHandle). */
            pDirEntry->Info.Attr.u.Unix.fFlags          = 0;
            pDirEntry->Info.Attr.u.Unix.GenerationId    = 0;
            pDirEntry->Info.Attr.u.Unix.Device          = 0;
            break;

        case RTFSOBJATTRADD_NOTHING:
            pDirEntry->Info.Attr.enmAdditional          = RTFSOBJATTRADD_NOTHING;
            break;

        case RTFSOBJATTRADD_UNIX_OWNER:
            pDirEntry->Info.Attr.enmAdditional          = RTFSOBJATTRADD_UNIX_OWNER;
            pDirEntry->Info.Attr.u.UnixOwner.uid        = ~0U;
            pDirEntry->Info.Attr.u.UnixOwner.szName[0]  = '\0'; /** @todo return something sensible here. */
            break;

        case RTFSOBJATTRADD_UNIX_GROUP:
            pDirEntry->Info.Attr.enmAdditional          = RTFSOBJATTRADD_UNIX_GROUP;
            pDirEntry->Info.Attr.u.UnixGroup.gid        = ~0U;
            pDirEntry->Info.Attr.u.UnixGroup.szName[0]  = '\0';
            break;

        default:
            AssertMsgFailed(("Impossible!\n"));
            return VERR_INTERNAL_ERROR;
    }

    return VINF_SUCCESS;
}


RTDECL(int) RTDirRenameUcs(const wchar_t *pszSrc, const wchar_t *pszDst, unsigned fRename)
{
    /*
     * Validate input.
     */
    AssertMsgReturn(VALID_PTR(pszSrc), ("%p\n", pszSrc), VERR_INVALID_POINTER);
    AssertMsgReturn(VALID_PTR(pszDst), ("%p\n", pszDst), VERR_INVALID_POINTER);
    AssertMsgReturn(*pszSrc, ("%p\n", pszSrc), VERR_INVALID_PARAMETER);
    AssertMsgReturn(*pszDst, ("%p\n", pszDst), VERR_INVALID_PARAMETER);
    AssertMsgReturn(!(fRename & ~RTPATHRENAME_FLAGS_REPLACE), ("%#x\n", fRename), VERR_INVALID_PARAMETER);

    /*
     * Call the worker.
     */
    int rc = rtPathWin32MoveRenameUcs(pszSrc, pszDst,
                                   fRename & RTPATHRENAME_FLAGS_REPLACE ? MOVEFILE_REPLACE_EXISTING : 0,
                                   RTFS_TYPE_DIRECTORY);

    LogFlow(("RTDirRename(%p:{%ls}, %p:{%ls}, %#x): returns 0x%x\n", pszSrc, pszSrc, pszDst, pszDst, fRename, rc));
    return rc;
}

