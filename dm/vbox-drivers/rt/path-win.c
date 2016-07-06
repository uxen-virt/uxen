/* $Id: path-win.cpp $ */
/** @file
 * IPRT - Path manipulation.
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
#define LOG_GROUP RTLOGGROUP_PATH
#include <windows.h>
#include <shlobj.h>

#include <iprt/path.h>
#include <iprt/assert.h>
#include <iprt/string.h>
#include <iprt/time.h>
#include <iprt/mem.h>
#include <iprt/param.h>
#include <iprt/log.h>
#include <iprt/err.h>
#include "internal/path.h"
#include "internal/fs.h"

/* Needed for lazy loading SHGetFolderPathW in RTPathUserDocuments(). */
typedef HRESULT FNSHGETFOLDERPATHW(HWND, int, HANDLE, DWORD, LPWSTR);
typedef FNSHGETFOLDERPATHW *PFNSHGETFOLDERPATHW;


RTR3DECL(int) RTPathQueryInfoExUcs(const wchar_t *pwszPath, PRTFSOBJINFO pObjInfo, RTFSOBJATTRADD enmAdditionalAttribs, uint32_t fFlags)
{
    /*
     * Validate input.
     */
    int rc;

    AssertPtrReturn(pwszPath, VERR_INVALID_POINTER);
    AssertReturn(*pwszPath, VERR_INVALID_PARAMETER);
    AssertPtrReturn(pObjInfo, VERR_INVALID_POINTER);
    AssertMsgReturn(    enmAdditionalAttribs >= RTFSOBJATTRADD_NOTHING
                    &&  enmAdditionalAttribs <= RTFSOBJATTRADD_LAST,
                    ("Invalid enmAdditionalAttribs=%p\n", enmAdditionalAttribs),
                    VERR_INVALID_PARAMETER);
    AssertMsgReturn(RTPATH_F_IS_VALID(fFlags, 0), ("%#x\n", fFlags), VERR_INVALID_PARAMETER);

    /*
     * Query file info.
     */
    WIN32_FILE_ATTRIBUTE_DATA Data;
    if (!GetFileAttributesExW(pwszPath, GetFileExInfoStandard, &Data))
    {
        /* Fallback to FindFileFirst in case of sharing violation. */
        if (GetLastError() == ERROR_SHARING_VIOLATION)
        {
            WIN32_FIND_DATAW FindData;
            HANDLE hDir = FindFirstFileW(pwszPath, &FindData);
            if (hDir == INVALID_HANDLE_VALUE)
            {
                rc = RTErrConvertFromWin32(GetLastError());
                return rc;
            }
            FindClose(hDir);

            Data.dwFileAttributes   = FindData.dwFileAttributes;
            Data.ftCreationTime     = FindData.ftCreationTime;
            Data.ftLastAccessTime   = FindData.ftLastAccessTime;
            Data.ftLastWriteTime    = FindData.ftLastWriteTime;
            Data.nFileSizeHigh      = FindData.nFileSizeHigh;
            Data.nFileSizeLow       = FindData.nFileSizeLow;
        }
        else
        {
            rc = RTErrConvertFromWin32(GetLastError());
            return rc;
        }
    }

    /*
     * Getting the information for the link target is a bit annoying and
     * subject to the same access violation mess as above.. :/
     */
    /** @todo we're too lazy wrt to error paths here... */
    if (   (fFlags & RTPATH_F_FOLLOW_LINK)
        && (Data.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT))
    {
        HANDLE hFinal = CreateFileW(pwszPath,
                                    GENERIC_READ,
                                    FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                                    NULL,
                                    OPEN_EXISTING,
                                    FILE_FLAG_BACKUP_SEMANTICS,
                                    NULL);
        if (hFinal != INVALID_HANDLE_VALUE)
        {
            BY_HANDLE_FILE_INFORMATION FileData;
            if (GetFileInformationByHandle(hFinal, &FileData))
            {
                Data.dwFileAttributes   = FileData.dwFileAttributes;
                Data.ftCreationTime     = FileData.ftCreationTime;
                Data.ftLastAccessTime   = FileData.ftLastAccessTime;
                Data.ftLastWriteTime    = FileData.ftLastWriteTime;
                Data.nFileSizeHigh      = FileData.nFileSizeHigh;
                Data.nFileSizeLow       = FileData.nFileSizeLow;
            }
            CloseHandle(hFinal);
        }
        else if (GetLastError() != ERROR_SHARING_VIOLATION)
        {
            rc = RTErrConvertFromWin32(GetLastError());
            return rc;
        }
    }


    /*
     * Setup the returned data.
     */
    pObjInfo->cbObject    = ((uint64_t)Data.nFileSizeHigh << 32)
                          |  (uint64_t)Data.nFileSizeLow;
    pObjInfo->cbAllocated = pObjInfo->cbObject;

    Assert(sizeof(uint64_t) == sizeof(Data.ftCreationTime));
    RTTimeSpecSetNtTime(&pObjInfo->BirthTime,         *(uint64_t *)&Data.ftCreationTime);
    RTTimeSpecSetNtTime(&pObjInfo->AccessTime,        *(uint64_t *)&Data.ftLastAccessTime);
    RTTimeSpecSetNtTime(&pObjInfo->ModificationTime,  *(uint64_t *)&Data.ftLastWriteTime);
    pObjInfo->ChangeTime  = pObjInfo->ModificationTime;
/* FIXME - do we need to pass real path here */
    pObjInfo->Attr.fMode  = rtFsModeFromDos((Data.dwFileAttributes << RTFS_DOS_SHIFT) & RTFS_DOS_MASK_NT,
//                                            pszPath, strlen(pszPath));
                                              "", 0);

    /*
     * Requested attributes (we cannot provide anything actually).
     */
    switch (enmAdditionalAttribs)
    {
        case RTFSOBJATTRADD_NOTHING:
            pObjInfo->Attr.enmAdditional          = RTFSOBJATTRADD_NOTHING;
            break;

        case RTFSOBJATTRADD_UNIX:
            pObjInfo->Attr.enmAdditional          = RTFSOBJATTRADD_UNIX;
            pObjInfo->Attr.u.Unix.uid             = ~0U;
            pObjInfo->Attr.u.Unix.gid             = ~0U;
            pObjInfo->Attr.u.Unix.cHardlinks      = 1;
            pObjInfo->Attr.u.Unix.INodeIdDevice   = 0; /** @todo use volume serial number */
            pObjInfo->Attr.u.Unix.INodeId         = 0; /** @todo use fileid (see GetFileInformationByHandle). */
            pObjInfo->Attr.u.Unix.fFlags          = 0;
            pObjInfo->Attr.u.Unix.GenerationId    = 0;
            pObjInfo->Attr.u.Unix.Device          = 0;
            break;

        case RTFSOBJATTRADD_UNIX_OWNER:
            pObjInfo->Attr.enmAdditional          = RTFSOBJATTRADD_UNIX_OWNER;
            pObjInfo->Attr.u.UnixOwner.uid        = ~0U;
            pObjInfo->Attr.u.UnixOwner.szName[0]  = '\0'; /** @todo return something sensible here. */
            break;

        case RTFSOBJATTRADD_UNIX_GROUP:
            pObjInfo->Attr.enmAdditional          = RTFSOBJATTRADD_UNIX_GROUP;
            pObjInfo->Attr.u.UnixGroup.gid        = ~0U;
            pObjInfo->Attr.u.UnixGroup.szName[0]  = '\0';
            break;

        case RTFSOBJATTRADD_EASIZE:
            pObjInfo->Attr.enmAdditional          = RTFSOBJATTRADD_EASIZE;
            pObjInfo->Attr.u.EASize.cb            = 0;
            break;

        default:
            AssertMsgFailed(("Impossible!\n"));
            return VERR_INTERNAL_ERROR;
    }

    return VINF_SUCCESS;
}


/**
 * Internal worker for RTFileRename and RTFileMove.
 *
 * @returns iprt status code.
 * @param   pszSrc      The source filename.
 * @param   pszDst      The destination filename.
 * @param   fFlags      The windows MoveFileEx flags.
 * @param   fFileType   The filetype. We use the RTFMODE filetypes here. If it's 0,
 *                      anything goes. If it's RTFS_TYPE_DIRECTORY we'll check that the
 *                      source is a directory. If Its RTFS_TYPE_FILE we'll check that it's
 *                      not a directory (we are NOT checking whether it's a file).
 */
DECLHIDDEN(int) rtPathWin32MoveRenameUcs(const wchar_t *pwszSrc, const wchar_t *pwszDst, uint32_t fFlags, RTFMODE fFileType)
{
    int rc = VINF_SUCCESS;
            /*
             * Check object type if requested.
             * This is open to race conditions.
             */
            if (fFileType)
            {
                DWORD dwAttr = GetFileAttributesW(pwszSrc);
                if (dwAttr == INVALID_FILE_ATTRIBUTES)
                    rc = RTErrConvertFromWin32(GetLastError());
                else if (RTFS_IS_DIRECTORY(fFileType))
                    rc = dwAttr & FILE_ATTRIBUTE_DIRECTORY ? VINF_SUCCESS : VERR_NOT_A_DIRECTORY;
                else
                    rc = dwAttr & FILE_ATTRIBUTE_DIRECTORY ? VERR_IS_A_DIRECTORY : VINF_SUCCESS;
            }
            if (RT_SUCCESS(rc))
            {
                if (MoveFileExW(pwszSrc, pwszDst, fFlags))
                    rc = VINF_SUCCESS;
                else
                {
                    DWORD Err = GetLastError();
                    rc = RTErrConvertFromWin32(Err);
                    Log(("MoveFileExW('%ls', '%ls', %#x, %RTfmode): fails with rc=0x%x & lasterr=%d\n",
                         pwszSrc, pwszDst, fFlags, fFileType, rc, Err));
                }
            }
    return rc;
}


