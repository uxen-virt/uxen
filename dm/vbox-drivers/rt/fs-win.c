/* $Id: fs-win.cpp $ */
/** @file
 * IPRT - File System, Win32.
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
/*
 * uXen changes:
 *
 * Copyright 2012-2015, Bromium, Inc.
 * SPDX-License-Identifier: ISC
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
 * SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION
 * OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
 * CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

/*******************************************************************************
*   Header Files                                                               *
*******************************************************************************/
#define LOG_GROUP RTLOGGROUP_FS
#include <windows.h>

#include <iprt/fs.h>
#include <iprt/path.h>
#include <iprt/string.h>
#include <iprt/param.h>
#include <iprt/err.h>
#include <iprt/log.h>
#include <iprt/assert.h>
#include "internal/fs.h"

/* from ntdef.h */
typedef LONG NTSTATUS;

/* from ntddk.h */
typedef struct _IO_STATUS_BLOCK {
    union {
        NTSTATUS Status;
        PVOID Pointer;
    };
    ULONG_PTR Information;
} IO_STATUS_BLOCK, *PIO_STATUS_BLOCK;

typedef enum _FSINFOCLASS {
    FileFsAttributeInformation = 5,
} FS_INFORMATION_CLASS, *PFS_INFORMATION_CLASS;

/* from ntifs.h */

typedef struct _FILE_FS_ATTRIBUTE_INFORMATION {
    ULONG FileSystemAttributes;
    LONG MaximumComponentNameLength;
    ULONG FIleSystemNameLength;
    WCHAR FileSystemName[1];
} FILE_FS_ATTRIBUTE_INFORMATION, *PFILE_FS_ATTRIBUTE_INFORMATION;

NTSTATUS NTAPI NtQueryVolumeInformationFile(HANDLE, PIO_STATUS_BLOCK, PVOID, ULONG, FS_INFORMATION_CLASS);

#define FS_ROOT_LEN 4
static int rtFsGetRoot(const wchar_t* pszFsPath_real, wchar_t* pwszFsRoot)
{
    const wchar_t* pszFsPath;
    if (wcsncmp(pszFsPath_real, L"\\\\?\\", 4))
        pszFsPath = pszFsPath_real;
    else
        pszFsPath = pszFsPath_real + 4;
    if (pszFsPath[1] != ':' || (pszFsPath[2] != '/' && pszFsPath[2] != '\\'))
        return VERR_INVALID_PARAMETER;
    memcpy(pwszFsRoot, pszFsPath, FS_ROOT_LEN*sizeof(wchar_t));
    pwszFsRoot[FS_ROOT_LEN - 1] = 0;
    return VINF_SUCCESS;
}


RTR3DECL(int) RTFsQuerySizesUnc(const wchar_t *pszFsPath, RTFOFF *pcbTotal, RTFOFF *pcbFree,
                             uint32_t *pcbBlock, uint32_t *pcbSector)
{
    /*
     * Validate & get valid root path.
     */
    wchar_t pwszFsRoot[FS_ROOT_LEN];
    AssertMsgReturn(VALID_PTR(pszFsPath) && *pszFsPath, ("%p", pszFsPath), VERR_INVALID_PARAMETER);
    int rc = rtFsGetRoot(pszFsPath, pwszFsRoot);
    if (RT_FAILURE(rc))
        return rc;

    /*
     * Free and total.
     */
    if (pcbTotal || pcbFree)
    {
        ULARGE_INTEGER cbTotal;
        ULARGE_INTEGER cbFree;
        if (GetDiskFreeSpaceExW(pwszFsRoot, &cbFree, &cbTotal, NULL))
        {
            if (pcbTotal)
                *pcbTotal = cbTotal.QuadPart;
            if (pcbFree)
                *pcbFree  = cbFree.QuadPart;
        }
        else
        {
            DWORD Err = GetLastError();
            rc = RTErrConvertFromWin32(Err);
            Log(("RTFsQuerySizes(%s,): GetDiskFreeSpaceEx failed with lasterr %d (0x%x)\n",
                 pszFsPath, Err, rc));
        }
    }

    /*
     * Block and sector size.
     */
    if (    RT_SUCCESS(rc)
        &&  (pcbBlock || pcbSector))
    {
        DWORD dwDummy1, dwDummy2;
        DWORD cbSector;
        DWORD cSectorsPerCluster;
        if (GetDiskFreeSpaceW(pwszFsRoot, &cSectorsPerCluster, &cbSector, &dwDummy1, &dwDummy2))
        {
            if (pcbBlock)
                *pcbBlock = cbSector * cSectorsPerCluster;
            if (pcbSector)
                *pcbSector = cbSector;
        }
        else
        {
            DWORD Err = GetLastError();
            rc = RTErrConvertFromWin32(Err);
            Log(("RTFsQuerySizes(%s,): GetDiskFreeSpace failed with lasterr %d (0x%x)\n",
                 pszFsPath, Err, rc));
        }
    }

    return rc;
}

/**
 * Query the properties of a mounted filesystem.
 *
 * @returns iprt status code.
 * @param   pszFsPath       Path within the mounted filesystem.
 * @param   pProperties     Where to store the properties.
 */
RTR3DECL(int) RTFsQueryPropertiesUnc(const wchar_t *pszFsPath, PRTFSPROPERTIES pProperties)
{
    /*
     * Validate & get valid root path.
     */
    AssertMsgReturn(VALID_PTR(pszFsPath) && *pszFsPath, ("%p", pszFsPath), VERR_INVALID_PARAMETER);
    AssertMsgReturn(VALID_PTR(pProperties), ("%p", pProperties), VERR_INVALID_PARAMETER);
    wchar_t pwszFsRoot[FS_ROOT_LEN];
    int rc = rtFsGetRoot(pszFsPath, pwszFsRoot);
    if (RT_FAILURE(rc))
        return rc;

    /*
     * Do work.
     */
    DWORD   dwMaxName;
    DWORD   dwFlags;
    DWORD   dwSerial;
    if (GetVolumeInformationW(pwszFsRoot, NULL, 0, &dwSerial, &dwMaxName, &dwFlags, NULL, 0))
    {
        memset(pProperties, 0, sizeof(*pProperties));
        pProperties->cbMaxComponent   = dwMaxName;
        pProperties->fFileCompression = !!(dwFlags & FILE_FILE_COMPRESSION);
        pProperties->fCompressed      = !!(dwFlags & FILE_VOLUME_IS_COMPRESSED);
        pProperties->fReadOnly        = !!(dwFlags & FILE_READ_ONLY_VOLUME);
        pProperties->fSupportsUnicode = !!(dwFlags & FILE_UNICODE_ON_DISK);
        pProperties->fCaseSensitive   = false;    /* win32 is case preserving only */
        pProperties->fRemote          = false;    /* no idea yet */
    }
    else
    {
        DWORD Err = GetLastError();
        rc = RTErrConvertFromWin32(Err);
        Log(("RTFsQuerySizes(%s,): GetVolumeInformation failed with lasterr %d (0x%x)\n",
             pszFsPath, Err, rc));
    }

    return rc;
}

