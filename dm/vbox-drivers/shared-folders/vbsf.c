/* $Id: vbsf.cpp $ */
/** @file
 * Shared Folders - VBox Shared Folders.
 */

/*
 * Copyright (C) 2006-2011 Oracle Corporation
 *
 * This file is part of VirtualBox Open Source Edition (OSE), as
 * available from http://www.virtualbox.org. This file is free software;
 * you can redistribute it and/or modify it under the terms of the GNU
 * General Public License (GPL) as published by the Free Software
 * Foundation, in version 2 as it comes in the "COPYING" file of the
 * VirtualBox OSE distribution. VirtualBox OSE is distributed in the
 * hope that it will be useful, but WITHOUT ANY WARRANTY of any kind.
 */
/*
 * uXen changes:
 *
 * Copyright 2012-2016, Bromium, Inc.
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

#ifdef UNITTEST
# include "testcase/tstSharedFolderService.h"
#endif

#include "mappings.h"
#include "mappings-opts.h"
#include "vbsf.h"
#include "shflhandle.h"
#include "filecrypt_helper.h"
#include "quota.h"

#include <iprt/alloc.h>
#include <iprt/assert.h>
#include <iprt/fs.h>
#include <iprt/dir.h>
#include <iprt/file.h>
#include <iprt/path.h>
#include <iprt/string.h>
#ifdef RT_OS_DARWIN
# include <Carbon/Carbon.h>
#endif

#ifdef UNITTEST
# include "teststubs.h"
#endif

#include "rt/rt.h"
#include "../internal/dir.h"
#include <dm/shared-folders.h>
#include <inttypes.h>

#define SHFL_RT_LINK(pClient) ((pClient)->fu32Flags & SHFL_CF_SYMLINKS ? RTPATH_F_ON_LINK : RTPATH_F_FOLLOW_LINK)
#define CRYPT_HDR_FIXED_SIZE 4096

static int resize_file(SHFLCLIENTDATA *pClient, SHFLROOT root, SHFLHANDLE handle,
                       uint64_t sz);

#ifdef ORIGINAL_VBOX
/**
 * @todo find a better solution for supporting the execute bit for non-windows
 * guests on windows host. Search for "0111" to find all the relevant places.
 */

void vbsfStripLastComponent(char *pszFullPath, uint32_t cbFullPathRoot)
{
    RTUNICP cp;

    /* Do not strip root. */
    char *s = pszFullPath + cbFullPathRoot;
    char *delimSecondLast = NULL;
    char *delimLast = NULL;

    LogFlowFunc(("%s -> %s\n", pszFullPath, s));

    for (;;)
    {
        cp = RTStrGetCp(s);

        if (cp == RTUNICP_INVALID || cp == 0)
        {
            break;
        }

        if (cp == RTPATH_DELIMITER)
        {
            if (delimLast != NULL)
            {
                delimSecondLast = delimLast;
            }

            delimLast = s;
        }

        s = RTStrNextCp(s);
    }

    if (cp == 0)
    {
        if (delimLast + 1 == s)
        {
            if (delimSecondLast)
            {
                *delimSecondLast = 0;
            }
            else if (delimLast)
            {
                *delimLast = 0;
            }
        }
        else
        {
            if (delimLast)
            {
                *delimLast = 0;
            }
        }
    }

    LogFlowFunc(("%s, %s, %s\n", pszFullPath, delimLast, delimSecondLast));
}

static int vbsfCorrectCasing(SHFLCLIENTDATA *pClient, char *pszFullPath, char *pszStartComponent)
{
    PRTDIRENTRYEX  pDirEntry = NULL;
    uint32_t       cbDirEntry, cbComponent;
    int            rc = VERR_FILE_NOT_FOUND;
    PRTDIR         hSearch = 0;
    char           szWildCard[4];

    Log2(("vbsfCorrectCasing: %s %s\n", pszFullPath, pszStartComponent));

    cbComponent = (uint32_t) strlen(pszStartComponent);

    cbDirEntry = 4096;
    pDirEntry  = (PRTDIRENTRYEX)RTMemAlloc(cbDirEntry);
    if (pDirEntry == 0)
    {
        AssertFailed();
        return VERR_NO_MEMORY;
    }

    /** @todo this is quite inefficient, especially for directories with many files */
    Assert(pszFullPath < pszStartComponent-1);
    Assert(*(pszStartComponent-1) == RTPATH_DELIMITER);
    *(pszStartComponent-1) = 0;
    strcpy(pDirEntry->szName, pszFullPath);
    szWildCard[0] = RTPATH_DELIMITER;
    szWildCard[1] = '*';
    szWildCard[2] = 0;
    strcat(pDirEntry->szName, szWildCard);

    rc = RTDirOpenFiltered(&hSearch, pDirEntry->szName, RTDIRFILTER_WINNT, 0);
    *(pszStartComponent-1) = RTPATH_DELIMITER;
    if (RT_FAILURE(rc))
        goto end;

    for (;;)
    {
        size_t cbDirEntrySize = cbDirEntry;

        rc = RTDirReadEx(hSearch, pDirEntry, &cbDirEntrySize, RTFSOBJATTRADD_NOTHING, SHFL_RT_LINK(pClient));
        if (rc == VERR_NO_MORE_FILES)
            break;

        if (   rc != VINF_SUCCESS
            && rc != VWRN_NO_DIRENT_INFO)
        {
            AssertFailed();
            if (   rc == VERR_NO_TRANSLATION
                || rc == VERR_INVALID_UTF8_ENCODING)
                continue;
            break;
        }

        Log2(("vbsfCorrectCasing: found %s\n", &pDirEntry->szName[0]));
        if (    pDirEntry->cbName == cbComponent
            &&  !RTStrICmp(pszStartComponent, &pDirEntry->szName[0]))
        {
            Log(("Found original name %s (%s)\n", &pDirEntry->szName[0], pszStartComponent));
            strcpy(pszStartComponent, &pDirEntry->szName[0]);
            rc = VINF_SUCCESS;
            break;
        }
    }

end:
    if (RT_FAILURE(rc))
        Log(("vbsfCorrectCasing %s failed with %d\n", pszStartComponent, rc));

    if (pDirEntry)
        RTMemFree(pDirEntry);

    if (hSearch)
        RTDirClose(hSearch);
    return rc;
}

/**
 * Do a simple path check given by pUtf8Path. Verify that the path is within
 * the root directory of the mapping. Count '..' and other path components
 * and check that we do not go over the root.
 *
 * @remarks This function assumes that the path will be appended to the root
 * directory of the shared folder mapping. Keep that in mind when checking
 * absolute pathes!
 */
static int vbsfPathCheck(const char *pUtf8Path, size_t cbPath)
{
    int rc = VINF_SUCCESS;

    size_t i = 0;
    int cComponents = 0; /* How many normal path components. */
    int cParentDirs = 0; /* How many '..' components. */

    for (;;)
    {
        /* Skip leading path delimiters. */
        while (   i < cbPath
               && (pUtf8Path[i] == '\\' || pUtf8Path[i] == '/'))
            i++;

        if (i >= cbPath)
            break;

        /* Check if that is a dot component. */
        int cDots = 0;
        while (i < cbPath && pUtf8Path[i] == '.')
        {
            cDots++;
            i++;
        }

        if (   cDots >= 2 /* Consider all multidots sequences as a 'parent dir'. */
            && (i >= cbPath || (pUtf8Path[i] == '\\' || pUtf8Path[i] == '/')))
        {
            cParentDirs++;
        }
        else if (   cDots == 1
                 && (i >= cbPath || (pUtf8Path[i] == '\\' || pUtf8Path[i] == '/')))
        {
            /* Single dot, nothing changes. */
        }
        else
        {
            /* Skip this component. */
            while (   i < cbPath
                   && (pUtf8Path[i] != '\\' && pUtf8Path[i] != '/'))
                i++;

            cComponents++;
        }

        Assert(i >= cbPath || (pUtf8Path[i] == '\\' || pUtf8Path[i] == '/'));

        /* Verify counters for every component. */
        if (cParentDirs > cComponents)
        {
            rc = VERR_INVALID_NAME;
            break;
        }
    }

    return rc;
}
#endif

static int
validate_ads_path(PSHFLSTRING path)
{
    const wchar_t *str = path->String.ucs2;
    int i;

    for (i = 0; i < path->u16Length/2; ++i) {
        if (str[i] == ':') {
            LogRel(("SharedFolders: path %ws invalid - ADS\n", &path->String.ucs2[0]));
            return VERR_INVALID_NAME;
        }
    }
    return VINF_SUCCESS;
}

static int vbsfPathCheckUcs(PSHFLSTRING pPath)
{
    int i;
    int len = pPath->u16Length/2;
    wchar_t* wstr = pPath->String.ucs2;
    if (wstr[len])
        return VERR_INVALID_PARAMETER;
    for (i=0; i<len; i++) {
        if (wstr[i] != '.' || wstr[i+1] != '.')
            continue;
        if (i == 0)
            return VERR_INVALID_PARAMETER;
        if (wstr[i-1] != '/' && wstr[i-1] != '\\')
            continue;
        if (wstr[i+2] == 0 || wstr[i+2] == '/' ||  wstr[i+2] == '\\')
            return VERR_INVALID_PARAMETER;
        /* Check for attempt to access ADS of .. directory, too. */
        if (wstr[i+2] == ':')
            return VERR_INVALID_PARAMETER;
    }
    return validate_ads_path(pPath);
}

static int vbsfBuildFullPathUcs(SHFLCLIENTDATA *pClient, SHFLROOT root, PSHFLSTRING pPath,
                             uint32_t cbPath, wchar_t **ppszFullPath, uint32_t *pcbFullPathRoot,
                             bool fWildCard, bool fPreserveLastComponent)
{
    wchar_t *pszFullPath = NULL;
    int rc;
    int len;
    const wchar_t *pszRoot = vbsfMappingsQueryHostRoot(root);
    if (!pszRoot) {
        Log(("vbsfBuildFullPath: invalid root!\n"));
        return VERR_INVALID_PARAMETER;
    }
    rc = vbsfPathCheckUcs(pPath);
    if (!RT_SUCCESS(rc)) {
        Log(("vbsfPathCheck_ucs failed!\n"));
        return rc;
    }
    if (pcbFullPathRoot)
        *pcbFullPathRoot = wcslen(pszRoot);
    len = 2 * (wcslen(pszRoot) + wcslen(pPath->String.ucs2) + 1 + 1);
    pszFullPath = (wchar_t *)RTMemAlloc(len);
    if (!pszFullPath)
        return VERR_NO_MEMORY;
    wcscpy(pszFullPath, pszRoot);
    if (pPath->String.ucs2[0] != '\\')
        wcscat(pszFullPath, L"\\");
    wcscat(pszFullPath, pPath->String.ucs2);
    *ppszFullPath = pszFullPath;
    return VINF_SUCCESS;
}
   

/**
 * Convert shared folder create flags (see include/iprt/shflsvc.h) into iprt create flags.
 *
 * @returns iprt status code
 * @param  fShflFlags shared folder create flags
 * @param  fMode      file attributes
 * @retval pfOpen     iprt create flags
 */
static int vbsfConvertFileOpenFlags(unsigned fShflFlags, RTFMODE fMode, SHFLHANDLE handleInitial, uint32_t *pfOpen)
{
    uint32_t fOpen = 0;
    int rc = VINF_SUCCESS;

    if (   (fMode & RTFS_DOS_MASK) != 0
        && (fMode & RTFS_UNIX_MASK) == 0)
    {
        /* A DOS/Windows guest, make RTFS_UNIX_* from RTFS_DOS_*.
         * @todo this is based on rtFsModeNormalize/rtFsModeFromDos.
         *       May be better to use RTFsModeNormalize here.
         */
        fMode |= RTFS_UNIX_IRUSR | RTFS_UNIX_IRGRP | RTFS_UNIX_IROTH;
        /* x for directories. */
        if (fMode & RTFS_DOS_DIRECTORY)
            fMode |= RTFS_TYPE_DIRECTORY | RTFS_UNIX_IXUSR | RTFS_UNIX_IXGRP | RTFS_UNIX_IXOTH;
        /* writable? */
        if (!(fMode & RTFS_DOS_READONLY))
            fMode |= RTFS_UNIX_IWUSR | RTFS_UNIX_IWGRP | RTFS_UNIX_IWOTH;

        /* Set the requested mode using only allowed bits. */
        fOpen |= ((fMode & RTFS_UNIX_MASK) << RTFILE_O_CREATE_MODE_SHIFT) & RTFILE_O_CREATE_MODE_MASK;
    }
    else
    {
        /* Old linux and solaris additions did not initialize the Info.Attr.fMode field
         * and it contained random bits from stack. Detect this using the handle field value
         * passed from the guest: old additions set it (incorrectly) to 0, new additions
         * set it to SHFL_HANDLE_NIL(~0).
         */
        if (handleInitial == 0)
        {
            /* Old additions. Do nothing, use default mode. */
        }
        else
        {
            /* New additions or Windows additions. Set the requested mode using only allowed bits.
             * Note: Windows guest set RTFS_UNIX_MASK bits to 0, which means a default mode
             *       will be set in fOpen.
             */
            fOpen |= ((fMode & RTFS_UNIX_MASK) << RTFILE_O_CREATE_MODE_SHIFT) & RTFILE_O_CREATE_MODE_MASK;
        }
    }

    switch (BIT_FLAG(fShflFlags, SHFL_CF_ACCESS_MASK_RW))
    {
        default:
        case SHFL_CF_ACCESS_NONE:
        {
            /** @todo treat this as read access, but theoretically this could be a no access request. */
            fOpen |= RTFILE_O_READ;
            Log(("FLAG: SHFL_CF_ACCESS_NONE\n"));
            break;
        }

        case SHFL_CF_ACCESS_READ:
        {
            fOpen |= RTFILE_O_READ;
            Log(("FLAG: SHFL_CF_ACCESS_READ\n"));
            break;
        }

        case SHFL_CF_ACCESS_WRITE:
        {
            fOpen |= RTFILE_O_WRITE;
            Log(("FLAG: SHFL_CF_ACCESS_WRITE\n"));
            break;
        }

        case SHFL_CF_ACCESS_READWRITE:
        {
            fOpen |= RTFILE_O_READWRITE;
            Log(("FLAG: SHFL_CF_ACCESS_READWRITE\n"));
            break;
        }
    }

    if (fShflFlags & SHFL_CF_ACCESS_APPEND)
    {
        fOpen |= RTFILE_O_APPEND;
    }

    switch (BIT_FLAG(fShflFlags, SHFL_CF_ACCESS_MASK_ATTR))
    {
        default:
        case SHFL_CF_ACCESS_ATTR_NONE:
        {
            fOpen |= RTFILE_O_ACCESS_ATTR_DEFAULT;
            Log(("FLAG: SHFL_CF_ACCESS_ATTR_NONE\n"));
            break;
        }

        case SHFL_CF_ACCESS_ATTR_READ:
        {
            fOpen |= RTFILE_O_ACCESS_ATTR_READ;
            Log(("FLAG: SHFL_CF_ACCESS_ATTR_READ\n"));
            break;
        }

        case SHFL_CF_ACCESS_ATTR_WRITE:
        {
            fOpen |= RTFILE_O_ACCESS_ATTR_WRITE;
            Log(("FLAG: SHFL_CF_ACCESS_ATTR_WRITE\n"));
            break;
        }

        case SHFL_CF_ACCESS_ATTR_READWRITE:
        {
            fOpen |= RTFILE_O_ACCESS_ATTR_READWRITE;
            Log(("FLAG: SHFL_CF_ACCESS_ATTR_READWRITE\n"));
            break;
        }
    }

    /* Sharing mask */
    switch (BIT_FLAG(fShflFlags, SHFL_CF_ACCESS_DENYREAD | SHFL_CF_ACCESS_DENYWRITE))
    {
    default:
    case 0:
        fOpen |= RTFILE_O_DENY_NONE;
        Log(("FLAG: SHFL_CF_ACCESS_DENYNONE\n"));
        break;

    case SHFL_CF_ACCESS_DENYREAD:
        fOpen |= RTFILE_O_DENY_READ;
        Log(("FLAG: SHFL_CF_ACCESS_DENYREAD\n"));
        break;

    case SHFL_CF_ACCESS_DENYWRITE:
        fOpen |= RTFILE_O_DENY_WRITE;
        Log(("FLAG: SHFL_CF_ACCESS_DENYWRITE\n"));
        break;

    case SHFL_CF_ACCESS_DENYREAD | SHFL_CF_ACCESS_DENYWRITE:
        fOpen |= RTFILE_O_DENY_ALL;
        Log(("FLAG: SHFL_CF_ACCESS_DENYALL\n"));
        break;
    }

    if (!(fShflFlags & SHFL_CF_ACCESS_DENYDELETE))
        fOpen |= RTFILE_O_DENY_NOT_DELETE;

    /* Open/Create action mask */
    switch (BIT_FLAG(fShflFlags, SHFL_CF_ACT_MASK_IF_EXISTS))
    {
    case SHFL_CF_ACT_OPEN_IF_EXISTS:
        if (SHFL_CF_ACT_CREATE_IF_NEW == BIT_FLAG(fShflFlags, SHFL_CF_ACT_MASK_IF_NEW))
        {
            fOpen |= RTFILE_O_OPEN_CREATE;
            Log(("FLAGS: SHFL_CF_ACT_OPEN_IF_EXISTS and SHFL_CF_ACT_CREATE_IF_NEW\n"));
        }
        else if (SHFL_CF_ACT_FAIL_IF_NEW == BIT_FLAG(fShflFlags, SHFL_CF_ACT_MASK_IF_NEW))
        {
            fOpen |= RTFILE_O_OPEN;
            Log(("FLAGS: SHFL_CF_ACT_OPEN_IF_EXISTS and SHFL_CF_ACT_FAIL_IF_NEW\n"));
        }
        else
        {
            Log(("FLAGS: invalid open/create action combination\n"));
            rc = VERR_INVALID_PARAMETER;
        }
        break;
    case SHFL_CF_ACT_FAIL_IF_EXISTS:
        if (SHFL_CF_ACT_CREATE_IF_NEW == BIT_FLAG(fShflFlags, SHFL_CF_ACT_MASK_IF_NEW))
        {
            fOpen |= RTFILE_O_CREATE;
            Log(("FLAGS: SHFL_CF_ACT_FAIL_IF_EXISTS and SHFL_CF_ACT_CREATE_IF_NEW\n"));
        }
        else
        {
            Log(("FLAGS: invalid open/create action combination\n"));
            rc = VERR_INVALID_PARAMETER;
        }
        break;
    case SHFL_CF_ACT_REPLACE_IF_EXISTS:
        if (SHFL_CF_ACT_CREATE_IF_NEW == BIT_FLAG(fShflFlags, SHFL_CF_ACT_MASK_IF_NEW))
        {
            fOpen |= RTFILE_O_CREATE_REPLACE;
            Log(("FLAGS: SHFL_CF_ACT_REPLACE_IF_EXISTS and SHFL_CF_ACT_CREATE_IF_NEW\n"));
        }
        else if (SHFL_CF_ACT_FAIL_IF_NEW == BIT_FLAG(fShflFlags, SHFL_CF_ACT_MASK_IF_NEW))
        {
            fOpen |= RTFILE_O_OPEN | RTFILE_O_TRUNCATE;
            Log(("FLAGS: SHFL_CF_ACT_REPLACE_IF_EXISTS and SHFL_CF_ACT_FAIL_IF_NEW\n"));
        }
        else
        {
            Log(("FLAGS: invalid open/create action combination\n"));
            rc = VERR_INVALID_PARAMETER;
        }
        break;
    case SHFL_CF_ACT_OVERWRITE_IF_EXISTS:
        if (SHFL_CF_ACT_CREATE_IF_NEW == BIT_FLAG(fShflFlags, SHFL_CF_ACT_MASK_IF_NEW))
        {
            fOpen |= RTFILE_O_CREATE_REPLACE;
            Log(("FLAGS: SHFL_CF_ACT_OVERWRITE_IF_EXISTS and SHFL_CF_ACT_CREATE_IF_NEW\n"));
        }
        else if (SHFL_CF_ACT_FAIL_IF_NEW == BIT_FLAG(fShflFlags, SHFL_CF_ACT_MASK_IF_NEW))
        {
            fOpen |= RTFILE_O_OPEN | RTFILE_O_TRUNCATE;
            Log(("FLAGS: SHFL_CF_ACT_OVERWRITE_IF_EXISTS and SHFL_CF_ACT_FAIL_IF_NEW\n"));
        }
        else
        {
            Log(("FLAGS: invalid open/create action combination\n"));
            rc = VERR_INVALID_PARAMETER;
        }
        break;
    default:
        rc = VERR_INVALID_PARAMETER;
        Log(("FLAG: SHFL_CF_ACT_MASK_IF_EXISTS - invalid parameter\n"));
    }

    if (RT_SUCCESS(rc))
    {
        *pfOpen = fOpen;
    }
    return rc;
}

/**
 * Open a file or create and open a new one.
 *
 * @returns IPRT status code
 * @param  pClient               Data structure describing the client accessing the shared folder
 * @param  pszPath               Path to the file or folder on the host.
 * @param  pParms->CreateFlags   Creation or open parameters, see include/VBox/shflsvc.h
 * @param  pParms->Info          When a new file is created this specifies the initial parameters.
 *                               When a file is created or overwritten, it also specifies the
 *                               initial size.
 * @retval pParms->Result        Shared folder status code, see include/VBox/shflsvc.h
 * @retval pParms->Handle        On success the (shared folder) handle of the file opened or
 *                               created
 * @retval pParms->Info          On success the parameters of the file opened or created
 */
static int vbsfOpenFile(SHFLCLIENTDATA *pClient, SHFLROOT root, const wchar_t *pszPath, SHFLCREATEPARMS *pParms)
{
    LogFlow(("vbsfOpenFile: pszPath = %ls, pParms = %p\n", pszPath, pParms));
    Log(("SHFL create flags %08x\n", pParms->CreateFlags));

    SHFLHANDLE      handle = SHFL_HANDLE_NIL;
    SHFLFILEHANDLE *pHandle = 0;

    RTFSOBJINFO info;

    /* Open or create a file. */
    uint32_t fOpen = 0;
    bool fNoError = false;
    bool fAlreadyExists = false;
    static int cErrors;

    int rc = vbsfConvertFileOpenFlags(pParms->CreateFlags, pParms->Info.Attr.fMode, pParms->Handle, &fOpen);
    if (RT_SUCCESS(rc))
    {
        rc = VERR_NO_MEMORY;  /* Default error. */
        handle  = vbsfAllocFileHandle(pClient, pszPath, fOpen);
        if (handle != SHFL_HANDLE_NIL)
        {
            pHandle = vbsfQueryFileHandle(pClient, handle);
            if (pHandle)
            {
                int already_exists = 0, created = 0, truncated = 0;
                struct quota_op qop;

                quota_start_op(&qop, pClient, root, SHFL_HANDLE_NIL, pszPath);
                quota_set_delta(&qop, -quota_get_filesize(&qop));

                rc = RTFileOpenUcs(&pHandle->file.Handle, pszPath, fOpen, &already_exists, &created,
                    &truncated);
                if ((RT_SUCCESS(rc)
                     && ((fOpen & RTFILE_O_ACTION_MASK) == RTFILE_O_OPEN_CREATE)
                     && already_exists))
                {
                    fAlreadyExists = true;
                }
                if (RT_SUCCESS(rc)) {
                    if (truncated)
                        quota_complete_op(&qop);
                    if (created || truncated)
                        rc = fch_create_crypt_hdr(pClient, root, handle);
                    else
                        rc = fch_read_crypt_hdr(pClient, root, handle, NULL);
                }
            }
        }
    }
    if (RT_FAILURE(rc))
    {
        switch (rc)
        {
        case VERR_FILE_NOT_FOUND:
            pParms->Result = SHFL_FILE_NOT_FOUND;

            /* This actually isn't an error, so correct the rc before return later,
               because the driver (VBoxSF.sys) expects rc = VINF_SUCCESS and checks the result code. */
            fNoError = true;
            break;
        case VERR_PATH_NOT_FOUND:
            pParms->Result = SHFL_PATH_NOT_FOUND;

            /* This actually isn't an error, so correct the rc before return later,
               because the driver (VBoxSF.sys) expects rc = VINF_SUCCESS and checks the result code. */
            fNoError = true;
            break;
        case VERR_ALREADY_EXISTS:
//            RTFSOBJINFO info;

            /** @todo Possible race left here. */
            if (RT_SUCCESS(RTPathQueryInfoExUcs(pszPath, &info, RTFSOBJATTRADD_NOTHING, SHFL_RT_LINK(pClient))))
            {
                fch_guest_fsinfo_path(pClient, root, (wchar_t*)pszPath, &info);
#ifdef RT_OS_WINDOWS
                info.Attr.fMode |= 0111;
#endif
                vbfsCopyFsObjInfoFromIprt(&pParms->Info, &info);
            }
            pParms->Result = SHFL_FILE_EXISTS;

            /* This actually isn't an error, so correct the rc before return later,
               because the driver (VBoxSF.sys) expects rc = VINF_SUCCESS and checks the result code. */
            fNoError = true;
            break;
        case VERR_TOO_MANY_OPEN_FILES:
            if (cErrors < 32)
            {
                LogRel(("SharedFolders host service: Cannot open '%s' -- too many open files.\n", pszPath));
#if defined RT_OS_LINUX || RT_OS_SOLARIS
                if (cErrors < 1)
                    LogRel(("SharedFolders host service: Try to increase the limit for open files (ulimit -n)\n"));
#endif
                cErrors++;
            }
            pParms->Result = SHFL_NO_RESULT;
            break;
        default:
            pParms->Result = SHFL_NO_RESULT;
        }
    }
    else
    {
        /** @note The shared folder status code is very approximate, as the runtime
          *       does not really provide this information. */
        pParms->Result = SHFL_FILE_EXISTS;  /* We lost the information as to whether it was
                                               created when we eliminated the race. */
        if (   (   SHFL_CF_ACT_REPLACE_IF_EXISTS
                == BIT_FLAG(pParms->CreateFlags, SHFL_CF_ACT_MASK_IF_EXISTS))
            || (   SHFL_CF_ACT_OVERWRITE_IF_EXISTS
                == BIT_FLAG(pParms->CreateFlags, SHFL_CF_ACT_MASK_IF_EXISTS)))
        {
            /* For now, we do not treat a failure here as fatal. */
            /* @todo Also set the size for SHFL_CF_ACT_CREATE_IF_NEW if
                     SHFL_CF_ACT_FAIL_IF_EXISTS is set. */
            uint64_t sz = fch_host_fileoffset(pClient, root, handle, pParms->Info.cbObject);
            resize_file(pClient, root, handle, sz);
            pParms->Result = SHFL_FILE_REPLACED;
        }
        if (   (   SHFL_CF_ACT_FAIL_IF_EXISTS
                == BIT_FLAG(pParms->CreateFlags, SHFL_CF_ACT_MASK_IF_EXISTS))
            || (   SHFL_CF_ACT_CREATE_IF_NEW
                == BIT_FLAG(pParms->CreateFlags, SHFL_CF_ACT_MASK_IF_NEW)))
        {
            pParms->Result = SHFL_FILE_CREATED;
        }
#if 0
        /* @todo */
        /* Set new attributes. */
        if (   (   SHFL_CF_ACT_REPLACE_IF_EXISTS
                == BIT_FLAG(pParms->CreateFlags, SHFL_CF_ACT_MASK_IF_EXISTS))
            || (   SHFL_CF_ACT_CREATE_IF_NEW
                == BIT_FLAG(pParms->CreateFlags, SHFL_CF_ACT_MASK_IF_NEW)))
        {
            RTFileSetTimes(pHandle->file.Handle,
                          &pParms->Info.AccessTime,
                          &pParms->Info.ModificationTime,
                          &pParms->Info.ChangeTime,
                          &pParms->Info.BirthTime
                          );

            RTFileSetMode (pHandle->file.Handle, pParms->Info.Attr.fMode);
        }
#endif
        RTFSOBJINFO info;

        /* Get file information */
        rc = RTFileQueryInfo(pHandle->file.Handle, &info, RTFSOBJATTRADD_NOTHING);
        if (RT_SUCCESS(rc))
        {
            fch_guest_fsinfo(pClient, root, handle, &info);
#ifdef RT_OS_WINDOWS
            info.Attr.fMode |= 0111;
#endif
            vbfsCopyFsObjInfoFromIprt(&pParms->Info, &info);
        }
    }
    /* Free resources if any part of the function has failed. */
    if (RT_FAILURE(rc))
    {
        if (   (0 != pHandle)
            && (NIL_RTFILE != pHandle->file.Handle)
            && (0 != pHandle->file.Handle))
        {
            RTFileClose(pHandle->file.Handle);
            pHandle->file.Handle = NIL_RTFILE;
        }
        if (SHFL_HANDLE_NIL != handle)
        {
            vbsfFreeFileHandle(pClient, handle);
        }
        pParms->Handle = SHFL_HANDLE_NIL;
    }
    else
    {
        pParms->Handle = handle;
    }

    if (fAlreadyExists)
        pParms->Result = SHFL_FILE_EXISTS;

    /* Report the driver that all is okay, we're done here */
    if (fNoError)
        rc = VINF_SUCCESS;
    if (RT_SUCCESS(rc) && handle != SHFL_HANDLE_NIL) {
        struct shfl_handle_data *d;

        d = vbsfQueryHandleData(pClient, handle);
        if (d) {
            d->folder_opts = _sf_get_opt(root, (wchar_t*)pszPath);
            if (d->folder_opts & SF_OPT_NO_FLUSH)
                pParms->CreateFlags |= SHFL_CF_NO_FLUSH;
            LogFlow(("vbsfOpenFile: opts=0x%" PRIx64 "\n", d->folder_opts));
        }
    }
    LogFlow(("vbsfOpenFile: rc = 0x%x\n", rc));
    return rc;
}

/**
 * Open a folder or create and open a new one.
 *
 * @returns IPRT status code
 * @param  pszPath               Path to the file or folder on the host.
 * @param  pParms->CreateFlags   Creation or open parameters, see include/VBox/shflsvc.h
 * @retval pParms->Result        Shared folder status code, see include/VBox/shflsvc.h
 * @retval pParms->Handle        On success the (shared folder) handle of the folder opened or
 *                               created
 * @retval pParms->Info          On success the parameters of the folder opened or created
 *
 * @note folders are created with fMode = 0777
 */
static int vbsfOpenDirUcs(SHFLCLIENTDATA *pClient, SHFLROOT root, const wchar_t *pszPath,
                       SHFLCREATEPARMS *pParms)
{
    LogFlow(("vbsfOpenDir: pszPath = %ls, pParms = %p\n", pszPath, pParms));
    Log(("SHFL create flags %08x\n", pParms->CreateFlags));

    int rc = VERR_NO_MEMORY;
    SHFLHANDLE      handle = vbsfAllocDirHandle(pClient);
    SHFLFILEHANDLE *pHandle = vbsfQueryDirHandle(pClient, handle);
    if (0 != pHandle)
    {
        rc = VINF_SUCCESS;
        pParms->Result = SHFL_FILE_EXISTS;  /* May be overwritten with SHFL_FILE_CREATED. */
        /** @todo Can anyone think of a sensible, race-less way to do this?  Although
                  I suspect that the race is inherent, due to the API available... */
        /* Try to create the folder first if "create if new" is specified.  If this
           fails, and "open if exists" is specified, then we ignore the failure and try
           to open the folder anyway. */
        if (   SHFL_CF_ACT_CREATE_IF_NEW
            == BIT_FLAG(pParms->CreateFlags, SHFL_CF_ACT_MASK_IF_NEW))
        {
            /** @todo render supplied attributes.
            * bird: The guest should specify this. For windows guests RTFS_DOS_DIRECTORY should suffice. */
            RTFMODE fMode = 0777;

            pParms->Result = SHFL_FILE_CREATED;
            rc = RTDirCreateUcs(pszPath, fMode, 0);
            if (RT_FAILURE(rc))
            {
                switch (rc)
                {
                case VERR_ALREADY_EXISTS:
                    pParms->Result = SHFL_FILE_EXISTS;
                    break;
                case VERR_PATH_NOT_FOUND:
                    pParms->Result = SHFL_PATH_NOT_FOUND;
                    break;
                default:
                    pParms->Result = SHFL_NO_RESULT;
                }
            }
        }
        if (   RT_SUCCESS(rc)
            || (SHFL_CF_ACT_OPEN_IF_EXISTS == BIT_FLAG(pParms->CreateFlags, SHFL_CF_ACT_MASK_IF_EXISTS)))
        {
            /* Open the directory now */
            rc = RTDirOpenFilteredUcs(&pHandle->dir.Handle, pszPath, RTDIRFILTER_NONE, 0);
            if (RT_SUCCESS(rc))
            {
                RTFSOBJINFO info;
                rc = RTPathQueryInfoExUcs(pszPath, &info, RTFSOBJATTRADD_NOTHING, RTPATH_F_FOLLOW_LINK);
                if (RT_SUCCESS(rc))
                {
                    fch_guest_fsinfo_path(pClient, root, (wchar_t*)pszPath, &info);
                    vbfsCopyFsObjInfoFromIprt(&pParms->Info, &info);
                }
            }
            else
            {
                switch (rc)
                {
                case VERR_FILE_NOT_FOUND:  /* Does this make sense? */
                    pParms->Result = SHFL_FILE_NOT_FOUND;
                    break;
                case VERR_PATH_NOT_FOUND:
                    pParms->Result = SHFL_PATH_NOT_FOUND;
                    break;
                case VERR_ACCESS_DENIED:
                    pParms->Result = SHFL_FILE_EXISTS;
                    break;
                default:
                    pParms->Result = SHFL_NO_RESULT;
                }
            }
        }
    }
    if (RT_FAILURE(rc))
    {
        if (   (0 != pHandle)
            && (0 != pHandle->dir.Handle))
        {
            RTDirClose(pHandle->dir.Handle);
            pHandle->dir.Handle = 0;
        }
        if (SHFL_HANDLE_NIL != handle)
        {
            vbsfFreeFileHandle(pClient, handle);
        }
        pParms->Handle = SHFL_HANDLE_NIL;
    }
    else
    {
        pParms->Handle = handle;
    }
    LogFlow(("vbsfOpenDir: rc = 0x%x\n", rc));
    return rc;
}

static int vbsfCloseDir(SHFLFILEHANDLE *pHandle)
{
    int rc = VINF_SUCCESS;

    LogFlow(("vbsfCloseDir: Handle = %08X Search Handle = %08X\n",
             pHandle->dir.Handle, pHandle->dir.SearchHandle));

    RTDirClose(pHandle->dir.Handle);

    if (pHandle->dir.SearchHandle)
        RTDirClose(pHandle->dir.SearchHandle);

    if (pHandle->dir.pLastValidEntry)
    {
        RTMemFree(pHandle->dir.pLastValidEntry);
        pHandle->dir.pLastValidEntry = NULL;
    }

    LogFlow(("vbsfCloseDir: rc = %d\n", rc));

    return rc;
}


static int vbsfCloseFile(SHFLFILEHANDLE *pHandle)
{
    int rc = VINF_SUCCESS;

    LogFlow(("vbsfCloseFile: Handle = %08X\n",
             pHandle->file.Handle));

    rc = RTFileClose(pHandle->file.Handle);

    LogFlow(("vbsfCloseFile: rc = %d\n", rc));

    return rc;
}

/**
 * Look up file or folder information by host path.
 *
 * @returns iprt status code (currently VINF_SUCCESS)
 * @param   pszFullPath    The path of the file to be looked up
 * @retval  pParms->Result Status of the operation (success or error)
 * @retval  pParms->Info   On success, information returned about the file
 */
static int vbsfLookupFile(SHFLCLIENTDATA *pClient, SHFLROOT root, wchar_t *pszPath, SHFLCREATEPARMS *pParms)
{
    RTFSOBJINFO info;
    int rc;

    rc = RTPathQueryInfoExUcs(pszPath, &info, RTFSOBJATTRADD_NOTHING, SHFL_RT_LINK(pClient));
    LogFlow(("SHFL_CF_LOOKUP\n"));
    /* Client just wants to know if the object exists. */
    switch (rc)
    {
        case VINF_SUCCESS:
        {
            fch_guest_fsinfo_path(pClient, root, pszPath, &info);
#ifdef RT_OS_WINDOWS
            info.Attr.fMode |= 0111;
#endif
            vbfsCopyFsObjInfoFromIprt(&pParms->Info, &info);
            pParms->Result = SHFL_FILE_EXISTS;
            break;
        }

        case VERR_FILE_NOT_FOUND:
        {
            pParms->Result = SHFL_FILE_NOT_FOUND;
            rc = VINF_SUCCESS;
            break;
        }

        case VERR_PATH_NOT_FOUND:
        {
            pParms->Result = SHFL_PATH_NOT_FOUND;
            rc = VINF_SUCCESS;
            break;
        }
    }
    pParms->Handle = SHFL_HANDLE_NIL;
    return rc;
}

#ifdef UNITTEST
/** Unit test the SHFL_FN_CREATE API.  Located here as a form of API
 * documentation. */
void testCreate(RTTEST hTest)
{
    /* Simple opening of an existing file. */
    testCreateFileSimple(hTest);
    /* Simple opening of an existing directory. */
    /** @todo How do wildcards in the path name work? */
    testCreateDirSimple(hTest);
    /* If the number or types of parameters are wrong the API should fail. */
    testCreateBadParameters(hTest);
    /* Add tests as required... */
}
#endif
/**
 * Create or open a file or folder.  Perform character set and case
 * conversion on the file name if necessary.
 *
 * @returns IPRT status code, but see note below
 * @param   pClient        Data structure describing the client accessing the shared
 *                         folder
 * @param   root           The index of the shared folder in the table of mappings.
 *                         The host path of the shared folder is found using this.
 * @param   pPath          The path of the file or folder relative to the host path
 *                         indexed by root.
 * @param   cbPath         Presumably the length of the path in pPath.  Actually
 *                         ignored, as pPath contains a length parameter.
 * @param   pParms->Info   If a new file is created or an old one overwritten, set
 *                         these attributes
 * @retval  pParms->Result Shared folder result code, see include/VBox/shflsvc.h
 * @retval  pParms->Handle Shared folder handle to the newly opened file
 * @retval  pParms->Info   Attributes of the file or folder opened
 *
 * @note This function returns success if a "non-exceptional" error occurred,
 *       such as "no such file".  In this case, the caller should check the
 *       pParms->Result return value and whether pParms->Handle is valid.
 */
int vbsfCreate(SHFLCLIENTDATA *pClient, SHFLROOT root, SHFLSTRING *pPath, uint32_t cbPath, SHFLCREATEPARMS *pParms)
{
    int rc = VINF_SUCCESS;

    LogFlow(("vbsfCreate: pClient = %p, pPath = %p, cbPath = %d, pParms = %p CreateFlags=%x\n",
             pClient, pPath, cbPath, pParms, pParms->CreateFlags));

    /* Check the client access rights to the root. */
    /** @todo */

    /* Build a host full path for the given path, handle file name case issues (if the guest
     * expects case-insensitive paths but the host is case-sensitive) and convert ucs2 to utf8 if
     * necessary.
     */
    wchar_t *pszFullPath = NULL;
    uint32_t cbFullPathRoot = 0;

    rc = vbsfBuildFullPathUcs(pClient, root, pPath, cbPath, &pszFullPath, &cbFullPathRoot, false, false);
    if (RT_SUCCESS(rc))
    {
        /* Reset return value in case client forgot to do so.
         * pParms->Handle must not be reset here, as it is used
         * in vbsfOpenFile to detect old additions.
         */
        pParms->Result = SHFL_NO_RESULT;

        if (BIT_FLAG(pParms->CreateFlags, SHFL_CF_LOOKUP))
        {
            rc = vbsfLookupFile(pClient, root, pszFullPath, pParms);
        }
        else
        {
            /* Query path information. */
            RTFSOBJINFO info;

            rc = RTPathQueryInfoExUcs(pszFullPath, &info, RTFSOBJATTRADD_NOTHING, SHFL_RT_LINK(pClient));
            LogFlow(("RTPathQueryInfoEx returned 0x%x\n", rc));

            if (RT_SUCCESS(rc))
            {
                /* Mark it as a directory in case the caller didn't. */
                /**
                  * @todo I left this in in order not to change the behaviour of the
                  *       function too much.  Is it really needed, and should it really be
                  *       here?
                  */
                if (BIT_FLAG(info.Attr.fMode, RTFS_DOS_DIRECTORY))
                {
                    pParms->CreateFlags |= SHFL_CF_DIRECTORY;
                }

                /**
                  * @todo This should be in the Windows Guest Additions, as no-one else
                  *       needs it.
                  */
                if (BIT_FLAG(pParms->CreateFlags, SHFL_CF_OPEN_TARGET_DIRECTORY))
                {
//                    vbsfStripLastComponent(pszFullPath, cbFullPathRoot);
                    pParms->CreateFlags &= ~SHFL_CF_ACT_MASK_IF_EXISTS;
                    pParms->CreateFlags &= ~SHFL_CF_ACT_MASK_IF_NEW;
                    pParms->CreateFlags |= SHFL_CF_DIRECTORY;
                    pParms->CreateFlags |= SHFL_CF_ACT_OPEN_IF_EXISTS;
                    pParms->CreateFlags |= SHFL_CF_ACT_FAIL_IF_NEW;
                }
            }
            rc = VINF_SUCCESS;

            /* Note: do not check the SHFL_CF_ACCESS_WRITE here, only check if the open operation
             * will cause changes.
             *
             * Actual operations (write, set attr, etc), which can write to a shared folder, have
             * the check and will return VERR_WRITE_PROTECT if the folder is not writable.
             */
             /* Why the above is needed ? Causes problems, aka KRY-8735.
             *  Denying write access to ro shares now.
             */
            if (   (pParms->CreateFlags & SHFL_CF_ACT_MASK_IF_EXISTS) == SHFL_CF_ACT_REPLACE_IF_EXISTS
                || (pParms->CreateFlags & SHFL_CF_ACT_MASK_IF_EXISTS) == SHFL_CF_ACT_OVERWRITE_IF_EXISTS
                || (pParms->CreateFlags & SHFL_CF_ACT_MASK_IF_NEW) == SHFL_CF_ACT_CREATE_IF_NEW
                || (pParms->CreateFlags & SHFL_CF_ACCESS_WRITE) == SHFL_CF_ACCESS_WRITE
               )
            {
                /* is the guest allowed to write to this share? */
                bool fWritable;
                rc = vbsfMappingsQueryWritable(pClient, root, &fWritable);
                if (RT_FAILURE(rc) || !fWritable)
                {
                    if ((pParms->CreateFlags & SHFL_CF_ACCESS_WRITE) == SHFL_CF_ACCESS_WRITE)
                    {
                        /*
                         * KRY-8735: Some applications expect ACCESS_DENIED
                         * to be returned on opening a read-only file for
                         * writing.  Other applications don't seem to mind
                         * getting either ACCESS_DENIED or WRITE_PROTECT. So 
                         * for this case we will return ACCESS_DENIED.
                         */
                        rc = VERR_ACCESS_DENIED;
                    }
                    else
                    {
                        rc = VERR_WRITE_PROTECT;
                    }
                }
            }

            if (RT_SUCCESS(rc))
            {
                if (BIT_FLAG(pParms->CreateFlags, SHFL_CF_DIRECTORY))
                {
                    rc = vbsfOpenDirUcs(pClient, root, pszFullPath, pParms);
                }
                else
                {
                    rc = vbsfOpenFile(pClient, root, pszFullPath, pParms);
                }
            }
            else
            {
                pParms->Handle = SHFL_HANDLE_NIL;
            }
        }

        /* free the path string */
        RTMemFree(pszFullPath);
    }

    Log(("vbsfCreate: handle = 0x%llx rc = 0x%x result=%x\n", (uint64_t)pParms->Handle, rc, pParms->Result));

    return rc;
}

#ifdef UNITTEST
/** Unit test the SHFL_FN_CLOSE API.  Located here as a form of API
 * documentation. */
void testClose(RTTEST hTest)
{
    /* If the API parameters are invalid the API should fail. */
    testCloseBadParameters(hTest);
    /* Add tests as required... */
}
#endif
int vbsfClose(SHFLCLIENTDATA *pClient, SHFLROOT root, SHFLHANDLE Handle)
{
    int rc = VINF_SUCCESS;

    LogFlow(("vbsfClose: pClient = %p, Handle = 0x%llx\n",
             pClient, Handle));

    uint32_t type = vbsfQueryHandleType(pClient, Handle);
    Assert((type & ~(SHFL_HF_TYPE_DIR | SHFL_HF_TYPE_FILE)) == 0);

    switch (type & (SHFL_HF_TYPE_DIR | SHFL_HF_TYPE_FILE))
    {
        case SHFL_HF_TYPE_DIR:
        {
            SHFLFILEHANDLE *pHandle = vbsfQueryDirHandle(pClient, Handle);

            if (pHandle)
                rc = vbsfCloseDir(pHandle);
            else
                return VERR_INVALID_PARAMETER;
            break;
        }
        case SHFL_HF_TYPE_FILE:
        {
            SHFLFILEHANDLE *pHandle = vbsfQueryFileHandle(pClient, Handle);

            if (pHandle)
                rc = vbsfCloseFile(vbsfQueryFileHandle(pClient, Handle));
            else
                return VERR_INVALID_PARAMETER;
            break;
        }
        default:
            return VERR_INVALID_HANDLE;
    }
    vbsfFreeFileHandle(pClient, Handle);

    Log(("vbsfClose: rc = 0x%x\n", rc));

    return rc;
}

#ifdef UNITTEST
/** Unit test the SHFL_FN_READ API.  Located here as a form of API
 * documentation. */
void testRead(RTTEST hTest)
{
    /* If the number or types of parameters are wrong the API should fail. */
    testReadBadParameters(hTest);
    /* Basic reading from a file. */
    testReadFileSimple(hTest);
    /* Add tests as required... */
}
#endif
int vbsfRead  (SHFLCLIENTDATA *pClient, SHFLROOT root, SHFLHANDLE Handle, uint64_t offset, uint32_t *pcbBuffer, uint8_t *pBuffer)
{
    SHFLFILEHANDLE *pHandle = vbsfQueryFileHandle(pClient, Handle);
    size_t count = 0;
    int rc;

    if (pHandle == 0 || pcbBuffer == 0 || pBuffer == 0)
    {
        AssertFailed();
        return VERR_INVALID_PARAMETER;
    }

    Log(("vbsfRead 0x%llx offset 0x%llx bytes %x\n", Handle, offset, *pcbBuffer));

    if (*pcbBuffer == 0)
        return VINF_SUCCESS; /* @todo correct? */

    rc = RTFileSeek(pHandle->file.Handle,
                    fch_host_fileoffset(pClient, root, Handle, offset),
                    RTFILE_SEEK_BEGIN, NULL);
    if (rc != VINF_SUCCESS)
    {
        AssertRC(rc);
        return rc;
    }

    rc = RTFileRead(pHandle->file.Handle, pBuffer, *pcbBuffer, &count);
    *pcbBuffer = (uint32_t)count;
    fch_decrypt(pClient, Handle, pBuffer, offset, *pcbBuffer);
    Log(("RTFileRead returned 0x%x bytes read %x\n", rc, count));
    return rc;
}

#ifdef UNITTEST
/** Unit test the SHFL_FN_WRITE API.  Located here as a form of API
 * documentation. */
void testWrite(RTTEST hTest)
{
    /* If the number or types of parameters are wrong the API should fail. */
    testWriteBadParameters(hTest);
    /* Simple test of writing to a file. */
    testWriteFileSimple(hTest);
    /* Add tests as required... */
}
#endif

static int
test_re_write(SHFLCLIENTDATA *pClient, SHFLROOT root, SHFLHANDLE Handle)
{
    int rc = 0;

    /* maybe necessary to rewrite whole file for new crypt settings */
    if (vbsfQueryHandleCryptChanged(pClient, Handle)) {
        int current = (vbsfQueryHandleFlags(pClient, Handle) & SHFL_HF_ENCRYPTED) ? 1:0;
        int desired;

        rc = fch_query_crypt_by_handle(pClient, root, Handle, &desired);
        if (RT_FAILURE(rc))
            return rc;
        if (desired)
            desired = 1;
        if (current != desired) {
            LogRel(("shared-folders: crypt mode changed on file 0x%llx mode %d, rewriting\n", Handle, desired));
            rc = fch_re_write_file(pClient, root, Handle);
            if (RT_FAILURE(rc)) {
                LogRel(("shared-folders: rewrite of %ls (%llx) failed with %x\n",
                        vbsfQueryHandlePath(pClient, Handle), Handle, rc));
                return rc;
            }
        }
        vbsfResetHandleCryptChanged(pClient, Handle);
    }
    return 0;
}

int vbsfWrite(SHFLCLIENTDATA *pClient, SHFLROOT root, SHFLHANDLE Handle, uint64_t offset, uint32_t *pcbBuffer, uint8_t *pBuffer)
{
    SHFLFILEHANDLE *pHandle = vbsfQueryFileHandle(pClient, Handle);
    size_t count = 0;
    uint64_t hostoffset;
    int64_t delta;
    int rc;
    struct quota_op qop;

    if (pHandle == 0 || pcbBuffer == 0 || pBuffer == 0)
    {
        AssertFailed();
        return VERR_INVALID_PARAMETER;
    }

    Log(("vbsfWrite 0x%llx offset 0x%llx bytes %x\n", Handle, offset, *pcbBuffer));

    /* Is the guest allowed to write to this share?
     * XXX Actually this check was still done in vbsfCreate() -- RTFILE_O_WRITE cannot be set if vbsfMappingsQueryWritable() failed. */
    bool fWritable;
    rc = fch_writable_file(pClient, root, Handle, NULL, &fWritable);
    if (RT_FAILURE(rc) || !fWritable)
        return VERR_WRITE_PROTECT;

    if (*pcbBuffer == 0)
        return VINF_SUCCESS; /** @todo correct? */

    /* maybe necessary to rewrite whole file for new crypt settings */
    rc = test_re_write(pClient, root, Handle);
    if (RT_FAILURE(rc))
        return rc;
    /* need to requery handle, might've changed on rewrite */
    pHandle = vbsfQueryFileHandle(pClient, Handle);
    if (!pHandle)
        return VERR_INVALID_HANDLE;
    hostoffset = fch_host_fileoffset(pClient, root, Handle, offset);
    quota_start_op(&qop, pClient, root, Handle, NULL);
    delta = hostoffset + *pcbBuffer - quota_get_filesize(&qop);
    if (delta > 0) {
        if (RT_FAILURE(quota_set_delta(&qop, delta))) {
            LogRel(("Error: quota exceeded for write h=0x%llx off=%lld len=%d\n",
                    Handle, offset, *pcbBuffer));
            return VERR_DISK_FULL;
        }
    }

    rc = RTFileSeek(pHandle->file.Handle,
                    hostoffset,
                    RTFILE_SEEK_BEGIN, NULL);
    if (RT_FAILURE(rc))
        return rc;

    fch_crypt(pClient, Handle, pBuffer, offset, *pcbBuffer);
    if (*pcbBuffer >= 4)
        Log(("RTFileWrite hostoff=%x %02x %02x %02x %02x\n", (int)hostoffset, pBuffer[0], pBuffer[1], pBuffer[2], pBuffer[3]));
    rc = RTFileWrite(pHandle->file.Handle, pBuffer, *pcbBuffer, &count);
    *pcbBuffer = (uint32_t)count;
    if (RT_SUCCESS(rc))
        quota_complete_op(&qop);
    Log(("RTFileWrite returned 0x%x bytes written %x\n", rc, count));
    return rc;
}


#ifdef UNITTEST
/** Unit test the SHFL_FN_FLUSH API.  Located here as a form of API
 * documentation. */
void testFlush(RTTEST hTest)
{
    /* If the number or types of parameters are wrong the API should fail. */
    testFlushBadParameters(hTest);
    /* Simple opening and flushing of a file. */
    testFlushFileSimple(hTest);
    /* Add tests as required... */
}
#endif
int vbsfFlush(SHFLCLIENTDATA *pClient, SHFLROOT root, SHFLHANDLE Handle)
{
    SHFLFILEHANDLE *pHandle = vbsfQueryFileHandle(pClient, Handle);
    struct shfl_handle_data *data;
    int rc = VINF_SUCCESS;

    if (pHandle == 0)
    {
        AssertFailed();
        return VERR_INVALID_HANDLE;
    }

    data = vbsfQueryHandleData(pClient, Handle);
    if (data->folder_opts & SF_OPT_NO_FLUSH)
        return VINF_SUCCESS;
    Log(("vbsfFlush 0x%llx\n", Handle));
    rc = RTFileFlush(pHandle->file.Handle);
    AssertRC(rc);
    return rc;
}

#ifdef UNITTEST
/** Unit test the SHFL_FN_LIST API.  Located here as a form of API
 * documentation. */
void testDirList(RTTEST hTest)
{
    /* If the number or types of parameters are wrong the API should fail. */
    testDirListBadParameters(hTest);
    /* Test listing an empty directory (simple edge case). */
    testDirListEmpty(hTest);
    /* Add tests as required... */
}
#endif

static int
hidden(SHFLROOT root, wchar_t *dir, wchar_t *entry)
{
    wchar_t name[512] = { 0 };
    int len = wcslen(dir);
    int i;

    if (len + wcslen(entry) + 2 >= 512)
        return 0;
    wcscat(name, dir);
    i = len-1;
    while (i > 0 && name[i] != '\\')
        name[i--] = 0;
    wcscat(name, entry);
    return _sf_hidden_path(root, name);
}

int vbsfDirList(SHFLCLIENTDATA *pClient, SHFLROOT root, SHFLHANDLE Handle, SHFLSTRING *pPath, uint32_t flags,
                uint32_t *pcbBuffer, uint8_t *pBuffer, uint32_t *pIndex, uint32_t *pcFiles)
{
    SHFLFILEHANDLE *pHandle = vbsfQueryDirHandle(pClient, Handle);
    PRTDIRENTRYEX  pDirEntry = 0, pDirEntryOrg;
    uint32_t       cbDirEntry, cbBufferOrg;
    int            rc = VINF_SUCCESS;
    PSHFLDIRINFO   pSFDEntry;
    PRTUTF16       pwszString;
    PRTDIR         DirHandle;
    int            crypt_mode;

    if (pHandle == 0 || pcbBuffer == 0 || pBuffer == 0)
    {
        AssertFailed();
        return VERR_INVALID_PARAMETER;
    }
    Assert(pIndex && *pIndex == 0);
    DirHandle = pHandle->dir.Handle;

    cbDirEntry = 4096;
    pDirEntryOrg = pDirEntry  = (PRTDIRENTRYEX)RTMemAlloc(cbDirEntry);
    if (pDirEntry == 0)
    {
        AssertFailed();
        return VERR_NO_MEMORY;
    }

    cbBufferOrg = *pcbBuffer;
    *pcbBuffer  = 0;
    pSFDEntry   = (PSHFLDIRINFO)pBuffer;

    *pIndex = 1; /* not yet complete */
    *pcFiles = 0;

    if (pPath)
    {
        if (pHandle->dir.SearchHandle == 0)
        {
            /* Build a host full path for the given path
             * and convert ucs2 to utf8 if necessary.
             */
            wchar_t *pszFullPath = NULL;

            Assert(pHandle->dir.pLastValidEntry == 0);

            rc = vbsfBuildFullPathUcs(pClient, root, pPath, pPath->u16Size, &pszFullPath, NULL, true, false);

            if (RT_SUCCESS(rc))
            {
                rc = RTDirOpenFilteredUcs(&pHandle->dir.SearchHandle, pszFullPath, RTDIRFILTER_WINNT, 0);

                /* free the path string */
                RTMemFree(pszFullPath);

                if (RT_FAILURE(rc))
                    goto end;
            }
            else
                goto end;
        }
        Assert(pHandle->dir.SearchHandle);
        DirHandle = pHandle->dir.SearchHandle;
    }

    crypt_mode = 0;
    fch_query_crypt_by_path(pClient, root, DirHandle->pwszPath, &crypt_mode);

    while (cbBufferOrg)
    {
        size_t cbDirEntrySize = cbDirEntry;
        uint32_t cbNeeded;

        /* Do we still have a valid last entry for the active search? If so, then return it here */
        if (pHandle->dir.pLastValidEntry)
        {
            pDirEntry = pHandle->dir.pLastValidEntry;
        }
        else
        {
            pDirEntry = pDirEntryOrg;

            rc = RTDirReadExUcs(DirHandle, pDirEntry, &cbDirEntrySize, RTFSOBJATTRADD_NOTHING, SHFL_RT_LINK(pClient));
            if (rc == VERR_NO_MORE_FILES)
            {
                *pIndex = 0; /* listing completed */
                break;
            }

            if (   rc != VINF_SUCCESS
                && rc != VWRN_NO_DIRENT_INFO)
            {
                //AssertFailed();
                if (   rc == VERR_NO_TRANSLATION
                    || rc == VERR_INVALID_UTF8_ENCODING)
                    continue;
                break;
            }
        }

        if (hidden(root, DirHandle->pwszPath, (wchar_t*)pDirEntry->szName))
            continue;

        cbNeeded = RT_OFFSETOF(SHFLDIRINFO, name.String);
        /* Overestimating, but that's ok */
        cbNeeded += pDirEntry->cbName + 2;

        if (cbBufferOrg < cbNeeded)
        {
            /* No room, so save this directory entry, or else it's lost forever */
            pHandle->dir.pLastValidEntry = pDirEntry;

            if (*pcFiles == 0)
            {
                AssertFailed();
                return VINF_BUFFER_OVERFLOW;    /* Return directly and don't free pDirEntry */
            }
            return VINF_SUCCESS;    /* Return directly and don't free pDirEntry */
        }

#ifdef RT_OS_WINDOWS
        pDirEntry->Info.Attr.fMode |= 0111;
#endif
        vbfsCopyFsObjInfoFromIprt(&pSFDEntry->Info, &pDirEntry->Info);
        pSFDEntry->cucShortName = 0;

        
        pSFDEntry->name.String.ucs2[0] = 0;
        pwszString = pSFDEntry->name.String.ucs2;
        wcscpy(pwszString, (wchar_t*)pDirEntry->szName);

        pSFDEntry->name.u16Length = (uint32_t)wcslen(pSFDEntry->name.String.ucs2) * 2;
        pSFDEntry->name.u16Size = pSFDEntry->name.u16Length + 2;

        Log(("SHFL: File name size %d\n", pSFDEntry->name.u16Size));
        Log(("SHFL: File name %ls\n", &pSFDEntry->name.String.ucs2));

        // adjust cbNeeded (it was overestimated before)
        cbNeeded = RT_OFFSETOF(SHFLDIRINFO, name.String) + pSFDEntry->name.u16Size;

        /* adjust reported file length for crypted files.
         * HACK warning: to be fully correct it would need to inspect the file to see if it's
         * actually scrambled or not. That's very slow for large directories, so we rely on current
         * crypt settings for that folder instead */
        if (crypt_mode && pSFDEntry->Info.cbObject >= CRYPT_HDR_FIXED_SIZE)
            pSFDEntry->Info.cbObject -= CRYPT_HDR_FIXED_SIZE;

        pSFDEntry   = (PSHFLDIRINFO)((uintptr_t)pSFDEntry + cbNeeded);
        *pcbBuffer += cbNeeded;
        cbBufferOrg-= cbNeeded;

        *pcFiles   += 1;

        /* Free the saved last entry, that we've just returned */
        if (pHandle->dir.pLastValidEntry)
        {
            RTMemFree(pHandle->dir.pLastValidEntry);
            pHandle->dir.pLastValidEntry = NULL;
        }

        if (flags & SHFL_LIST_RETURN_ONE)
            break; /* we're done */
    }
    Assert(rc != VINF_SUCCESS || *pcbBuffer > 0);

end:
    if (pDirEntry)
        RTMemFree(pDirEntry);

    return rc;
}

#ifdef UNITTEST
/** Unit test the SHFL_FN_READLINK API.  Located here as a form of API
 * documentation. */
void testReadLink(RTTEST hTest)
{
    /* If the number or types of parameters are wrong the API should fail. */
    testReadLinkBadParameters(hTest);
    /* Add tests as required... */
}
#endif
int vbsfReadLink(SHFLCLIENTDATA *pClient, SHFLROOT root, SHFLSTRING *pPath, uint32_t cbPath, uint8_t *pBuffer, uint32_t cbBuffer)
{
#ifdef ORIGINAL_VBOX    
    int rc = VINF_SUCCESS;

    if (pPath == 0 || pBuffer == 0)
    {
        AssertFailed();
        return VERR_INVALID_PARAMETER;
    }

    /* Build a host full path for the given path, handle file name case issues
     * (if the guest expects case-insensitive paths but the host is
     * case-sensitive) and convert ucs2 to utf8 if necessary.
     */
    char *pszFullPath = NULL;
    uint32_t cbFullPathRoot = 0;

    rc = vbsfBuildFullPath(pClient, root, pPath, cbPath, &pszFullPath, &cbFullPathRoot, false, false);

    if (RT_SUCCESS(rc))
    {
        rc = RTSymlinkRead(pszFullPath, (char *) pBuffer, cbBuffer, 0);

        /* free the path string */
        vbsfFreeFullPath(pszFullPath);
    }

    return rc;
#endif
    return VERR_NOT_IMPLEMENTED;
}

int vbsfQueryFileInfo(SHFLCLIENTDATA *pClient, SHFLROOT root, SHFLHANDLE Handle, uint32_t flags, uint32_t *pcbBuffer, uint8_t *pBuffer)
{
    uint32_t type = vbsfQueryHandleType(pClient, Handle);
    int            rc = VINF_SUCCESS;
    SHFLFSOBJINFO   *pObjInfo = (SHFLFSOBJINFO *)pBuffer;
    RTFSOBJINFO    fileinfo;


    if (   !(type == SHFL_HF_TYPE_DIR || type == SHFL_HF_TYPE_FILE)
        || pcbBuffer == 0
        || pObjInfo == 0
        || *pcbBuffer < sizeof(SHFLFSOBJINFO))
    {
        AssertFailed();
        return VERR_INVALID_PARAMETER;
    }

    /* @todo other options */
    Assert(flags == (SHFL_INFO_GET|SHFL_INFO_FILE));

    *pcbBuffer  = 0;

    if (type == SHFL_HF_TYPE_DIR)
    {
        SHFLFILEHANDLE *pHandle = vbsfQueryDirHandle(pClient, Handle);
        if (!pHandle)
            return VERR_INVALID_HANDLE;
        rc = RTDirQueryInfo(pHandle->dir.Handle, &fileinfo, RTFSOBJATTRADD_NOTHING);
    }
    else
    {
        SHFLFILEHANDLE *pHandle = vbsfQueryFileHandle(pClient, Handle);
        if (!pHandle)
            return VERR_INVALID_HANDLE;
        rc = RTFileQueryInfo(pHandle->file.Handle, &fileinfo, RTFSOBJATTRADD_NOTHING);
        if (RT_SUCCESS(rc))
            fch_guest_fsinfo(pClient, root, Handle, &fileinfo);
#ifdef RT_OS_WINDOWS
        if (RT_SUCCESS(rc) && RTFS_IS_FILE(pObjInfo->Attr.fMode)) {
            pObjInfo->Attr.fMode |= 0111;
        }
#endif
    }
    if (rc == VINF_SUCCESS)
    {
        bool fWritable = false;
        int rc = fch_writable_file(pClient, root, Handle, NULL, &fWritable);
        if (RT_FAILURE(rc))
            fWritable = false;
        vbfsCopyFsObjInfoFromIprt(pObjInfo, &fileinfo);
        if (!fWritable)
            pObjInfo->Attr.fMode |= RTFS_DOS_READONLY;
        *pcbBuffer = sizeof(SHFLFSOBJINFO);
    }
    else
        AssertFailed();

    return rc;
}

static int vbsfSetFileInfo(SHFLCLIENTDATA *pClient, SHFLROOT root, SHFLHANDLE Handle, uint32_t flags, uint32_t *pcbBuffer, uint8_t *pBuffer)
{
    uint32_t type = vbsfQueryHandleType(pClient, Handle);
    int             rc = VINF_SUCCESS;
    SHFLFSOBJINFO  *pSFDEntry;

    if (   !(type == SHFL_HF_TYPE_DIR || type == SHFL_HF_TYPE_FILE)
        || pcbBuffer == 0
        || pBuffer == 0
        || *pcbBuffer < sizeof(SHFLFSOBJINFO))
    {
        AssertFailed();
        return VERR_INVALID_PARAMETER;
    }

    *pcbBuffer  = 0;
    pSFDEntry   = (SHFLFSOBJINFO *)pBuffer;

    Assert(flags == (SHFL_INFO_SET | SHFL_INFO_FILE));

    /* Change only the time values that are not zero */
    if (type == SHFL_HF_TYPE_DIR)
    {
        SHFLFILEHANDLE *pHandle = vbsfQueryDirHandle(pClient, Handle);
        if (!pHandle)
            return VERR_INVALID_HANDLE;
        rc = RTDirSetTimes(pHandle->dir.Handle,
                            (RTTimeSpecGetNano(&pSFDEntry->AccessTime)) ?       &pSFDEntry->AccessTime : NULL,
                            (RTTimeSpecGetNano(&pSFDEntry->ModificationTime)) ? &pSFDEntry->ModificationTime: NULL,
                            (RTTimeSpecGetNano(&pSFDEntry->ChangeTime)) ?       &pSFDEntry->ChangeTime: NULL,
                            (RTTimeSpecGetNano(&pSFDEntry->BirthTime)) ?        &pSFDEntry->BirthTime: NULL
                            );
    }
    else
    {
        SHFLFILEHANDLE *pHandle = vbsfQueryFileHandle(pClient, Handle);
        if (!pHandle)
            return VERR_INVALID_HANDLE;
        rc = RTFileSetTimes(pHandle->file.Handle,
                            (RTTimeSpecGetNano(&pSFDEntry->AccessTime)) ?       &pSFDEntry->AccessTime : NULL,
                            (RTTimeSpecGetNano(&pSFDEntry->ModificationTime)) ? &pSFDEntry->ModificationTime: NULL,
                            (RTTimeSpecGetNano(&pSFDEntry->ChangeTime)) ?       &pSFDEntry->ChangeTime: NULL,
                            (RTTimeSpecGetNano(&pSFDEntry->BirthTime)) ?        &pSFDEntry->BirthTime: NULL
                            );
    }
    if (rc != VINF_SUCCESS)
    {
        Log(("RTFileSetTimes failed with 0x%x\n", rc));
        Log(("AccessTime       0x%llx\n", RTTimeSpecGetNano(&pSFDEntry->AccessTime)));
        Log(("ModificationTime 0x%llx\n", RTTimeSpecGetNano(&pSFDEntry->ModificationTime)));
        Log(("ChangeTime       0x%llx\n", RTTimeSpecGetNano(&pSFDEntry->ChangeTime)));
        Log(("BirthTime        0x%llx\n", RTTimeSpecGetNano(&pSFDEntry->BirthTime)));
        /* temporary hack */
        rc = VINF_SUCCESS;
    }

    if (type == SHFL_HF_TYPE_FILE)
    {
        SHFLFILEHANDLE *pHandle = vbsfQueryFileHandle(pClient, Handle);
        if (!pHandle)
            return VERR_INVALID_HANDLE;
        /* Change file attributes if necessary */
        if (pSFDEntry->Attr.fMode)
        {
            RTFMODE fMode = pSFDEntry->Attr.fMode;

#ifndef RT_OS_WINDOWS
            /* Don't allow the guest to clear the own bit, otherwise the guest wouldn't be
             * able to access this file anymore. Only for guests, which set the UNIX mode. */
            if (fMode & RTFS_UNIX_MASK)
                fMode |= RTFS_UNIX_IRUSR;
#endif

            rc = RTFileSetMode(pHandle->file.Handle, fMode);
            if (rc != VINF_SUCCESS)
            {
                Log(("RTFileSetMode %x failed with 0x%x\n", fMode, rc));
                /* silent failure, because this tends to fail with e.g. windows guest & linux host */
                rc = VINF_SUCCESS;
            }
        }
    }
    /* TODO: mode for directories */

    if (rc == VINF_SUCCESS)
    {
        uint32_t bufsize = sizeof(*pSFDEntry);

        rc = vbsfQueryFileInfo(pClient, root, Handle, SHFL_INFO_GET|SHFL_INFO_FILE, &bufsize, (uint8_t *)pSFDEntry);
        if (rc == VINF_SUCCESS)
        {
            *pcbBuffer = sizeof(SHFLFSOBJINFO);
        }
        else
            AssertFailed();
    }

    return rc;
}


static
int rewrite_empty_portion(SHFLCLIENTDATA *pClient, SHFLROOT root, SHFLHANDLE handle,
                          uint64_t guest_off, uint64_t len)
{
    uint8_t zeroes[32768];
    uint64_t p = guest_off;
    int rc;

    while (len) {
        uint32_t n = len;
        if (n > sizeof(zeroes))
            n = sizeof(zeroes);
        memset(zeroes, 0, n); // vbsfWrite can modify buffer contents
        rc = vbsfWrite(pClient, root, handle, p, &n, zeroes);
        if (RT_FAILURE(rc))
            return rc;
        len -= n;
        p += n;
    }
    return VINF_SUCCESS;
}

static
int resize_file(SHFLCLIENTDATA *pClient, SHFLROOT root, SHFLHANDLE handle,
                uint64_t sz)
{
    SHFLFILEHANDLE *pHandle = vbsfQueryFileHandle(pClient, handle);
    RTFSOBJINFO fileinfo;
    int crypt_mode = 0;
    uint64_t prev_sz, prev_sz_guest;
    int rc;
    struct quota_op qop;

    if (!pHandle)
        return VERR_INVALID_HANDLE;

    rc = fch_query_crypt_by_handle(pClient, root, handle, &crypt_mode);
    if (RT_FAILURE(rc))
        return rc;

    rc = RTFileQueryInfo(pHandle->file.Handle, &fileinfo, RTFSOBJATTRADD_NOTHING);
    if (RT_FAILURE(rc))
        return rc;

    prev_sz = fileinfo.cbObject;
    fch_guest_fsinfo(pClient, root, handle, &fileinfo);
    prev_sz_guest = fileinfo.cbObject;
    quota_start_op(&qop, pClient, root, handle, NULL);
    if (RT_FAILURE(quota_set_delta(&qop, sz - prev_sz)))
        return VERR_DISK_FULL;
    rc = RTFileSetSize(pHandle->file.Handle, sz);
    if (rc != VINF_SUCCESS)
        return rc;
    quota_complete_op(&qop);
    /* if encryption in use and file was extended, we need to rewrite the extended part */
    if (crypt_mode && sz > prev_sz) {
        rc = rewrite_empty_portion(pClient, root, handle,
                                   prev_sz_guest,
                                   sz - prev_sz);
        if (RT_FAILURE(rc))
            return rc;
    }
    return VINF_SUCCESS;
}

static
int vbsfSetEndOfFile(SHFLCLIENTDATA *pClient, SHFLROOT root, SHFLHANDLE Handle,
                     uint32_t flags, uint32_t *pcbBuffer, uint8_t *pBuffer)
{
    SHFLFILEHANDLE *pHandle = vbsfQueryFileHandle(pClient, Handle);
    int             rc = VINF_SUCCESS;
    SHFLFSOBJINFO  *pSFDEntry;

    if (pHandle == 0 || pcbBuffer == 0 || pBuffer == 0 || *pcbBuffer < sizeof(SHFLFSOBJINFO))
    {
        AssertFailed();
        return VERR_INVALID_PARAMETER;
    }

    *pcbBuffer  = 0;
    pSFDEntry   = (SHFLFSOBJINFO *)pBuffer;

    if (flags & SHFL_INFO_SIZE)
    {
        /* add crypt hdr if truncating to 0 len */
        int crypt_mode;
        uint64_t sz;

        rc = fch_query_crypt_by_handle(pClient, root, Handle, &crypt_mode);
        if (RT_SUCCESS(rc) && crypt_mode) {
            if (pSFDEntry->cbObject == 0 &&
                !(vbsfQueryHandleFlags(pClient, Handle) & SHFL_HF_ENCRYPTED)) {
                rc = fch_create_crypt_hdr(pClient, root, Handle);
                if (RT_FAILURE(rc))
                    return rc;
            }
        }
        sz = fch_host_fileoffset(pClient, root, Handle, pSFDEntry->cbObject);
        rc = resize_file(pClient, root, Handle, sz);
        if (rc != VINF_SUCCESS)
            return rc;
    }
    else
        AssertFailed();

    if (rc == VINF_SUCCESS)
    {
        RTFSOBJINFO fileinfo;

        /* Query the new object info and return it */
        rc = RTFileQueryInfo(pHandle->file.Handle, &fileinfo, RTFSOBJATTRADD_NOTHING);
        if (rc == VINF_SUCCESS)
        {
            fch_guest_fsinfo(pClient, root, Handle, &fileinfo);
#ifdef RT_OS_WINDOWS
            fileinfo.Attr.fMode |= 0111;
#endif
            vbfsCopyFsObjInfoFromIprt(pSFDEntry, &fileinfo);
            *pcbBuffer = sizeof(SHFLFSOBJINFO);
        }
        else
            AssertFailed();
    }

    return rc;
}

int vbsfQueryVolumeInfo(SHFLCLIENTDATA *pClient, SHFLROOT root, uint32_t flags, uint32_t *pcbBuffer, uint8_t *pBuffer)
{
    int            rc = VINF_SUCCESS;
    SHFLVOLINFO   *pSFDEntry;
    wchar_t          *pszFullPath = NULL;
    SHFLSTRING     dummy;

    if (pcbBuffer == 0 || pBuffer == 0 || *pcbBuffer < sizeof(SHFLVOLINFO))
    {
        AssertFailed();
        return VERR_INVALID_PARAMETER;
    }

    /* @todo other options */
    Assert(flags == (SHFL_INFO_GET|SHFL_INFO_VOLUME));

    *pcbBuffer  = 0;
    pSFDEntry   = (PSHFLVOLINFO)pBuffer;

    ShflStringInitBuffer(&dummy, sizeof(dummy));
    rc = vbsfBuildFullPathUcs(pClient, root, &dummy, 0, &pszFullPath, NULL, false, false);

    if (RT_SUCCESS(rc))
    {
        rc = RTFsQuerySizesUnc(pszFullPath, &pSFDEntry->ullTotalAllocationBytes, &pSFDEntry->ullAvailableAllocationBytes, &pSFDEntry->ulBytesPerAllocationUnit, &pSFDEntry->ulBytesPerSector);
        if (rc != VINF_SUCCESS)
            goto exit;

#ifdef ORIGINAL_VBOX
        rc = RTFsQuerySerial(pszFullPath, &pSFDEntry->ulSerial);
        if (rc != VINF_SUCCESS)
            goto exit;
#endif
        memset(&pSFDEntry->ulSerial, 0, sizeof(pSFDEntry->ulSerial));

        RTFSPROPERTIES FsProperties;
        rc = RTFsQueryPropertiesUnc(pszFullPath, &FsProperties);
        if (rc != VINF_SUCCESS)
            goto exit;
        vbfsCopyFsPropertiesFromIprt(&pSFDEntry->fsProperties, &FsProperties);

        *pcbBuffer = sizeof(SHFLVOLINFO);
    }
    else AssertFailed();

exit:
    AssertMsg(rc == VINF_SUCCESS, ("failure: rc = 0x%x\n", rc));
    /* free the path string */
    RTMemFree(pszFullPath);
    return rc;
}

int vbsfQueryFSInfo(SHFLCLIENTDATA *pClient, SHFLROOT root, SHFLHANDLE Handle, uint32_t flags, uint32_t *pcbBuffer, uint8_t *pBuffer)
{
    if (pcbBuffer == 0 || pBuffer == 0)
    {
        AssertFailed();
        return VERR_INVALID_PARAMETER;
    }

    if (flags & SHFL_INFO_FILE)
        return vbsfQueryFileInfo(pClient, root, Handle, flags, pcbBuffer, pBuffer);

    if (flags & SHFL_INFO_VOLUME)
        return vbsfQueryVolumeInfo(pClient, root, flags, pcbBuffer, pBuffer);

    AssertFailed();
    return VERR_INVALID_PARAMETER;
}

#ifdef UNITTEST
/** Unit test the SHFL_FN_INFORMATION API.  Located here as a form of API
 * documentation. */
void testFSInfo(RTTEST hTest)
{
    /* If the number or types of parameters are wrong the API should fail. */
    testFSInfoBadParameters(hTest);
    /* Basic get and set file size test. */
    testFSInfoQuerySetFMode(hTest);
    /* Basic get and set dir atime test. */
    testFSInfoQuerySetDirATime(hTest);
    /* Basic get and set file atime test. */
    testFSInfoQuerySetFileATime(hTest);
    /* Basic set end of file. */
    testFSInfoQuerySetEndOfFile(hTest);
    /* Add tests as required... */
}
#endif
int vbsfSetFSInfo(SHFLCLIENTDATA *pClient, SHFLROOT root, SHFLHANDLE Handle, uint32_t flags, uint32_t *pcbBuffer, uint8_t *pBuffer)
{
    uint32_t type =   vbsfQueryHandleType(pClient, Handle)
                    & (SHFL_HF_TYPE_DIR|SHFL_HF_TYPE_FILE|SHFL_HF_TYPE_VOLUME);

    if (type == 0 || pcbBuffer == 0 || pBuffer == 0)
    {
        AssertFailed();
        return VERR_INVALID_PARAMETER;
    }

    /* is the guest allowed to write to this share? */
    bool fWritable;
    int rc = vbsfMappingsQueryWritable(pClient, root, &fWritable);
    if (RT_FAILURE(rc) || !fWritable)
        return VERR_WRITE_PROTECT;

    if (flags & SHFL_INFO_FILE)
        return vbsfSetFileInfo(pClient, root, Handle, flags, pcbBuffer, pBuffer);

    if (flags & SHFL_INFO_SIZE)
        return vbsfSetEndOfFile(pClient, root, Handle, flags, pcbBuffer, pBuffer);

//    if (flags & SHFL_INFO_VOLUME)
//        return vbsfVolumeInfo(pClient, root, Handle, flags, pcbBuffer, pBuffer);
    AssertFailed();
    return VERR_INVALID_PARAMETER;
}

static int
vbsfCompression(SHFLCLIENTDATA *pClient, SHFLROOT root, SHFLHANDLE Handle,
                uint32_t *compression, int set)
{
    uint32_t type = vbsfQueryHandleType(pClient, Handle);
    HANDLE winhandle = INVALID_HANDLE_VALUE;
    int rc = VINF_SUCCESS;

    if (type == SHFL_HF_TYPE_FILE) {
        SHFLFILEHANDLE *fh =  vbsfQueryFileHandle(pClient, Handle);

        if (!fh)
            return VERR_INVALID_PARAMETER;
        winhandle = fh->file.Handle;
    } else if (type == SHFL_HF_TYPE_DIR) {
        SHFLFILEHANDLE *fh =  vbsfQueryDirHandle(pClient, Handle);
        PRTDIR dir = fh->dir.Handle;

        if (!dir || !dir->pwszPath)
            return VERR_INVALID_PARAMETER;

        winhandle = CreateFileW(dir->pwszPath, GENERIC_READ|GENERIC_WRITE,
                   FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE,
                   NULL, OPEN_EXISTING,
                   FILE_FLAG_BACKUP_SEMANTICS, NULL);
        if (winhandle == INVALID_HANDLE_VALUE)
            return RTErrConvertFromWin32(GetLastError());
    } else
        return VERR_INVALID_PARAMETER;

    if (set) {
        USHORT compr = (USHORT) *compression;
        DWORD nbytes;

        if (!DeviceIoControl(winhandle, FSCTL_SET_COMPRESSION,
                             &compr, sizeof(compr),
                             NULL, 0, &nbytes, NULL))
            rc = RTErrConvertFromWin32(GetLastError());
    } else {
        USHORT compr = 0;
        DWORD nbytes;

        if (!DeviceIoControl(winhandle, FSCTL_GET_COMPRESSION,
                             NULL, 0,
                             &compr, sizeof(compr), &nbytes, NULL))
            rc = RTErrConvertFromWin32(GetLastError());
        else
            *compression = compr;
    }

    if (type == SHFL_HF_TYPE_DIR)
        CloseHandle(winhandle);

    return rc;
}

int
vbsfCompressionSet(SHFLCLIENTDATA *pClient, SHFLROOT root, SHFLHANDLE Handle, uint32_t compression)
{
    return vbsfCompression(pClient, root, Handle, &compression, 1);
}

int
vbsfCompressionGet(SHFLCLIENTDATA *pClient, SHFLROOT root, SHFLHANDLE Handle, uint32_t *compression)
{
    return vbsfCompression(pClient, root, Handle, compression, 0);
}

#ifdef UNITTEST
/** Unit test the SHFL_FN_LOCK API.  Located here as a form of API
 * documentation. */
void testLock(RTTEST hTest)
{
    /* If the number or types of parameters are wrong the API should fail. */
    testLockBadParameters(hTest);
    /* Simple file locking and unlocking test. */
    testLockFileSimple(hTest);
    /* Add tests as required... */
}
#endif
int vbsfLock(SHFLCLIENTDATA *pClient, SHFLROOT root, SHFLHANDLE Handle, uint64_t offset, uint64_t length, uint32_t flags)
{
    SHFLFILEHANDLE *pHandle = vbsfQueryFileHandle(pClient, Handle);
    uint32_t        fRTLock = 0;
    int             rc;

    Assert((flags & SHFL_LOCK_MODE_MASK) != SHFL_LOCK_CANCEL);

    if (pHandle == 0)
    {
        AssertFailed();
        return VERR_INVALID_HANDLE;
    }
    if (   ((flags & SHFL_LOCK_MODE_MASK) == SHFL_LOCK_CANCEL)
        || (flags & SHFL_LOCK_ENTIRE)
       )
    {
        AssertFailed();
        return VERR_INVALID_PARAMETER;
    }

    /* Lock type */
    switch(flags & SHFL_LOCK_MODE_MASK)
    {
    case SHFL_LOCK_SHARED:
        fRTLock = RTFILE_LOCK_READ;
        break;

    case SHFL_LOCK_EXCLUSIVE:
        fRTLock = RTFILE_LOCK_READ | RTFILE_LOCK_WRITE;
        break;

    default:
        AssertFailed();
        return VERR_INVALID_PARAMETER;
    }

    /* Lock wait type */
    if (flags & SHFL_LOCK_WAIT)
        fRTLock |= RTFILE_LOCK_WAIT;
    else
        fRTLock |= RTFILE_LOCK_IMMEDIATELY;

    offset = fch_host_fileoffset(pClient, root, Handle, offset);
#ifdef RT_OS_WINDOWS
    rc = RTFileLock(pHandle->file.Handle, fRTLock, offset, length);
    if (rc != VINF_SUCCESS)
        Log(("RTFileLock %RTfile 0x%llx 0x%llx failed with 0x%x\n", pHandle->file.Handle, offset, length, rc));
#else
    Log(("vbsfLock: Pretend success handle=%x\n", Handle));
    rc = VINF_SUCCESS;
#endif
    return rc;
}

int vbsfUnlock(SHFLCLIENTDATA *pClient, SHFLROOT root, SHFLHANDLE Handle, uint64_t offset, uint64_t length, uint32_t flags)
{
    SHFLFILEHANDLE *pHandle = vbsfQueryFileHandle(pClient, Handle);
    int             rc;

    Assert((flags & SHFL_LOCK_MODE_MASK) == SHFL_LOCK_CANCEL);

    if (pHandle == 0)
    {
        return VERR_INVALID_HANDLE;
    }
    if (   ((flags & SHFL_LOCK_MODE_MASK) != SHFL_LOCK_CANCEL)
        || (flags & SHFL_LOCK_ENTIRE)
       )
    {
       return VERR_INVALID_PARAMETER;
    }

    offset = fch_host_fileoffset(pClient, root, Handle, offset);
#ifdef RT_OS_WINDOWS
    rc = RTFileUnlock(pHandle->file.Handle, offset, length);
    if (rc != VINF_SUCCESS)
        Log(("RTFileUnlock %RTfile 0x%llx %RTX64 failed with 0x%x\n", pHandle->file.Handle, offset, length, rc));
#else
    Log(("vbsfUnlock: Pretend success handle=%x\n", Handle));
    rc = VINF_SUCCESS;
#endif

    return rc;
}


#ifdef UNITTEST
/** Unit test the SHFL_FN_REMOVE API.  Located here as a form of API
 * documentation. */
void testRemove(RTTEST hTest)
{
    /* If the number or types of parameters are wrong the API should fail. */
    testRemoveBadParameters(hTest);
    /* Add tests as required... */
}
#endif
int vbsfRemove(SHFLCLIENTDATA *pClient, SHFLROOT root, SHFLSTRING *pPath, uint32_t cbPath, uint32_t flags)
{
    int rc = VINF_SUCCESS;

    /* Validate input */
    if (   flags & ~(SHFL_REMOVE_FILE|SHFL_REMOVE_DIR|SHFL_REMOVE_SYMLINK)
        || cbPath == 0
        || pPath == 0)
    {
        AssertFailed();
        return VERR_INVALID_PARAMETER;
    }

    /* Build a host full path for the given path
     * and convert ucs2 to utf8 if necessary.
     */
    wchar_t *pszFullPath = NULL;

    rc = vbsfBuildFullPathUcs(pClient, root, pPath, cbPath, &pszFullPath, NULL, false, false);
    if (RT_SUCCESS(rc))
    {
        /* is the guest allowed to write to this share? */
        bool fWritable;
        rc = vbsfMappingsQueryWritable(pClient, root, &fWritable);

        if (RT_FAILURE(rc) || !fWritable)
            rc = VERR_WRITE_PROTECT;

        if (RT_SUCCESS(rc))
        {
            if (flags & SHFL_REMOVE_SYMLINK)
                rc = VERR_NOT_IMPLEMENTED;
            else if (flags & SHFL_REMOVE_FILE) {
                struct quota_op qop;

                quota_start_op(&qop, pClient, root, SHFL_HANDLE_NIL, pszFullPath);
                quota_set_delta(&qop, -quota_get_filesize(&qop));
                rc = RTFileDeleteUcs(pszFullPath);
                if (RT_SUCCESS(rc))
                    quota_complete_op(&qop);
            } else
                rc = RTDirRemoveUcs(pszFullPath);
        }

#ifndef DEBUG_dmik
        // VERR_ACCESS_DENIED for example?
        // Assert(rc == VINF_SUCCESS || rc == VERR_DIR_NOT_EMPTY);
#endif
        /* free the path string */
        RTMemFree(pszFullPath);
    }
    return rc;
}


#ifdef UNITTEST
/** Unit test the SHFL_FN_RENAME API.  Located here as a form of API
 * documentation. */
void testRename(RTTEST hTest)
{
    /* If the number or types of parameters are wrong the API should fail. */
    testRenameBadParameters(hTest);
    /* Add tests as required... */
}
#endif
int vbsfRename(SHFLCLIENTDATA *pClient, SHFLROOT root, SHFLSTRING *pSrc, SHFLSTRING *pDest, uint32_t flags)
{
    int rc = VINF_SUCCESS;

    /* Validate input */
    if (   flags & ~(SHFL_REMOVE_FILE|SHFL_REMOVE_DIR|SHFL_RENAME_REPLACE_IF_EXISTS)
        || pSrc == 0
        || pDest == 0)
    {
        AssertFailed();
        return VERR_INVALID_PARAMETER;
    }

    /* Build a host full path for the given path
     * and convert ucs2 to utf8 if necessary.
     */
    wchar_t *pszFullPathSrc = NULL;
    wchar_t *pszFullPathDest = NULL;

    rc = vbsfBuildFullPathUcs(pClient, root, pSrc, pSrc->u16Size, &pszFullPathSrc, NULL, false, false);
    if (rc != VINF_SUCCESS)
        return rc;

    rc = vbsfBuildFullPathUcs(pClient, root, pDest, pDest->u16Size, &pszFullPathDest, NULL, false, true);
    if (RT_SUCCESS (rc))
    {
        Log(("Rename %ls to %ls\n", pszFullPathSrc, pszFullPathDest));

        /* is the guest allowed to write to this share? */
        bool fWritable;
        rc = vbsfMappingsQueryWritable(pClient, root, &fWritable);

        if (RT_FAILURE(rc) || !fWritable)
            rc = VERR_WRITE_PROTECT;

        if (RT_SUCCESS(rc))
        {
            if (flags & SHFL_RENAME_FILE)
            {
                rc = RTFileMoveUcs(pszFullPathSrc, pszFullPathDest,
                                  ((flags & SHFL_RENAME_REPLACE_IF_EXISTS) ? RTFILEMOVE_FLAGS_REPLACE : 0));
            }
            else
            {
                /* NT ignores the REPLACE flag and simply return and already exists error. */
                rc = RTDirRenameUcs(pszFullPathSrc, pszFullPathDest,
                                   ((flags & SHFL_RENAME_REPLACE_IF_EXISTS) ? RTPATHRENAME_FLAGS_REPLACE : 0));
            }
        }

#ifndef DEBUG_dmik
        AssertRC(rc);
#endif
        /* free the path string */
        RTMemFree(pszFullPathDest);
    }
    /* free the path string */
    RTMemFree(pszFullPathSrc);
    return rc;
}

#ifdef UNITTEST
/** Unit test the SHFL_FN_SYMLINK API.  Located here as a form of API
 * documentation. */
void testSymlink(RTTEST hTest)
{
    /* If the number or types of parameters are wrong the API should fail. */
    testSymlinkBadParameters(hTest);
    /* Add tests as required... */
}
#endif
int vbsfSymlink(SHFLCLIENTDATA *pClient, SHFLROOT root, SHFLSTRING *pNewPath, SHFLSTRING *pOldPath, SHFLFSOBJINFO *pInfo)
{
#ifdef ORIGINAL_VBOX
    int rc = VINF_SUCCESS;

    char *pszFullNewPath = NULL;
    const char *pszOldPath = (const char *)pOldPath->String.utf8;

    /* XXX: no support for UCS2 at the moment. */
    if (!BIT_FLAG(pClient->fu32Flags, SHFL_CF_UTF8))
        return VERR_NOT_IMPLEMENTED;

    bool fSymlinksCreate;
    rc = vbsfMappingsQuerySymlinksCreate(pClient, root, &fSymlinksCreate);
    AssertRCReturn(rc, rc);
    if (!fSymlinksCreate)
        return VERR_WRITE_PROTECT; /* XXX or VERR_TOO_MANY_SYMLINKS? */

    rc = vbsfBuildFullPath(pClient, root, pNewPath, pNewPath->u16Size, &pszFullNewPath, NULL, false, false);
    AssertRCReturn(rc, rc);

    rc = RTSymlinkCreate(pszFullNewPath, (const char *)pOldPath->String.utf8,
                         RTSYMLINKTYPE_UNKNOWN, 0);
    if (RT_SUCCESS(rc))
    {
        RTFSOBJINFO info;
        rc = RTPathQueryInfoEx(pszFullNewPath, &info, RTFSOBJATTRADD_NOTHING, SHFL_RT_LINK(pClient));
        if (RT_SUCCESS(rc))
            vbfsCopyFsObjInfoFromIprt(pInfo, &info);
    }

    vbsfFreeFullPath(pszFullNewPath);

    return rc;
#endif
    return VERR_NOT_IMPLEMENTED;
}

/*
 * Clean up our mess by freeing all handles that are still valid.
 *
 */
int vbsfDisconnect(SHFLCLIENTDATA *pClient)
{
    for (int i=0; i<SHFLHANDLE_MAX; i++)
    {
        SHFLHANDLE Handle = (SHFLHANDLE)i;
        if (vbsfQueryHandleType(pClient, Handle))
        {
            LogRel(("Shared Folders - close leftover handle %08x\n", i));
            vbsfClose(pClient, SHFL_HANDLE_ROOT /* incorrect, but it's not important */, (SHFLHANDLE)i);
        }
    }
    return VINF_SUCCESS;
}
