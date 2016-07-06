/* $Id: fileio-win.cpp $ */
/** @file
 * IPRT - File I/O, native implementation for the Windows host platform.
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

/*******************************************************************************
*   Header Files                                                               *
*******************************************************************************/
#include <dm/config.h>
#define LOG_GROUP RTLOGGROUP_DIR
#ifndef _WIN32_WINNT
# define _WIN32_WINNT 0x0600
#endif
#include <windows.h>

#include <iprt/file.h>
#include <iprt/path.h>
#include <iprt/assert.h>
#include <iprt/string.h>
#include <iprt/err.h>
#include <iprt/log.h>
#include "internal/file.h"
#include "internal/fs.h"
#include "internal/path.h"
#include "rt/rtPathWin32MoveRenameUcs.h"
/*******************************************************************************
*   Defined Constants And Macros                                               *
*******************************************************************************/

#include <dm/debug.h>

/**
 * This is wrapper around the ugly SetFilePointer api.
 *
 * It's equivalent to SetFilePointerEx which we so unfortunately cannot use because of
 * it not being present in NT4 GA.
 *
 * @returns Success indicator. Extended error information obtainable using GetLastError().
 * @param   hFile       Filehandle.
 * @param   offSeek     Offset to seek.
 * @param   poffNew     Where to store the new file offset. NULL allowed.
 * @param   uMethod     Seek method. (The windows one!)
 */
DECLINLINE(bool) MySetFilePointer(RTFILE hFile, uint64_t offSeek, uint64_t *poffNew, unsigned uMethod)
{
    bool            fRc;
    LARGE_INTEGER   off;

    off.QuadPart = offSeek;
#if 1
    if (off.LowPart != INVALID_SET_FILE_POINTER)
    {
        off.LowPart = SetFilePointer((HANDLE)(uintptr_t)RTFileToNative(hFile), off.LowPart, &off.HighPart, uMethod);
        fRc = off.LowPart != INVALID_SET_FILE_POINTER;
    }
    else
    {
        SetLastError(NO_ERROR);
        off.LowPart = SetFilePointer((HANDLE)(uintptr_t)RTFileToNative(hFile), off.LowPart, &off.HighPart, uMethod);
        fRc = GetLastError() == NO_ERROR;
    }
#else
    fRc = SetFilePointerEx((HANDLE)(uintptr_t)RTFileToNative(hFile), off, &off, uMethod);
#endif
    if (fRc && poffNew)
        *poffNew = off.QuadPart;
    return fRc;
}


/**
 * This is a helper to check if an attempt was made to grow a file beyond the
 * limit of the filesystem.
 *
 * @returns true for file size limit exceeded.
 * @param   hFile       Filehandle.
 * @param   offSeek     Offset to seek.
 * @param   uMethod     The seek method.
 */
DECLINLINE(bool) IsBeyondLimit(RTFILE hFile, uint64_t offSeek, unsigned uMethod)
{
    bool fIsBeyondLimit = false;

    /*
     * Get the current file position and try set the new one.
     * If it fails with a seek error it's because we hit the file system limit.
     */
/** @todo r=bird: I'd be very interested to know on which versions of windows and on which file systems
 * this supposedly works. The fastfat sources in the latest WDK makes no limit checks during
 * file seeking, only at the time of writing (and some other odd ones we cannot make use of). */
    uint64_t offCurrent;
    if (MySetFilePointer(hFile, 0, &offCurrent, FILE_CURRENT))
    {
        if (!MySetFilePointer(hFile, offSeek, NULL, uMethod))
            fIsBeyondLimit = GetLastError() == ERROR_SEEK;
        else /* Restore file pointer on success. */
            MySetFilePointer(hFile, offCurrent, NULL, FILE_BEGIN);
    }

    return fIsBeyondLimit;
}


RTR3DECL(int) RTFileFromNative(PRTFILE pFile, RTHCINTPTR uNative)
{
    HANDLE h = (HANDLE)(uintptr_t)uNative;
    // AssertCompile(sizeof(h) == sizeof(uNative));
    if (h == INVALID_HANDLE_VALUE)
    {
        AssertMsgFailed(("%p\n", uNative));
        *pFile = NIL_RTFILE;
        return VERR_INVALID_HANDLE;
    }
    *pFile = (RTFILE)h;
    return VINF_SUCCESS;
}


RTR3DECL(RTHCINTPTR) RTFileToNative(RTFILE hFile)
{
    // AssertReturn(hFile != NIL_RTFILE, (RTHCINTPTR)INVALID_HANDLE_VALUE);
    return (RTHCINTPTR)(uintptr_t)hFile;
}


RTR3DECL(int) RTFileOpenUcs(PRTFILE pFile, const wchar_t *pwszFilename, uint64_t fOpen,
                            int *pfAlreadyExists,
                            int *pfCreated,
                            int *pfTruncated)
{
    if (pfAlreadyExists) *pfAlreadyExists = 0;
    if (pfCreated) *pfCreated = 0;
    if (pfTruncated) *pfTruncated = 0;

    /*
     * Validate input.
     */
    if (!pFile)
    {
        AssertMsgFailed(("Invalid pFile\n"));
        return VERR_INVALID_PARAMETER;
    }
    *pFile = NIL_RTFILE;
    if (!pwszFilename)
    {
        AssertMsgFailed(("Invalid pszFilename\n"));
        return VERR_INVALID_PARAMETER;
    }

    /*
     * Merge forced open flags and validate them.
     */
    int rc = rtFileRecalcAndValidateFlags(&fOpen);
    if (RT_FAILURE(rc))
        return rc;

    /*
     * Determine disposition, access, share mode, creation flags, and security attributes
     * for the CreateFile API call.
     */
    DWORD dwCreationDisposition;
    switch (fOpen & RTFILE_O_ACTION_MASK)
    {
        case RTFILE_O_OPEN:
            dwCreationDisposition = fOpen & RTFILE_O_TRUNCATE ? TRUNCATE_EXISTING : OPEN_EXISTING;
            break;
        case RTFILE_O_OPEN_CREATE:
            dwCreationDisposition = OPEN_ALWAYS;
            break;
        case RTFILE_O_CREATE:
            dwCreationDisposition = CREATE_NEW;
            break;
        case RTFILE_O_CREATE_REPLACE:
            dwCreationDisposition = CREATE_ALWAYS;
            break;
        default:
            AssertMsgFailed(("Impossible fOpen=%#llx\n", fOpen));
            return VERR_INVALID_PARAMETER;
    }

    DWORD dwDesiredAccess;
    switch (fOpen & RTFILE_O_ACCESS_MASK)
    {
        case RTFILE_O_READ:
            dwDesiredAccess = FILE_GENERIC_READ; /* RTFILE_O_APPEND is ignored. */
            break;
        case RTFILE_O_WRITE:
            /* we always permit read access, necessary for crypt code */
#if 0
            dwDesiredAccess = fOpen & RTFILE_O_APPEND
                            ? FILE_GENERIC_WRITE & ~FILE_WRITE_DATA
                            : FILE_GENERIC_WRITE;
            break;
#endif
        case RTFILE_O_READWRITE:
            dwDesiredAccess = fOpen & RTFILE_O_APPEND
                            ? FILE_GENERIC_READ | (FILE_GENERIC_WRITE & ~FILE_WRITE_DATA)
                            : FILE_GENERIC_READ | FILE_GENERIC_WRITE;
            break;
        default:
            AssertMsgFailed(("Impossible fOpen=%#llx\n", fOpen));
            return VERR_INVALID_PARAMETER;
    }
    if (dwCreationDisposition == TRUNCATE_EXISTING ||
        /* write during CREATE_ALWAYS/CREATE_NEW required for writing crypt hdr */
        dwCreationDisposition == CREATE_ALWAYS ||
        dwCreationDisposition == CREATE_NEW)
        /* Required for truncating the file (see MSDN), it is *NOT* part of FILE_GENERIC_WRITE. */
        dwDesiredAccess |= GENERIC_WRITE;

    /* RTFileSetMode needs following rights as well. */
    switch (fOpen & RTFILE_O_ACCESS_ATTR_MASK)
    {
        case RTFILE_O_ACCESS_ATTR_READ:      dwDesiredAccess |= FILE_READ_ATTRIBUTES  | SYNCHRONIZE; break;
        case RTFILE_O_ACCESS_ATTR_WRITE:     dwDesiredAccess |= FILE_WRITE_ATTRIBUTES | SYNCHRONIZE; break;
        case RTFILE_O_ACCESS_ATTR_READWRITE: dwDesiredAccess |= FILE_READ_ATTRIBUTES | FILE_WRITE_ATTRIBUTES | SYNCHRONIZE; break;
        default:
            /* Attributes access is the same as the file access. */
            switch (fOpen & RTFILE_O_ACCESS_MASK)
            {
                case RTFILE_O_READ:          dwDesiredAccess |= FILE_READ_ATTRIBUTES  | SYNCHRONIZE; break;
                case RTFILE_O_WRITE:         dwDesiredAccess |= FILE_WRITE_ATTRIBUTES | SYNCHRONIZE; break;
                case RTFILE_O_READWRITE:     dwDesiredAccess |= FILE_READ_ATTRIBUTES | FILE_WRITE_ATTRIBUTES | SYNCHRONIZE; break;
                default:
                    AssertMsgFailed(("Impossible fOpen=%#llx\n", fOpen));
                    return VERR_INVALID_PARAMETER;
            }
    }

    DWORD dwShareMode;
    switch (fOpen & RTFILE_O_DENY_MASK)
    {
        case RTFILE_O_DENY_NONE:                                dwShareMode = FILE_SHARE_READ | FILE_SHARE_WRITE; break;
        case RTFILE_O_DENY_READ:                                dwShareMode = FILE_SHARE_WRITE; break;
        case RTFILE_O_DENY_WRITE:                               dwShareMode = FILE_SHARE_READ; break;
        case RTFILE_O_DENY_READWRITE:                           dwShareMode = 0; break;

        case RTFILE_O_DENY_NOT_DELETE | RTFILE_O_DENY_NONE:     dwShareMode = FILE_SHARE_DELETE | FILE_SHARE_READ | FILE_SHARE_WRITE; break;
        case RTFILE_O_DENY_NOT_DELETE | RTFILE_O_DENY_READ:     dwShareMode = FILE_SHARE_DELETE | FILE_SHARE_READ | FILE_SHARE_WRITE; break;
        case RTFILE_O_DENY_NOT_DELETE | RTFILE_O_DENY_WRITE:    dwShareMode = FILE_SHARE_DELETE | FILE_SHARE_READ; break;
        case RTFILE_O_DENY_NOT_DELETE | RTFILE_O_DENY_READWRITE:dwShareMode = FILE_SHARE_READ | FILE_SHARE_DELETE; break;
        default:
            AssertMsgFailed(("Impossible fOpen=%#llx\n", fOpen));
            return VERR_INVALID_PARAMETER;
    }

    /* we always share read access, necessary for crypt code */
    dwShareMode |= FILE_SHARE_READ;

    SECURITY_ATTRIBUTES  SecurityAttributes;
    PSECURITY_ATTRIBUTES pSecurityAttributes = NULL;
    if (fOpen & RTFILE_O_INHERIT)
    {
        SecurityAttributes.nLength              = sizeof(SecurityAttributes);
        SecurityAttributes.lpSecurityDescriptor = NULL;
        SecurityAttributes.bInheritHandle       = TRUE;
        pSecurityAttributes = &SecurityAttributes;
    }

    DWORD dwFlagsAndAttributes;
    dwFlagsAndAttributes = FILE_ATTRIBUTE_NORMAL;
    if (fOpen & RTFILE_O_WRITE_THROUGH)
        dwFlagsAndAttributes |= FILE_FLAG_WRITE_THROUGH;
    if (fOpen & RTFILE_O_ASYNC_IO)
        dwFlagsAndAttributes |= FILE_FLAG_OVERLAPPED;
    if (fOpen & RTFILE_O_NO_CACHE)
    {
        dwFlagsAndAttributes |= FILE_FLAG_NO_BUFFERING;
        dwDesiredAccess &= ~FILE_APPEND_DATA;
    }

    /*
     * Open/Create the file.
     */

    HANDLE hFile = CreateFileW(pwszFilename,
                               dwDesiredAccess,
                               dwShareMode,
                               pSecurityAttributes,
                               dwCreationDisposition,
                               dwFlagsAndAttributes,
                               NULL);
    if (hFile != INVALID_HANDLE_VALUE)
    {
        bool fCreated = dwCreationDisposition == CREATE_ALWAYS
                     || dwCreationDisposition == CREATE_NEW
                     || (dwCreationDisposition == OPEN_ALWAYS && GetLastError() == 0);

        if (pfCreated)
            *pfCreated = fCreated;
        /*
         * Turn off indexing of directory through Windows Indexing Service.
         */
        if (    fCreated
            &&  (fOpen & RTFILE_O_NOT_CONTENT_INDEXED))
        {
            if (!SetFileAttributesW(pwszFilename, FILE_ATTRIBUTE_NOT_CONTENT_INDEXED))
                rc = RTErrConvertFromWin32(GetLastError());
        }
        /*
         * Do we need to truncate the file?
         */
        else if (    !fCreated
                 &&     (fOpen & (RTFILE_O_TRUNCATE | RTFILE_O_ACTION_MASK))
                     == (RTFILE_O_TRUNCATE | RTFILE_O_OPEN_CREATE))
        {
            if (pfTruncated)
                *pfTruncated = 1;
            if (!SetEndOfFile(hFile))
                rc = RTErrConvertFromWin32(GetLastError());
        }
        else if ( GetLastError() == ERROR_ALREADY_EXISTS
                   && dwCreationDisposition == OPEN_ALWAYS
                   && pfAlreadyExists)
            *pfAlreadyExists = 1;

        if (RT_SUCCESS(rc))
        {
            *pFile = (RTFILE)hFile;
            Assert((HANDLE)(uintptr_t)*pFile == hFile);
            return VINF_SUCCESS;
        }
        CloseHandle(hFile);
    }
    else
        rc = RTErrConvertFromWin32(GetLastError());
    return rc;
}


RTR3DECL(int)  RTFileClose(RTFILE hFile)
{
    if (hFile == NIL_RTFILE)
        return VINF_SUCCESS;
    if (CloseHandle((HANDLE)(uintptr_t)RTFileToNative(hFile)))
        return VINF_SUCCESS;
    return RTErrConvertFromWin32(GetLastError());
}



RTR3DECL(int)  RTFileSeek(RTFILE hFile, int64_t offSeek, unsigned uMethod, uint64_t *poffActual)
{
    static ULONG aulSeekRecode[] =
    {
        FILE_BEGIN,
        FILE_CURRENT,
        FILE_END,
    };

    /*
     * Validate input.
     */
    if (uMethod > RTFILE_SEEK_END)
    {
        AssertMsgFailed(("Invalid uMethod=%d\n", uMethod));
        return VERR_INVALID_PARAMETER;
    }

    /*
     * Execute the seek.
     */
    if (MySetFilePointer(hFile, offSeek, poffActual, aulSeekRecode[uMethod]))
        return VINF_SUCCESS;
    return RTErrConvertFromWin32(GetLastError());
}


RTR3DECL(int)  RTFileRead(RTFILE hFile, void *pvBuf, size_t cbToRead, size_t *pcbRead)
{
    if (cbToRead <= 0)
        return VINF_SUCCESS;
    ULONG cbToReadAdj = (ULONG)cbToRead;
    AssertReturn(cbToReadAdj == cbToRead, VERR_NUMBER_TOO_BIG);

    ULONG cbRead = 0;
    if (ReadFile((HANDLE)(uintptr_t)RTFileToNative(hFile), pvBuf, cbToReadAdj, &cbRead, NULL))
    {
        if (pcbRead)
            /* Caller can handle partial reads. */
            *pcbRead = cbRead;
        else
        {
            /* Caller expects everything to be read. */
            while (cbToReadAdj > cbRead)
            {
                ULONG cbReadPart = 0;
                if (!ReadFile((HANDLE)(uintptr_t)RTFileToNative(hFile), (char*)pvBuf + cbRead, cbToReadAdj - cbRead, &cbReadPart, NULL))
                    return RTErrConvertFromWin32(GetLastError());
                if (cbReadPart == 0)
                    return VERR_EOF;
                cbRead += cbReadPart;
            }
        }
        return VINF_SUCCESS;
    }

    /*
     * If it's a console, we might bump into out of memory conditions in the
     * ReadConsole call.
     */
    DWORD dwErr = GetLastError();
    if (dwErr == ERROR_NOT_ENOUGH_MEMORY)
    {
        ULONG cbChunk = cbToReadAdj / 2;
        if (cbChunk > 16*_1K)
            cbChunk = 16*_1K;
        else
            cbChunk = RT_ALIGN_32(cbChunk, 256);

        cbRead = 0;
        while (cbToReadAdj > cbRead)
        {
            ULONG cbToRead   = RT_MIN(cbChunk, cbToReadAdj - cbRead);
            ULONG cbReadPart = 0;
            if (!ReadFile((HANDLE)(uintptr_t)RTFileToNative(hFile), (char *)pvBuf + cbRead, cbToRead, &cbReadPart, NULL))
            {
                /* If we failed because the buffer is too big, shrink it and
                   try again. */
                dwErr = GetLastError();
                if (   dwErr == ERROR_NOT_ENOUGH_MEMORY
                    && cbChunk > 8)
                {
                    cbChunk /= 2;
                    continue;
                }
                return RTErrConvertFromWin32(dwErr);
            }
            cbRead += cbReadPart;

            /* Return if the caller can handle partial reads, otherwise try
               fill the buffer all the way up. */
            if (pcbRead)
            {
                *pcbRead = cbRead;
                break;
            }
            if (cbReadPart == 0)
                return VERR_EOF;
        }
        return VINF_SUCCESS;
    }

    return RTErrConvertFromWin32(dwErr);
}


RTR3DECL(int)  RTFileWrite(RTFILE hFile, const void *pvBuf, size_t cbToWrite, size_t *pcbWritten)
{
    if (cbToWrite <= 0)
        return VINF_SUCCESS;
    ULONG cbToWriteAdj = (ULONG)cbToWrite;
    AssertReturn(cbToWriteAdj == cbToWrite, VERR_NUMBER_TOO_BIG);

    ULONG cbWritten = 0;
    if (WriteFile((HANDLE)(uintptr_t)RTFileToNative(hFile), pvBuf, cbToWriteAdj, &cbWritten, NULL))
    {
        if (pcbWritten)
            /* Caller can handle partial writes. */
            *pcbWritten = cbWritten;
        else
        {
            /* Caller expects everything to be written. */
            while (cbToWriteAdj > cbWritten)
            {
                ULONG cbWrittenPart = 0;
                if (!WriteFile((HANDLE)(uintptr_t)RTFileToNative(hFile), (char*)pvBuf + cbWritten,
                               cbToWriteAdj - cbWritten, &cbWrittenPart, NULL))
                {
                    int rc = RTErrConvertFromWin32(GetLastError());
                    if (   rc == VERR_DISK_FULL
                        && IsBeyondLimit(hFile, cbToWriteAdj - cbWritten, FILE_CURRENT)
                       )
                        rc = VERR_FILE_TOO_BIG;
                    return rc;
                }
                if (cbWrittenPart == 0)
                    return VERR_WRITE_ERROR;
                cbWritten += cbWrittenPart;
            }
        }
        return VINF_SUCCESS;
    }

    /*
     * If it's a console, we might bump into out of memory conditions in the
     * WriteConsole call.
     */
    DWORD dwErr = GetLastError();
    if (dwErr == ERROR_NOT_ENOUGH_MEMORY)
    {
        ULONG cbChunk = cbToWriteAdj / 2;
        if (cbChunk > _32K)
            cbChunk = _32K;
        else
            cbChunk = RT_ALIGN_32(cbChunk, 256);

        cbWritten = 0;
        while (cbToWriteAdj > cbWritten)
        {
            ULONG cbToWrite     = RT_MIN(cbChunk, cbToWriteAdj - cbWritten);
            ULONG cbWrittenPart = 0;
            if (!WriteFile((HANDLE)(uintptr_t)RTFileToNative(hFile), (const char *)pvBuf + cbWritten, cbToWrite, &cbWrittenPart, NULL))
            {
                /* If we failed because the buffer is too big, shrink it and
                   try again. */
                dwErr = GetLastError();
                if (   dwErr == ERROR_NOT_ENOUGH_MEMORY
                    && cbChunk > 8)
                {
                    cbChunk /= 2;
                    continue;
                }
                int rc = RTErrConvertFromWin32(dwErr);
                if (   rc == VERR_DISK_FULL
                    && IsBeyondLimit(hFile, cbToWriteAdj - cbWritten, FILE_CURRENT))
                    rc = VERR_FILE_TOO_BIG;
                return rc;
            }
            cbWritten += cbWrittenPart;

            /* Return if the caller can handle partial writes, otherwise try
               write out everything. */
            if (pcbWritten)
            {
                *pcbWritten = cbWritten;
                break;
            }
            if (cbWrittenPart == 0)
                return VERR_WRITE_ERROR;
        }
        return VINF_SUCCESS;
    }

    int rc = RTErrConvertFromWin32(dwErr);
    if (   rc == VERR_DISK_FULL
        && IsBeyondLimit(hFile, cbToWriteAdj - cbWritten, FILE_CURRENT))
        rc = VERR_FILE_TOO_BIG;
    return rc;
}


RTR3DECL(int)  RTFileFlush(RTFILE hFile)
{
    if (!FlushFileBuffers((HANDLE)(uintptr_t)RTFileToNative(hFile)))
    {
        int rc = GetLastError();
        Log(("FlushFileBuffers failed with %d\n", rc));
        return RTErrConvertFromWin32(rc);
    }
    return VINF_SUCCESS;
}


RTR3DECL(int)  RTFileSetSize(RTFILE hFile, uint64_t cbSize)
{
    /*
     * Get current file pointer.
     */
    int         rc;
    uint64_t    offCurrent;
    if (MySetFilePointer(hFile, 0, &offCurrent, FILE_CURRENT))
    {
        /*
         * Set new file pointer.
         */
        if (MySetFilePointer(hFile, cbSize, NULL, FILE_BEGIN))
        {
            /* set file pointer */
            if (SetEndOfFile((HANDLE)(uintptr_t)RTFileToNative(hFile)))
            {
                /*
                 * Restore file pointer and return.
                 * If the old pointer was beyond the new file end, ignore failure.
                 */
                if (    MySetFilePointer(hFile, offCurrent, NULL, FILE_BEGIN)
                    ||  offCurrent > cbSize)
                    return VINF_SUCCESS;
            }

            /*
             * Failed, try restoring the file pointer.
             */
            rc = GetLastError();
            MySetFilePointer(hFile, offCurrent, NULL, FILE_BEGIN);
        }
        else
            rc = GetLastError();
    }
    else
        rc = GetLastError();

    return RTErrConvertFromWin32(rc);
}


RTR3DECL(bool) RTFileIsValid(RTFILE hFile)
{
    if (hFile != NIL_RTFILE)
    {
        DWORD dwType = GetFileType((HANDLE)(uintptr_t)RTFileToNative(hFile));
        switch (dwType)
        {
            case FILE_TYPE_CHAR:
            case FILE_TYPE_DISK:
            case FILE_TYPE_PIPE:
            case FILE_TYPE_REMOTE:
                return true;

            case FILE_TYPE_UNKNOWN:
                if (GetLastError() == NO_ERROR)
                    return true;
                break;
        }
    }
    return false;
}


#define LOW_DWORD(u64) ((DWORD)u64)
#define HIGH_DWORD(u64) (((DWORD *)&u64)[1])

RTR3DECL(int)  RTFileLock(RTFILE hFile, unsigned fLock, int64_t offLock, uint64_t cbLock)
{
    Assert(offLock >= 0);

    /* Check arguments. */
    if (fLock & ~RTFILE_LOCK_MASK)
    {
        AssertMsgFailed(("Invalid fLock=%08X\n", fLock));
        return VERR_INVALID_PARAMETER;
    }

    /* Prepare flags. */
    Assert(RTFILE_LOCK_WRITE);
    DWORD dwFlags = (fLock & RTFILE_LOCK_WRITE) ? LOCKFILE_EXCLUSIVE_LOCK : 0;
    Assert(RTFILE_LOCK_WAIT);
    if (!(fLock & RTFILE_LOCK_WAIT))
        dwFlags |= LOCKFILE_FAIL_IMMEDIATELY;

    /* Windows structure. */
    OVERLAPPED Overlapped;
    memset(&Overlapped, 0, sizeof(Overlapped));
    Overlapped.Offset = LOW_DWORD(offLock);
    Overlapped.OffsetHigh = HIGH_DWORD(offLock);

    /* Note: according to Microsoft, LockFileEx API call is available starting from NT 3.5 */
    if (LockFileEx((HANDLE)(uintptr_t)RTFileToNative(hFile), dwFlags, 0, LOW_DWORD(cbLock), HIGH_DWORD(cbLock), &Overlapped))
        return VINF_SUCCESS;

    return RTErrConvertFromWin32(GetLastError());
}


RTR3DECL(int)  RTFileUnlock(RTFILE hFile, int64_t offLock, uint64_t cbLock)
{
    Assert(offLock >= 0);

    if (UnlockFile((HANDLE)(uintptr_t)RTFileToNative(hFile),
                   LOW_DWORD(offLock), HIGH_DWORD(offLock),
                   LOW_DWORD(cbLock), HIGH_DWORD(cbLock)))
        return VINF_SUCCESS;

    return RTErrConvertFromWin32(GetLastError());
}



RTR3DECL(int) RTFileQueryInfo(RTFILE hFile, PRTFSOBJINFO pObjInfo, RTFSOBJATTRADD enmAdditionalAttribs)
{
    /*
     * Validate input.
     */
    if (hFile == NIL_RTFILE)
    {
        AssertMsgFailed(("Invalid hFile=%RTfile\n", hFile));
        return VERR_INVALID_PARAMETER;
    }
    if (!pObjInfo)
    {
        AssertMsgFailed(("Invalid pObjInfo=%p\n", pObjInfo));
        return VERR_INVALID_PARAMETER;
    }
    if (    enmAdditionalAttribs < RTFSOBJATTRADD_NOTHING
        ||  enmAdditionalAttribs > RTFSOBJATTRADD_LAST)
    {
        AssertMsgFailed(("Invalid enmAdditionalAttribs=%p\n", enmAdditionalAttribs));
        return VERR_INVALID_PARAMETER;
    }

    /*
     * Query file info.
     */
    BY_HANDLE_FILE_INFORMATION Data;
    if (!GetFileInformationByHandle((HANDLE)(uintptr_t)RTFileToNative(hFile), &Data))
    {
        DWORD dwErr = GetLastError();
        /* Only return if we *really* don't have a valid handle value,
         * everything else is fine here ... */
        if (dwErr != ERROR_INVALID_HANDLE)
            return RTErrConvertFromWin32(dwErr);
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

    pObjInfo->Attr.fMode  = rtFsModeFromDos((Data.dwFileAttributes << RTFS_DOS_SHIFT) & RTFS_DOS_MASK_NT, "", 0);

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
            pObjInfo->Attr.u.Unix.cHardlinks      = Data.nNumberOfLinks ? Data.nNumberOfLinks : 1;
            pObjInfo->Attr.u.Unix.INodeIdDevice   = 0; /** @todo Use the volume serial number (see GetFileInformationByHandle). */
            pObjInfo->Attr.u.Unix.INodeId         = 0; /** @todo Use the fileid (see GetFileInformationByHandle). */
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


RTR3DECL(int) RTFileSetTimes(RTFILE hFile, PCRTTIMESPEC pAccessTime, PCRTTIMESPEC pModificationTime,
                             PCRTTIMESPEC pChangeTime, PCRTTIMESPEC pBirthTime)
{
    if (!pAccessTime && !pModificationTime && !pBirthTime)
        return VINF_SUCCESS;    /* NOP */

    FILETIME    CreationTimeFT;
    PFILETIME   pCreationTimeFT = NULL;
    if (pBirthTime)
        pCreationTimeFT = RTTimeSpecGetNtFileTime(pBirthTime, &CreationTimeFT);

    FILETIME    LastAccessTimeFT;
    PFILETIME   pLastAccessTimeFT = NULL;
    if (pAccessTime)
        pLastAccessTimeFT = RTTimeSpecGetNtFileTime(pAccessTime, &LastAccessTimeFT);

    FILETIME    LastWriteTimeFT;
    PFILETIME   pLastWriteTimeFT = NULL;
    if (pModificationTime)
        pLastWriteTimeFT = RTTimeSpecGetNtFileTime(pModificationTime, &LastWriteTimeFT);

    int rc = VINF_SUCCESS;
    if (!SetFileTime((HANDLE)(uintptr_t)RTFileToNative(hFile), pCreationTimeFT, pLastAccessTimeFT, pLastWriteTimeFT))
    {
        DWORD Err = GetLastError();
        rc = RTErrConvertFromWin32(Err);
        Log(("RTFileSetTimes(%RTfile, %p, %p, %p, %p): SetFileTime failed with lasterr %d (0x%x)\n",
             hFile, pAccessTime, pModificationTime, pChangeTime, pBirthTime, Err, rc));
    }
    return rc;
}

RTR3DECL(int) RTPathSetTimesUcs(const wchar_t *pwszPath, 
    PCRTTIMESPEC pAccessTime,
    PCRTTIMESPEC pModificationTime, PCRTTIMESPEC pChangeTime, 
    PCRTTIMESPEC pBirthTime)
{
    int rc;
    HANDLE hFile = CreateFileW(pwszPath,
        FILE_WRITE_ATTRIBUTES,   /* dwDesiredAccess */
        FILE_SHARE_WRITE | FILE_SHARE_READ | FILE_SHARE_DELETE, /* dwShareMode */
        NULL,                    /* security attribs */
        OPEN_EXISTING,           /* dwCreationDisposition */
        FILE_FLAG_BACKUP_SEMANTICS | FILE_ATTRIBUTE_NORMAL,
        NULL);

    if (hFile == INVALID_HANDLE_VALUE)
        return RTErrConvertFromWin32(GetLastError());
    rc = RTFileSetTimes((RTFILE)hFile, pAccessTime, pModificationTime, 
        pChangeTime, pBirthTime);
    CloseHandle(hFile);
    return rc;
}
                    

/* This comes from a source file with a different set of system headers (DDK)
 * so it can't be declared in a common header, like internal/file.h.
 */
extern int rtFileNativeSetAttributes(HANDLE FileHandle, ULONG FileAttributes);

/* RTFileSetMode version that does not use rtFileNativeSetAttributes */
RTR3DECL(int) RTFileSetMode(RTFILE hFile, RTFMODE fMode)
{
    /*
     * Normalize the mode and call the API.
     */
    ULONG FileAttributes;
    FILE_BASIC_INFO info;
    fMode = rtFsModeNormalize(fMode, NULL, 0);
    if (!rtFsModeIsValid(fMode))
        return VERR_INVALID_PARAMETER;
    FileAttributes = (fMode & RTFS_DOS_MASK) >> RTFS_DOS_SHIFT;
    if (GetFileInformationByHandleEx(hFile,
            FileBasicInfo,
            &info,
            sizeof(info)))
        return RTErrConvertFromWin32(GetLastError());
    info.FileAttributes = FileAttributes;
    if (SetFileInformationByHandle(hFile,
            FileBasicInfo,
            &info,
            sizeof(info)))
        return RTErrConvertFromWin32(GetLastError());
    return VINF_SUCCESS;
}


RTR3DECL(int)  RTFileDeleteUcs(const wchar_t *pwszFilename)
{
    int rc;
    if (!DeleteFileW(pwszFilename))
        rc = RTErrConvertFromWin32(GetLastError());
    else
        rc = VINF_SUCCESS;

    return rc;
}


RTDECL(int) RTFileRenameUcs(const wchar_t *pszSrc, const wchar_t *pszDst, unsigned fRename)
{
    /*
     * Validate input.
     */
    AssertMsgReturn(VALID_PTR(pszSrc), ("%p\n", pszSrc), VERR_INVALID_POINTER);
    AssertMsgReturn(VALID_PTR(pszDst), ("%p\n", pszDst), VERR_INVALID_POINTER);
    AssertMsgReturn(!(fRename & ~RTPATHRENAME_FLAGS_REPLACE), ("%#x\n", fRename), VERR_INVALID_PARAMETER);

    /*
     * Hand it on to the worker.
     */
    int rc = rtPathWin32MoveRenameUcs(pszSrc, pszDst,
                                   fRename & RTPATHRENAME_FLAGS_REPLACE ? MOVEFILE_REPLACE_EXISTING : 0,
                                   RTFS_TYPE_FILE);

    LogFlow(("RTFileMove(%p:{%ls}, %p:{%ls}, %#x): returns 0x%x\n",
             pszSrc, pszSrc, pszDst, pszDst, fRename, rc));
    return rc;

}


RTDECL(int) RTFileMoveUcs(const wchar_t *pszSrc, const wchar_t *pszDst, unsigned fMove)
{
    /*
     * Validate input.
     */
    AssertMsgReturn(VALID_PTR(pszSrc), ("%p\n", pszSrc), VERR_INVALID_POINTER);
    AssertMsgReturn(VALID_PTR(pszDst), ("%p\n", pszDst), VERR_INVALID_POINTER);
    AssertMsgReturn(!(fMove & ~RTFILEMOVE_FLAGS_REPLACE), ("%#x\n", fMove), VERR_INVALID_PARAMETER);

    /*
     * Hand it on to the worker.
     */
    int rc = rtPathWin32MoveRenameUcs(pszSrc, pszDst,
                                   fMove & RTFILEMOVE_FLAGS_REPLACE
                                   ? MOVEFILE_COPY_ALLOWED | MOVEFILE_REPLACE_EXISTING
                                   : MOVEFILE_COPY_ALLOWED,
                                   RTFS_TYPE_FILE);

    LogFlow(("RTFileMove(%p:{%s}, %p:{%s}, %#x): returns 0x%x\n",
             pszSrc, pszSrc, pszDst, pszDst, fMove, rc));
    return rc;
}

