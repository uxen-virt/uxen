/* $Id: fs.cpp $ */
/** @file
 * IPRT - File System.
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
#include <iprt/fs.h>
#include "internal/iprt.h"

#include <iprt/assert.h>
#include <iprt/ctype.h>
#include <iprt/path.h>
#include <iprt/string.h>
#include <iprt/time.h>
#include "internal/fs.h"

/**
 * Converts Unix attributes to Dos-style attributes.
 *
 * @returns File mode mask.
 * @param   fMode       The mode mask containing dos-style attributes only.
 * @param   pszName     The filename which this applies to (hidden check).
 * @param   cbName      The length of that filename. (optional, set 0)
 */
RTFMODE rtFsModeFromUnix(RTFMODE fMode, const char *pszName, size_t cbName)
{
    NOREF(cbName);

    fMode &= RTFS_UNIX_MASK;

    if (!(fMode & (RTFS_UNIX_IWUSR | RTFS_UNIX_IWGRP | RTFS_UNIX_IWOTH)))
        fMode |= RTFS_DOS_READONLY;
    if (RTFS_IS_DIRECTORY(fMode))
        fMode |= RTFS_DOS_DIRECTORY;
    if (!(fMode & RTFS_DOS_MASK))
        fMode |= RTFS_DOS_NT_NORMAL;
    if (!(fMode & RTFS_DOS_HIDDEN) && pszName)
    {
#ifdef ORIGINAL_VBOX        
        pszName = RTPathFilename(pszName);
        if (pszName && *pszName == '.')
            fMode |= RTFS_DOS_HIDDEN;
#endif            
    }
    return fMode;
}



/**
 * Converts dos-style attributes to Unix attributes.
 *
 * @returns
 * @param   fMode       The mode mask containing dos-style attributes only.
 * @param   pszName     The filename which this applies to (exe check).
 * @param   cbName      The length of that filename. (optional, set 0)
 */
RTFMODE rtFsModeFromDos(RTFMODE fMode, const char *pszName, size_t cbName)
{
    fMode &= ~((1 << RTFS_DOS_SHIFT) - 1);

    /* everything is readable. */
    fMode |= RTFS_UNIX_IRUSR | RTFS_UNIX_IRGRP | RTFS_UNIX_IROTH;
    if (fMode & RTFS_DOS_DIRECTORY)
        /* directories are executable. */
        fMode |= RTFS_TYPE_DIRECTORY | RTFS_UNIX_IXUSR | RTFS_UNIX_IXGRP | RTFS_UNIX_IXOTH;
    else
    {
        fMode |= RTFS_TYPE_FILE;
        if (!cbName && pszName)
            cbName = strlen(pszName);
        if (cbName >= 4 && pszName[cbName - 4] == '.')
        {
            /* check for executable extension. */
            const char *pszExt = &pszName[cbName - 3];
            char szExt[4];
            szExt[0] = RT_C_TO_LOWER(pszExt[0]);
            szExt[1] = RT_C_TO_LOWER(pszExt[1]);
            szExt[2] = RT_C_TO_LOWER(pszExt[2]);
            szExt[3] = '\0';
            if (    !memcmp(szExt, "exe", 4)
                ||  !memcmp(szExt, "bat", 4)
                ||  !memcmp(szExt, "com", 4)
                ||  !memcmp(szExt, "cmd", 4)
                ||  !memcmp(szExt, "btm", 4)
               )
                fMode |= RTFS_UNIX_IXUSR | RTFS_UNIX_IXGRP | RTFS_UNIX_IXOTH;
        }
    }

    /* Is it really a symbolic link? */
    if (fMode & RTFS_DOS_NT_REPARSE_POINT)
        fMode = (fMode & ~RTFS_TYPE_MASK) | RTFS_TYPE_SYMLINK;

    /* writable? */
    if (!(fMode & RTFS_DOS_READONLY))
        fMode |= RTFS_UNIX_IWUSR | RTFS_UNIX_IWGRP | RTFS_UNIX_IWOTH;
    return fMode;
}



/**
 * Normalizes the give mode mask.
 *
 * It will create the missing unix or dos mask from the other (one
 * of them is required by all APIs), and guess the file type if that's
 * missing.
 *
 * @returns Normalized file mode.
 * @param   fMode       The mode mask that may contain a partial/incomplete mask.
 * @param   pszName     The filename which this applies to (exe check).
 * @param   cbName      The length of that filename. (optional, set 0)
 */
RTFMODE rtFsModeNormalize(RTFMODE fMode, const char *pszName, size_t cbName)
{
    if (!(fMode & RTFS_UNIX_MASK))
        fMode = rtFsModeFromDos(fMode, pszName, cbName);
    else if (!(fMode & RTFS_DOS_MASK))
        fMode = rtFsModeFromUnix(fMode, pszName, cbName);
    else if (!(fMode & RTFS_TYPE_MASK))
        fMode |= fMode & RTFS_DOS_DIRECTORY ? RTFS_TYPE_DIRECTORY : RTFS_TYPE_FILE;
    else if (RTFS_IS_DIRECTORY(fMode))
        fMode |= RTFS_DOS_DIRECTORY;
    return fMode;
}


/**
 * Checks if the file mode is valid or not.
 *
 * @return  true if valid.
 * @return  false if invalid, done bitching.
 * @param   fMode       The file mode.
 */
bool rtFsModeIsValid(RTFMODE fMode)
{
    AssertMsgReturn(   (!RTFS_IS_DIRECTORY(fMode) && !(fMode & RTFS_DOS_DIRECTORY))
                    || (RTFS_IS_DIRECTORY(fMode) && (fMode & RTFS_DOS_DIRECTORY)),
                    ("%RTfmode\n", fMode), false);
    AssertMsgReturn(RTFS_TYPE_MASK & fMode,
                    ("%RTfmode\n", fMode), false);
    /** @todo more checks! */
    return true;
}


/**
 * Checks if the file mode is valid as a permission mask or not.
 *
 * @return  true if valid.
 * @return  false if invalid, done bitching.
 * @param   fMode       The file mode.
 */
bool rtFsModeIsValidPermissions(RTFMODE fMode)
{
    AssertMsgReturn(   (!RTFS_IS_DIRECTORY(fMode) && !(fMode & RTFS_DOS_DIRECTORY))
                    || (RTFS_IS_DIRECTORY(fMode) && (fMode & RTFS_DOS_DIRECTORY)),
                    ("%RTfmode\n", fMode), false);
    /** @todo more checks! */
    return true;
}


