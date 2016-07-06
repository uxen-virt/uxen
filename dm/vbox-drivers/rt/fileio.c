/* $Id: fileio.cpp $ */
/** @file
 * IPRT - File I/O.
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
#include <iprt/file.h>
#include <iprt/alloc.h>
#include <iprt/assert.h>
#include <iprt/alloca.h>
#include <iprt/err.h>
#include "internal/file.h"


/*******************************************************************************
*   Global Variables                                                           *
*******************************************************************************/
/** Set of forced set open flags for files opened read-only. */
static unsigned g_fOpenReadSet = 0;

/** Set of forced cleared open flags for files opened read-only. */
static unsigned g_fOpenReadMask = 0;

/** Set of forced set open flags for files opened write-only. */
static unsigned g_fOpenWriteSet = 0;

/** Set of forced cleared open flags for files opened write-only. */
static unsigned g_fOpenWriteMask = 0;

/** Set of forced set open flags for files opened read-write. */
static unsigned g_fOpenReadWriteSet = 0;

/** Set of forced cleared open flags for files opened read-write. */
static unsigned g_fOpenReadWriteMask = 0;


/**
 * Adjusts and validates the flags.
 *
 * The adjustments are made according to the wishes specified using the RTFileSetForceFlags API.
 *
 * @returns IPRT status code.
 * @param   pfOpen      Pointer to the user specified flags on input.
 *                      Updated on successful return.
 * @internal
 */
int rtFileRecalcAndValidateFlags(uint64_t *pfOpen)
{
    /*
     * Recalc.
     */
    uint32_t fOpen = *pfOpen;
    switch (fOpen & RTFILE_O_ACCESS_MASK)
    {
        case RTFILE_O_READ:
            fOpen |= g_fOpenReadSet;
            fOpen &= ~g_fOpenReadMask;
            break;
        case RTFILE_O_WRITE:
            fOpen |= g_fOpenWriteSet;
            fOpen &= ~g_fOpenWriteMask;
            break;
        case RTFILE_O_READWRITE:
            fOpen |= g_fOpenReadWriteSet;
            fOpen &= ~g_fOpenReadWriteMask;
            break;
        default:
            AssertMsgFailed(("Invalid RW value, fOpen=%#llx\n", fOpen));
            return VERR_INVALID_PARAMETER;
    }

    /*
     * Validate                                                                                                                                       .
     */
    AssertMsgReturn(fOpen & RTFILE_O_ACCESS_MASK, ("Missing RTFILE_O_READ/WRITE: fOpen=%#llx\n", fOpen), VERR_INVALID_PARAMETER);
#if defined(RT_OS_WINDOWS) || defined(RT_OS_OS2)
    AssertMsgReturn(!(fOpen & (~(uint64_t)RTFILE_O_VALID_MASK | RTFILE_O_NON_BLOCK)), ("%#llx\n", fOpen), VERR_INVALID_PARAMETER);
#else
    AssertMsgReturn(!(fOpen & ~(uint64_t)RTFILE_O_VALID_MASK), ("%#llx\n", fOpen), VERR_INVALID_PARAMETER);
#endif
    AssertMsgReturn((fOpen & (RTFILE_O_TRUNCATE | RTFILE_O_WRITE)) != RTFILE_O_TRUNCATE, ("%#llx\n", fOpen), VERR_INVALID_PARAMETER);

    switch (fOpen & RTFILE_O_ACTION_MASK)
    {
        case 0: /* temporarily */
            AssertMsgFailed(("Missing RTFILE_O_OPEN/CREATE*! (continuable assertion)\n"));
            fOpen |= RTFILE_O_OPEN;
            break;
        case RTFILE_O_OPEN:
            AssertMsgReturn(!(RTFILE_O_NOT_CONTENT_INDEXED & fOpen), ("%#llx\n", fOpen), VERR_INVALID_PARAMETER);
        case RTFILE_O_OPEN_CREATE:
        case RTFILE_O_CREATE:
        case RTFILE_O_CREATE_REPLACE:
            break;
        default:
            AssertMsgFailed(("Invalid action value: fOpen=%#llx\n", fOpen));
            return VERR_INVALID_PARAMETER;
    }

    switch (fOpen & RTFILE_O_DENY_MASK)
    {
        case 0: /* temporarily */
            AssertMsgFailed(("Missing RTFILE_O_DENY_*! (continuable assertion)\n"));
            fOpen |= RTFILE_O_DENY_NONE;
            break;
        case RTFILE_O_DENY_NONE:
        case RTFILE_O_DENY_READ:
        case RTFILE_O_DENY_WRITE:
        case RTFILE_O_DENY_WRITE | RTFILE_O_DENY_READ:
        case RTFILE_O_DENY_NOT_DELETE | RTFILE_O_DENY_NONE:
        case RTFILE_O_DENY_NOT_DELETE:
        case RTFILE_O_DENY_NOT_DELETE | RTFILE_O_DENY_READ:
        case RTFILE_O_DENY_NOT_DELETE | RTFILE_O_DENY_WRITE:
        case RTFILE_O_DENY_NOT_DELETE | RTFILE_O_DENY_WRITE | RTFILE_O_DENY_READ:
            break;
        default:
            AssertMsgFailed(("Invalid deny value: fOpen=%#llx\n", fOpen));
            return VERR_INVALID_PARAMETER;
    }

    /* done */
    *pfOpen = fOpen;
    return VINF_SUCCESS;
}



