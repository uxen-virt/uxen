/******************************Module*Header*******************************\
* Module Name: bdd_util.cxx
*
* Basic Display Driver utility functions
*
* Created: 29-Mar-2011
* Author: Amos Eshel [amosesh]
*
* Copyright (c) 2011 Microsoft Corporation
\**************************************************************************/
/*
 * uXen changes:
 *
 * Copyright 2014-2015, Bromium, Inc.
 * Author: Kris Uchronski <kuchronski@gmail.com>
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

#include "BDD.hxx"

#ifdef VERIFY_EDID
BOOLEAN IsEdidHeaderValid(const BYTE* pEdid)
{
    static const UCHAR EDID1Header[8] = {0,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0};
    return memcmp(pEdid, EDID1Header, sizeof(EDID1Header)) == 0;
}

BOOLEAN IsEdidChecksumValid(const BYTE* pEdid)
{
    BYTE CheckSum = 0;
    for (const BYTE* pEdidStart = pEdid; pEdidStart < (pEdid + EDID_V1_BLOCK_SIZE); ++pEdidStart)
    {
        CheckSum += *pEdidStart;
    }

    return CheckSum == 0;
}
#endif  /* VERIFY_EDID */

//
// Frame buffer map/unmap
//

NTSTATUS
MapFrameBuffer(
    _In_                       PHYSICAL_ADDRESS    PhysicalAddress,
    _In_                       ULONG               Length,
    _Outptr_result_bytebuffer_(Length) VOID**              VirtualAddress)
{
    //
    // Check for parameters
    //
    if ((PhysicalAddress.QuadPart == (ULONGLONG)0) ||
        (Length == 0) ||
        (VirtualAddress == NULL))
    {
        uxen_err("One of PhysicalAddress.QuadPart (0x%I64x), Length (0x%I64x), VirtualAddress (0x%I64x) is NULL or 0",
                        PhysicalAddress.QuadPart, Length, VirtualAddress);
        return STATUS_INVALID_PARAMETER;
    }

    *VirtualAddress = MmMapIoSpace(PhysicalAddress,
                                   Length,
                                   MmWriteCombined);
    if (*VirtualAddress == NULL)
    {
        // The underlying call to MmMapIoSpace failed. This may be because, MmWriteCombined
        // isn't supported, so try again with MmNonCached

        *VirtualAddress = MmMapIoSpace(PhysicalAddress,
                                       Length,
                                       MmNonCached);
        if (*VirtualAddress == NULL)
        {
            ASSERT_FAIL("MmMapIoSpace returned a NULL buffer when trying to allocate 0x%I64x bytes", Length);
            return STATUS_NO_MEMORY;
        }
    }

    return STATUS_SUCCESS;
}

NTSTATUS
UnmapFrameBuffer(
    _In_reads_bytes_(Length) VOID* VirtualAddress,
    _In_                ULONG Length)
{
    //
    // Check for parameters
    //
    if ((VirtualAddress == NULL) && (Length == 0))
    {
        // Allow this function to be called when there's no work to do, and treat as successful
        return STATUS_SUCCESS;
    }
    else if ((VirtualAddress == NULL) || (Length == 0))
    {
        uxen_err("Only one of Length (0x%I64x), VirtualAddress (0x%I64x) is NULL or 0",
                        Length, VirtualAddress);
        return STATUS_INVALID_PARAMETER;
    }

    MmUnmapIoSpace(VirtualAddress,
                   Length);

    return STATUS_SUCCESS;
}

