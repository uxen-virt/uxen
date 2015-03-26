/** @file
 *
 * VirtualBox Windows Guest Shared Folders
 *
 * File System Driver helpers
 */

/*
 * Copyright (C) 2012 Oracle Corporation
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
 * Copyright 2013-2015, Bromium, Inc.
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

#ifndef __VBSFHLP__H
#define __VBSFHLP__H

#include <ntifs.h>
#include <ntverp.h>

#include "VBoxGuestR0LibSharedFolders.h"

void vbsfHlpSleep (ULONG ulMillies);
NTSTATUS vbsfHlpCreateDriveLetter (WCHAR Letter, UNICODE_STRING *pDeviceName);
NTSTATUS vbsfHlpDeleteDriveLetter (WCHAR Letter);

/**
 * Convert VBox IRT file attributes to NT file attributes
 *
 * @returns NT file attributes
 * @param   fMode       IRT file attributes
 *
 */
uint32_t VBoxToNTFileAttributes (uint32_t fMode);

/**
 * Convert VBox IRT file attributes to NT file attributes
 *
 * @returns NT file attributes
 * @param   fMode       IRT file attributes
 *
 */
uint32_t NTToVBoxFileAttributes (uint32_t fMode);

/**
 * Convert VBox error code to NT status code
 *
 * @returns NT status code
 * @param   vboxRC          VBox error code
 *
 */
NTSTATUS VBoxErrorToNTStatus (int vboxRC);

PVOID vbsfAllocNonPagedMem (ULONG ulSize);
void vbsfFreeNonPagedMem (PVOID lpMem);

#if defined(DEBUG) || defined (LOG_ENABLED)
PCHAR MajorFunctionString(UCHAR MajorFunction, LONG MinorFunction);
#endif

#endif /* __VBSFHLP__H */
