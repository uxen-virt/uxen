/** @file
 *
 * Shared Folders:
 * Handles helper functions header.
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
 */
/*
 * uXen changes:
 *
 * Copyright 2012-2017, Bromium, Inc.
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

#ifndef __SHFLHANDLE__H
#define __SHFLHANDLE__H

#include "shfl.h"
#include <VBox/shflsvc.h>
#include <iprt/dir.h>

#include "filecrypt.h"

#define SHFL_HF_TYPE_MASK       (0x000000FF)
#define SHFL_HF_TYPE_DIR        (0x00000001)
#define SHFL_HF_TYPE_FILE       (0x00000002)
#define SHFL_HF_TYPE_VOLUME     (0x00000004)
#define SHFL_HF_TYPE_DONTUSE    (0x00000080)

#define SHFL_HF_ENCRYPTED       (0x00000100)
#define SHFL_HF_VALID           (0x80000000)

#define SHFLHANDLE_MAX          (4096)

typedef struct _SHFLHANDLEHDR
{
    uint32_t u32Flags;
} SHFLHANDLEHDR;

#define ShflHandleType(__Handle) BIT_FLAG(((SHFLHANDLEHDR *)(__Handle))->u32Flags, SHFL_HF_TYPE_MASK)

typedef struct _SHFLFILEHANDLE
{
    SHFLHANDLEHDR Header;
    union
    {
        struct
        {
            RTFILE        Handle;
        } file;
        struct
        {
            PRTDIR        Handle;
            PRTDIR        SearchHandle;
            PRTDIRENTRYEX pLastValidEntry; /* last found file in a directory search */
        } dir;
    };
} SHFLFILEHANDLE;

struct shfl_handle_data {
    uint64_t folder_opts;
    int64_t fsize;
    int link;
    int quota_cachedattrs;
};

SHFLHANDLE      vbsfAllocDirHandle(PSHFLCLIENTDATA pClient, const wchar_t *pwszPath, const wchar_t *pwszGuestPath);
SHFLHANDLE      vbsfAllocFileHandle(PSHFLCLIENTDATA pClient, const wchar_t *pwszFileName, const wchar_t *pwszGuestPath, uint32_t uOpenFlags);
void            vbsfFreeFileHandle (PSHFLCLIENTDATA pClient, SHFLHANDLE hHandle);

int         vbsfInitHandleTable();
int         vbsfFreeHandleTable();
SHFLHANDLE  vbsfAllocHandle(PSHFLCLIENTDATA pClient, uint32_t uType,
                            uintptr_t pvUserData, const wchar_t *pwszFilename,
                            const wchar_t *pwszGuestPath, uint32_t uOpenFlags);
SHFLFILEHANDLE *vbsfQueryFileHandle(PSHFLCLIENTDATA pClient,
                                    SHFLHANDLE handle);
SHFLFILEHANDLE *vbsfQueryDirHandle(PSHFLCLIENTDATA pClient, SHFLHANDLE handle);
uint32_t        vbsfQueryHandleType(PSHFLCLIENTDATA pClient,
                                    SHFLHANDLE handle);
int             vbsfQueryHandleFileExistence(SHFLHANDLE handle);
int             vbsfQueryHandleFileScrambled(SHFLHANDLE handle);
wchar_t*        vbsfQueryHandlePath(PSHFLCLIENTDATA pClient, SHFLHANDLE handle);
wchar_t*        vbsfQueryHandleGuestPath(PSHFLCLIENTDATA pClient, SHFLHANDLE handle);
uint32_t        vbsfQueryHandleFlags(PSHFLCLIENTDATA pClient,
                                     SHFLHANDLE handle);
void            vbsfModifyHandleFlags(PSHFLCLIENTDATA pClient,
                                      SHFLHANDLE handle,
                                      uint32_t add,
                                      uint32_t remove);

filecrypt_hdr_t *vbsfQueryHandleCrypt(PSHFLCLIENTDATA pClient, SHFLHANDLE handle);
void vbsfSetHandleCrypt(PSHFLCLIENTDATA pClient, SHFLHANDLE handle, filecrypt_hdr_t *h);
int vbsfQueryHandleCryptChanged(PSHFLCLIENTDATA client, SHFLHANDLE handle);
void vbsfResetHandleCryptChanged(PSHFLCLIENTDATA client, SHFLHANDLE handle);
void vbsfNotifyCryptChanged(void);
struct shfl_handle_data *vbsfQueryHandleData(PSHFLCLIENTDATA client, SHFLHANDLE handle);

/* reopen handles to given path with action performed between close of existing one and reopen */
int vbsfReopenPathHandles(PSHFLCLIENTDATA client, wchar_t *path,
                          void *opaque, int (*action)(void *));

#endif /* __SHFLHANDLE__H */
