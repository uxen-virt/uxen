/** @file
 * VBox Shared Folders header.
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

#ifndef __VBSF__H
#define __VBSF__H

#include "shfl.h"
#include <VBox/shflsvc.h>

int vbsfCreate (SHFLCLIENTDATA *pClient, SHFLROOT root, SHFLSTRING *pPath, uint32_t cbPath, SHFLCREATEPARMS *pParms);
int vbsfClose (SHFLCLIENTDATA *pClient, SHFLROOT root, SHFLHANDLE Handle);
int vbsfRead(SHFLCLIENTDATA *pClient, SHFLROOT root, SHFLHANDLE Handle, uint64_t offset, uint32_t *pcbBuffer, uint8_t *pBuffer);
int vbsfWrite(SHFLCLIENTDATA *pClient, SHFLROOT root, SHFLHANDLE Handle, uint64_t offset, uint32_t *pcbBuffer, uint8_t *pBuffer);
int vbsfLock(SHFLCLIENTDATA *pClient, SHFLROOT root, SHFLHANDLE Handle, uint64_t offset, uint64_t length, uint32_t flags);
int vbsfUnlock(SHFLCLIENTDATA *pClient, SHFLROOT root, SHFLHANDLE Handle, uint64_t offset, uint64_t length, uint32_t flags);
int vbsfRemove(SHFLCLIENTDATA *pClient, SHFLROOT root, SHFLSTRING *pPath, uint32_t cbPath, uint32_t flags);
int vbsfRename(SHFLCLIENTDATA *pClient, SHFLROOT root, SHFLSTRING *pSrc, SHFLSTRING *pDest, uint32_t flags);
int vbsfDirList(SHFLCLIENTDATA *pClient, SHFLROOT root, SHFLHANDLE Handle, SHFLSTRING *pPath, uint32_t flags, uint32_t *pcbBuffer, uint8_t *pBuffer, uint32_t *pIndex, uint32_t *pcFiles);
int vbsfFileInfo(SHFLCLIENTDATA *pClient, SHFLROOT root, SHFLHANDLE Handle, uint32_t flags, uint32_t *pcbBuffer, uint8_t *pBuffer);
int vbsfQueryFSInfo(SHFLCLIENTDATA *pClient, SHFLROOT root, SHFLHANDLE Handle, uint32_t flags, uint32_t *pcbBuffer, uint8_t *pBuffer);
int vbsfSetFSInfo(SHFLCLIENTDATA *pClient, SHFLROOT root, SHFLHANDLE Handle, uint32_t flags, uint32_t *pcbBuffer, uint8_t *pBuffer);
int vbsfFlush(SHFLCLIENTDATA *pClient, SHFLROOT root, SHFLHANDLE Handle);
int vbsfDisconnect(SHFLCLIENTDATA *pClient);
int vbsfQueryFileInfo(SHFLCLIENTDATA *pClient, SHFLROOT root, SHFLHANDLE Handle, uint32_t flags, uint32_t *pcbBuffer, uint8_t *pBuffer);
int vbsfReadLink(SHFLCLIENTDATA *pClient, SHFLROOT root, SHFLSTRING *pPath, uint32_t cbPath, uint8_t *pBuffer, uint32_t cbBuffer);
int vbsfSymlink(SHFLCLIENTDATA *pClient, SHFLROOT root, SHFLSTRING *pNewPath, SHFLSTRING *pOldPath, SHFLFSOBJINFO *pInfo);

#endif /* __VBSF__H */
