/** @file
 *
 * Shared Folders:
 * Handles helper functions.
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

#include "os.h"
#include "shflhandle.h"
#include <iprt/alloc.h>
#include <iprt/assert.h>
#include <iprt/file.h>
#include "rt/rt.h"
#include "config.h"
#include <file.h>

#define FILE_REOPEN_TIMEOUT_MS 20000

struct timeout_open_ctx {
    PRTFILE pFile;
    const wchar_t *filename;
    uint64_t flags;
    int *pfAlreadyExists;
    int rc;
    filecrypt_hdr_t *crypt;
};

/*
 * Very basic and primitive handle management. Should be sufficient for our needs.
 * Handle allocation can be rather slow, but at least lookup is fast.
 *
 */
typedef struct
{
    uint32_t         uFlags;
    uintptr_t        pvUserData;
    PSHFLCLIENTDATA  pClient;
    const wchar_t    *pwszFilename;
    uint32_t         uOpenFlags;
    uint8_t          bFileNotFound, bOpening, bReopening;
    struct timeout_open_ctx *to_ctx;
    filecrypt_hdr_t *crypt;
    uint8_t cryptchanged; /* do we need to re-verify crypt settings when writing */
    ioh_event ready_ev;
} SHFLINTHANDLE, *PSHFLINTHANDLE;

static SHFLINTHANDLE   *pHandles = NULL;
static int32_t          lastHandleIndex = 0;
static critical_section reopen_lock;

extern SHFLCLIENTDATA clientData;

int vbsfInitHandleTable()
{
    pHandles = (SHFLINTHANDLE *)RTMemAllocZ (sizeof (SHFLINTHANDLE) * SHFLHANDLE_MAX);
    if (pHandles == NULL)
    {
        AssertFailed();
        return VERR_NO_MEMORY;
    }
    /* Never return handle 0 */
    pHandles[0].uFlags = SHFL_HF_TYPE_DONTUSE;
    lastHandleIndex    = 1;
    critical_section_init(&reopen_lock);

    return 0;
}

int vbsfFreeHandleTable()
{
    if (pHandles)
        RTMemFree(pHandles);

    pHandles = NULL;

    return VINF_SUCCESS;
}

static void wait_handle_ready_(SHFLINTHANDLE *h)
{
    if (!h->bOpening)
        return;

    LogRel(("Shared folders: waiting for handle readiness %ws\n",
            h->pwszFilename));
    ioh_event_wait(&h->ready_ev);
    if (h->bOpening)
        LogRel(("Shared folders: error - file still being opened?\n"));
}

static void wait_handle_ready(SHFLHANDLE h)
{
    if (h < SHFLHANDLE_MAX)
        wait_handle_ready_(&pHandles[h]);
}

static DWORD WINAPI
timeout_open_run(LPVOID p)
{
    struct timeout_open_ctx *ctx = (struct timeout_open_ctx*) p;

    ctx->rc = RTFileOpenUcs(ctx->pFile, ctx->filename,
                            ctx->flags, ctx->pfAlreadyExists,
                            NULL, NULL);
    if (ctx->rc == 0) {
        filecrypt_hdr_t *hdr = NULL;
        int iscrypt;
        int rc = fc_read_hdr((HANDLE)(*ctx->pFile), &iscrypt, &hdr);
        if (rc)
            LogRel(("fc_read_hdr failed %d when reopening file\n", rc));
        if (iscrypt) {
            if (rc) {
                ctx->rc = RTErrConvertFromWin32(rc);
                ctx->crypt = NULL;
            } else
                ctx->crypt = hdr;
        } else
            ctx->crypt = NULL;
        RTFileSeek(*ctx->pFile, 0, RTFILE_SEEK_BEGIN, NULL);
    }
    return 0;
}

static int
timeout_open(DWORD timeoutms,
             SHFLINTHANDLE *h,
             PRTFILE pFile,
             const wchar_t *filename,
             uint64_t flags,
             int *pfAlreadyExists)
{
    uxen_thread th;
    int rc;

    if (!h->to_ctx)
        h->to_ctx = calloc(1, sizeof(struct timeout_open_ctx));
    if (!h->to_ctx)
        return VERR_NO_MEMORY;

    h->to_ctx->pFile = pFile;
    h->to_ctx->filename = filename;
    h->to_ctx->flags = flags;
    h->to_ctx->pfAlreadyExists = pfAlreadyExists;
    h->to_ctx->rc = 0;
    h->to_ctx->crypt = NULL;

    if (create_thread(&th, timeout_open_run, h->to_ctx) < 0) {
        return VERR_NO_MEMORY;
    }
    rc = WaitForSingleObject(th, timeoutms);
    close_thread_handle(th);
    switch (rc) {
    case WAIT_OBJECT_0:
        h->crypt = h->to_ctx->crypt;
        return h->to_ctx->rc;
    case WAIT_TIMEOUT:
        LogRel(("Shared folders: timeout waiting for %ws to reopen\n", filename));
        TerminateThread(h, 0);
        return VERR_FILE_NOT_FOUND;
    default:
        LogRel(("Shared folders: WaitForSingleObject error %d while reopening %ws\n", rc, filename));
        TerminateThread(h, 0);
        return VERR_FILE_NOT_FOUND;
    }
}

static int
reopen_file(SHFLINTHANDLE *h)
{
    int delay, rc;
    uint32_t fOpen = h->uOpenFlags;
    /* Recreate the handle and reopen the file. */
    SHFLFILEHANDLE *fh = (SHFLFILEHANDLE *)RTMemAllocZ (sizeof (SHFLFILEHANDLE));

    if (!fh)
        return VERR_NO_MEMORY;

    fh->Header.u32Flags = SHFL_HF_TYPE_FILE;

    /* Br: There are many pitfalls wrt reopening of writable files,
     * so we sanitize flags (truncate etc.), so that
     * dwCreationDisposition is OPEN_EXISTING. */

    fOpen = (fOpen & ~(RTFILE_O_ACTION_MASK|RTFILE_O_TRUNCATE)) |
        RTFILE_O_OPEN; /* Effective OPEN_EXISTING */
    LogRel(("Shared folders: reopening file %ws\n", h->pwszFilename));
    for (delay = 10;;delay += 10) {
        rc = timeout_open(FILE_REOPEN_TIMEOUT_MS, h,
                          &fh->file.Handle, h->pwszFilename, fOpen, NULL);
        if (rc != VERR_SHARING_VIOLATION)
            break;
        if ((delay % 1000) == 10)
            LogRel(("Shared folders: reopen file %ws sharing violation\n",
                    h->pwszFilename));
        Sleep(delay > 50 ? 50 : delay);
    }
    LogRel(("Shared folders: reopening file %ws done rc %d\n", h->pwszFilename, rc));

    h->pClient = &clientData;

    if (RT_FAILURE(rc) && rc != VERR_FILE_NOT_FOUND) {
        LogRel(("Shared folders: reopen file %ws fails 0x%x\n", h->pwszFilename, rc));
        RTMemFree((void*)fh);
        fh = NULL;

        RTMemFree((void*)(h->pwszFilename));
        h->pwszFilename = NULL;
        h->uOpenFlags = 0;
        h->pvUserData = 0;
        goto out;
    }

    h->pvUserData = (uintptr_t) fh;

    if (rc == VERR_FILE_NOT_FOUND) {
        LogRel(("Shared folders: reopen file %ws fails, file not found - continuing\n",
                h->pwszFilename, rc));
        h->bFileNotFound = 1;
    }

out:
    /* crypt settings might've changed on reopen */
    if (h->crypt)
        h->uFlags |= SHFL_HF_ENCRYPTED;
    else
        h->uFlags &= ~SHFL_HF_ENCRYPTED;
    h->cryptchanged = 0;
    h->bOpening = 0;
    ioh_event_set(&h->ready_ev);
    return rc;
}

static DWORD WINAPI
reopen_files(LPVOID opaque)
{
    int i;
    LogRel(("Shared folders: reopening handles in background\n"));
    for (i = 1; i < SHFLHANDLE_MAX; ++i) {
        if (pHandles[i].pwszFilename) {
            reopen_file(&pHandles[i]);
        }
    }
    LogRel(("Shared folders: done reopening handles\n"));
    return 0;
}

int
vbsfReopenPathHandles(PSHFLCLIENTDATA client, wchar_t *path,
                      void *opaque, int (*action)(void*))
{
    int i, rc = 0;

    if (!path)
        return VERR_INVALID_PARAMETER;

    critical_section_enter(&reopen_lock);

    /* close existing handles */
    for (i = 1; i < SHFLHANDLE_MAX; ++i) {
        pHandles[i].bReopening = 0;
        if ((pHandles[i].uFlags & SHFL_HF_VALID) &&
            (pHandles[i].uFlags & SHFL_HF_TYPE_FILE) &&
             pHandles[i].pwszFilename &&
            !wcscmp(path, pHandles[i].pwszFilename))
        {
            SHFLFILEHANDLE *f = vbsfQueryFileHandle(client, i);
            if (f) {
                ioh_event_reset(&pHandles[i].ready_ev);
                CloseHandle(f->file.Handle);
                pHandles[i].bReopening = 1;
            }
        }
    }
    /* invoke action */
    if (action)
        rc = action(opaque);
    if (rc) {
        /* mark as ready on error */
        for (i = 1; i < SHFLHANDLE_MAX; ++i) {
            if (pHandles[i].bReopening)
                ioh_event_set(&pHandles[i].ready_ev);
        }
        goto out;
    }
    /* reopen handles */
    for (i = 1; i < SHFLHANDLE_MAX; ++i) {
        int reopen_rc;

        if (pHandles[i].bReopening) {
            if (pHandles[i].pvUserData) {
                RTMemFree((void*)pHandles[i].pvUserData);
                pHandles[i].pvUserData = 0;
            }
            pHandles[i].bOpening = 1;
            if (pHandles[i].crypt) {
                fc_free_hdr(pHandles[i].crypt);
                pHandles[i].crypt = NULL;
            }
            reopen_rc = reopen_file(&pHandles[i]);
            if (reopen_rc) {
                LogRel(("shared folders: reopen error handle %d error %d\n", i, reopen_rc));
                if (rc == 0)
                    rc = reopen_rc;
            }
        }
    }

out:
    critical_section_leave(&reopen_lock);
    return rc;
}

/* Br: When saving a VM we save the names and open flags of
 * all files that are currently open, to be able to reopen
 * them when the VM is loaded. */

void vbsfSaveHandleTable(QEMUFile *f)
{
    if (pHandles != NULL)
    {
        uint32_t i;

        /* Start from 1, 0 is the invalid file handle and we
         * use it to mark the end of the saved list. */

        for (i = 1; i < SHFLHANDLE_MAX; ++i)
        {
            const wchar_t *pwszFilename = pHandles[i].pwszFilename;

            if (pwszFilename != NULL)
            {
                uint32_t len = sizeof(wchar_t) * (wcslen(pwszFilename) + 1);
                qemu_put_be32(f, i);
                qemu_put_be32(f, pHandles[i].uFlags);
                qemu_put_be32(f, len);
                qemu_put_buffer(f, (uint8_t*)pwszFilename, len);
                qemu_put_be32(f, pHandles[i].uOpenFlags);
            }
        }
    }

    /* Since file handle 0 means invalid, we use that as an end-of-list
     * marker. */

    qemu_put_be32(f, 0);
}

/* Br: Load names of open files and attempt to open them. We treat failure to
 * open a file as fatal, as we believe we have fairly tight control of which
 * files the VM should be allowed to open, and when they are unlinked on the
 * host side. We don't currently save open directory handles, so we can a
 * assume that loaded handles point to files. */
int vbsfLoadHandleTable(QEMUFile *f)
{
    int rc;
    wchar_t *pwszFilename;

    LogRel(("Shared folders - loading handle table\n"));

    /* Read file names and flags, until we see handle #0. */

    for (;;)
    {
        uint32_t len;
        uint32_t idx;

        idx = qemu_get_be32(f);

        if (idx == 0)
        {
            /* End of list, done. */
            rc = VINF_SUCCESS;
            break;
        }
        if (idx > SHFLHANDLE_MAX)
        {
            /* Invalid handle in list, what gives? */
            rc = VERR_INVALID_HANDLE;
            break;
        }

        /* Handles array must have already been allocated. */
        if (pHandles == NULL)
        {
            return VERR_INTERNAL_ERROR;
        }

        pHandles[idx].uFlags = qemu_get_be32(f);
        len = qemu_get_be32(f);

        pwszFilename = (wchar_t*) RTMemAlloc(len);

        if (pwszFilename == NULL)
        {
            rc = VERR_NO_MEMORY;
            break;
        }

        qemu_get_buffer(f, (uint8_t*)pwszFilename, len);

        pHandles[idx].pwszFilename = pwszFilename;
        pHandles[idx].uOpenFlags = qemu_get_be32(f);
        pHandles[idx].bFileNotFound = 0;
        pHandles[idx].bOpening = 1;
        pHandles[idx].cryptchanged = 0; /* will get handled in reopen */
        pHandles[idx].crypt = NULL;
        ioh_event_init(&pHandles[idx].ready_ev);
    }

    if (pHandles && rc == VINF_SUCCESS) {
        uxen_thread th;
        /* reopen files in background */
        create_thread(&th, reopen_files, NULL);
        close_thread_handle(th);
    }

    return rc;
}


SHFLHANDLE  vbsfAllocHandle(PSHFLCLIENTDATA pClient, uint32_t uType,
    uintptr_t pvUserData, const wchar_t *pwszFilename, uint32_t uOpenFlags)
{
    SHFLHANDLE handle;

    Assert((uType & SHFL_HF_TYPE_MASK) != 0 && pvUserData);

    /* Find next free handle */
    if(lastHandleIndex >= SHFLHANDLE_MAX-1)
    {
        lastHandleIndex = 1;
    }

    /* Nice linear search */
    for(handle=lastHandleIndex;handle<SHFLHANDLE_MAX;handle++)
    {
        if(pHandles[handle].pvUserData == 0)
        {
            lastHandleIndex = handle;
            break;
        }
    }

    if(handle == SHFLHANDLE_MAX)
    {
        /* Try once more from the start */
        for(handle=1;handle<SHFLHANDLE_MAX;handle++)
        {
            if(pHandles[handle].pvUserData == 0)
            {
                lastHandleIndex = handle;
                break;
            }
        }
        if(handle == SHFLHANDLE_MAX)
        { /* Out of handles */
            AssertFailed();
            return SHFL_HANDLE_NIL;
        }
    }
    pHandles[handle].uFlags     = (uType & SHFL_HF_TYPE_MASK) | SHFL_HF_VALID;
    pHandles[handle].pvUserData = pvUserData;
    pHandles[handle].pClient    = pClient;
    pHandles[handle].pwszFilename = pwszFilename;
    pHandles[handle].uOpenFlags = uOpenFlags;
    pHandles[handle].bOpening = 0;
    pHandles[handle].cryptchanged = 1; /* mark so that it's tested on 1st write */
    pHandles[handle].crypt = NULL;
    ioh_event_init(&pHandles[handle].ready_ev);

    lastHandleIndex++;

    return handle;
}

int vbsfFreeHandle(PSHFLCLIENTDATA pClient, SHFLHANDLE handle)
{
    if (handle < SHFLHANDLE_MAX && (pHandles[handle].uFlags & SHFL_HF_VALID)
        && pHandles[handle].pClient == pClient)
    {
        pHandles[handle].uFlags     = 0;
        pHandles[handle].pvUserData = 0;
        pHandles[handle].pClient    = 0;

        if (pHandles[handle].pwszFilename != NULL)
        {
            RTMemFree((void*) pHandles[handle].pwszFilename);
            pHandles[handle].pwszFilename = NULL;
        }

        if (pHandles[handle].crypt) {
            fc_free_hdr(pHandles[handle].crypt);
            pHandles[handle].crypt = NULL;
        }
        pHandles[handle].cryptchanged = 0;

        if (pHandles[handle].ready_ev) {
            ioh_event_close(&pHandles[handle].ready_ev);
            pHandles[handle].ready_ev = NULL;
        }

        pHandles[handle].uOpenFlags = 0;
        return VINF_SUCCESS;
    }
    return VERR_INVALID_HANDLE;
}

SHFLHANDLE vbsfAllocFileHandle (PSHFLCLIENTDATA pClient, const wchar_t *pwszFilename, uint32_t uOpenFlags)
{
    wchar_t *pszDup;
    SHFLFILEHANDLE *pHandle = (SHFLFILEHANDLE *)RTMemAllocZ (sizeof (SHFLFILEHANDLE));

    if (pHandle)
    {
        pHandle->Header.u32Flags = SHFL_HF_TYPE_FILE;

        /* Duplicate file name string to be stored in handle table,
         * for use when saving VM. */

        pszDup = RTwcsdup((wchar_t*)pwszFilename);

        if (pszDup == NULL)
        {
            RTMemFree((void*) pHandle);
            return SHFL_HANDLE_NIL;
        }

        return vbsfAllocHandle(pClient, pHandle->Header.u32Flags, (uintptr_t)pHandle,
                pszDup, uOpenFlags);
    }

    return SHFL_HANDLE_NIL;
}

uintptr_t vbsfQueryHandle(PSHFLCLIENTDATA pClient, SHFLHANDLE handle,
                          uint32_t uType)
{
    wait_handle_ready(handle);

    if (   handle < SHFLHANDLE_MAX
        && (pHandles[handle].uFlags & SHFL_HF_VALID)
        && pHandles[handle].pClient == pClient)
    {
        Assert((uType & SHFL_HF_TYPE_MASK) != 0);

        if (pHandles[handle].uFlags & uType)
            return pHandles[handle].pvUserData;
    }
    return 0;
}

SHFLFILEHANDLE *vbsfQueryFileHandle(PSHFLCLIENTDATA pClient, SHFLHANDLE handle)
{
    return (SHFLFILEHANDLE *)vbsfQueryHandle(pClient, handle,
                                             SHFL_HF_TYPE_FILE);
}

SHFLFILEHANDLE *vbsfQueryDirHandle(PSHFLCLIENTDATA pClient, SHFLHANDLE handle)
{
    return (SHFLFILEHANDLE *)vbsfQueryHandle(pClient, handle,
                                             SHFL_HF_TYPE_DIR);
}

uint32_t vbsfQueryHandleType(PSHFLCLIENTDATA pClient, SHFLHANDLE handle)
{
    if (   handle < SHFLHANDLE_MAX
        && (pHandles[handle].uFlags & SHFL_HF_VALID)
        && pHandles[handle].pClient == pClient)
        return pHandles[handle].uFlags & SHFL_HF_TYPE_MASK;
    else
        return 0;
}

uint32_t vbsfQueryHandleFlags(PSHFLCLIENTDATA pClient, SHFLHANDLE handle)
{
    wait_handle_ready(handle);

    if (   handle < SHFLHANDLE_MAX
        && (pHandles[handle].uFlags & SHFL_HF_VALID)
        && pHandles[handle].pClient == pClient)
        return pHandles[handle].uFlags;
    else
        return 0;
}

void vbsfModifyHandleFlags(PSHFLCLIENTDATA pClient, SHFLHANDLE handle,
                           uint32_t add, uint32_t remove)
{
    wait_handle_ready(handle);

    if (handle < SHFLHANDLE_MAX) {
        SHFLINTHANDLE *h = &pHandles[handle];
        h->uFlags &= ~remove;
        h->uFlags |= add;
    }
}

filecrypt_hdr_t *vbsfQueryHandleCrypt(PSHFLCLIENTDATA pClient, SHFLHANDLE handle)
{
    wait_handle_ready(handle);

    if (   handle < SHFLHANDLE_MAX
        && (pHandles[handle].uFlags & SHFL_HF_VALID)
        && pHandles[handle].pClient == pClient)
        return pHandles[handle].crypt;
    else
        return NULL;
}

int
vbsfQueryHandleCryptChanged(PSHFLCLIENTDATA client, SHFLHANDLE handle)
{
    wait_handle_ready(handle);

    if (   handle < SHFLHANDLE_MAX
        && (pHandles[handle].uFlags & SHFL_HF_VALID)
        && pHandles[handle].pClient == client)
        return pHandles[handle].cryptchanged;
    else
        return 0;
}

void
vbsfResetHandleCryptChanged(PSHFLCLIENTDATA client, SHFLHANDLE handle)
{
    wait_handle_ready(handle);

    if (   handle < SHFLHANDLE_MAX
        && (pHandles[handle].uFlags & SHFL_HF_VALID)
        && pHandles[handle].pClient == client)
        pHandles[handle].cryptchanged = 0;
}

void
vbsfNotifyCryptChanged(void)
{
    uint32_t i;
    /* Start from 1, 0 is the invalid file handle and we
     * use it to mark the end of the saved list. */
    for (i = 1; i < SHFLHANDLE_MAX; ++i) {
        const wchar_t *pwszFilename = pHandles[i].pwszFilename;
        if (pwszFilename != NULL)
            pHandles[i].cryptchanged = 1;
    }
}

wchar_t *vbsfQueryHandlePath(PSHFLCLIENTDATA pClient, SHFLHANDLE handle)
{
    wait_handle_ready(handle);

    if (   handle < SHFLHANDLE_MAX
        && (pHandles[handle].uFlags & SHFL_HF_VALID)
        && pHandles[handle].pClient == pClient)
        return (wchar_t*)pHandles[handle].pwszFilename;
    else
        return NULL;
}

void vbsfSetHandleCrypt(PSHFLCLIENTDATA pClient, SHFLHANDLE handle, filecrypt_hdr_t *h)
{
    wait_handle_ready(handle);

    if (handle < SHFLHANDLE_MAX) {
        SHFLINTHANDLE *inth = &pHandles[handle];

        Assert(inth->crypt == NULL);
        inth->crypt = h;
    }
}

int vbsfQueryHandleFileExistence(SHFLHANDLE handle)
{
    wait_handle_ready(handle);

    return handle < SHFLHANDLE_MAX && !pHandles[handle].bFileNotFound;
}

SHFLHANDLE vbsfAllocDirHandle(PSHFLCLIENTDATA pClient)
{
    SHFLFILEHANDLE *pHandle = (SHFLFILEHANDLE *)RTMemAllocZ (sizeof (SHFLFILEHANDLE));

    if (pHandle)
    {
        pHandle->Header.u32Flags = SHFL_HF_TYPE_DIR;
        return vbsfAllocHandle(pClient, pHandle->Header.u32Flags,
                               (uintptr_t)pHandle, NULL, 0);
    }

    return SHFL_HANDLE_NIL;
}

void vbsfFreeFileHandle(PSHFLCLIENTDATA pClient, SHFLHANDLE hHandle)
{
    SHFLFILEHANDLE *pHandle = (SHFLFILEHANDLE *)vbsfQueryHandle(pClient,
               hHandle, SHFL_HF_TYPE_DIR|SHFL_HF_TYPE_FILE);

    if (pHandle)
    {
        vbsfFreeHandle(pClient, hHandle);
        RTMemFree (pHandle);
    }
    else
        AssertFailed();

    return;
}
