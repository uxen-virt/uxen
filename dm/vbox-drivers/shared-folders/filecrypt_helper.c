/*
 * Copyright 2015, Bromium, Inc.
 * Author: Tomasz Wroblewski <tomasz.wroblewski@gmail.com>
 * SPDX-License-Identifier: ISC
 */

#include "filecrypt_helper.h"

#include <iprt/alloc.h>
#include <iprt/assert.h>
#include <iprt/fs.h>
#include <iprt/dir.h>
#include <iprt/file.h>
#include <iprt/path.h>
#include <iprt/string.h>

#include <windows.h>
#include <err.h>

int fch_create_crypt_hdr(SHFLCLIENTDATA *pClient, SHFLROOT root, SHFLHANDLE handle)
{
    filecrypt_hdr_t *hdr;
    SHFLFILEHANDLE *pHandle = vbsfQueryFileHandle(pClient, handle);
    int rc;

    bool fCrypt;
    rc = vbsfMappingsQueryCrypt(pClient, root, &fCrypt);
    if (RT_FAILURE(rc))
        return VERR_INVALID_PARAMETER;
    if (!fCrypt)
        return VINF_SUCCESS;

    if (!pHandle)
        return VERR_INVALID_PARAMETER;

    hdr = fc_init_hdr();
    if (!hdr)
        return VERR_NO_MEMORY;

    rc = fc_write_hdr(pHandle->file.Handle, hdr);
    if (rc) {
        fc_free_hdr(hdr);
        return RTErrConvertFromWin32(rc);
    }

    vbsfModifyHandleFlags(pClient, handle, SHFL_HF_ENCRYPTED, 0);
    vbsfSetHandleCrypt(pClient, handle, hdr);

    return VINF_SUCCESS;
}

int fch_read_crypt_hdr(SHFLCLIENTDATA *pClient, SHFLROOT root, SHFLHANDLE handle,
                       filecrypt_hdr_t **hdr)
{
    SHFLFILEHANDLE *pHandle = vbsfQueryFileHandle(pClient, handle);
    int rc;
    int iscrypt;
    filecrypt_hdr_t *h = NULL;

    if (hdr) *hdr = NULL;

    bool fCrypt;
    rc = vbsfMappingsQueryCrypt(pClient, root, &fCrypt);
    if (RT_FAILURE(rc))
        return VERR_INVALID_PARAMETER;
    if (!fCrypt)
        return VINF_SUCCESS;

    if (!pHandle)
        return VERR_INVALID_PARAMETER;

    vbsfModifyHandleFlags(pClient, handle, 0, SHFL_HF_ENCRYPTED);
    vbsfSetHandleCrypt(pClient, handle, NULL);

    rc = fc_read_hdr((HANDLE)(pHandle->file.Handle), &iscrypt, &h);
    if (iscrypt && rc)
        return RTErrConvertFromWin32(rc);
    if (iscrypt) {
        vbsfModifyHandleFlags(pClient, handle, SHFL_HF_ENCRYPTED, 0);
        vbsfSetHandleCrypt(pClient, handle, h);
    }

    if (hdr) *hdr = h;

    return VINF_SUCCESS;
}

uint64_t fch_host_fileoffset(SHFLCLIENTDATA *pClient, SHFLROOT root, SHFLHANDLE handle,
                             uint64_t guest_off)
{
    int rc;
    bool fCrypt;

    rc = vbsfMappingsQueryCrypt(pClient, root, &fCrypt);
    if (RT_FAILURE(rc) || !fCrypt)
        return guest_off;

    filecrypt_hdr_t *hdr = vbsfQueryHandleCrypt(pClient, handle);

    if (vbsfQueryHandleFlags(pClient, handle) & SHFL_HF_ENCRYPTED) {
        Assert(hdr);
        return guest_off + hdr->hdrlen;
    }
    return guest_off;
}

static void _guest_fsinfo_common(filecrypt_hdr_t *crypt, RTFSOBJINFO *info)
{
    if (crypt) {
        /* mod file size */
        info->cbObject -= crypt->hdrlen;
    }
}

void fch_guest_fsinfo(SHFLCLIENTDATA *pClient, SHFLROOT root, SHFLHANDLE handle,
                      RTFSOBJINFO *info)
{
    int rc;
    bool fCrypt;

    rc = vbsfMappingsQueryCrypt(pClient, root, &fCrypt);
    if (RT_FAILURE(rc) || !fCrypt)
        return;

    filecrypt_hdr_t *hdr = vbsfQueryHandleCrypt(pClient, handle);
    if (vbsfQueryHandleFlags(pClient, handle) & SHFL_HF_ENCRYPTED) {
        Assert(hdr);
        _guest_fsinfo_common(hdr, info);
    }
}

void fch_guest_fsinfo_path(SHFLCLIENTDATA *pClient, SHFLROOT root, wchar_t *path,
                           RTFSOBJINFO *info)
{
    HANDLE h;
    int rc;

    bool fCrypt;
    rc = vbsfMappingsQueryCrypt(pClient, root, &fCrypt);
    if (RT_FAILURE(rc) || !fCrypt)
        return;

    h = CreateFileW(path, GENERIC_READ,
                    FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
                    OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h != INVALID_HANDLE_VALUE) {
        int iscrypt;
        filecrypt_hdr_t *crypt;

        fc_read_hdr(h, &iscrypt, &crypt);
        if (crypt)
            _guest_fsinfo_common(crypt, info);
        fc_free_hdr(crypt);
        CloseHandle(h);
    }
}

int fch_writable_file(SHFLCLIENTDATA *pClient, SHFLROOT root,
                      SHFLHANDLE handle, const wchar_t *path,
                      bool *out_fWritable)
{
    int rc;
    bool fConfigCrypt = 0;
    bool fWritable = 0;
    int filecrypted = 0;

    Assert(handle != SHFL_HANDLE_NIL || path);

    *out_fWritable = 0;

    rc = vbsfMappingsQueryCrypt(pClient, root, &fConfigCrypt);
    if (RT_FAILURE(rc))
        return rc;

    rc = vbsfMappingsQueryWritable(pClient, root, &fWritable);
    if (RT_FAILURE(rc))
        return rc;

    if (handle != SHFL_HANDLE_NIL) {
        uint32_t type = vbsfQueryHandleType(pClient, handle)
            & (SHFL_HF_TYPE_DIR|SHFL_HF_TYPE_FILE|SHFL_HF_TYPE_VOLUME);
        /* non file handles are writable based on config setting */
        if (type != SHFL_HF_TYPE_FILE) {
            *out_fWritable = fWritable;
            return VINF_SUCCESS;
        }
        filecrypted = vbsfQueryHandleFlags(pClient, handle) & SHFL_HF_ENCRYPTED;
    } else {
        filecrypt_hdr_t *crypt;
        HANDLE h = CreateFileW(
            path, GENERIC_READ,
            FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
            OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
        if (h != INVALID_HANDLE_VALUE) {
            rc = fc_read_hdr(h, &filecrypted, &crypt);
            fc_free_hdr(crypt);
            CloseHandle(h);
            if (rc)
                return RTErrConvertFromWin32(rc);
        } else
            rc = RTErrConvertFromWin32(GetLastError());
    }

    /* if encryption is active, non-encrypted files are readonly */
    if (fConfigCrypt && !filecrypted) {
        warnx("Shared Folders - deny access to non-encrypted file %08x %ls",
              (uint32_t)handle, path ? path : L"");
        *out_fWritable = 0;
    } else
        *out_fWritable = fWritable;
    return VINF_SUCCESS;
}

/*
 * get entry filename for dirname and entry name, dirname typically includes
 * wildcards such as c:\temp\* or c:\temp\foo*
 */
static int dir_entry_filename(wchar_t *dir, wchar_t *entry,
                              wchar_t *filename, size_t filename_sz)
{
    size_t len = wcslen(dir);
    if (len + wcslen(entry) + 2 >= filename_sz)
        return VERR_NO_MEMORY;
    wcscpy(filename, dir);
    while (len) {
        if (filename[len-1] == '\\') {
            filename[len] = 0;
            break;
        }
        --len;
    }
    wcscat(filename, entry);
    return 0;
}

int fch_read_dir_entry_crypthdr(SHFLCLIENTDATA *pClient, SHFLROOT root,
                                wchar_t *dir, wchar_t *entry, filecrypt_hdr_t **crypt)
{
    int rc;
    int iscrypt;
    HANDLE h;
    wchar_t filename[RTPATH_MAX];

    *crypt = NULL;
    if ((rc = dir_entry_filename(dir, entry, filename, RTPATH_MAX)))
        return rc;
    h = CreateFileW(filename, GENERIC_READ,
                     FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
                     OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h != INVALID_HANDLE_VALUE) {
        fc_read_hdr(h, &iscrypt, crypt);
        CloseHandle(h);
    }
    return VINF_SUCCESS;
}

void fch_crypt(SHFLCLIENTDATA *pClient, SHFLHANDLE handle, uint8_t *buf, uint64_t off, uint64_t len)
{
    if (vbsfQueryHandleFlags(pClient, handle) & SHFL_HF_ENCRYPTED) {
        filecrypt_hdr_t *hdr = vbsfQueryHandleCrypt(pClient, handle);

        Assert(hdr);
        fc_crypt(hdr, buf, off, len);
    }
}

void fch_decrypt(SHFLCLIENTDATA *pClient, SHFLHANDLE handle,
                 uint8_t *buf, uint64_t off, uint64_t len)
{
    if (vbsfQueryHandleFlags(pClient, handle) & SHFL_HF_ENCRYPTED) {
        filecrypt_hdr_t *hdr = vbsfQueryHandleCrypt(pClient, handle);

        Assert(hdr);
        fc_decrypt(hdr, buf, off, len);
    }
}
