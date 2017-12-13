/*
 * Copyright 2015-2017, Bromium, Inc.
 * Author: Tomasz Wroblewski <tomasz.wroblewski@gmail.com>
 * SPDX-License-Identifier: ISC
 */

#include <dm/config.h>
#include "mappings.h"
#include "mappings-opts.h"
#include "vbsf.h"
#include "shflhandle.h"
#include "quota.h"

#include <iprt/assert.h>
#include <iprt/fs.h>
#include <iprt/dir.h>
#include <iprt/file.h>
#include <iprt/path.h>
#include <iprt/string.h>

#include "rt/rt.h"

#include <dm/debug.h>
#include <dm/shared-folders.h>

//#define SCAN_DIR_SIZE

//#define QDBG(format, ...) debug_printf("QUOTA: " format, ##__VA_ARGS__)
#define QDBG(format, ...)

#ifdef SCAN_DIR_SIZE
static uint64_t
scan_size(wchar_t *dir)
{
    wchar_t pat[MAX_PATH] = { 0 };
    uint64_t sz = 0;
    WIN32_FIND_DATAW fd;
    HANDLE h;

    if (wcslen(dir) + 3 > MAX_PATH)
        return 0;
    wcscat(pat, dir);
    wcscat(pat, L"\\*");
    h = FindFirstFileW((LPCWSTR)pat, &fd);
    if (h == INVALID_HANDLE_VALUE)
        return 0;

    for (;;) {
        if ( (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) &&
            !(fd.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT)) {
                if (wcscmp(L".", fd.cFileName) &&
                    wcscmp(L"..", fd.cFileName)) {
                    if (wcslen(dir) + wcslen(fd.cFileName) + 2 < MAX_PATH) {
                        wchar_t child[MAX_PATH] = { 0 };

                        wcscat(child, dir);
                        wcscat(child, L"\\");
                        wcscat(child, (wchar_t*)&fd.cFileName[0]);
                        sz += scan_size(child);
                    }
                }
        } else if (
            !(fd.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT)) {
            sz += ((uint64_t)fd.nFileSizeHigh * (MAXDWORD+1)) + fd.nFileSizeLow;
        }
        if (!FindNextFileW(h, &fd))
            break;
    }
    FindClose(h);
    return sz;
}
#endif

static int
fileattrs(HANDLE h, uint64_t *size, uint32_t *attrs, uint32_t *nlinks)
{
    uint64_t off, sz = 0;
    BY_HANDLE_FILE_INFORMATION info = { 0 };
    int rc;

    *size = 0;
    *attrs = 0;
    rc = RTFileSeek(h, 0, RTFILE_SEEK_CURRENT, &off);
    if (RT_FAILURE(rc))
        return rc;
    rc = RTFileSeek(h, 0, RTFILE_SEEK_END, &sz);
    if (RT_FAILURE(rc))
        return rc;
    RTFileSeek(h, off, RTFILE_SEEK_BEGIN, NULL);
    GetFileInformationByHandle(h, &info);
    *size = sz;
    *attrs = info.dwFileAttributes;
    *nlinks = info.nNumberOfLinks;
    return 0;
}

static int
resolve_path(struct quota_op *op, const wchar_t *name, HANDLE h)
{
//    const wchar_t *root = vbsfMappingsQueryHostRoot(op->root);
    uint32_t attrs = 0, nlinks = 0;
    struct shfl_handle_data *data = NULL;

    if (op->shflhandle != SHFL_HANDLE_NIL) {
        data = vbsfQueryHandleData(op->client, op->shflhandle);
        if (data && data->quota_cachedattrs) {
            op->filesize = data->fsize;
            op->islink = data->link;
            return 0;
        }
    }
    if (name) {
        h = CreateFileW(name, GENERIC_READ,
                        FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE, NULL,
                        OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
        if (h == INVALID_HANDLE_VALUE) {
#if 0
            debug_printf("error opening file %ls for resolving final path name %d\n",
                         name, (int)GetLastError());
#endif
            return RTErrConvertFromWin32(GetLastError());
        }
    }
    fileattrs(h, &op->filesize, &attrs, &nlinks);
#if 0
    if (!GetFinalPathNameByHandleW(h, op->path,
                                   sizeof(op->path) / sizeof(wchar_t),
                                   FILE_NAME_NORMALIZED)) {
        debug_printf("error resolving final path name %d", (int)GetLastError());
        if (name)
            CloseHandle(h);
        return RTErrConvertFromWin32(GetLastError());
    }
#endif
    if (name)
        CloseHandle(h);
    /*
    if ((root && !is_path_prefixof((wchar_t*)root, op->path)) ||
        (attrs & FILE_ATTRIBUTE_REPARSE_POINT))
        op->islink = 1;
    */
    QDBG("prefix test path=%ls nlinks=%d islink=%d\n", op->path,
         nlinks, op->islink);

    if (data) {
        data->fsize = op->filesize;
        data->link = op->islink;
        data->quota_cachedattrs = 1;
    }
    return 0;
}

static int
quota_disabled(SHFLCLIENTDATA *client, SHFLROOT root,
               SHFLHANDLE handle, const wchar_t *path)
{
    if (handle != SHFL_HANDLE_NIL) {
        struct shfl_handle_data *d;

        d = vbsfQueryHandleData(client, handle);
        return d->folder_opts & SF_OPT_NO_QUOTA;
    }
    if (path)
        return _sf_has_opt(root, (wchar_t*)path, SF_OPT_NO_QUOTA);
    return 0;
}

int
quota_start_op(struct quota_op *op,
               SHFLCLIENTDATA *client,
               SHFLROOT root,
               SHFLHANDLE shflhandle,
               const wchar_t *path,
               const wchar_t *guest_path)
{
    uint64_t qmax, qcur;
    SHFLFILEHANDLE *filehandle = NULL;

    if (shflhandle != SHFL_HANDLE_NIL)
        filehandle = vbsfQueryFileHandle(client, shflhandle);

    memset(op, 0, sizeof(*op));
    vbsfMappingsQueryQuota(client, root, &qmax, &qcur);
    if (!qmax)
        return VINF_SUCCESS;
    if (quota_disabled(client, root, shflhandle, guest_path))
        return VINF_SUCCESS;
    if (qcur == QUOTA_INVALID) {
#ifdef SCAN_DIR_SIZE
        wchar_t *str_root = (wchar_t*)vbsfMappingsQueryHostRoot(root);
        qcur = scan_size(str_root);
#else
        qcur = 0;
#endif

        QDBG("first estimate %d\n", (int)qcur);
        vbsfMappingsUpdateQuota(client, root, qcur);
    }
    op->client = client;
    op->root = root;
    op->qmax = qmax;
    op->qcur = qcur;
    op->shflhandle = shflhandle;
    resolve_path(op, path,  filehandle ? filehandle->file.Handle : NULL);
    QDBG("start quota op %ls link=%d\n", op->path, op->islink);
    return VINF_SUCCESS;
}

uint64_t
quota_get_filesize(struct quota_op *op)
{
    return op->filesize;
}

int
quota_set_delta(struct quota_op *op, int64_t delta)
{
    op->delta = delta;
    if (!op->qmax || op->islink)
        return VINF_SUCCESS;
    QDBG("delta is %d\n", (int)delta);
    return (delta <= 0 || (op->qcur + delta <= op->qmax)) ? VINF_SUCCESS : VERR_DISK_FULL;
}

int
quota_complete_op(struct quota_op *op)
{
    int64_t q;
    struct shfl_handle_data *data;

    if (!op->qmax || op->islink)
        return VINF_SUCCESS;
    if ((op->delta > 0) && (op->qcur + op->delta > op->qmax))
        return VERR_DISK_FULL;
    q = (int64_t)op->qcur + op->delta;
    if (q < 0) q = 0;
    QDBG("new estimate %d (delta %d)\n", (int)q, (int)op->delta);
    vbsfMappingsUpdateQuota(op->client, op->root, q);
    if (op->shflhandle != SHFL_HANDLE_NIL) {
        data = vbsfQueryHandleData(op->client, op->shflhandle);
        if (data)
            data->fsize += op->delta;
    }
    return VINF_SUCCESS;
}
