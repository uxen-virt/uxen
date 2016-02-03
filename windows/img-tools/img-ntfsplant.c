/*
 * Copyright 2011-2016, Bromium, Inc.
 * Author: Gianni Tedesco
 * SPDX-License-Identifier: ISC
 */

#include <err.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "sys.h"
#include "disklib.h"
#include "partition.h"
#include "fs-ntfs.h"

#if defined(_WIN32)
#include <windows.h>
#endif	/* _WIN32 */

#if defined(_WIN32)
DECLARE_PROGNAME;
#endif	/* _WIN32 */

#define TYPE_FILE   0
#define TYPE_DIR    1
#define TYPE_SKIP   2

#if defined(_WIN32)
static int classify_file(const wchar_t *fn, unsigned *type)
{
    DWORD val;
    val = GetFileAttributesW(fn);
    if ( val == INVALID_FILE_ATTRIBUTES )
        return 0;

    if ( val & FILE_ATTRIBUTE_DIRECTORY )
        *type = TYPE_DIR;
    else if ( val & (FILE_ATTRIBUTE_DEVICE|FILE_ATTRIBUTE_REPARSE_POINT) )
        *type = TYPE_SKIP;
    else
        *type = TYPE_FILE;
    return 1;
}
#else
static int classify_file(const wchar_t *fn, unsigned *type)
{
    return 0;
}
#endif



static int do_copy(ntfs_fs_t fs, const wchar_t *src, const wchar_t *dst);

static wchar_t *path_splice(const wchar_t *path, const wchar_t *name, int win32)
{
    size_t flen, plen;
    int ts;
    wchar_t *fp;

    /* libntfs likes normalized paths */
    plen = wcslen(path);
    ts = (plen && path[plen - 1] == '/');
    flen = plen + wcslen(name) + 2;
    if ( ts )
        flen--;

    fp = (wchar_t *) malloc(sizeof(wchar_t) * flen);
    if ( NULL == fp ) {
        return NULL;
    }

    _snwprintf(fp, flen, L"%s%s%s", path, (ts) ? L"" : (win32) ? L"\\" : L"/", name);

    return fp;
}

//
//  NOTE(martin): Atomic P2V
//
//  This function should now work with either normal paths (c:\..)
//  -OR- shadow copy volume paths (\\?\GLOBAL\....).
//

static int copy_file(ntfs_fs_t fs, const wchar_t *src, const wchar_t *dst)
{
    HANDLE input;
    uint64_t tot = 0;
    int ret = 0;
    DWORD bufSz = 16<<20;
    DWORD bytes_read;
    void *buf = malloc(bufSz);
    const char *src_utf8 = utf8(src);

    if ((buf == NULL) || (src_utf8 == NULL)) {
        LogAlways(("  couldn't allocate memory"));
        goto out;
    }

    LogAlways(("copying file: '%s' to '%ls'\n", src_utf8, dst));

    input = CreateFileW(
                src,
                GENERIC_READ,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                NULL,
                OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL | FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM,
                NULL);
    if (input == INVALID_HANDLE_VALUE) {
        LogAlways(("%s: open failed : %u\n", src_utf8, (uint32_t) GetLastError()));
        goto out;
    }

    for(;;) {
        if (! ReadFile(input, buf, bufSz, & bytes_read, NULL)) {
            LogAlways(("couldn't read file - %s - %ld\n", src_utf8, GetLastError()));
            goto out;
        }

        if (bytes_read <= 0) {
            break;
        }

        bytes_read = disklib_write_simple(fs, dst, buf, bytes_read, tot, 0, NULL);
        if (bytes_read <= 0)
            break;

        tot += bytes_read;
    }

    LogAlways(("  Wrote %"PRId64" bytes\n", tot));

    ret = 1;

    CloseHandle(input);

out:
    if (buf) {
        free(buf);
    }
    if (src_utf8) {
        free((void *) src_utf8);
    }

    return ret;
}

#ifdef _WIN32

static int copy_dir(ntfs_fs_t fs, const wchar_t *src, const wchar_t *dst)
{
    unsigned int flags = DISKLIB_NAME_DOS_AND_WIN32;
    (void)flags;
    wchar_t pathbuf[MAX_PATH];
    WIN32_FIND_DATAW fd;
    HANDLE hf;
    int ret = 0;
    const char *dst_utf8 = utf8(dst);
    const char *src_utf8 = utf8(src);

    if ((dst_utf8 == NULL) || (src_utf8 == NULL)) {
        LogAlways(("couldn't allocate memory\n"));
        goto out;
    }

    LogAlways(("copying directory: '%s' to '%s'\n", src_utf8, dst_utf8));

    if ( disklib_ntfs_mkdir(fs, dst_utf8, 1) &&
            disklib_errno() != DISKLIB_ERR_EXIST) {
        LogAlways(("%s: mkdir: %s\n", dst_utf8, disklib_strerror(disklib_errno())));
        goto out;
    }

    LogRel(("Created dir: %s\n", dst_utf8));

    _snwprintf(pathbuf, MAX_PATH, L"%s\\*", src);

    hf = FindFirstFileW(pathbuf, &fd);
    if ( hf == INVALID_HANDLE_VALUE ) {
        LogAlways(("%ls: FindFirstFile: %ld\n", src, GetLastError()));
        goto out;
    }
    do {
        wchar_t *s2, *d2;
        const wchar_t *name;

        name = fd.cFileName;

        if ( !wcscmp(name, L".") || !wcscmp(name, L"..") )
            continue;

        s2 = path_splice(src, name, 1);
        d2 = path_splice(dst, name, 0);
        if ( NULL == s2 || NULL == d2 ) {
            LogAlways(("out of memory\n"));
            goto out_closedir;
        }
        ret = do_copy(fs, s2, d2);
        free(s2);
        free(d2);
        if ( !ret )
            goto out_closedir;
    }while( FindNextFileW(hf, &fd) );

    if ( GetLastError() != ERROR_NO_MORE_FILES ) {
        LogAlways(("%ls: FindNextFile: %ld\n", src, GetLastError()));
        ret = 0;
    }else{
        ret = 1;
    }

out_closedir:
    CloseHandle(hf);

out:
    if (dst_utf8) {
        free((void *) dst_utf8);
    }
    if (src_utf8) {
        free((void *) src_utf8);
    }

    return ret;
}
#else
static int copy_dir(ntfs_fs_t fs, const wchar_t *src, const wchar_t *dst)
{
    LogAlways(("Unsupported op\n"));
    return 0;
}
#endif

static int do_copy(ntfs_fs_t fs, const wchar_t *src, const wchar_t *dst)
{
    int ret = 0;
    unsigned type;

    if ( !classify_file(src, &type) ) {
        LogAlways(("%s: classify_file: FAILED on %s\n", __FUNCTION__,
                   utf8(src)));
        return 0;
    }

    switch(type) {
    case TYPE_SKIP:
        LogRel(("skipping link or special: %s\n", utf8(src)));
        ret = 1;
        break;
    case TYPE_DIR:
        ret = copy_dir(fs, src, dst);
        break;
    case TYPE_FILE:
        ret = copy_file(fs, src, dst);
        break;
    default:
        AssertFailed();
        break;
    }

    return ret;
}

static int do_partition(partition_t part, const wchar_t *src, const wchar_t *dst)
{
    uint8_t type, status;
    ntfs_fs_t fs;
    int ret = 0;

    type = part_type(part);
    status = part_status(part);
    (void)status;

    if ( !disklib_ntfs_partition(type) ) {
        ret = 1;
        goto out;
    }

    fs = disklib_ntfs_mount(part, 1);
    if ( NULL == fs )
        goto out;

    ret = do_copy(fs, src, dst);

//out_unmount:
    disklib_ntfs_umount(fs);
out:
    return ret;
}

static int enum_partitions(char *fn, int partno,
                           const wchar_t *src, const wchar_t *dst)
{
    partition_t part;
    disk_handle_t hdd;
    ptbl_t ptbl;
    int ret = 0;

    if (!disklib_open_image(fn, 1, &hdd)) {
        LogAlways(("fail to open %s\n", fn));
        return 0;
    }

    ptbl = ptbl_open(hdd);
    if ( NULL == ptbl )
        return 0;

    part = ptbl_get_partition(ptbl, partno);
    if ( NULL == part ) {
        LogAlways(("requested partition %d not found\n", partno));
        return 0;
    }

    if ( do_partition(part, src, dst) )
        ret = 1;

    ptbl_close(ptbl);
    disklib_close_image(hdd);
    return ret;
}

static int begins_with(const char *str, const char *prefix)
{
    size_t plen = strlen(prefix);
    size_t slen = strlen(str);

    if ( slen < plen )
        return 0;

    return memcmp(str, prefix, plen) == 0;
}

int main(int argc, char **argv)
{
    char *vdfile;
    int part = 0;

    LPWSTR *argv_w;
    int argc_w;

    setprogname(argv[0]);

    RTR3Init();

    if ( argc < 5 ) {
        printf("Usage: %s --partition=<n> <vd> <src> <dst>\n", argv[0]);
        return EXIT_FAILURE;
    }

    if ( begins_with(argv[1], "--partition=") ) {
        const char *val = argv[1] + strlen("--partition=");
        part = atoi(val);
        LogAlways(("partition %d\n", part));
    }

#ifdef _WIN32
    /* Use wide-char arguments from here... */
    argv_w = CommandLineToArgvW(GetCommandLineW(), &argc_w);
    if( NULL == argv_w )
    {
        LogAlways(("CommandLineToArgvW failed: %ld\n", GetLastError()));
        return EXIT_FAILURE;
    }
#else
#error "may need to deal with wide-char argv on this platform?"
#endif

    /* The uXen swap blkdrv backend is UTF8-compatible, and the remaining
     * backends will get there eventually, so we pass the first arg down as
     * that.  The rest of the code that deals with the wide-char win32 APIs
     * will stay that way for now. As soon as we can retire the VBox version of
     * these tools we can do a full conversion over to using UTF8 everywhere.
     * */

    vdfile = utf8(argv_w[2]);
    if (!vdfile) {
        LogAlways(("wide->utf8 conversion failed.\n"));
        return EXIT_FAILURE;
    }

    reduce_io_priority();

    if ( !enum_partitions(vdfile, part, argv_w[3], argv_w[4]) ) {
        LogAlways(("couldn't enumerate partitions\n"));
        return EXIT_FAILURE;
    }

    VDShutdown();
    LogAlways(("OK\n"));
    return EXIT_SUCCESS;
}
