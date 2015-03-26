/*
 * Copyright 2011-2015, Bromium, Inc.
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

#if defined(_WIN32)
static int make_dir(const char *dirname)
{
    /* Convert input string from UTF-8 to wide. */
    int r;
    wchar_t *dirname_w = wide(dirname);

    if (dirname_w == NULL) {
        LogAlways(("dirname conversion failure!\n"));
        return 0;
    }

    r = (CreateDirectoryW(dirname_w, NULL) ||
            GetLastError() == ERROR_ALREADY_EXISTS);

    free(dirname_w);

    return r;
}
#else
static int make_dir(const char *dirname)
{
    return (mkdir(dirname) == 0 || errno == EEXIST);
}
#endif

static int do_copy(ntfs_fs_t fs, const char *src, const char *dst);

static char *path_splice(const char *path, const char *name)
{
        size_t flen, plen;
        int ts;
        char *fp;

        /* libntfs likes normalized paths */
        plen = strlen(path);
        ts = (plen && path[plen - 1] == '/');
        flen = plen + strlen(name) + 2;
        if ( ts )
            flen--;

        fp = (char *)RTMemAlloc(flen);
        if ( NULL == fp ) {
            return NULL;
        }

        RTStrPrintf(fp, flen, "%s%s%s", path, (ts) ? "" : "/", name);
        return fp;
}

static int copy_file(ntfs_fs_t fs, const char *src, const char *dst)
{
    FILE *out;
    ntfs_fd_t fd;
    const size_t buf_size = 16<<20;
    char *buf = (char*) malloc(buf_size);
    uint64_t tot = 0;
    int ret = 0;
    const wchar_t *dst_w = wide(dst);

    if (dst_w == NULL) {
        LogAlways(("error getting wide string\n"));
        return 0;
    }

    fd = disklib_ntfs_open(fs, src, DISKLIB_FD_READ);
    if ( NULL == fd ) {
        LogAlways(("%s: open: %s\n", src, disklib_strerror(disklib_errno())));
        goto out;
    }

    out = _wfopen(dst_w, L"wb");
    if (out == NULL) {
        LogAlways(("couldn't open stream %s\n", dst));
        goto out_close;
    }

    for(;;) {
        ssize_t r;
        r = disklib_ntfs_read(fd, buf, buf_size);
        if ( r <= 0 )
            break;
        if (fwrite(buf, r, 1, out) <= 0) {
            LogAlways(("error writing output stream %s\n", dst));
            goto out_close_out;
        }
        tot += r;
    }

    LogRel(("Wrote %"PRId64" bytes to %s\n", tot, dst));
    ret = 1;

out_close_out:
    free((void*) dst_w);
    fclose(out);
out_close:
    disklib_ntfs_close(fd);
out:
    free(buf);
    return ret;
}

static int copy_dir(ntfs_fs_t fs, const char *src, const char *dst)
{
    unsigned int flags = DISKLIB_NAME_DOS_AND_WIN32;
    const char *name;
    ntfs_dir_t dir;
    unsigned int i;
    int ret = 0;

    if ( !make_dir(dst) ) {
        LogAlways(("failed to create dir %s!\n", dst));
        goto out;
    }

    LogRel(("Created dir: %s\n", dst));

    dir = disklib_ntfs_opendir(fs, src, flags);
    if ( NULL == dir ) {
        LogAlways(("%s: opendir: %s\n", src, disklib_strerror(disklib_errno())));
        goto out;
    }
    for(i = 0; (name = disklib_ntfs_readdir(dir, i)); i++) {
        char *s2, *d2;

        s2 = path_splice(src, name);
        d2 = path_splice(dst, name);
        if ( NULL == s2 || NULL == d2 ) {
            LogAlways(("out of memory\n"));
            goto out_closedir;
        }
        ret = do_copy(fs, s2, d2);
        RTMemFree(s2);
        RTMemFree(d2);
        if ( !ret )
            goto out_closedir;
    }

    ret = 1;

out_closedir:
    disklib_ntfs_closedir(dir);
out:
    return ret;
}

static int do_copy(ntfs_fs_t fs, const char *src, const char *dst)
{
    struct disklib_stat st;
    int ret = 0;

    if ( disklib_ntfs_stat(fs, src, &st) ) {
        LogAlways(("%s: stat: %s\n", src, disklib_strerror(disklib_errno())));
        goto out;
    }

    if ( st.f_mode & (DISKLIB_ISREPARSE|DISKLIB_ISLNK|DISKLIB_ISSPECIAL) ) {
        LogRel(("skipping link or special: %s\n", src));
        ret = 1;
        goto out;
    }

    if ( st.f_mode & DISKLIB_ISDIR ) {
        ret = copy_dir(fs, src, dst);
    }else{
        ret = copy_file(fs, src, dst);
    }

out:
    return ret;
}

static int do_partition(partition_t part, const char * src, const char *dst)
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

    fs = disklib_ntfs_mount(part, 0);
    if ( NULL == fs )
        goto out;

    ret = do_copy(fs, src, dst);

//out_unmount:
    disklib_ntfs_umount(fs);
out:
    return ret;
}

static int enum_partitions(char *fn, int partno, const char * src, const char *dst)
{
    partition_t part;
    disk_handle_t hdd;
    ptbl_t ptbl;
    int ret = 0;

    if (!disklib_open_image(fn, 0, &hdd)) {
        LogAlways(("disklib_open_image %s fails\n", fn));
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

    return (strncmp(str, prefix, plen) == 0);
}

int main(int argc, char **argv)
{
    char *dst;
    char * src = "/";
    char *vdfile;
    int part = 0;

    setprogname(argv[0]);

    RTR3Init();

    if ( argc < 5 ) {
        RTPrintf("Usage: %s --partition=<n> <path-to-image> <src> <dst>\n", argv[0]);
        return EXIT_FAILURE;
    }

    if ( begins_with(argv[1], "--partition=") ) {
        const char *val = argv[1] + strlen("--partition=");
        part = atoi(val);
    }

#ifdef RT_OS_WINDOWS
    /* Most VBox file functions accept UTF8 input, as does libntfs, so
     * we will work in that. */
    LPWSTR *argv_w;
    int argc_w;
    /* Use wide-char arguments from here... */
    argv_w = CommandLineToArgvW(GetCommandLineW(), &argc_w);
    if( NULL == argv_w )
    {
        RTPrintf("CommandLineToArgvW failed\n");
        return EXIT_FAILURE;
    }

    vdfile = utf8(argv_w[2]);
    src = utf8(argv_w[3]);
    dst = utf8(argv_w[4]);

    if (vdfile == NULL || src == NULL || dst == NULL) {
        RTPrintf("String conversion failed.\n");
        LogAlways(("String conversion failed.\n"));
        return EXIT_FAILURE;
    }
#else
    vdfile = argv[2];
    src    = argv[3];
    dst    = argv[4];
#endif

    reduce_io_priority();

    if ( !enum_partitions(vdfile, part, src, dst) ) {
        LogAlways(("FAIL\n"));
        return EXIT_FAILURE;
    }

    VDShutdown();
    LogAlways(("OK\n"));
    return EXIT_SUCCESS;
}
