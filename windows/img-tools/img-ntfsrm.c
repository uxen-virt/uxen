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

#include "disklib.h"
#include "partition.h"
#include "fs-ntfs.h"
#include "sys.h"

#if defined(_WIN32)
DECLARE_PROGNAME;
#endif	/* _WIN32 */

struct exclude_list {
    char **list;
    unsigned int count;
};

static int read_exclude_list(struct exclude_list *exc, const char *path)
{
    PRTSTREAM strm;
    char buf[1024];
    int rc, ret = 0;
    unsigned int i;

    rc = RTStrmOpen(path, "r", &strm);
    if ( RT_FAILURE(rc) ) {
        RTPrintf("RTStrmOpen: %s: %d\n", path, rc);
        goto out;
    }

    exc->list = NULL;
    exc->count = 0;

    while(rc != VERR_EOF) {
        rc = RTStrmGetLine(strm, buf, sizeof(buf));
        if ( RT_FAILURE(rc) && rc != VERR_EOF )
            goto out_close;

        /* no RTStrChr???? */
        if ( *buf && buf[0] != '#' ) {
            unsigned int c;
            char **l;

            c = exc->count + 1;
            l = (char **)RTMemRealloc(exc->list, sizeof(*exc->list) * c);
            if ( NULL == l )
                goto out_free;

            exc->list = l;
            exc->list[exc->count] = RTStrDup(buf);
            if ( NULL == exc->list[exc->count] )
                goto out_free;
            exc->count = c;

        }
    }

    /* success */
    ret = 1;
    for(i = 0; i < exc->count; i++) {
        RTPrintf("%d: %s\n", i, exc->list[i]);
    }
    goto out_close;

out_free:
    for(i = 0; i < exc->count; i++) {
        RTStrFree(exc->list[i]);
    }
    RTMemFree(exc->list);
out_close:
    RTStrmClose(strm);
out:
    return ret;
}

static int exclude_list_match(struct exclude_list *exc, const char *path)
{
    unsigned int i;
    size_t len;

    if ( NULL == exc )
        return 0;

    len = strlen(path);

    for(i = 0; i < exc->count; i++) {
        size_t clen;

        clen = strlen(exc->list[i]);
        if ( clen > len )
            continue;

        if ( !RTStrNICmp(exc->list[i], path, clen) )
            return 1;
    }

    return 0;
}

static int do_rm(ntfs_fs_t fs, const char *rmpath, struct exclude_list *exc)
{
    int recurse = 1;
    int ret = 1;

    if ( exclude_list_match(exc, rmpath) ) {
        RTPrintf("EXCLUDED: %s\n", rmpath);
        return ret;
    }

again:
    if ( !disklib_ntfs_unlink(fs, rmpath) ) {
        return ret;
    }

    if ( recurse && (disklib_errno() == DISKLIB_ERR_NOTEMPTY ||
                     disklib_errno() == DISKLIB_ERR_IS_SPECIAL)) {
        ntfs_dir_t dir;

        dir = disklib_ntfs_opendir(fs, rmpath, DISKLIB_NAME_ALL);
        if ( dir ) {
            const char *path;
            unsigned int i;

            for(i = 0; (path = disklib_ntfs_readdir(dir, i)); i++) {
                size_t plen;
                char *fp;

                plen = strlen(rmpath) + strlen(path) + 2;
                fp = (char *)RTMemAlloc(plen);
                if ( NULL == fp ) {
                    RTPrintf("%s/%s: out of memory constructing path\n",
                             rmpath, path);
                    ret = 0;
                    goto out;
                }

                RTStrPrintf(fp, plen, "%s/%s", rmpath, path);
                ret = do_rm(fs, fp, exc);
                RTMemFree(fp);

                if ( !ret )
                    goto out;
            }
            disklib_ntfs_closedir(dir);
        }else if ( disklib_errno() != DISKLIB_ERR_NOTDIR ) {
                RTPrintf("%s: readdir: %s\n", rmpath,
                        disklib_strerror(disklib_errno()));
        }
        recurse = 0;
        goto again;
    }else if ( disklib_errno() != DISKLIB_ERR_NOENT ) {
        /* Don't print errors for NOENT, this can happen because we're
         * trying to delete all names of all files, maybe the underlying
         * object was already deleted. It makes no sense to complain we
         * couldn't delete a file because we already deleted it */
        RTPrintf("%s: unlink: %s\n", rmpath,
                disklib_strerror(disklib_errno()));
    }

out:
    return ret;
}

static int do_partition(partition_t part, const char *rmpath,
                        struct exclude_list *exc)
{
    PRTSTREAM strm;
    char buf[1024];
    ntfs_fs_t fs;
    int rc;

    rc = RTStrmOpen(rmpath, "r", &strm);
    if ( RT_FAILURE(rc) ) {
        RTPrintf("RTStrmOpen: %s: %d\n", rmpath, rc);
        goto out;
    }

    fs = disklib_ntfs_mount(part, 1);
    if ( NULL == fs ) {
        RTPrintf("Unable to mount filesystem: %s\n",
                disklib_strerror(disklib_errno()));
        rc = VERR_PDM_MEDIA_NOT_MOUNTED;
        goto out_close;
    }

    while(rc != VERR_EOF) {
        rc = RTStrmGetLine(strm, buf, sizeof(buf));
        if ( RT_FAILURE(rc) && rc != VERR_EOF )
            goto out_umount;

        /* no RTStrChr???? */
        if ( *buf && buf[0] != '#' ) {
            do_rm(fs, buf, exc);
        }
    }

    rc = VINF_SUCCESS;

out_umount:
    disklib_ntfs_umount(fs);
out_close:
    RTStrmClose(strm);
out:
    return rc;
}

static int enum_partitions(char *fn, const char *rmpath, const char *expath)
{
    struct exclude_list exc;
    unsigned int cnt, i;
    disk_handle_t hdd;
    ptbl_t ptbl;
    int rc;
    int ret = 0;

    if (!disklib_open_image(fn, 1, &hdd)) {
        RTPrintf("disklib_open_image: failed\n");
        return 0;
    }
    
    ptbl = ptbl_open(hdd);
    if ( NULL == ptbl ) {
        RTPrintf("ptbl_open: failed\n");
        goto out_close;
    }

    if ( expath && !read_exclude_list(&exc, expath) ) {
        RTPrintf("read_exclude_list: failed\n");
        goto out_close_ptbl;
    }

    cnt = ptbl_count_partitions(ptbl);
    RTPrintf("Got %u partitions\n", cnt);
    for(i = 0; i < cnt; i++) {
        partition_t part;
        uint8_t type, status;

        part = ptbl_get_partition(ptbl, i);
        type = part_type(part);
        status = part_status(part);

        if ( !disklib_ntfs_partition(type) ) {
            RTPrintf("p%u: not NTFS, skipping\n", i);
            continue;
        }

        RTPrintf("p%u: %sNTFS partition\n", i,
            (status == 0x80) ? "bootable " : "");

        rc = do_partition(part, rmpath, (expath) ? &exc : NULL);
        if ( RT_FAILURE(rc) ) {
            RTPrintf(" - Error: %d\n", rc);
        }
    }

    ret = 1;
    (void)ret;

out_close_ptbl:
    ptbl_close(ptbl);
out_close:
    disklib_close_image(hdd);
    return 1;
}

int main(int argc, char **argv)
{
    char *vdfile, *rmpath, *expath = NULL;

    setprogname(argv[0]);
    convert_args(argc, argv);

    RTR3Init();
    RTPrintf("*** NTFS unlink() example ***\n");

    if ( argc < 3 ) {
        RTPrintf("Usage: %s <path-to-image> <paths.txt> <excludes.txt>\n", argv[0]);
        return EXIT_FAILURE;
    }

    vdfile = argv[1];
    rmpath = argv[2];
    if ( argc > 3 )
        expath = argv[3];

    if ( !enum_partitions(vdfile, rmpath, expath) )
        return EXIT_FAILURE;

    RTPrintf("SUCCESS\n");
    VDShutdown();
    return EXIT_SUCCESS;
}
