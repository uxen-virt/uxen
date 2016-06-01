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

#include "disklib.h"
#include "partition.h"
#include "fs-ntfs.h"

#include "fileset.h"
#include "sha1.h"
#include "sys.h"

#if defined(_WIN32)
DECLARE_PROGNAME;
#endif	/* _WIN32 */

static int lsdir(ntfs_fs_t fs, fileset_t fset,
                 const char *path, int recurse, int depth)
{
    ntfs_dir_t dir;
    unsigned int i;
    const char *name;
    int ret = 1;
    unsigned int flags = DISKLIB_NAME_DOS_AND_WIN32;

    if ( recurse )
        flags |= DISKLIB_SYMLINK_NOFOLLOW;

    dir = disklib_ntfs_opendir(fs, path, flags);
    if ( NULL == dir ) {
        if ( disklib_errno() == DISKLIB_ERR_ISLNK ) {
            return 1;
        }else{
            RTPrintf("%s: opendir: %s\n", path,
                    disklib_strerror(disklib_errno()));
            return 0;
        }
    }

    if ( !recurse )
        RTPrintf("Directory listing for: %s\n", path);

    for(i = 0; (name = disklib_ntfs_readdir(dir, i)); i++) {
        struct disklib_stat st;
        size_t flen, plen;
        fsent_t f;
        int ts;
        char *fp;

        if ( !recurse ) {
            RTPrintf(" \\- '%s'\n", name);
            continue;
        }

        /* libntfs likes normalized paths */
        plen = strlen(path);
        ts = (plen && path[plen - 1] == '/');
        flen = plen + strlen(name) + 2;
        if ( ts )
            flen--;

        fp = (char *)RTMemAlloc(flen);
        if ( NULL == fp ) {
            ret = 0;
            goto out;
        }

        RTStrPrintf(fp, flen, "%s%s%s", path, (ts) ? "" : "/", name);
        /* We set priority as depth so as to get breadth first search order
         * when we sort on priority later.
        */
        f = fileset_insert_prio(fset, FILESET_VOL_BOOT, fp, depth);
        if ( f ) {
            fsent_stat(f, &st);
            if ( st.f_mode & DISKLIB_ISDIR )
                ret = lsdir(fs, fset, fp, recurse, depth + 1);
        }else{
            ret = 0;
        }

        RTMemFree(fp);
        if ( !ret )
            goto out;
    }

out:
    disklib_ntfs_closedir(dir);
    return ret;
}

/* We used the depth as the priority field in the fileset to get BFS order.
 * So we get a stable output if we sort on that followed by the filename.
*/
static DECLCALLBACK(int) sortfn(const void *A, const void *B)
{
    const fsent_t a = *(fsent_t *)A;
    const fsent_t b = *(fsent_t *)B;
    int ret;

    /* should never happen */
    ret = fsent_vol(b) - fsent_vol(a);
    if ( ret )
        return ret;

    ret = fsent_prio(a) - fsent_prio(b);
    if ( ret )
        return ret;

    return RTStrICmp(fsent_path(a), fsent_path(b));
}

static void dump_contents(ntfs_fs_t fs, const char *name)
{
    ntfs_fd_t fd;
    RTSHA1CONTEXT ctx;
    const size_t buf_size = 16 << 20;
    char *buf = malloc(buf_size);
    uint8_t md[RTSHA1_HASH_SIZE];
    ssize_t ret;

    fd = disklib_ntfs_open(fs, name, DISKLIB_FD_READ);
    if ( NULL == fd )
        return;

    RTSha1Init(&ctx);

    for(;;) {
        ret = disklib_ntfs_read(fd, buf, buf_size);
        if ( ret <= 0 )
            break;

        RTSha1Update(&ctx, buf, ret);
        //hex_dump((uint8_t *)buf, ret, 16, 0);
    }

    RTSha1Final(&ctx, md);

    disklib_ntfs_close(fd);
    RTPrintf("sha1=%.2x%.2x%.2x%.2x%.2x%.2x%.2x%.2x%.2x%.2x"
             "%.2x%.2x%.2x%.2x%.2x%.2x%.2x%.2x%.2x%.2x",
             md[0],md[1],md[2],md[3],md[4],
             md[5],md[6],md[7],md[8],md[9],
             md[10],md[11],md[12],md[13],md[14],md[15],
             md[16],md[17],md[18],md[19]);
    free(buf);
}

static void dump_item(ntfs_fs_t fs, struct disklib_stat *st, const char *name)
{
    unsigned int type;
    char *lnk = NULL;

    if ( st->f_mode & DISKLIB_ISDIR ) {
        RTPrintf("dir ");
    }else{
        RTPrintf("file ");
    }

    switch(st->f_mode & (DISKLIB_ISREPARSE|DISKLIB_ISLNK)) {
    case DISKLIB_ISREPARSE:
        RTPrintf("reparse(unhandled) ");
        break;
    case DISKLIB_ISREPARSE|DISKLIB_ISLNK:
        type = 0;
        lnk = disklib_ntfs_readlink(fs, name, &type);
        switch(type) {
        case DISKLIB_LINK_SYMBOLIC:
            RTPrintf("symlink ");
            break;
        case DISKLIB_LINK_SYM_FULL:
            RTPrintf("full-symlink ");
            break;
        case DISKLIB_LINK_JUNCTION:
            RTPrintf("junction ");
            break;
        default:
            RTPrintf("reparse ");
            break;
        }
        break;
    }

    if ( st->f_mode & DISKLIB_ISSPECIAL ) {
        RTPrintf("special ");
    }

    if ( !(st->f_mode & DISKLIB_ISDIR) )
        RTPrintf("size=%"PRId64" ", st->f_size);

    RTPrintf("'%s'", name);
    if ( lnk ) {
        RTPrintf(" -> %s", lnk);
        RTMemFree(lnk);
    }

    RTPrintf(" ");

    if ( !(st->f_mode & (DISKLIB_ISSPECIAL|DISKLIB_ISREPARSE|DISKLIB_ISDIR)) )
        dump_contents(fs, name);
    RTPrintf("\n");
}

static int dump_results(ntfs_fs_t fs, fileset_t fset)
{
    unsigned int mcnt, i;
    struct disklib_stat st;
    fsent_t *man;
    uint64_t tot_size = 0;
    int ret = 0, rc;

    /* We want stable sort order of the different names for hard-linked files.
     * This is so that given the same set of files we always get the same one
     * being the 'real file' and all the links in the same order in the output
     */
    rc = fileset_manifest_stable(fset, &man, &mcnt);
    if (RT_FAILURE(rc))
        goto out;

    qsort(man, mcnt, sizeof(*man), sortfn);

    for(i = 0; i < mcnt; i++) {
        fsent_stat(man[i], &st);
        tot_size += st.f_size;
        dump_item(fs, &st, fsent_path(man[i]));
    }

    for(i = 0; i < mcnt; i++) {
        unsigned int nlnk, j;
        const char *target;

        nlnk = fsent_nlnk(man[i]);
        if ( !nlnk )
            continue;

        target = fsent_path(man[i]);
        for(j = 0; j < nlnk; j++) {
            const char *lnk;
            lnk = fsent_get_link(man[i], j, NULL);
            RTPrintf("LINK: %s -> %s\n", lnk, target);
        }
    }

    RTPrintf("total_size=%"PRId64"\n", tot_size);
    ret = 1;
//out_free:
    RTMemFree(man);
out:
    return ret;
}

static int do_partition(partition_t part, unsigned int idx,
                        const char *path, int recurse)
{
    uint8_t type, status;
    fileset_t fset = NULL;
    ntfs_fs_t fs;
    int rc, ret = 0;

    type = part_type(part);
    status = part_status(part);

    if ( !disklib_ntfs_partition(type) ) {
        ret = 1;
        goto out;
    }

    RTPrintf("p%u: %sNTFS partition\n", idx,
        (status == 0x80) ? "bootable " : "");

    fs = disklib_ntfs_mount(part, 0);
    if ( NULL == fs )
        goto out;

    if ( recurse ) {
        rc = fileset_new(&fset, fs, NULL);
        if ( RT_FAILURE(rc) )
            goto out_unmount;
    }

    ret = lsdir(fs, fset, path, recurse, 0);
    if ( !ret )
        goto out_free;

    if ( recurse && !dump_results(fs, fset) )
        goto out_free;

    ret = 1;

out_free:
    fileset_free(fset);
out_unmount:
    disklib_ntfs_umount(fs);
out:
    return ret;
}

static int enum_partitions(char *fn, const char *path, int recurse)
{
    unsigned int cnt, i;
    disk_handle_t hdd;
    ptbl_t ptbl;

    if (!disklib_open_image(fn, 0, &hdd)) {
        return 0;
    }

    ptbl = ptbl_open(hdd);
    if ( NULL == ptbl )
        return 0;

    if ( !recurse )
        RTPrintf("Disk signature: 0x%.8x\n", ptbl_disk_signature(ptbl));

    cnt = ptbl_count_partitions(ptbl);
    for(i = 0; i < cnt; i++) {
        partition_t part;
        part = ptbl_get_partition(ptbl, i);
        if ( !do_partition(part, i, path, recurse) ) {
            RTPrintf("*** ERROR ***\n");
            //exit(1);
        }
    }

    ptbl_close(ptbl);
    disklib_close_image(hdd);
    return 1;
}

int main(int argc, char **argv)
{
    const char *path = "/";
    char *vdfile;
    int idx;
    int r;

    setprogname(argv[0]);
    convert_args(argc, argv);

    RTR3Init();

    if ( argc < 2 ) {
        RTPrintf("Usage: %s [-r] <path-to-image> [path]\n", argv[0]);
        return EXIT_FAILURE;
    }

    idx = 1;
    if ( !RTStrCmp(argv[idx], "-r") ) {
        idx++;
        r = 1;
    }else{
        r = 0;
    }

    vdfile = argv[idx++];
    if ( idx + 1 <= argc )
        path = argv[idx++];

    if ( !enum_partitions(vdfile, path, r) )
        return EXIT_FAILURE;

    VDShutdown();
    return EXIT_SUCCESS;
}
