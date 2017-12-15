/*
 * Copyright 2011-2018, Bromium, Inc.
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

#include <windows.h>

#if defined(_WIN32)
DECLARE_PROGNAME;
#endif	/* _WIN32 */

static int do_compact(disk_handle_t in, disk_handle_t out)
{
    static uint8_t sec[SECTOR_SIZE];
    unsigned int i, pcnt;
    uint8_t *bitmap;
    uint8_t *cluster;
    partition_t p;
    ntfs_fd_t fd;
    ntfs_fs_t fs;
    ptbl_t ptbl;
    uint64_t scnt, sect;
    int rc = VERR_FILE_IO_ERROR;

    printf(" - Copying MBR\n");
    if (!disk_read_sectors(in, sec, 0, 1, NULL)) {
        goto out;
    }
    
    if (!disk_write_sectors(out, sec, 0, 1)) {
        goto out;
    }

    ptbl = ptbl_open(in);
    pcnt = ptbl_count_partitions(ptbl);

    for(i = 0; i < pcnt; i++) {
        uint64_t nr_cluster, start, copied = 0;
        uint32_t cluster_sz;
        uint64_t j;
        ssize_t bsz;

        p = ptbl_get_partition(ptbl, i);
        if ( part_type(p) == PART_TYPE_EMPTY )
            continue;

        printf(" - Partition #%d populated\n", i);

        if ( !disklib_ntfs_partition(part_type(p)) ) {
            RTPrintf(" - not NTFS, copying every sector\n");
            scnt = part_num_sectors(p);
            for (sect = 0; sect < scnt; sect++) {
                if (!disk_read_sectors(in, sec, sect, 1, NULL)) {
                    goto out;
                }
                if (!disk_write_sectors(out, sec, sect, 1)) {
                    goto out;
                }
            }
            continue;
        }

        start = part_start_sector(p) * SECTOR_SIZE;

        fs = disklib_ntfs_mount(p, 0);
        if ( NULL == fs ) {
            rc = VERR_PDM_MEDIA_NOT_MOUNTED;
            goto out_close_ptbl;
        }

        cluster_sz = disklib_ntfs_cluster_size(fs);
        nr_cluster = disklib_ntfs_nr_clusters(fs);
        printf(" - %"PRId64"/%"PRId64" clusters of %d bytes\n",
               disklib_ntfs_free_clusters(fs), nr_cluster, cluster_sz);

        fd = disklib_ntfs_open_bitmap(fs);
        if ( NULL == fd ) {
            rc = VERR_PDM_MEDIA_NOT_MOUNTED;
            goto out_umount;
        }

        bitmap = (uint8_t *)RTMemAlloc((nr_cluster + 7) >> 3);
        if ( NULL == bitmap ) {
            rc = VERR_NO_MEMORY;
            goto out_close;
        }

        bsz = disklib_ntfs_read(fd, bitmap, (nr_cluster + 7) >> 3);
        if ( bsz < 0 || (size_t)bsz < (nr_cluster + 7) >> 3 ) {
            goto out_free_bitmap;
        }

        cluster = (uint8_t *)RTMemAlloc(cluster_sz);
        if ( NULL == cluster )
            goto out_free_bitmap;

        printf(" - Read NTFS bitmap!\n");
        for(j = 0; j < nr_cluster; j++) {
            uint64_t byte;
            uint8_t bit;
            byte = j >> 3;
            bit = 1 << (j & 7);
            if ( bitmap[byte] & bit ) {

                if (!disk_read_sectors(in, cluster,
                            (start + j * cluster_sz)/SECTOR_SIZE,
                            cluster_sz/SECTOR_SIZE, NULL)) {

                    goto out_free_cluster;
                }

                if (!disk_write_sectors(out, cluster,
                            (start + j * cluster_sz)/SECTOR_SIZE,
                            cluster_sz/SECTOR_SIZE)) {

                    goto out_free_cluster;
                }

                if ( !(j % 1024) ) {
                    printf(".");
                    fflush(stdout);
                }
                copied++;
            }
        }
        printf("\n - copied %"PRId64"/%"PRId64" expected\n\n",
                copied, nr_cluster - disklib_ntfs_free_clusters(fs));

        RTMemFree(cluster);
        RTMemFree(bitmap);
        disklib_ntfs_close(fd);
        disklib_ntfs_umount(fs);
    }

    rc = VINF_SUCCESS;
    goto out_close_ptbl;

out_free_cluster:
    RTMemFree(cluster);
out_free_bitmap:
    RTMemFree(bitmap);
out_close:
    disklib_ntfs_close(fd);
out_umount:
    disklib_ntfs_umount(fs);
out_close_ptbl:
    ptbl_close(ptbl);
out:
    return rc;
}

static int create_from_src(const char *fn, disk_handle_t src, const char *fmt,
        disk_handle_t *r)
{
    VDGEOMETRY geom = {0}, geom2 = {0};
    disk_handle_t ret;
    uint64_t sz;
    int rc;

    sz = disk_get_size(src);

    /* Always create a vbox type handle. */
    rc = VDCreate(NULL, VDTYPE_HDD, &ret.vboxhandle);

    if (!RT_SUCCESS(rc))
        return 0;

    rc = VDCreateBase(ret.vboxhandle, fmt, fn, sz,
                  VD_IMAGE_FLAGS_NONE, "Created by bro-vmdkcompact",
                  &geom, &geom2, NULL,
                  VD_OPEN_FLAGS_NORMAL, NULL, NULL);

    if (!RT_SUCCESS(rc)) return 0;
    
    *r = ret;
    return 1;
}

int main(int argc, char **argv)
{
    disk_handle_t in, out;
    const char *fmt = "VHD";
    char *src, *dst;
    int rc;
    int uncompressed = 0;

    setprogname(argv[0]);

    RTR3Init();

    if ( argc < 3 ) {
        RTPrintf("Usage: %s <src> <dst> [format]\n", argv[0]);
        return EXIT_FAILURE;
    }

#ifdef RT_OS_WINDOWS
    LPWSTR *argv_w;
    int argc_w;
    /* Use wide-char arguments from here... */
    argv_w = CommandLineToArgvW(GetCommandLineW(), &argc_w);
    if( NULL == argv_w )
    {
        RTPrintf("CommandLineToArgvW failed\n");
        return EXIT_FAILURE;
    }

    src = utf8(argv_w[1]);
    dst = utf8(argv_w[2]);
    if (!src || !dst) {
        LogAlways(("wide to utf8 conversion failed!\n"));
        return EXIT_FAILURE;
    }

#else
    src = argv[1];
    dst = argv[2];
#endif

    if ( argc > 3 )
        fmt = argv[3];

        if (!strcmp(fmt, "SWAP-uncompressed")) {
            uncompressed = 1;
            fmt = "SWAP";
        }

    else {
        char *_fmt;
        rc = vd_get_format(dst, &_fmt);
        if (!rc)
            fmt = _fmt;
    }

    reduce_io_priority();

    if (!disklib_open_image(src, 0, &in)) {
        LogAlways(("Failed to open: %s\n", src));
        return EXIT_FAILURE;
    }

    RTPrintf("%s\n", fmt);
    if (!create_from_src(dst, in, fmt, &out)) {
        LogAlways(("Failed to create: %s\n", dst));
        return EXIT_FAILURE;
    }

    if (uncompressed) {
        vd_set_uncompressed(out.vboxhandle);
    }

    rc = do_compact(in, out);
    if ( RT_FAILURE(rc) ) {
        LogAlways(("Compaction failed... %d\n", rc));
        return EXIT_FAILURE;
    }

    disklib_close_image(in);
    disklib_close_image(out);
    VDShutdown();
    LogAlways(("Compaction complete.\n"));
    return EXIT_SUCCESS;
}
