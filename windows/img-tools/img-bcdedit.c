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
#include "reghive.h"
#include "bcd.h"

#if defined(_WIN32)
DECLARE_PROGNAME;
#endif	/* _WIN32 */

static partition_t find_vol(ptbl_t ptbl, const uint8_t *buf, size_t sz, int fix)
{
    unsigned int i, cnt;
    uint32_t vol_sig;
    uint64_t start;

    if ( sz < 0x40 )
        return NULL;

    /* yes, it's pure black magic */
    start = *(uint64_t *)(buf + 0x20);
    vol_sig = *(uint32_t *)(buf + 0x38);

    if ( vol_sig != ptbl_disk_signature(ptbl) ) {
        RTPrintf("No idea about disk with sig: 0x%.8x\n", vol_sig);
        if ( fix ) {
            if ( !ptbl_set_signature(ptbl, vol_sig) )
                return NULL;
            RTPrintf("... FIXED UP!\n");
        }else
            return NULL;
    }

    cnt = ptbl_count_partitions(ptbl);
    for(i = 0; i < cnt; i++) {
        partition_t part;

        part = ptbl_get_partition(ptbl, i);
        if ( start == part_start_sector(part) * SECTOR_SIZE ) {
            RTPrintf("p%u: is ${BOOTVOL} partition\n", i);
            if ( !disklib_ntfs_partition(part_type(part)) ) {
                RTPrintf("but it's not NTFS?!\n");
                return NULL;
            }
            return part;
        }
    }

    return NULL;
}

static partition_t get_boot_partition(ptbl_t ptbl)
{
    partition_t part;
    unsigned int cnt, i;

    cnt = ptbl_count_partitions(ptbl);
    for(i = 0; i < cnt; i++) {
        uint8_t type, status;

        part = ptbl_get_partition(ptbl, i);
        type = part_type(part);
        status = part_status(part);

        if ( status != 0x80 )
            continue;
        if ( !disklib_ntfs_partition(type) )
            continue;

        RTPrintf("p%u: is boot NTFS partition\n", i);
        RTPrintf(" - it starts at %"PRId64"\n", part_start_sector(part));
        return part;
    }

    return NULL;
}

static int reg_filesize(void *user, size_t *sz)
{
    ntfs_fd_t fd = (ntfs_fd_t)user;
    *sz = disklib_ntfs_filesize(fd);
    return 1;
}

static int reg_read(void *user, uint8_t *ptr, size_t len)
{
    ntfs_fd_t fd = (ntfs_fd_t)user;
    ssize_t ret;

    disklib_ntfs_seek_set(fd, 0);

    ret = disklib_ntfs_read(fd, ptr, len);
    if ( ret < 0 || (size_t)ret != len )
        return 0;

    return 1;
}

static int reg_write(void *user, const uint8_t *ptr, size_t len)
{
    return 0;
}

static void reg_close(void *user)
{
    /* noop */
}

static const char *reg_filename(void *user)
{
    return "boot/bcd";
}

static const struct hive_iops ops = {
    /* I can't wait until 1999 */
    /* .filesize = */ reg_filesize,
    /* .read = */ reg_read,
    /* .write = */ reg_write,
    /* .close = */ reg_close,
    /* .reg_filename = */ reg_filename,
};

static int dump_key(rhkey_t key, int depth)
{
    struct reg_key_info info;
    unsigned int i;
    char *n;
    uint8_t *d;
    size_t nlen, dlen;
    int rc = 0;

    if ( !reghive_query_info_key(key, &info) )
        goto out;

#if 0
    RTPrintf("bdedit: key has: %d subkeys %d values\n",
             info.ki_subkeys, info.ki_values);
    RTPrintf("bcdedit: max subkey name len is %d bytes\n",
             info.ki_max_subkey_len);
#endif

    nlen = info.ki_max_subkey_len + 1;
    if ( nlen < info.ki_max_value_name_len + 1 )
        nlen = info.ki_max_value_name_len + 1;
    dlen = info.ki_max_value_len;

    n = (char *)RTMemAlloc(nlen);
    if ( NULL == n )
        goto out;

    d = (uint8_t *)RTMemAlloc(dlen);
    if ( NULL == d )
        goto out_free_name;

    for(i = 0; i < info.ki_values; i++) {
        unsigned int type;
        unsigned int j;
        char *ptr;
        size_t dl;

        dl = dlen;
        if ( !reghive_enum_value(key, i, n, nlen, d, &dl, &type) )
            goto out_free;

        switch(type) {
        case REG_SZ:
            RTPrintf("%*c+ %s : %s : %s\n", depth, ' ',
                    n, reghive_type_name(type), d);
            break;
        case REG_MULTI_SZ:
            for(ptr = (char *)d, j = 0; strlen(ptr);
                    j++, ptr += strlen(ptr) + 1) {
                RTPrintf("%*c+ %s[%d] : %s : %s\n", depth, ' ',
                        n, j, reghive_type_name(type), ptr);
            }
            break;
        case REG_DWORD:
            RTPrintf("%*c+ %s : %s : %d (0x%.8x)\n", depth, ' ',
                    n, reghive_type_name(type),
                    *(uint32_t *)d,
                    *(uint32_t *)d);
            break;
        case REG_BINARY:
            RTPrintf("%*c+ %s : %s : %"PRIuS" bytes\n", depth, ' ',
                    n, reghive_type_name(type), dl);
            hex_dump(d, dl, 16, depth);
            break;
        default:
            RTPrintf("%*c+ %s : %s\n", depth, ' ',
                    n, reghive_type_name(type));
            break;
        }
    }

    for(i = 0; i < info.ki_subkeys; i++) {
        rhkey_t subkey;

        if ( !reghive_enum_key(key, i, n, nlen) )
            goto out_free;

        RTPrintf("%*c- %s\n", depth, ' ', n);
        if ( !reghive_open_key(key, n, &subkey) )
            continue;

        dump_key(subkey, depth + 1);
        reghive_close_key(subkey);
    }

    rc = 1;

out_free:
    RTMemFree(d);
out_free_name:
    RTMemFree(n);
out:
    return rc;
}

static int do_bcdedit(char *fn, int fixup)
{
    rhkey_t key;
    partition_t part, boot;
    disk_handle_t hdd;
    ntfs_fd_t fd;
    ptbl_t ptbl;
    ntfs_fs_t fs;
    bcd_t bcd;
    bootmgr_t bmgr;
    const uint8_t *buf;
    size_t sz;
    int ret = 0;

    if (!disklib_open_image(fn, !!fixup, &hdd)) {
        return 0;
    }
    
    ptbl = ptbl_open(hdd);
    if ( NULL == ptbl )
        return 0;

    RTPrintf("Disk signature: 0x%.8x\n", ptbl_disk_signature(ptbl));

    part = get_boot_partition(ptbl);
    if ( NULL == part )
        goto out;

    fs = disklib_ntfs_mount(part, 0);
    if ( NULL == fs )
        goto out;

    fd = disklib_ntfs_open(fs, "/boot/bcd", DISKLIB_FD_READ);
    if ( NULL == fd )
        goto out_unmount;
    RTPrintf("bcdeit: opened /boot/bcd\n");

    if ( !reghive_open_hive(&ops, fd, &key) )
        goto out_close;

    RTPrintf("bcdeit: opened hive\n");
    if (0) dump_key(key, 1);

    bcd = bcd_open(key);
    if ( NULL == bcd )
        goto out_close_reg;
    RTPrintf("bcdeit: opened BCD\n");

    bmgr = bcd_bootmgr_get_default(bcd);
    if ( NULL == bmgr )
        goto out_close_bcd;

    RTPrintf("bcdeit: opened default boot: '%s'\n",
            bootmgr_description(bmgr));
    RTPrintf("bcdedit:    sysroot: %s\n",
            bootmgr_sysroot(bmgr));
    RTPrintf("bcdedit:   app path: %s\n",
            bootmgr_app_path(bmgr));

    buf = bootmgr_app_device(bmgr, &sz);
    if ( NULL == buf )
        goto out_close_bmgr;

    boot = find_vol(ptbl, buf, sz, fixup);
    (void)boot;

    ret = 1;

out_close_bmgr:
    bootmgr_close(bmgr);
out_close_bcd:
    bcd_close(bcd);
out_close_reg:
    reghive_close_key(key);
out_close:
    disklib_ntfs_close(fd);
out_unmount:
    disklib_ntfs_umount(fs);
out:
    ptbl_close(ptbl);
    disklib_close_image(hdd);
    return ret;
}

int main(int argc, char **argv)
{
    char *vdfile;
    int fix = 0;

    setprogname(argv[0]);

    RTR3Init();
    RTPrintf("*** bcdedit example ***\n");

    if ( argc < 2 ) {
        RTPrintf("Usage: bcdedit <imgfile> [SIGFIXUP]\n");
        return EXIT_FAILURE;
    }

    vdfile = argv[1];
    if ( argc > 2 && !RTStrCmp(argv[2], "SIGFIXUP") )
        fix = 1;

    if ( !do_bcdedit(vdfile, fix) )
        return EXIT_FAILURE;

    VDShutdown();
    RTPrintf("SUCCESS\n");
    return EXIT_SUCCESS;
}
