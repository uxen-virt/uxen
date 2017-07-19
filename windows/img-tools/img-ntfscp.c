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
#include "reghive.h"
#include "bcd.h"
#include "fnmatch.h"
#include "glob.h"

#include <windows.h>

#ifndef PROCESS_MODE_BACKGROUND_BEGIN
#define PROCESS_MODE_BACKGROUND_BEGIN 0x00100000
#endif

#include "fileset.h"

static int EXT_MANIFEST_ENTRY_SZ = 256;

#if defined(_WIN32)
DECLARE_PROGNAME;
#endif	/* _WIN32 */

/* Global Windows exit code, to be returned by main(). */
static int exit_status = ERROR_SUCCESS;

/* Don't actually modify destination image, just print stuff to be copied */
#undef DRY_RUN

#if 0
#define dprintf(...) RTPrintf(__VA_ARGS__)
#else
#define dprintf(...) do {}while(0);
#endif

/* Working set size, that we will try to pin from Windows. If we don't succeed
 * we will halve it until we do. */

static uint64_t wss_size = 512ULL << 20ULL;

struct pat {
    unsigned int vol;
    char *pattern;
};

struct pat_list {
    struct pat *list;
    unsigned int count;
};

struct disk {
    disk_handle_t hdd;
    ptbl_t ptbl;
    partition_t p_sysvol;
    partition_t p_bootvol;
    ntfs_fs_t sysvol;
    ntfs_fs_t bootvol;
};

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
    if ( ret < 0 || (size_t)ret != len ) {
        LogAlways(("%s: disk read error %"PRIdS"\n", __FUNCTION__, ret));
        return 0;
    }

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

static int rip_ext(const char *entry,char *ext, uint64_t *size)
{
    //example 
    //exe:10MB

    char size_val[EXT_MANIFEST_ENTRY_SZ];
    char size_unit[3];
    size_t clen = strlen(entry);
    unsigned int i;
    for(i = 0; i < clen; i++) {
        if(entry[i] == ':'){
            if(i == clen-1)
            {
                //incorrect format
                LogAlways(("%s: Incorrect entry found. Correct format is .exe:10MB\n",entry));
                return 0;
            }

            strncpy(ext, entry, i);
            ext[i] = '\0'; 

            strncpy(size_val, &entry[i+1], clen-i-3);
            size_val[clen-i-3] = '\0'; 

            strncpy(size_unit, &entry[clen-2], 2);
            size_unit[2] = '\0'; 

            break;
        }
    }

    //convert extension to size. Currently we only support MB and KB
    uint64_t file_size = atol(size_val);
   
    if(0 == strcmp(size_unit, "KB"))
        file_size = file_size * 1024;
    else if(0 == strcmp(size_unit, "MB"))
        file_size = file_size * 1048576;
    else{
        //incorrect format
        LogAlways(("%s: Incorrect entry found. Correct format is .exe:10MB\n",entry));
        return 0;
    }

    *size = file_size;

    return 1;
}

static const char *rip_path(const char *cppath, unsigned int *voltype)
{
    size_t clen = strlen(cppath);
    unsigned int i;
    static const char * const tags[FILESET_VOL_MAX] = {
        /* cl.exe has no named array initializers... GUH?!!!!! */
        /* [FILESET_VOL_BOOT] */ "${BOOTVOL}",
        /* [FILESET_VOL_SYS] */ "${SYSVOL}",
    };

    for(i = 0; i < sizeof(tags)/sizeof(tags[0]); i++) {
        size_t tlen;
        tlen = strlen(tags[i]);
        if ( clen < tlen )
            continue;
        if ( RTStrNICmp(cppath, tags[i], tlen) )
            continue;
        *voltype = i;
        return cppath + tlen;
    }

    /* assume no tag was specified at all */
    *voltype = FILESET_VOL_MAX;
    return cppath;
}

static int pat_list_append(struct pat_list *pat, unsigned int vol,
                           const char *pattern)
{
    unsigned int c;
    struct pat *l;

    c = pat->count + 1;

    l = (struct pat *)RTMemRealloc(pat->list, sizeof(*pat->list) * c);
    if ( NULL == l )
        return 0;

    pat->list = l;
    pat->list[pat->count].vol = vol;
    pat->list[pat->count].pattern = RTStrDup(pattern);
    if ( NULL == pat->list[pat->count].pattern )
        return 0;
    pat->count = c;

    return 1;
}

static void pat_list_init(struct pat_list *pat)
{
    pat->count = 0;
    pat->list = NULL;
}

static void pat_list_free(struct pat_list *pat)
{
    unsigned int i;
    for(i = 0; i < pat->count; i++) {
        RTStrFree(pat->list[i].pattern);
    }
    RTMemFree(pat->list);
    pat_list_init(pat);
}

static int exclude_list_match(struct pat_list *exc,
                                unsigned int vol, const char *path)
{
    unsigned int i;

    if ( NULL == exc )
        return 0;

    for(i = 0; i < exc->count; i++) {
        if ( exc->list[i].vol != vol )
            continue;
        if ( fnmatch(exc->list[i].pattern, path, FNM_PATHNAME|FNM_CASEFOLD) )
            continue;
        return 1;
    }

    return 0;
}

static int do_scan(fileset_t fs, unsigned int vol,
                   const char *path, struct pat_list *exc)
{
    unsigned int i;
    const char *name;
    ntfs_fs_t fs_in;
    ntfs_dir_t dir;
    fsent_t ent;
    int ret = 0;

    if ( exclude_list_match(exc, vol, path) ) {
        LogRel(("EXCLUDED: %s\n", path));
        ret = 1;
        exit_status = ERROR_BAD_FORMAT;
        goto out;
    }

    ent = fileset_insert(fs, vol, path);
    if ( NULL == ent ) {
        LogRel(("%s: insert error\n", path));
        exit_status = ERROR_BAD_FORMAT;
        goto out;
    }

    switch(vol) {
    case FILESET_VOL_SYS:
        fs_in = fileset_sysvol(fs);
        break;
    case FILESET_VOL_BOOT:
    default:
        /* assume main system partition of unknown volume tag */
        fs_in = fileset_bootvol(fs);
        break;
    }

    dir = disklib_ntfs_opendir(fs_in, path,
                                DISKLIB_NAME_DOS_AND_WIN32|
                                DISKLIB_SYMLINK_NOFOLLOW);
    if ( NULL == dir ) {
        if ( disklib_errno() == DISKLIB_ERR_NOTDIR ||
                disklib_errno() == DISKLIB_ERR_ISLNK) {
            /* normal/expected conditions */
            ret = 1;
        }else{
            LogRel(("%s: readdir: %s\n", path,
                     disklib_strerror(disklib_errno())));
        }
        exit_status = ERROR_DIRECTORY;
        goto out;
    }

    for(i = 0; (name = disklib_ntfs_readdir(dir, i)); i++) {
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
            LogAlways(("%s/%s: out of memory constructing path\n",
                    path, name));
            exit_status = ERROR_NOT_ENOUGH_MEMORY;
            goto out_closedir;
        }

        RTStrPrintf(fp, flen, "%s%s%s", path, (ts) ? "" : "/", name);
        ret = do_scan(fs, vol, fp, exc);
        RTMemFree(fp);

        if ( !ret ) {
            exit_status = ERROR_CANNOT_COPY;
            goto out_closedir;
        }
    }

    ret = 1;

out_closedir:
    disklib_ntfs_closedir(dir);
out:
    return ret;
}

static int scan_one_pattern(fileset_t fs,
                        unsigned int vol, const char *pattern,
                      struct pat_list *exc, int failhard)
{
    unsigned int i, gflags;
    ntfs_fs_t fs_in;
    int ret = 1;
    glob_t g;

    switch(vol) {
    case FILESET_VOL_SYS:
        fs_in = fileset_sysvol(fs);
        break;
    case FILESET_VOL_BOOT:
    default:
        /* assume main system partition of unknown volume tag */
        fs_in = fileset_bootvol(fs);
        break;
    }

    g.gl_dirflags = DISKLIB_NAME_DOS_AND_WIN32 | DISKLIB_SYMLINK_NOFOLLOW;
    gflags = GLOB_NOSORT | GLOB_PERIOD;
    if (failhard)
        gflags |= GLOB_NOCHECK;

    Log(("SOURCE: %s\n", pattern));
    ret = disklib_glob(fs_in, pattern, gflags, NULL, &g);
    switch(ret) {
    case 0:
        break;
    case GLOB_NOMATCH:
        //LogRel((" - no matches\n"));
        goto out;
    case GLOB_NOSPACE:
        LogAlways(("%s: disklib_glob: out of memory\n", pattern));
        ret = 0;
        goto out;
    case GLOB_ABORTED:
    default:
        LogAlways(("%s: disklib_glob: %s\n", pattern,
                 disklib_strerror(disklib_errno())));
        ret = 0;
        goto out;
    }

    for(i = 0; i < g.gl_pathc; i++) {
        ret = do_scan(fs, vol, g.gl_pathv[i], exc);
        if ( !ret )
            goto out;

    }

out:
    disklib_globfree(&g);
    return ret;
}

static int start_scan(fileset_t fs, struct pat_list *src,
                      struct pat_list *exc, int failhard)
{
    unsigned int i;
    for(i = 0; i < src->count; i++) {
        int ret;
        ret = scan_one_pattern(fs,
                            src->list[i].vol, src->list[i].pattern,
                            exc, failhard);
        if ( !ret )
            return 0;
    }

    return 1;
}

static partition_t get_active_partition(ptbl_t ptbl)
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

        LogRel(("p%u: is ${SYSVOL} NTFS partition\n", i));
        LogRel((" - it starts at %"PRId64"\n", part_start_sector(part)));
        return part;
    }

    return NULL;
}

static partition_t find_bootvol(ptbl_t ptbl, const uint8_t *buf, size_t sz)
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
        LogAlways(("No idea about disk with sig: 0x%.8x\n", vol_sig));
        return NULL;
    }

    cnt = ptbl_count_partitions(ptbl);
    for(i = 0; i < cnt; i++) {
        partition_t part;

        part = ptbl_get_partition(ptbl, i);
        if ( start == part_start_sector(part) * SECTOR_SIZE ) {
            LogRel(("p%u: is ${BOOTVOL} partition\n", i));
            if ( !disklib_ntfs_partition(part_type(part)) ) {
                LogAlways(("but it's not NTFS?!\n"));
                return NULL;
            }
            return part;
        }
    }

    return NULL;
}

static int disk_open_by_bcd(char *fn, int rw, struct disk *disk)
{
    rhkey_t key = NULL;
    ntfs_fd_t fd = NULL;
    bcd_t bcd = NULL;
    bootmgr_t bmgr = NULL;
    const uint8_t *buf;
    size_t sz;
    int ret = 0;

    LogRel(("open image: %s\n", fn));

    disk_error_context(fn);
    if (!disklib_open_image(fn, rw, &disk->hdd)) {
        RTPrintf("%s: failure to open %s\n", __FUNCTION__, fn);
        LogAlways(("%s: failure to open %s\n", __FUNCTION__, fn));
        goto out;
    }

    LogRel(("open partition table: %s\n", fn));
    disk->ptbl = ptbl_open(disk->hdd);
    if ( NULL == disk->ptbl ) {
        LogAlways(("ptbl_open: %s: %s\n", fn, disklib_strerror(disklib_errno())));
        goto out_disk;
    }

    LogRel(("Disk signature: 0x%.8x\n",
            ptbl_disk_signature(disk->ptbl)));

    disk->p_sysvol = get_active_partition(disk->ptbl);
    if ( NULL == disk->p_sysvol ) {
        LogAlways(("%s: No active partition found\n", fn));
        goto out_ptbl;
    }

    disk->sysvol = disklib_ntfs_mount(disk->p_sysvol, rw);
    if ( NULL == disk->sysvol ) {
        LogAlways(("Mounting sysvol: %s: %s\n",
                 fn, disklib_strerror(disklib_errno())));
        goto out_ptbl;
    }

    fd = disklib_ntfs_open(disk->sysvol, "/boot/bcd", DISKLIB_FD_READ);
    if ( NULL == fd ) {
        LogAlways(("bcd open: %s: %s\n", fn, disklib_strerror(disklib_errno())));
        goto out_unmount;
    }
    LogRel(("volmgr: opened /boot/bcd\n"));

    if ( !reghive_open_hive(&ops, fd, &key) ) {
        LogAlways(("reghive_open_hive fails!\n"));
        goto out_close;
    }

    LogRel(("volmgr: opened hive\n"));

    bcd = bcd_open(key);
    if ( NULL == bcd ) {
        LogAlways(("bcd_open fails!\n"));
        goto out_close_reg;
    }
    LogRel(("volmgr: opened BCD\n"));

    bmgr = bcd_bootmgr_get_default(bcd);
    if ( NULL == bmgr ) {
        LogAlways(("unable to get default bootmgr object\n"));
        goto out_close_bcd;
    }

    LogRel(("volmgr: opened default boot: '%s'\n",
            bootmgr_description(bmgr)));
    LogRel(("volmgr:    sysroot: %s\n",
            bootmgr_sysroot(bmgr)));
    LogRel(("volmgr:   app path: %s\n",
            bootmgr_app_path(bmgr)));

    buf = bootmgr_app_device(bmgr, &sz);
    if ( NULL == buf ) {
        LogAlways(("bootmgr_app_device call fails!\n"));
        goto out_close_bmgr;
    }

    disk->p_bootvol = find_bootvol(disk->ptbl, buf, sz);
    if ( NULL == disk->p_bootvol ) {
        LogAlways(("Error: Unable to locate ${BOOTVOL}\n"));
        LogAlways(("Dumping state:\n"));
        hex_dump(buf, sz, 16, 0);
        goto out_close_bmgr;
    }else if ( disk->p_bootvol == disk->p_sysvol ) {
        disk->bootvol = disk->sysvol;
    }else{
        disk->bootvol = disklib_ntfs_mount(disk->p_bootvol, rw);
        if ( NULL == disk->bootvol ) {
            LogAlways(("Error mounting bootvol: %s: %s\n",
                     fn, disklib_strerror(disklib_errno())));
            goto out_close_bmgr;
        }
    }

    ret = 1;

out_close_bmgr:
    if ( bmgr )
        bootmgr_close(bmgr);
out_close_bcd:
    if ( bcd )
        bcd_close(bcd);
out_close_reg:
    if ( key )
        reghive_close_key(key);
out_close:
    if ( fd )
        disklib_ntfs_close(fd);
out_unmount:
    if ( !ret )
        disklib_ntfs_umount(disk->sysvol);
out_ptbl:
    if ( !ret )
        ptbl_close(disk->ptbl);
out_disk:
    if ( !ret )
        disklib_close_image(disk->hdd);
out:
    if ( !ret )
        memset(disk, 0, sizeof(*disk));
    LogRel(("\n"));
    return ret;
}

static int disk_open(char *fn, int rw, struct disk *disk,
                     int sysvol, int bootvol)
{
    int ret = 0;

    memset(disk, 0, sizeof(*disk));

    LogRel(("open image: %s (sysvol=%d, bootvol=%d)\n", fn, sysvol, bootvol));

    /* If we don't get the sysvol and bootvol args from Krypton, we have to guess
     * them. From a non-raw backend that means reading the BCD. */

    if (strcmp(fn + strlen(fn)-7, ".rawvss") != 0 && (sysvol < 0 || bootvol < 0 )) {
        return disk_open_by_bcd(fn, rw, disk);
    }

    if (!disklib_open_image(fn, rw, &disk->hdd)) {
        RTPrintf("could not open image %s\n", fn);
        goto out;
    }

    if ( sysvol < 0 || bootvol < 0 ) {
        return ret;
    }

    LogRel(("open partition table: %s\n", fn));
    disk->ptbl = ptbl_open(disk->hdd);
    if ( NULL == disk->ptbl ) {
        LogAlways(("ptbl_open: %s: %s\n", fn, disklib_strerror(disklib_errno())));
        goto out_disk;
    }

    disk->p_sysvol = ptbl_get_partition(disk->ptbl, sysvol);
    if ( NULL == disk->p_sysvol ) {
        LogAlways(("%s: sysvol not found (%d)\n", fn, sysvol));
        goto out_ptbl;
    }

    disk->sysvol = disklib_ntfs_mount(disk->p_sysvol, rw);
    if ( NULL == disk->sysvol ) {
        LogAlways(("Mounting sysvol: %s: %s\n",
                 fn, disklib_strerror(disklib_errno())));
        goto out_ptbl;
    }

    if ( bootvol == sysvol ) {
        disk->bootvol = disk->sysvol;
        disk->p_bootvol = disk->p_sysvol;
    }else{
        disk->p_bootvol = ptbl_get_partition(disk->ptbl, bootvol);
        if ( NULL == disk->p_bootvol ) {
            LogAlways(("%s: bootvol not found (%d)\n", fn, bootvol));
            goto out_unmount;
        }

        disk->bootvol = disklib_ntfs_mount(disk->p_bootvol, rw);
        if ( NULL == disk->bootvol ) {
            LogAlways(("Mounting bootvol: %s: %s\n",
                     fn, disklib_strerror(disklib_errno())));
            goto out_unmount;
        }
    }

    ret = 1;
    goto done;

out_unmount:
    disklib_ntfs_umount(disk->sysvol);
out_ptbl:
    ptbl_close(disk->ptbl);
out_disk:
    disklib_close_image(disk->hdd);
out:
    memset(disk, 0, sizeof(*disk));
done:
    LogRel(("\n"));
    return ret;
}

static void disk_close(struct disk *disk)
{
    disklib_ntfs_umount(disk->sysvol);
    if ( disk->sysvol != disk->bootvol )
        disklib_ntfs_umount(disk->bootvol);
    ptbl_close(disk->ptbl);
    disklib_close_image(disk->hdd);
    memset(disk, 0, sizeof(*disk));
}

#define TYPE_NODE       0
#define TYPE_RESIDENT   1
#define TYPE_FILE       2

static int node_type(const fsent_t a)
{
    struct disklib_stat st;

    fsent_stat(a, &st);

    if ( st.f_mode & DISKLIB_ISDIR || st.f_mode & DISKLIB_ISSPECIAL )
        return TYPE_NODE;

    if ( st.f_mode & (DISKLIB_ISCMP | DISKLIB_ISREPARSE) )
        return TYPE_RESIDENT;
    if ( !(st.a_mode & DISKLIB_ISATTR) )
        return TYPE_RESIDENT;
    if ( st.a_mode & DISKLIB_ISRESIDENT )
        return TYPE_RESIDENT;

    return TYPE_FILE;
}

static uint64_t node_ofs(const fsent_t a)
{
    const struct disklib_extent *rl;
    unsigned int rl_cnt, i;

    fsent_runlist(a, &rl, &rl_cnt);
    if ( NULL == rl || 0 == rl_cnt )
        return 0;

    for(i = 0; i < rl_cnt; i++) {
        if ( rl[i].off != DISKLIB_EXTENT_HOLE )
            return rl[i].off;
    }

    return 0;
}

static uint64_t node_ino(const fsent_t a)
{
    struct disklib_stat st;
    fsent_stat(a, &st);
    return st.f_ino;
}

static DECLCALLBACK(int) sortfn(const void *A, const void *B)
{
    const fsent_t a = *(fsent_t *)A;
    const fsent_t b = *(fsent_t *)B;
    int type;
    int ret;

    ret = fsent_vol(b) - fsent_vol(a);
    if ( ret )
        return ret;

    ret = node_type(a) - node_type(b);
    if ( ret )
        return ret;

    type = node_type(a);

    switch(type) {
    case TYPE_RESIDENT:
        /* order my MFT number */
        ret = node_ino(a) - node_ino(b);
        if ( ret )
            return ret;
        break;
    case TYPE_FILE:
        /* Order by first extent offset */
        ret = node_ofs(a) - node_ofs(b);
        if ( ret )
            return ret;
        break;
    default:
        break;
    }
    ret = fsent_prio(a) - fsent_prio(b);
    return ret;
}

static void prep_manifest(fsent_t *man, unsigned int mcnt)
{
    /* Use shell-sort because filename sort order is likely to be
     * very similar to directory scan sort order, so let's avoid worst case
     * of qsort
    */
    qsort(man, mcnt, sizeof(*man), sortfn);
}

struct RUNTIME_ENTRY
{
    RTTIMESPEC  t0;
    RTTIMESPEC  t1;
    int64_t     d0;
};

struct RUNTIMES
{
    RUNTIME_ENTRY   Scan;
    RUNTIME_ENTRY   Copy;
    RUNTIME_ENTRY   Link;
    RUNTIME_ENTRY   Total;
};

/* Progress bar support. */

struct STAGE { char name[32]; float percent; };

struct STAGE stages[] = {
    { "Initializing", 1.0},
    { "Loading MFT", 9.0},
    { "Scanning", 10.0},
    { "Copying small files", 10.0},
    { "Creating references", 10.0},
    { "Copying large files", 45.0},
    { "Closing files", 10.0},
    { "Creating hardlinks", 5.0},
    { "Done", 0.0},
};

static int current_stage = -1;
static float baseline = 0.0;

/* Call within worker loop with float between 0 and 1. */

static void show_progress(float percent, int force)
{
    static float last = -10.0;
    assert(current_stage >= 0);
    float total = baseline + stages[current_stage].percent * percent;

    if ( total - last >= 1.0 || force) {
        last = total;
        fprintf(stderr, "\rNTFSCP: %3.1f%% complete (%s...)            \n",
                total, stages[current_stage].name);
        fflush(stderr);
    }
}

/* Advance to next stage. */

static void next_stage(int line)
{
    if (current_stage >= 0) {
        baseline += stages[current_stage].percent;
    }
    ++current_stage;
    LogAlways(("Going into stage '%s'\n", stages[current_stage].name));
    disk_error_context0(__FILE__, line, stages[current_stage].name);
    show_progress(0.0, 1);
}

struct file_type {
    char * ext;
    uint64_t max_size;
};

struct file_type_list {
    struct file_type *list;
    unsigned int count;
};

static int file_type_list_append(struct file_type_list *flist, uint64_t size,
                           const char *ext)
{
    unsigned int c;
    struct file_type *l;

    c = flist->count + 1;

    l = (struct file_type *)RTMemRealloc(flist->list, sizeof(*flist->list) * c);
    if ( NULL == l )
        return 0;

    flist->list = l;
    flist->list[flist->count].max_size = size;
    flist->list[flist->count].ext = RTStrDup(ext);
    if ( NULL == flist->list[flist->count].ext )
        return 0;
    flist->count = c;

    return 1;
}

static void file_type_list_init(struct file_type_list *flist)
{
    flist->count = 0;
    flist->list = NULL;
}

static void file_type_list_free(struct file_type_list *flist)
{
    unsigned int i;
    for(i = 0; i < flist->count; i++) {
        RTStrFree(flist->list[i].ext);
    }
    RTMemFree(flist->list);
    file_type_list_init(flist);
}


static int read_manifest(fileset_t fs, FILE *manifest, int failhard, 
    uint64_t * default_log_file_size, uint64_t * default_copy_file_size, struct file_type_list* flist )
{
    struct pat_list src, exc;
    unsigned int line;
    char *sec_name = NULL;
    char buf[1024];
    int rc = VINF_SUCCESS;

    pat_list_init(&src);
    pat_list_init(&exc);

    for(line = 1; rc != VERR_EOF; line++) {
        char *ptr;
        char *last;

        if (!(fgets(buf, sizeof(buf), manifest))) {
            rc = VERR_EOF;
            buf[0] = '\0';
        } else {
            /* Chop off newline at end to be compatible with formerly
             * used VBox RTStrm API behaviour. */
            last = buf + strlen(buf) - 1;
            if (*last == '\n') *last-- = '\0';
            if (*last == '\r') *last-- = '\0';
        }

        ptr = buf;
        if ( ptr[0] == '\0' || ptr[0] == '#' )
            continue;

        if ( ptr[0] == '[' ) {
            if ( sec_name ) {
                LogRel(("Processing section: %s\n", sec_name));
                if ( !start_scan(fs, &src, &exc, failhard) ) {
                    LogAlways(("ERROR: directory scan failed\n"));
                    rc = VERR_FILE_IO_ERROR;
                    goto out;
                }
            }
            pat_list_free(&src);
            pat_list_free(&exc);
            RTMemFree(sec_name);
            sec_name = RTStrDup(ptr);
        }else{
            unsigned int vol;
            const char *pattern;
            struct pat_list *l;

            if ( NULL == sec_name ) {
                rc = VERR_INVALID_PARAMETER;
                LogAlways(("manifest:%u: Missing section name\n", line));
                goto out;
            }

            switch(ptr[0]) {
            case '+':
                l = &src;
                break;
            case '-':
                l = &exc;
                break;
            case '.':
                {
                    ptr++;

                    uint64_t file_size = 0;
                    char file_ext[EXT_MANIFEST_ENTRY_SZ];

                    if(!rip_ext(ptr, file_ext, &file_size)){
                        rc = VERR_INVALID_PARAMETER;
                         goto out;
                    }
                    else{
                        //extension entry found
                        if(!strcmp(file_ext, "brbigfilelogdefault")){

                            *default_log_file_size = file_size;
                            LogAlways(("File Rule found: file log default > %"PRId64" bytes\n", file_size));
                        } else if(!strcmp(file_ext, "brbigfilecopydefault")){

                            *default_copy_file_size = file_size;
                             LogAlways(("File Rule found: file copy default > %"PRId64" bytes\n", file_size));
                        } else{
                            if ( !file_type_list_append(flist, file_size, file_ext) ) {
                                rc = VERR_NO_MEMORY;
                                goto out;
                            }
                            LogAlways(("File Rule found: file copy with extension %s > %"PRId64" bytes\n", file_ext, file_size));
                        }
                        continue;
                    }
                }
                break;
            default:
                rc = VERR_INVALID_PARAMETER;
                LogAlways(("manifest:%u: Missing +/-\n", line));
                goto out;
            }

            ptr++;

            pattern = rip_path(ptr, &vol);
            if ( !pat_list_append(l, vol, pattern) ) {
                rc = VERR_NO_MEMORY;
                goto out;
            }
        }
    }

    if ( sec_name && !start_scan(fs, &src, &exc, failhard) ) {
        LogAlways(("ERROR: directory scan failed\n"));
        rc = VERR_FILE_IO_ERROR;
        goto out;
    }

    rc = VINF_SUCCESS;

out:
    RTMemFree(sec_name);
    pat_list_free(&src);
    pat_list_free(&exc);
    return rc;
}

struct sched {
    fsent_t f;
    uint64_t off;
    uint64_t voff;
    uint64_t len;
};

static int match_ext(const char * file_path, const char* ext)
{
    //get the file extension
    char file_ext[EXT_MANIFEST_ENTRY_SZ];
    file_ext[0] = '\0'; 
    size_t clen = strlen(file_path);
    int i = clen - 1;

    while(i > -1) {
        if (file_path[i] == '.')
        {
            //corner case
            if(i != clen - 1)
            {
                strcpy (file_ext, &file_path[i+1]);
            }
            break;
        }
        
        i--;
    }

    //case insensitive comparison
    clen = strlen(file_ext); 
    if(clen == strlen(ext))
    {
        unsigned int j;
        for(j = 0;j < clen;j++)
        {
            if(tolower(file_ext[j]) != tolower(ext[j]))
            {
                return 0;
            }
        }

        return 1;
    }

    return 0;
}

static int AppliedFileCopyFilterRules(struct sched * file, uint64_t default_copy_file_size, struct file_type_list* flist)
{
    uint64_t file_size = file->len;
    const char *file_path = fsent_path(file->f);

    //check extension rule
    unsigned int i;
    for(i = 0; i < flist->count; i++) {
        if((match_ext(file_path, flist->list[i].ext)) && (file_size > flist->list[i].max_size)){
            LogAlways(("BR Analyze: (file ext skip rule triggered) Skipping the Big File found: ,%s ,%"PRId64", bytes\n", file_path, file_size));
            return 1;
        }
    }

    //check global rule
    if((file_size > default_copy_file_size) && (default_copy_file_size > 0)){
        LogAlways(("BR Analyze: (file default skip rule triggered) Skipping the Big File found: ,%s ,%"PRId64", bytes\n", file_path, file_size));
        return 1;
    }

    return 0;
}

static DECLCALLBACK(int) sched_cmp(const void *A, const void *B)
{
    const struct sched *a = (const struct sched *)A;
    const struct sched *b = (const struct sched *)B;
    if ( a->off < b->off )
        return -1;
    if ( a->off > b->off )
        return 1;
    return 0;
}

static struct sched *mkschedule(fsent_t *man, unsigned int mcnt, uint64_t
        *nr_extent, partition_t bootvol, partition_t sysvol)
{
    const struct disklib_extent *rl;
    unsigned int rl_cnt, i, j;
    uint64_t nr, v;
    struct sched *sched;
    void *cont;

    for(nr = 0, i = 0; i < mcnt; i++) {
        struct disklib_stat st;
        cont = fsent_get_priv(man[i]);
        if ( NULL == cont )
            continue;

        fsent_runlist(man[i], &rl, &rl_cnt);
        if ( NULL == rl || 0 == rl_cnt ) {
            RTPrintf("Problem with %s, skipping it.\n", fsent_path(man[i]));
            continue;
        }

        fsent_stat(man[i], &st);
        dprintf("FILE %"PRId64" %d %s\n",
                 st.f_size, rl_cnt, fsent_path(man[i]));
        for(j = 0; j < rl_cnt; j++) {
            if ( rl[j].off== DISKLIB_EXTENT_HOLE ) {
                dprintf("HOLE %"PRId64"\n", rl[j].len);
            }else{
                dprintf(" - %"PRId64" bytes from 0x%"PRIx64"\n",
                         rl[j].len, rl[j].off);
                nr++;
            }
        }
    }

    sched = (struct sched *)RTMemAlloc(sizeof(*sched) * nr);
    if ( NULL == sched )
        return NULL;

    for(nr = 0, i = 0; i < mcnt; i++) {
        cont = fsent_get_priv(man[i]);
        if ( NULL == cont )
            continue;

        fsent_runlist(man[i], &rl, &rl_cnt);
        if ( NULL == rl || 0 == rl_cnt )
            continue;

        for(v = 0, j = 0; j < rl_cnt; j++) {

            partition_t partition = (fsent_vol(man[i]) == FILESET_VOL_BOOT && bootvol) ?
                bootvol : sysvol;

            if ( rl[j].off != DISKLIB_EXTENT_HOLE ) {

                sched[nr].f = man[i];
                sched[nr].voff = v;

                /* Partition-translate offset before sorting, just to be perfect. */
                sched[nr].off = SECTOR_SIZE *
                    part_translate_sector(partition, rl[j].off/SECTOR_SIZE);

                sched[nr].len = rl[j].len;
                nr++;
            }
            v += rl[j].len;
        }
    }

    *nr_extent = nr;

    return sched;
}

/* partition numbers for sysvol/bootvol on destination image.
 * ALWAYS hardcoded
*/
#define DST_SYSVOL      0
#define DST_BOOTVOL     1

/* How many outstanding reads do we allow, and how big. Max
 * space used for buffering is the product of the two. */

#define NUM_OVERLAPPING 32
#define MAX_READ_SIZE (2ULL<<20ULL)

static int ntfscp_main(char *fin, char *fout,
                           const wchar_t *mpath,
                           int sysvol, int bootvol,
                           int failhard,
                           int do_reordering,
                           RUNTIMES *Runtimes)
{
    struct disk din, dout;
    FILE *manifest;
    fileset_t fs;
    int rc = VERR_PDM_MEDIA_NOT_MOUNTED;
    fsent_t *man;
    unsigned int mcnt, i;
    char    time[1024];
    uint64_t nr_extent;
    struct sched *sched;
    char rootdrive = 'c';
    char *systemroot;

    next_stage(__LINE__);

    /* Check for a well-formed SystemRoot env var, use its drive letter as the
     * root for the shallow map entries. */

    systemroot = getenv("SystemRoot");
    if (systemroot && systemroot[1] == ':') {
        rootdrive = systemroot[0];
    }

    if ( !disk_open(fin, 0, &din, sysvol, bootvol) ) {
        LogAlways(("%s, input disk open error\n", __FUNCTION__));
        exit_status = ERROR_FILE_NOT_FOUND;
        goto out;
    }

    if (do_reordering) {
        do_reordering = 0;
        RTPrintf("IGNORING reordering option for VBox input backend!\n");
    }

    if (do_reordering && stricmp(fout + strlen(fout)-5, ".swap") != 0) {
        do_reordering = 0;
        RTPrintf("IGNORING reordering option for non-swap output backend\n");
    }

    if ( !disk_open(fout, 1, &dout, DST_SYSVOL, DST_BOOTVOL) ) {
        LogAlways(("%s, output disk open error\n", __FUNCTION__));
        exit_status = ERROR_FILE_NOT_FOUND;
        goto out_din;
    }

    /* Tell the swap backend we need at PushDown at the end. */
    disklib_set_slow_flush(dout.hdd);

    /* Add a read cache for the input disk. The size is currently
     * hard-coded in part.c. */
    if ( !ptbl_add_read_cache(din.ptbl) ) {
        exit_status = ERROR_NOT_ENOUGH_MEMORY;
        goto out_dout;
    }

    rc = fileset_new(&fs, din.bootvol, din.sysvol);
    if ( RT_FAILURE(rc) ) {
        LogAlways(("fileset_new: %d\n", rc));
        exit_status = ERROR_NOT_ENOUGH_MEMORY;
        goto out_dout;
    }

    manifest = _wfopen(mpath, L"r");
    if ( manifest == NULL) {
        LogAlways(("manifest open fails!\n"));
        exit_status = ERROR_FILE_NOT_FOUND;
        goto out_fs;
    }

    RTTimeNow(& Runtimes->Scan.t0);
    RTTimeSpecToString(& Runtimes->Scan.t0, time, 1024);
    LogAlways(("\n  START of scan phase: %s\n\n", time));
    next_stage(__LINE__);

    /* Prime the read cache with the Master File Table, up to a sane limit of
     * 512MB. */

    ntfs_fd_t mft = disklib_ntfs_open_mft(din.bootvol);
    if (mft == NULL) {

        LogAlways(("%s: unable to open MFT for pre-loading!\n", __FUNCTION__));
        exit_status = ERROR_FILE_NOT_FOUND;
        goto out_fs;

    } else {
        size_t mftsz =0;
        size_t mftBufSz = 0x100000;
        void *mftBuf = malloc(mftBufSz);

        if (mftBuf == NULL) {
            LogAlways(("%s: unable to allocate buffer for MFT!\n", __FUNCTION__));
            exit_status = ERROR_NOT_ENOUGH_MEMORY;
            goto out_fs;
        }

        for (mftsz = 0; mftsz < (512 << 20);) {
            ssize_t ret;

            ret = disklib_ntfs_read(mft, mftBuf, mftBufSz);
            if (ret == 0) {
                break;
            }
            if (ret < 0) {
                LogAlways(("MTF pre-load read error %"PRIdS"\n", ret));
                break;
            }

            mftsz += ret;
            show_progress(  (float) mftsz / ((float) (512 << 20)), 0);
        }
        free(mftBuf);
    }

    /* After cache warmup, the actual scan starts here. */

    next_stage(__LINE__);
    uint64_t default_copy_file_size = 0;
    uint64_t default_log_file_size = 0;
    struct file_type_list file_types;
   
    file_type_list_init(&file_types);

    rc = read_manifest(fs, manifest, failhard, &default_log_file_size, &default_copy_file_size, &file_types);
    if ( RT_FAILURE(rc) ) {
        LogAlways(("error reading manifest on line %d\n", __LINE__));
        exit_status = ERROR_BAD_FORMAT;
        goto out_close;
    }

    RTTimeNow(& Runtimes->Scan.t1);
    RTTimeSpecToString(& Runtimes->Scan.t1, time, 1024);
    LogAlways(("\n  END of scan phase: %s\n\n", time));

    rc = fileset_manifest(fs, &man, &mcnt);
    if ( RT_FAILURE(rc) ) {
        LogAlways(("fileset_manifest: %d\n", rc));
        exit_status = ERROR_BAD_FORMAT;
        goto out_close;
    }

    prep_manifest(man, mcnt);


    /* We now know what to copy. */

    RTTimeNow(& Runtimes->Copy.t0);
    RTTimeSpecToString(& Runtimes->Copy.t0, time, 1024);
    LogAlways(("\n  START of BR Analyzing %u files phase: %s\n\n", mcnt, time));
    next_stage(__LINE__);

    /* Make read-cache immutable from now on. The file data
     * will not compress as well as the MFT, and we don't want it
     * growing uncontrollably. */

    ptbl_reduce_read_cache(din.ptbl);

    for(i = 0; i < mcnt; i++) {

        /* Most files are just copied straight from A to B. However, the files
         * in /Boot are not present on all machines (i.e., not on EFI machines)
         * but fortunately we can take them from /Windows/Boot, so we hard-code
         * the rewiring of those locations. */
        
        show_progress( ((float) i) / ((float) mcnt), 0);

        const char *rawpath;
        const char bootmgr[] = "bootmgr";
        const char bootloader_fonts[] = "/Windows/Boot/Fonts/";
        const char bios_bootloader_files[] = "/Windows/Boot/PCAT/";
        char cookedpath[MAX_PATH];
        ntfs_fs_t fs_in, fs_out;
        void *ptr;
        int ret;

        switch(fsent_vol(man[i])) {
        case FILESET_VOL_BOOT:
            fs_in = din.bootvol;
            fs_out = dout.bootvol;
            break;
        case FILESET_VOL_SYS:
            fs_in = din.sysvol;
            fs_out = dout.sysvol;
            break;
        default:
            AssertFailed();
            continue;
        }

        rawpath = fsent_path(man[i]);

        Log(("COPY: %s\n", rawpath));
        strcpy(cookedpath, rawpath);

        disk_error_context(rawpath);

        unsigned int j;

        for(j = 0; j < fsent_nlnk(man[i]) + 1; j++) {

            /* The first time we use the base file name, and then if that does
             * not match we proceed to check any hardlink alternative names. */

            if (j > 0) {
                rawpath = fsent_get_link(man[i], j - 1, NULL);
            }

            if (!strnicmp(rawpath, bios_bootloader_files,
                        sizeof(bios_bootloader_files) - 1)) {
                if (!strnicmp(rawpath + strlen(rawpath) - sizeof(bootmgr) + 1,
                            bootmgr, sizeof(bootmgr) - 1)) {
                    strcpy(cookedpath, "/");
                    strcat(cookedpath, bootmgr);
                } else {
                    strcpy(cookedpath, "/Boot/");
                    strcat(cookedpath, rawpath + sizeof(bios_bootloader_files) - 1);
                }

                LogRel(("Rewiring %s to %s\n", rawpath, cookedpath));
                fs_out = dout.sysvol;
                break;

            } else if (!strnicmp(rawpath, bootloader_fonts,
                        sizeof(bootloader_fonts) - 1)) {
                strcpy(cookedpath, "/Boot/Fonts/");
                strcat(cookedpath, rawpath + sizeof(bootloader_fonts) - 1);

                LogRel(("Rewiring %s to %s\n", rawpath, cookedpath));
                fs_out = dout.sysvol;
                break;

            } else {
                /* No match, try alternatives. */
                continue;
            }
        }



#ifndef DRY_RUN
        ptr = NULL;
        if ( do_reordering )
            ret = disklib_ntfs_copy(fs_in, fs_out, rawpath, cookedpath, &ptr);
        else
            ret = disklib_ntfs_copy(fs_in, fs_out, rawpath, cookedpath, NULL);
        if ( ret ) {
                /* existing files, and refusal to copy system files
                 * such as $Boot or $Mft are totally expected and harmless
                 * conditions...
                */
                if ( disklib_errno() != DISKLIB_ERR_EXIST &&
                    disklib_errno() != DISKLIB_ERR_IS_SPECIAL &&
                    disklib_errno() != DISKLIB_ERR_ACCES) {
                    LogAlways(("%s: error BR Analyzing: %s\n", rawpath,
                            disklib_strerror(disklib_errno())));
                    rc = VERR_FILE_IO_ERROR;
                    exit_status = ERROR_WRITE_FAULT;
                    goto out_free_manifest;
                } else {
                    LogAlways(("%s: ignoring BR Analyzing error:  %s\n", rawpath,
                                disklib_strerror(disklib_errno())));
                }
        }
        if ( ptr ) {
            fsent_set_priv(man[i], ptr);
        }
#endif
    }

    /* The space used for the read cache is no longer useful, free it. */
    ptbl_del_read_cache(din.ptbl);

    if ( !do_reordering || mcnt == 0 )
        goto skip_bulk;

    sched = mkschedule(man, mcnt, &nr_extent, din.p_bootvol, din.p_sysvol);

    if ( NULL == sched ) {
        exit_status = ERROR_NOT_ENOUGH_MEMORY;
        LogAlways(("out of memory error on line %d\n", __LINE__));
        goto out_free_manifest;
    }

    /* sort first time. */
    qsort(sched, nr_extent, sizeof(*sched), &sched_cmp);

    LogAlways(("creating map of referenced files on host...\n"));
    next_stage(__LINE__);

    char map_fn[MAX_PATH];
    char hardlinks[MAX_PATH];
    char bromiumhardlinks[MAX_PATH];

    /* Set up path for swapdata map.idx, creating swapdata (though should never
     * be needed, dubtree should have created it for us.) */

    strcpy(map_fn, fout);
    RTPathStripFilename(map_fn);

    /* First append swapdata and create it. */
    RTPathAppend(map_fn, sizeof(map_fn), "swapdata");
    RTDirCreate(map_fn, 0);

    /* Then append map.idx. */
    RTPathAppend(map_fn, sizeof(map_fn), "map.idx");

    /* Set up path for hardlinks directory under swapdata and create it. */
    RTPathAbs(fout, hardlinks, sizeof(hardlinks));
    char *c = hardlinks;
    while (*c) {
        if (*c == '\\') *c = '/';
        ++c;
    }
    RTPathStripFilename(hardlinks);
    RTPathAppend(hardlinks, sizeof(hardlinks), "swapdata");
    RTPathAppend(hardlinks, sizeof(hardlinks), "hardlinks");
    RTDirCreate(hardlinks, 0);
    /* Get rid of the C: in front for strcmp etc. uses below. */
    strcpy(bromiumhardlinks, hardlinks + 2);

    FILE *map_file = fopen(map_fn, "wb");

    if (map_file == NULL) {
        LogAlways(("failed creating map.idx!\n"));
        RTPrintf("failed creating map.idx!\n");
        exit(-1);
    }


    size_t mapped_sum = 0;
    size_t skipped_sum = 0;
    unsigned int num_shortcuts = 0;
    const size_t chunk = (16<<20);
    void *mapBuffer = (void*) malloc(chunk);
    char *mb = (char*) mapBuffer;


    /* When we intercept the writes coming from ntfslib, we look for a magic
     * pattern to decide which writes to shallow. Ugly but the alternative is
     * to hack ntfslib. */

    LogAlways(("START of shallow BR Analyze phase!\n"));
    uint64_t total_size_deep_copy_skip = 0;
    for (i = 0; i < chunk / SECTOR_SIZE; ++i) {

        fill_with_magic_bytes(mb);
        mb += SECTOR_SIZE;
    }

    for (i = 0; i < nr_extent; ++i) {

        show_progress( ((float) i) / ((float) nr_extent), 0);

        const char aspnet4[] = "/windows/inf/asp.net_4";
        const char assembly[] = "/windows/assembly";
        const char boot2[] = "/windows/boot";
        const char boot[] = "/boot";
        const char devicemetadata[] = "/ProgramData/Microsoft/Windows/devicemetadatastore/";
        const char dotnetassembly[] = "/Windows/microsoft.net/assembly/";
        const char dotnetframework[] = "/Windows/microsoft.net/framework";
        const char downloaded[] = "/Windows/downloaded installations/";
        const char filerepo[] = "/windows/system32/driverstore/filerepository";
        const char fonts[] = "/windows/fonts";
        const char globalization[] = "/windows/globalization/mct/";
        const char inst[] = "/windows/installer";
        const char msocache[] = "/msocache";
        const char servicingpackages[] = "/windows/servicing/packages/";
        const char silverlight4[] = "/program files (x86)/microsoft silverlight/4";
        const char silverlight5[] = "/program files (x86)/microsoft silverlight/5";
        const char silverlight5_64[] = "/program files/microsoft silverlight/5";
        const char softwaredist[] = "/windows/softwaredistribution/download/";
        const char sxs[] = "/windows/winsxs";
        const char sxstmp[] = "/windows/winsxs/temp/";
        const char symbols[] = "/windows/symbols/";

        char bromiumlink[MAX_PATH];
        size_t size  = sched[i].len;
        const char *c;
        char *p;
        char path[MAX_PATH];

        /* Lower-case and copy path to ease string-comparing and make sure hashing works
         * out consistently. */
        for (c = fsent_path(sched[i].f), p = path; ; ++c, ++p) {

            *p = tolower(*c);
            /* Check for end after copying terminating zero. */
            if (*p == '\0') break;
        }

        if (       !strnicmp(path, silverlight4, sizeof(silverlight4)-1)
                || !strnicmp(path, silverlight5, sizeof(silverlight5)-1)
                || !strnicmp(path, silverlight5_64, sizeof(silverlight5_64)-1)
                || !strnicmp(path, aspnet4, sizeof(aspnet4)-1)
                || !strnicmp(path, dotnetframework, sizeof(dotnetframework)-1)
                || !strnicmp(path, inst, sizeof(inst)-1)) {

            char source[MAX_PATH];
            char pathhash[64];
            uint8_t md[RTSHA1_HASH_SIZE];

            RTSHA1CONTEXT ctx;
            RTSha1Init(&ctx);
            RTSha1Update(&ctx, path, strlen(path));
            RTSha1Final(&ctx, md);
            RTSha1ToString(md, pathhash, sizeof(pathhash));

            sprintf(bromiumlink, "%c:%s/%s", rootdrive, bromiumhardlinks, pathhash);
            sprintf(source, "%c:%s", rootdrive, path);

            if (CreateHardLink(bromiumlink, source, NULL) 
                    || GetLastError() == ERROR_ALREADY_EXISTS) {
                /* We created a hardlink, use that instead of original file name. */
                strcpy(path, bromiumlink + 2); // XXX skipping C:  - ugly

            } else {
                Log(("info: link %s <- %s fails %lu\n", bromiumlink, source, GetLastError()));
            }

        } else {

            /* Test for presence of uniquely named hardlink, e.g., in WinSXS, but
             * exclude anything that is linked from within winsxs/temp,
             * because of PendingDeletes links. */
            unsigned int j;
            const char *prefer = NULL;
            for(j = 0; j < fsent_nlnk(sched[i].f); j++) {
                const char *lnk = fsent_get_link(sched[i].f, j, NULL);
                if (!strnicmp(lnk, sxstmp, sizeof(sxstmp)-1)) {
                    LogAlways(("excluding %s from shallow!\n", lnk));
                    prefer = NULL;
                    break;
                }
                if (       !strnicmp(lnk, sxs, sizeof(sxs)-1)
                        || !strnicmp(lnk, filerepo, sizeof(filerepo)-1)
                        || !strnicmp(lnk, assembly, sizeof(assembly)-1)) {
                    prefer = lnk;
                }
            }

            if (prefer) {
                strcpy(path, prefer);
            }

        }

        uint64_t dest = sched[i].voff;
        void *priv = fsent_get_priv(sched[i].f);

        /* Check for directories that can be handled as shallow. */

        if (size > SECTOR_SIZE &&
                (  !strnicmp(path, assembly, sizeof(assembly)-1)
                || !strnicmp(path, boot, sizeof(boot)-1) 
                || !strnicmp(path, boot2, sizeof(boot2)-1) 
                || !strnicmp(path, bromiumhardlinks, strlen(bromiumhardlinks)) 
                || !strnicmp(path, devicemetadata, sizeof(devicemetadata)-1)
                || !strnicmp(path, dotnetassembly, sizeof(dotnetassembly)-1)
                || !strnicmp(path, downloaded, sizeof(downloaded)-1)
                || !strnicmp(path, filerepo, sizeof(filerepo)-1) 
                || !strnicmp(path, fonts, sizeof(fonts)-1)
                || !strnicmp(path, globalization, sizeof(globalization)-1)
                || !strnicmp(path, msocache, sizeof(msocache)-1)
                || !strnicmp(path, servicingpackages, sizeof(servicingpackages)-1)
                || !strnicmp(path, silverlight4, sizeof(silverlight4)-1)
                || !strnicmp(path, softwaredist, sizeof(softwaredist)-1)
                || !strnicmp(path, sxs, sizeof(sxs)-1) 
                || !strnicmp(path, symbols, sizeof(symbols)-1)
                )) {

            char path2[MAX_PATH] = {rootdrive, ':', '\0'};
            strcat(path2, path);

            /* Stupid libntfs wants to copy all the data it writes, so we
             * cannot just pass it a fake or null buffer pointer. Files may
             * get really large so we have to chunk up the writes, even
             * though that will translate into more map.idx entries. */

            size_t take;

            while (size > 0) {

                Log(("SHALLOW COPY: %s\n", path2));
                mapped_sum += size;

                set_current_filename(path2, dest, 0);

                take = size < chunk ? size : chunk;

                if ( disklib_ntfs_copy_cont(priv, (char*)mapBuffer, take, dest, 1)) {

                    RTPrintf("write failure!\n");
                    LogAlways(("%s: copy_cont: %s\n", fsent_path(sched[i].f),
                                disklib_strerror(disklib_errno())));
                    exit_status = ERROR_WRITE_FAULT;
                    goto out_free_sched;
                }

                size -= take;
                dest += take;
            }

            sched[i].off = ~0ULL;
            ++num_shortcuts;

        } else {

            if(!AppliedFileCopyFilterRules(&sched[i], default_copy_file_size, &file_types )){
                
                //this file will surely be deep copied
                skipped_sum += size;
            }
            else {
                //skipped from deep copy
                 total_size_deep_copy_skip += sched[i].len;
                sched[i].off = ~0ULL;
                ++num_shortcuts;
            }
        }
    }
    free(mapBuffer);
    file_type_list_free(&file_types);
    LogAlways(("END of shallow BR Analyze phase!\n"));
    LogAlways(("Saved by shallowing %"PRIuS"MB, Skipped from BR Analyze %"PRIu64"MB, To BR Analyze %"PRIuS"MB\n", mapped_sum>>20ULL, total_size_deep_copy_skip>>20ULL, skipped_sum>>20ULL));

    flush_map_to_file(map_file);
    fclose(map_file);

    /* Bulk copying of file data using Windows overlapped IO. */

    next_stage(__LINE__);

    LogAlways(("START of deep BR Analyze phase!\n"));

    set_current_filename(NULL, 0, 0);
    qsort(sched, nr_extent, sizeof(*sched), &sched_cmp);
    nr_extent -= num_shortcuts; /* truncate list. */

    typedef struct buffered_read {
        struct buffered_read *next;
        void *priv;
        const char *path;
        uint64_t dest;
        uint64_t size;
        void *buffer;
        HANDLE file;
    } buffered_read_t;


    int j;
    OVERLAPPED ovl[NUM_OVERLAPPING];
    HANDLE events[NUM_OVERLAPPING];
    buffered_read_t *buffered_reads[NUM_OVERLAPPING];

    buffered_read_t *reads_head = NULL;
    (void)reads_head;
    buffered_read_t *reads_tail = NULL;
    (void)reads_tail;

    uint64_t offset = 0, dest = 0, size;
    void *priv;
    const char *path;

    int outstanding;
    buffered_read_t *r;

    memset(buffered_reads, 0, sizeof(buffered_reads));
    memset(ovl, 0, sizeof(ovl));

    for (i = 0; i < NUM_OVERLAPPING; ++i) {
        events[i] = CreateEvent(NULL, TRUE, TRUE, NULL);
        if (events[i] == NULL) {
            LogAlways(("%s: unable to create event handle on line %d\n",
                        __FUNCTION__, __LINE__));
            exit_status = ERROR_NOT_ENOUGH_MEMORY;
            goto out_free_sched;
        }
    }

    /* This loop runs until there is no more extents to read, and nothing more
     * to write. 'i' is the index into a circular buffer of outstanding read
     * slots, each of which has a Windows event associated. When a read
     * completes, the buffer will be appended to a linked list of buffered data
     * to be written to disk. Once 512MB (or less if we couldn't set the WSS to
     * 1GB) of reads have been buffered, the list is emptied by writing the
     * extents to the relevant output files. */

    size_t read_sum = 0;
    size_t write_sum = 0;
    uint64_t total_size_deep_copy = 0;

    for (size = 0, i = j = 0, outstanding = 0;
            j < nr_extent || outstanding > 0;
            i = (i + 1) % NUM_OVERLAPPING) {

        show_progress( ((float) j) / ((float) nr_extent), 0);

        uint64_t take;
        void *file;

        /* Consume a new extent from the input array, unless we reached the
         * end of it. In that case leave size==0 to signal completion. */

        if (size == 0 && j < nr_extent) {

            /* To not interrupt the streamlined copying with file lookups, we
             * pre-open a big batch of files once in a while. We do not bother
             * keeping the file handles, but rely on the host OS kernel to
             * cache the relevant bits. */
            if (use_vss_logical_reads()) {
                const int prefetch = 256;
                if (!(j % prefetch)) {
                    int k;
                    for (k = j; k < nr_extent && k < j + prefetch; ++k) {
                        file = open_vss_logical_file(fsent_path(sched[k].f), 1);
                        if (file) {
                            close_vss_logical_file(file);
                        }
                    }
                }
            }

            offset = sched[j].off;
            dest   = sched[j].voff;
            size   = sched[j].len;
            priv   = fsent_get_priv(sched[j].f);
            path   = fsent_path(sched[j].f);
            Log(("DEEP COPY: %s %"PRIu64"\n", path, size));
            if((size > default_log_file_size) && (default_log_file_size > 0)){

                LogAlways(("DEEP BR Analyze: (file default log rule triggered) Big File found: ,%s ,%"PRId64", bytes\n", path, size));
            }

            total_size_deep_copy += size;

            if (offset == ~0ULL) {
                assert(0);
            }
            ++j;
        }

        /* If this slot was use to issue IO previously we make sure that
         * the previous read completed, and buffer that read in our write
         * queue before we reuse the slot to issue a new read. */

        OVERLAPPED *o = &ovl[i];

        WaitForSingleObject(events[i], INFINITE);
        /* Find the read descriptor corresponding to this slot, if any. */

        if (buffered_reads[i]) {

            r = buffered_reads[i];
            disk_error_context(r->path);

            /* Check if previous IO in this slot completed successfully.
             * Note that the calls signal error in different ways. */
            if (use_vss_logical_reads()) {
                if (vss_check_result((void*)r->file, o) < 0) {
                    LogAlways(("%s: vss_read_check_result fails on line %d\n",
                                __FUNCTION__, __LINE__));
                }
                close_vss_logical_file((void*)r->file);
            } else {
                if (!disk_read_check_result(din.hdd, o)) {
                    LogAlways(("%s: disk_read_check_result fails on line %d\n",
                                __FUNCTION__, __LINE__));
                }
            }

            buffered_reads[i] = NULL;

            write_sum += r->size;
            if ( disklib_ntfs_copy_cont(r->priv,
                        (char*)r->buffer, r->size, r->dest, 0)) {

                LogAlways(("%s: copy_cont: %s\n", fsent_path(sched[j].f),
                            disklib_strerror(disklib_errno())));
                exit_status = ERROR_WRITE_FAULT;
                goto out_free_sched;
            }
            VirtualUnlock(r->buffer, r->size);
            VirtualFree(r->buffer, 0, MEM_RELEASE);
            free(r);

            /* One less read outstanding. */
            --outstanding;
        }

        /* Anything left to read? If so, start a read up to 4MB in size. Files
         * greater than 4MB will get consumed in 4MB chunks. */

        if (size > 0) {

            /* Read file data in MAX_READ_SIZE chunks. */

            take = size < MAX_READ_SIZE ? size : MAX_READ_SIZE;

            /* Create a read context descriptor, so that when the IO completes
             * we know what to do. */

            r = (buffered_read_t*) RTMemAlloc(sizeof(buffered_read_t));

            if (r == NULL) {
                RTPrintf("out of mem!\n");
                LogAlways(("%s: out of memory at line %d\n", __FUNCTION__, __LINE__));
                exit_status = ERROR_NOT_ENOUGH_MEMORY;
                goto out_free_buffers;
            }

            r->next = NULL;
            r->priv = priv;
            r->path = path;
            r->dest = dest;
            r->size = take;
            r->buffer = VirtualAlloc(NULL, take, MEM_COMMIT, PAGE_READWRITE);

            if (r->buffer == NULL) {
                LogAlways(("%s: out of memory!\n", __FUNCTION__));
                exit_status = ERROR_NOT_ENOUGH_MEMORY;
                goto out_free_buffers;
            }

            /* Not much value in having a buffer if it gets paged out, so try
             * to pin it. If that fails reduce the overall buffer size a
             * little. */

            if (!VirtualLock(r->buffer, take)) {
                RTPrintf("could not lock buffer %lu\n", GetLastError());
            }

            if (use_vss_logical_reads()) {
                /* Note that open_vss_logical_file returns NULL for invalid! */
                file = open_vss_logical_file(r->path, 1);
                if (!file) {
                    LogAlways(("unable to open %s %u\n", r->path,
                                (uint32_t)GetLastError()));
                    VirtualUnlock(r->buffer, r->size);
                    VirtualFree(r->buffer, 0, MEM_RELEASE);
                    free(r);
                    buffered_reads[i] = NULL;
                    size = 0;
                    continue;
                }
                r->file = (HANDLE) file;
            }

            buffered_reads[i] = r;

            /* The rest of o will get filled in by disk_read_sectors(). */
            memset(o, 0, sizeof(*o));
            ResetEvent(events[i]);
            o->hEvent = events[i];

            read_sum += take;
            disk_error_context(r->path);

            if (use_vss_logical_reads()) {
                /* Read file via mounted snapshot path. */
                o->OffsetHigh = dest >> 32ULL;
                o->Offset = dest &  0xffffffff;
                if (read_vss_logical_file((void*)r->file, r->buffer, take,
                            (void*) o) < 0) {

                    if (GetLastError() != ERROR_IO_PENDING) {
                        LogAlways(("%s: ReadFile fails with error %u\n",
                                    __FUNCTION__, (uint32_t)GetLastError()));
                        exit_status = ERROR_READ_FAULT;
                        goto out_free_buffers;
                    }
                }

            } else {

                /* Normal block read. */
                if (!disk_read_sectors(din.hdd, r->buffer,
                            offset/SECTOR_SIZE,
                            (take+SECTOR_SIZE-1)/SECTOR_SIZE, o)) {
                    LogAlways(("%s: disk_read_sectors fails, last error %u\n",
                                __FUNCTION__, (uint32_t)GetLastError()));
                    exit_status = ERROR_READ_FAULT;
                    goto out_free_buffers;
                }
            }


            /* Count outstanding read IOs, so that we don't quit the loop
             * prematurely. */
            ++outstanding;

            offset += take;
            dest += take;
            size -= take;
        }

    }

    for (i = 0; i < NUM_OVERLAPPING; ++i) {
        CloseHandle(events[i]);
    }

    LogAlways(("END of deep BR Analyze phase!\n"));
    LogAlways(("Total actual data BR Analyzed into guest: %"PRId64" bytes\n", total_size_deep_copy));

    RTTimeNow(& Runtimes->Copy.t1);
    RTTimeSpecToString(& Runtimes->Copy.t1, time, 1024);
    LogAlways(("\n  END of BR Analyze file phase: %s\n\n", time));

    RTMemFree(sched);

    next_stage(__LINE__);

    for(i = 0; i < mcnt; i++) {
        void *cont = fsent_get_priv(man[i]);
        if ( cont )
            disklib_ntfs_copy_finish(cont);

        show_progress( ((float) i) / ((float) mcnt), 0);
    }

skip_bulk:


    RTTimeNow(& Runtimes->Link.t0);
    RTTimeSpecToString(& Runtimes->Link.t0, time, 1024);
    LogAlways(("\n  START of link creation phase: %s\n\n", time));
    next_stage(__LINE__);

    for(i = 0; i < mcnt; i++) {

        show_progress( ((float) i) / ((float) mcnt), 0);

        unsigned int nlnk, j;
        const char *target;
        ntfs_fs_t fs_out;

        nlnk = fsent_nlnk(man[i]);
        if ( !nlnk )
            continue;

        switch(fsent_vol(man[i])) {
        case FILESET_VOL_BOOT:
            fs_out = dout.bootvol;
            break;
        case FILESET_VOL_SYS:
            fs_out = dout.sysvol;
            break;
        default:
            AssertFailed();
            continue;
        }

        target = fsent_path(man[i]);
        for(j = 0; j < nlnk; j++) {
            const char *lnk;

            lnk = fsent_get_link(man[i], j, NULL);
#ifndef DRY_RUN
            if ( disklib_ntfs_link(fs_out, target, lnk) ) {
                if ( disklib_errno() != DISKLIB_ERR_EXIST ) {
                    /* Because we moved some files to /Boot, some SXS
                     * hardlinks will fail, but we should still be OK.  */

                    LogRel(("%s: hardlink failed: %s\n", lnk,
                            disklib_strerror(disklib_errno())));
                }
            }
#endif
            Log(("LINK: %s -> %s\n", lnk, target));
        }
    }

    RTTimeNow(& Runtimes->Link.t1);
    RTTimeSpecToString(& Runtimes->Link.t1, time, 1024);
    LogAlways(("\n  END of link creation phase: %s\n\n", time));

    rc = VINF_SUCCESS;
    exit_status = ERROR_SUCCESS;
    goto out_free_manifest;

out_free_buffers:
    /* XXX free buffers - let's be lazy and have the system
     * handle it for us, OK? */

out_free_sched:
    RTMemFree(sched);
out_free_manifest:
    RTMemFree(man);
out_close:
    fclose(manifest);
    file_type_list_free(&file_types);
out_fs:
    fileset_free(fs);
out_dout:
    disk_close(&dout);
out_din:
    disk_close(&din);
out:
    if (RT_SUCCESS(rc)) {
        next_stage(__LINE__);
    }
    return rc;
}

static int begins_with(const char *str, const char *prefix)
{
    size_t plen = strlen(prefix);
    size_t slen = strlen(str);

    if ( slen < plen )
        return 0;

    return RTStrNCmp(str, prefix, plen) == 0;
}

int main(int argc, char **argv)
{
    char *vdin, *vdout;
    wchar_t *mpath;
    int rc, failhard = 0, do_reordering = 1;
    int sysvol, bootvol;
    int i;
    RUNTIMES    runtimes    =   {
        {{ 0 }, { 0 }, 0 },
        {{ 0 }, { 0 }, 0 },
        {{ 0 }, { 0 }, 0 },
        {{ 0 }, { 0 }, 0 }
    };
    char startTime[1024];
    char endTime[1024];

    setprogname(argv[0]);

    RTTimeNow(& runtimes.Total.t0);
    RTR3Init();

    RTTimeSpecToString(& runtimes.Total.t0, startTime, 1024);
    LogAlways(("  START process run: %s\n\n", startTime));

    if ( argc < 4 ) {
        goto usage;
    }

#ifdef _WIN32
    LPWSTR *argv_w;
    int argc_w;
    /* Use wide-char arguments from here... */
    argv_w = CommandLineToArgvW(GetCommandLineW(), &argc_w);
    if( NULL == argv_w )
    {
        wprintf(L"CommandLineToArgvW failed\n");
        return EXIT_FAILURE;
    }

#else
#error "may need to deal with wide-char argv on this platform?"
#endif

    sysvol = bootvol = -1;

    for(i = 1; /* nothing */; i++) {
        if ( !RTStrCmp(argv[i], "-f") ) {
            failhard = 1;
        }else if ( begins_with(argv[i], "--sysvol=") ) {
            const char *val = argv[i] + strlen("--sysvol=");
            sysvol = atoi(val);
        }else if ( begins_with(argv[i], "--bootvol=") ) {
            const char *val = argv[i] + strlen("--bootvol=");
            bootvol = atoi(val);
        }else if ( begins_with(argv[i], "--vsspath=") ) {
            /* Reads go via VSS mount instead of block IO. */
            wchar_t *val = argv_w[i] + strlen("--vsspath=");
            size_t l = wcslen(val);
            /* Krypton may have quoted the vss path. */
            if (val[0] == L'"' && val[l - 1] == L'"') {
                val[l - 1] = L'\0';
                ++val;
            }
            LogAlways(("set VSS path '%s'\n", utf8(val)));
            set_vss_path(val);
        }else if ( !RTStrCmp(argv[i], "--no-reordering") ) {
            do_reordering = 0;
        }else{
            break;
        }
    }

    if ( i + 3 > argc )
        goto usage;

    vdin = utf8(argv_w[i++]);
    vdout = utf8(argv_w[i++]);
    if (!vdin || !vdout) {
        LogAlways(("wide to utf8 conversion failed!\n"));
        exit(EXIT_FAILURE);
    }
    mpath = argv_w[i++]; /* using wide version to support Unicode install path. */

    LogRel(("Got partition mapping:bootvol = %d, sysvol = %d\n",
             bootvol, sysvol));
    LogAlways(("Block reordering: %s\n", (do_reordering) ? "ENABLED" : "DISABLED"));


    /* Attempt to pin down a good chunk of memory, as our buffering will be
     * wasted if all it does is cause more paging IO. */

    while (wss_size && !SetProcessWorkingSetSize(GetCurrentProcess(),
                wss_size, wss_size)) {
        wss_size >>= 1;
    }
    if (!wss_size) {
        RTPrintf("unable to set working set size, giving up.\n");
        return ERROR_NOT_ENOUGH_MEMORY;
    }

    /* Try to reduce our impact on the rest of the system as much as possible. */
    reduce_io_priority();

    /* Call actual ntfscp functionality. */

    rc = ntfscp_main(vdin, vdout, mpath,
                     sysvol, bootvol,
                     failhard, do_reordering,
                     &runtimes);
    if ( RT_FAILURE(rc) )
    {
        LogAlways(("ntscp_main(): %d\n", rc));
        RTPrintf("ntscp_main(): %d\n", rc);
        int i;

        RTPrintf("failing command line:\n");
        for (i = 0; i < argc; ++i) {
            RTPrintf("%s ", argv[i]);
        }
        RTPrintf("\n");
        return exit_status;
    }

    LogRel(("SUCCESS\n"));
    VDShutdown();

    RTTimeNow(& runtimes.Total.t1);
    RTTimeSpecToString(& runtimes.Total.t1, endTime, 1024);
    LogAlways(("\n  END process run: %s\n\n", endTime));

    runtimes.Copy.d0    =   (runtimes.Copy.t1.i64NanosecondsRelativeToUnixEpoch  - runtimes.Copy.t0.i64NanosecondsRelativeToUnixEpoch)  / 1000000000;
    runtimes.Scan.d0    =   (runtimes.Scan.t1.i64NanosecondsRelativeToUnixEpoch  - runtimes.Scan.t0.i64NanosecondsRelativeToUnixEpoch)  / 1000000000;
    runtimes.Link.d0    =   (runtimes.Link.t1.i64NanosecondsRelativeToUnixEpoch  - runtimes.Link.t0.i64NanosecondsRelativeToUnixEpoch)  / 1000000000;
    runtimes.Total.d0   =   (runtimes.Total.t1.i64NanosecondsRelativeToUnixEpoch - runtimes.Total.t0.i64NanosecondsRelativeToUnixEpoch) / 1000000000;

    RTTimeSpecToString(& runtimes.Total.t0, startTime, 1024);
    RTTimeSpecToString(& runtimes.Total.t1, endTime, 1024);

    LogAlways(("\n"));
    LogAlways(("\n"));
    LogAlways(("Total Process Runtime: %s - %s (%"PRIdMAX" s)\n", startTime, endTime, runtimes.Total.d0));

    RTTimeSpecToString(& runtimes.Scan.t0, startTime, 1024);
    RTTimeSpecToString(& runtimes.Scan.t1, endTime, 1024);

    LogAlways(("  Total Scan Runtime: %s - %s (%"PRIdMAX" s)\n", startTime, endTime, runtimes.Scan.d0));

    RTTimeSpecToString(& runtimes.Copy.t0, startTime, 1024);
    RTTimeSpecToString(& runtimes.Copy.t1, endTime, 1024);

    LogAlways(("  Total Copy Runtime: %s - %s (%"PRIdMAX" s)\n", startTime, endTime, runtimes.Copy.d0));

    RTTimeSpecToString(& runtimes.Link.t0, startTime, 1024);
    RTTimeSpecToString(& runtimes.Link.t1, endTime, 1024);

    LogAlways(("  Total Link Runtime: %s - %s (%"PRIdMAX" s)\n", startTime, endTime, runtimes.Link.d0));

    LogAlways(("\n"));

    return ERROR_SUCCESS;
usage:
    RTPrintf("Usage: [-f] <src> <dst> <includes.txt> [excludes.txt]\n");
    return ERROR_BAD_COMMAND;
}
