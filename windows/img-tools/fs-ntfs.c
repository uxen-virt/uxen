/*
 * Copyright 2011-2016, Bromium, Inc.
 * Author: Gianni Tedesco
 * SPDX-License-Identifier: ISC
 */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "compat.h"
#include "disklib.h"
#include "partition.h"
#include "fs-ntfs.h"
#include "disklib-internal.h"

#include <sys/param.h>
#include <sys/time.h>
#ifdef __WIN__
#include <ntfs-3g/compat.h>
#else
#define ntfs_get_errno() errno
#define ntfs_set_errno(x) errno = x
#endif
#include <ntfs-3g/device.h>
#include <ntfs-3g/dir.h>
#include <ntfs-3g/attrib.h>
#include <errno.h>

#include <sys/stat.h>

#include "ntdev.h"

static void *sec_context = NULL;
#if 1
#define dprintf RTPrintf
#else
#define dprintf(x...) do {}while(0);
#endif

struct _ntfs_fs {
    ntfs_volume *vol;
    ptbl_t pt;
    unsigned int write;
    unsigned int ref;
};

struct _ntfs_fd {
    struct _ntfs_fs *fs;
    ntfs_inode *ni;
    ntfs_attr *na;
    unsigned int mode;
    uint64_t ofs;
};

int disklib_ntfs_partition(uint8_t type)
{
    switch(type) {
    case PART_TYPE_NTFS:
    case PART_TYPE_NTFS_HIDDEN:
    case PART_TYPE_NTFS_RE:
        return 1;
    default:
        return 0;
    }
}

static ntfs_fs_t fs_ref(ntfs_fs_t fs)
{
    fs->ref++;
    return fs;
}

static void fs_unref(ntfs_fs_t fs)
{
    fs->ref--;

    if ( !fs->ref ) {
        if (sec_context) {
            ntfs_leave_security(sec_context);
            sec_context = NULL;
        }
        ntfs_umount(fs->vol, 0);
        RTMemFree(fs);
    }
}

static int generic_error(int ntfs_errno)
{
    switch(ntfs_errno) {
    case 0:
        return DISKLIB_ERR_SUCCESS;
    case EIO:
    case ENXIO:
    case EPIPE:
    case EINVAL:
        return DISKLIB_ERR_IO;
    case ENOMEM:
        return DISKLIB_ERR_NOMEM;
    case EEXIST:
        return DISKLIB_ERR_EXIST;
    case ENOENT:
        return DISKLIB_ERR_NOENT;
    case EISDIR:
        return DISKLIB_ERR_ISDIR;
    case ENOTDIR:
        return DISKLIB_ERR_NOTDIR;
    case ENOTEMPTY:
        return DISKLIB_ERR_NOTEMPTY;
    case EROFS:
        return DISKLIB_ERR_ROFS;
    case EACCES:
    case EPERM:
        return DISKLIB_ERR_ACCES;
    case ENOSPC:
        return DISKLIB_ERR_NOSPC;
    case EILSEQ:
    case ENAMETOOLONG:
        return DISKLIB_ERR_BAD_CHARS;
    default:
        RTPrintf("disklib: Unknown errno: %d\n", ntfs_errno);
        LogRel(("disklib: Unknown errno: %d\n", ntfs_errno));
        return DISKLIB_ERR_GENERAL;
    }
}

static int mount_error(int ntfs_errno)
{
    switch(ntfs_volume_error(ntfs_errno)) {
    case NTFS_VOLUME_OK:
        return DISKLIB_ERR_SUCCESS;
    case NTFS_VOLUME_NOT_NTFS:
        return DISKLIB_ERR_BAD_MAGIC;
    case NTFS_VOLUME_CORRUPT:
        return DISKLIB_ERR_CORRUPT;
    case NTFS_VOLUME_HIBERNATED:
        return DISKLIB_ERR_HIBERNATED;
    case NTFS_VOLUME_UNCLEAN_UNMOUNT:
        return DISKLIB_ERR_UNCLEAN;
    case NTFS_VOLUME_LOCKED:
        return DISKLIB_ERR_BUSY;
    case NTFS_VOLUME_NO_PRIVILEGE:
        return DISKLIB_ERR_NO_PRIVILEGE;
    case NTFS_VOLUME_OUT_OF_MEMORY:
        return DISKLIB_ERR_NOMEM;
    case NTFS_VOLUME_UNKNOWN_REASON:
    default:
        break;
    }

    return generic_error(ntfs_errno);
}

ntfs_fs_t disklib_ntfs_mount(partition_t part, unsigned rw)
{
    static int done_init;
    struct ntfs_device *dev;
    unsigned int flags = MS_RECOVER;
    ntfs_fs_t fs = NULL;
    int err;

    if ( !done_init ) {
        ntfs_log_set_handler(ntfs_log_handler_null);
        //ntfs_log_set_handler(ntfs_log_handler_stdout);
        done_init = 1;
    }

    dev = ntfs_device_alloc("", 0, &part_io_ops, part);
    if ( NULL == dev) {
        dprintf("%s: failed to alloc device\n", __func__);
        err = DISKLIB_ERR_NOMEM;
        goto out;
    }

    fs = RTMemAllocZ(sizeof(*fs));
    if ( NULL == fs ) {
        err = DISKLIB_ERR_NOMEM;
        goto out_free_dev;
    }

    fs->write = !!rw;
    fs->pt = part_get_ptbl(part);

    if ( !rw )
        flags |= MS_RDONLY;

    fs->vol = ntfs_device_mount(dev, flags);
    if ( NULL == fs->vol ) {
        err = mount_error(ntfs_get_errno());
        goto out_free;
    }

    sec_context = ntfs_initialize_security(fs->vol, flags);
    if ( NULL == sec_context) {
        dprintf("%s: failed to secure device\n", __func__);
        err = DISKLIB_ERR_NO_PRIVILEGE;
        goto out;
    }

    ntfs_set_ignore_case(fs->vol);

    err = DISKLIB_ERR_SUCCESS;
    fs_ref(fs);
    goto out;

out_free:
    RTMemFree(fs);
    fs = NULL;
out_free_dev:
    ntfs_device_free(dev);
out:
    disklib__set_errno(err);;
    return fs;
}

const char *disklib_ntfs_volname(ntfs_fs_t fs)
{
    return fs->vol->vol_name;
}

uint32_t disklib_ntfs_cluster_size(ntfs_fs_t fs)
{
    return fs->vol->cluster_size;
}

uint64_t disklib_ntfs_nr_clusters(ntfs_fs_t fs)
{
    return fs->vol->nr_clusters;
}

uint64_t disklib_ntfs_free_clusters(ntfs_fs_t fs)
{
    ntfs_volume_get_free_space(fs->vol);
    return fs->vol->free_clusters;
}

void disklib_ntfs_umount(ntfs_fs_t fs)
{
    if ( fs )
        fs_unref(fs);
}

int disklib_ntfs_truncate(ntfs_fd_t fd, uint64_t sz)
{
    if ( ntfs_attr_truncate(fd->na, sz) ) {
        disklib__set_errno(generic_error(ntfs_get_errno()));
        return -1;
    }
    disklib__set_errno(DISKLIB_ERR_SUCCESS);
    return 0;
}

static int filename_split(const char *path, char **dir, char **file)
{
    const char *last_slash;
    size_t dir_len, file_len;

    last_slash = strrchr(path, '/');
    if ( NULL == last_slash ) {
        /* must be a full path, nothing is relative... */
        disklib__set_errno(DISKLIB_ERR_NOENT);
        return 0;
    }

    dir_len = last_slash - path;
    file_len = strlen(last_slash) - 1;

    /* first slash == last slash */
    if ( !dir_len )
        dir_len++;

    if ( dir ) {
        *dir = RTMemAlloc(dir_len + 1);
        if ( NULL == *dir ) {
            disklib__set_errno(DISKLIB_ERR_NOMEM);
            return 0;
        }
        /* lets not call directory '' when it should be '/',
         * this could happen if path only has one slash
         * (eg. /hiberfil.sys)
         */
        if ( last_slash == path ) {
            sprintf(*dir, "/");
        }else{
            sprintf(*dir, "%.*s", (int)dir_len, path);
        }
    }

    if ( file ) {
        *file = RTMemAlloc(file_len + 1);
        if ( NULL == file ) {
            RTMemFree(*dir);
            disklib__set_errno(DISKLIB_ERR_NOMEM);
            return 0;
        }
        sprintf(*file, "%s", last_slash + 1);
    }

    return 1;
}

static ntfs_inode *do_copy(ntfs_fs_t src, ntfs_fs_t dst,
                           const char *src_path, const char *dst_path,
                           void **cont);
static ntfs_inode *new_file(ntfs_fs_t fs, const char *path,
                            mode_t mode, int mkp, ntfs_fs_t srcvol)
{
    ntfs_inode *dir_ni;
    ntfschar *ufilename;
    ntfs_inode *ni = NULL;
    int ufilename_len;
    char *pdir, *file;

    if ( !filename_split(path, &pdir, &file) )
        goto out;

    dir_ni = ntfs_pathname_to_inode(fs->vol, NULL, pdir);
    if ( NULL == dir_ni ) {
        if ( mkp ) {
            if ( srcvol ) {
                /* If creating as part of a copy, make sure we copy all the
                 * details we need of directory on original source volume
                */
                LogRel((" - CREATE PARENT DIR: %s\n", pdir));
                dir_ni = do_copy(srcvol, fs, pdir, pdir, NULL);
            }else{
                dir_ni = new_file(fs, pdir, S_IFDIR, mkp, srcvol);
            }
            if ( NULL == dir_ni )
                goto out_free_split;
            Assert(dir_ni->mrec->flags & MFT_RECORD_IS_DIRECTORY);
        }else
            goto out_free_split;
    }

    ufilename = NULL;
    ufilename_len = ntfs_mbstoucs(file, &ufilename);
    if (ufilename_len == -1)
        goto out_close;

    ni = ntfs_create(dir_ni, 0, ufilename, ufilename_len, mode);

out_close:
    ntfs_inode_close(dir_ni);
    ntfs_ucsfree((void *)ufilename);
out_free_split:
    RTMemFree(pdir);
    RTMemFree(file);
out:
    return ni;
}

static ntfs_fd_t open_system_file(ntfs_fs_t fs, NTFS_SYSTEM_FILES sys)
{
    ntfs_fd_t fd;
    int err;

    fd = RTMemAllocZ(sizeof(*fd));
    if ( NULL == fd ) {
        err = DISKLIB_ERR_NOMEM;
        goto out;
    }

    fd->ni = ntfs_inode_open(fs->vol, sys);
    if ( NULL == fd->ni ) {
        err = generic_error(ntfs_get_errno());
        goto out_free;
    }

    /* Open default data attribute */
    fd->na = ntfs_attr_open(fd->ni, AT_DATA, AT_UNNAMED, 0);
    if ( NULL == fd->na ) {
        err = generic_error(ntfs_get_errno());
        goto out_close;
    }

    err = DISKLIB_ERR_SUCCESS;
    fd->mode = DISKLIB_FD_READ;
    fd->fs = fs;
    fs_ref(fd->fs);
    goto out;

out_close:
    ntfs_inode_close(fd->ni);
out_free:
    RTMemFree(fd);
    fd = NULL;
out:
    disklib__set_errno(err);;
    return fd;
}

ntfs_fd_t disklib_ntfs_open_bitmap(ntfs_fs_t fs)
{
    return open_system_file(fs, FILE_Bitmap);
}

ntfs_fd_t disklib_ntfs_open_mft(ntfs_fs_t fs)
{
    return open_system_file(fs, FILE_MFT);
}

ntfs_fd_t disklib_ntfs_open(ntfs_fs_t fs, const char *path, unsigned flags)
{
    ntfs_fd_t fd = NULL;
    int err;

    disk_error_context(path);

    if ( (flags & DISKLIB_FD_WRITE) && !fs->write ) {
        err = DISKLIB_ERR_ROFS;
        goto out;
    }

    /* need to open for read or write or both */
    if ( (flags & (DISKLIB_FD_READ|DISKLIB_FD_WRITE)) == 0 ) {
        err = DISKLIB_ERR_INVAL;
        goto out;
    }

    /* require write access for truncate */
    if ( (flags & (DISKLIB_FD_WRITE|DISKLIB_FD_TRUNC)) == DISKLIB_FD_TRUNC ) {
        err = DISKLIB_ERR_ACCES;
        goto out;
    }

    fd = RTMemAllocZ(sizeof(*fd));
    if ( NULL == fd ) {
        err = DISKLIB_ERR_NOMEM;
        goto out;
    }

    /* Try to open file */
    fd->ni = ntfs_pathname_to_inode(fs->vol, NULL, path);
    if ( NULL == fd->ni ) {
        /* It didn't exist and we are supposed to create it? */
        if ( ntfs_get_errno() == ENOENT &&
                (flags & (DISKLIB_FD_WRITE|DISKLIB_FD_CREAT)) ==
                (DISKLIB_FD_WRITE|DISKLIB_FD_CREAT) ) {
            fd->ni = new_file(fs, path, S_IFREG, 0, NULL);
            if ( NULL == fd->ni ) {
                /* new file just a libntfs wrapper */
                err = generic_error(ntfs_get_errno());
                goto out_free;
            }
        }else{
            /* Open failed */
            err = generic_error(ntfs_get_errno());
            goto out_free;
        }
    }

    if ( fd->ni->mrec->flags & MFT_RECORD_IS_DIRECTORY ) {
        err = DISKLIB_ERR_ISDIR;
        goto out_close_inode;
    }
    if ( ntfsx_is_special_file(fd->ni) ) {
        err = DISKLIB_ERR_IS_SPECIAL;
        goto out_close_inode;
    }

    /* Open default data attribute */
    fd->na = ntfs_attr_open(fd->ni, AT_DATA, AT_UNNAMED, 0);
    if ( NULL == fd->na ) {
        if ( ntfs_get_errno() == ENOENT ) {
            err = DISKLIB_ERR_IS_SPECIAL;
        }else{
            err = generic_error(ntfs_get_errno());
        }
        goto out_close_inode;
    }

    /* Do we need to truncate it? */
    if ( flags & DISKLIB_FD_TRUNC ) {
        if ( ntfs_attr_truncate(fd->na, 0) ) {
            err = generic_error(ntfs_get_errno());
            goto out_close_attr;
        }
    }

    fd->mode = flags;
    fd->fs = fs;
    fs_ref(fd->fs);
    err = DISKLIB_ERR_SUCCESS;

    goto out;

out_close_attr:
    ntfs_attr_close(fd->na);
out_close_inode:
    ntfs_inode_close(fd->ni);
out_free:
    RTMemFree(fd);
    fd = NULL;
out:
    disklib__set_errno(err);
    return fd;
}

int disklib_ntfs_seek_set(ntfs_fd_t fd, uint64_t ofs)
{
    fd->ofs = ofs;
    disklib__set_errno(DISKLIB_ERR_SUCCESS);
    return 0;
}

ssize_t disklib_ntfs_read(ntfs_fd_t fd, void *buf, size_t len)
{
    ssize_t ret;

    if ( !(fd->mode & DISKLIB_FD_READ) ) {
        disklib__set_errno(DISKLIB_ERR_ACCES);
        return -1;
    }

    ret = ntfs_attr_pread(fd->na, fd->ofs, len, buf);
    if ( ret < 0 ) {
        disklib__set_errno(generic_error(ntfs_get_errno()));
        return -1;
    }

    fd->ofs += len;
    disklib__set_errno(DISKLIB_ERR_SUCCESS);

    return ret;
}

ssize_t disklib_ntfs_write(ntfs_fd_t fd, const void *buf, size_t len)
{
    ssize_t ret;

    if ( !(fd->mode & DISKLIB_FD_WRITE) ) {
        disklib__set_errno(DISKLIB_ERR_ACCES);
        return -1;
    }

    if ( !fd->fs->write ) {
        disklib__set_errno(DISKLIB_ERR_ROFS);
        return -1;
    }

    ret = ntfs_attr_pwrite(fd->na, fd->ofs, len, buf);
    if ( ret < 0 ) {
        disklib__set_errno(generic_error(ntfs_get_errno()));
        return -1;
    }

    fd->ofs += len;
    disklib__set_errno(DISKLIB_ERR_SUCCESS);

    return ret;
}

uint64_t disklib_ntfs_filesize(ntfs_fd_t fd)
{
    disklib__set_errno(DISKLIB_ERR_SUCCESS);
    return fd->na->data_size;
}

void disklib_ntfs_close(ntfs_fd_t fd)
{
    if ( fd ) {
        ntfs_attr_close(fd->na);
        ntfs_inode_close(fd->ni);
        fs_unref(fd->fs);
        RTMemFree(fd);
    }
}

struct _ntfs_dirent {
    char *name;
    MFT_REF mref;
};

struct _ntfs_dir {
    struct _ntfs_dirent *res;
    unsigned int nmemb;
    unsigned int flags;
};

static DECLCALLBACK(int) cmp_dirent(const void *A, const void *B)
{
    const struct _ntfs_dirent *a = (const struct _ntfs_dirent *)A;
    const struct _ntfs_dirent *b = (const struct _ntfs_dirent *)B;
    if ( a->mref < b->mref )
        return -1;
    if ( a->mref > b->mref )
        return 1;
    return 0;
}

static int lsdirent(void *dirent, const ntfschar *name,
                    const int name_len, const int name_type, const s64 pos,
                    const MFT_REF mref, const unsigned dt_type)
{
    struct _ntfs_dir *closure = dirent;
    char *fnbuf, *tbuf;
    int ret;

    /* strip fake . and .. */
    if ( pos < 2 )
        return 0;

    if ( closure->flags == FILE_NAME_WIN32_AND_DOS ) {
        if ( (name_type & FILE_NAME_WIN32_AND_DOS) == FILE_NAME_DOS )
            return 0;
    }else if ( ~closure->flags && !(name_type & closure->flags) )
        return 0;


    tbuf = NULL;
    ret = ntfs_ucstombs(name, name_len, &tbuf, 0);
    if ( ret <= 0 ) {
        return -1;
    }

    fnbuf = RTStrDup(tbuf);
    ntfs_ucsfree((void *)tbuf);
    if ( NULL == fnbuf ) {
        ntfs_set_errno(ENOMEM);
        return -1;
    }

    closure->res[closure->nmemb].name = fnbuf;
    closure->res[closure->nmemb].mref = mref;
    closure->nmemb++;
    return 0;
}

static int lsdir_cnt(void *dirent, const ntfschar *name,
                     const int name_len, const int name_type, const s64 pos,
                     const MFT_REF mref, const unsigned dt_type)
{
    struct _ntfs_dir *closure = dirent;

    /* strip fake . and .. */
    if ( pos < 2 )
        return 0;

    if ( closure->flags == FILE_NAME_WIN32_AND_DOS ) {
        if ( (name_type & FILE_NAME_WIN32_AND_DOS) == FILE_NAME_DOS )
            return 0;
    }else if ( ~closure->flags && !(name_type & closure->flags) )
        return 0;

    closure->nmemb++;
    return 0;
}

ntfs_dir_t disklib_ntfs_opendir(ntfs_fs_t fs,
                                const char *path,
                                unsigned int flags)
{
    struct _ntfs_dir *ret = NULL;
    struct _ntfs_dirent *results;
    ntfs_inode *ni;
    unsigned int n;
    s64 pos;
    int err;

    ni = ntfs_pathname_to_inode(fs->vol, NULL, path);
    if ( NULL == ni ) {
        err = generic_error(ntfs_get_errno());
        goto out;
    }

    if ((flags & DISKLIB_SYMLINK_NOFOLLOW) &&
            (ni->flags & FILE_ATTR_REPARSE_POINT)) {
        err = DISKLIB_ERR_ISLNK;
        goto out_close;
    }

    ret = RTMemAllocZ(sizeof(*ret));
    if ( NULL == ret ) {
        err = DISKLIB_ERR_NOMEM;
        goto out_close;
    }

    if ( flags & DISKLIB_NAME_ALL ) {
        ret->flags = ~0;
    }else{
        ret->flags = flags & (DISKLIB_NAME_DOS_AND_WIN32);
    }

    ret->res = NULL;
    ret->nmemb = 0;
    n = 0;

    pos = 0;
    if ( ntfs_readdir(ni, &pos, ret, lsdir_cnt) ) {
        err = generic_error(ntfs_get_errno());
        goto out_free;
    }

    results = RTMemAllocZ(sizeof(*results) * ret->nmemb);
    if ( NULL == results ) {
        err = DISKLIB_ERR_NOMEM;
        goto out_free;
    }

    n = ret->nmemb;
    ret->res = results;
    ret->nmemb = 0;
    pos = 0;
    if ( ntfs_readdir(ni, &pos, ret, lsdirent) ) {
        err = generic_error(ntfs_get_errno());
        goto out_free;
    }

    qsort(ret->res, ret->nmemb, sizeof(*ret->res), &cmp_dirent);

    Assert(n == ret->nmemb);
    err = DISKLIB_ERR_SUCCESS;
    goto out_close;

out_free:
    Assert(ret->nmemb <= n);
    disklib_ntfs_closedir(ret);
    ret = NULL;
out_close:
    ntfs_inode_close(ni);
out:
    disklib__set_errno(err);
    return ret;
}

unsigned int disklib_ntfs_szdir(ntfs_dir_t dir)
{
    return (dir) ? dir->nmemb : 0;
}

const char *disklib_ntfs_readdir(ntfs_dir_t dir, unsigned int index)
{
    /* allow while loop */
    if ( index >= dir->nmemb )
        return NULL;
    return dir->res[index].name;
}

void disklib_ntfs_closedir(ntfs_dir_t dir)
{
    if ( dir ) {
        if ( dir->res ) {
            unsigned int i;
            for(i = 0; i < dir->nmemb; i++) {
                RTMemFree(dir->res[i].name);
            }
        }
        RTMemFree(dir->res);
    }
}


int disklib_ntfs_mkdir(ntfs_fs_t fs, const char *path, int mkp)
{
    ntfs_inode *ni;
    int err = DISKLIB_ERR_SUCCESS;

    ni = new_file(fs, path, S_IFDIR, mkp, NULL);
    if ( NULL == ni ) {
        err = generic_error(ntfs_get_errno());
        goto out;
    }

    ntfs_inode_close(ni);
out:
    disklib__set_errno(err);
    if ( err )
        return -1;
    return 0;
}

#define CACHE_NAME_MAX 256
#define CACHE_DEPTH_MAX 32

/* To avoid repeated inum lookups, use a cache an element per
 * path component. The variable cache_valid decided the depth
 * of the path prefix that is currently cached and valid. */
static struct {
    wchar_t name[CACHE_NAME_MAX];
    size_t name_len;
    uint64_t inum;
} cache[64];

static int cache_valid = -1;

int disklib_ntfs_setsecurityattr(ntfs_fs_t fs, const void *attr, long long attrsz)
{
    assert (fs);
    assert(fs->vol);
    assert(attr);

    return ntfs_setsecurityattr(fs->vol, attr, attrsz);
}

static
ntfs_inode *create_simple(ntfs_fs_t fs, const wchar_t *path, int mode,
        uint32_t securid)
{
    ntfs_inode *parent = ntfs_inode_open(fs->vol, FILE_root);
    ntfs_inode *inode = NULL;
    const wchar_t *p;
    const wchar_t *b;
    wchar_t c = 1;
    int i;

    for (i = 0, b = p = path + 1; c; ++p) {
        c = *p;
        if (c == L'/' || c == L'\0') {
            size_t name_len = p - b;
            wchar_t *cn = cache[i].name;
            uint64_t *inum = &cache[i].inum;

            if (i >= CACHE_DEPTH_MAX || name_len >= CACHE_NAME_MAX) {
                printf("path or path-component too long: [%ls]\n", path);
                ntfs_inode_close(parent);
                goto out;
            }

            if (!(i <= cache_valid && cache[i].name_len == name_len
                        && memcmp(cn, b, sizeof(wchar_t) * name_len) == 0)) {
                /* Cache miss. */
                memcpy(cn, b, sizeof(wchar_t) * name_len);
                cn[name_len] = L'\0';
                cache[i].name_len = name_len;

                *inum = ntfs_inode_lookup_by_name(parent, cn, name_len);
                if (*inum != ~0ULL) {
                    cache_valid = i;
                } else {
                    cache_valid = i - 1;
                }
            }
            inode = (*inum != ~0ULL) ? ntfs_inode_open(fs->vol, *inum) : NULL;
            if (!inode) {
                if (mode) {
                    if (c) {
                        printf("WARNING: creating %ls (for %ls) with no securid!\n",
                                cn, path);
                    }
                    inode = ntfs_create(parent, c ? 0 : securid, cn, name_len,
                            c ? S_IFDIR : mode);
                    if (!inode) {
                        printf("not able to create %ls : %s\n",
                                path, strerror(ntfs_get_errno()));
                        ntfs_inode_close(parent);
                        cache_valid = i - 1;
                        goto out;
                    }
                    *inum = ntfs_inode_lookup_by_name(parent, cn, name_len);
                    cache_valid = i;
                } else {
                    printf("not able to open %ls : %s\n",
                            path, strerror(ntfs_get_errno()));
                    ntfs_inode_close(parent);
                    cache_valid = i - 1;
                    goto out;
                }
            }
            ntfs_inode_close(parent);
            parent = inode;
            b = p + 1;
            ++i;
        }
    }

out:
    return inode;
}

int disklib_mkdir_simple(ntfs_fs_t fs, const wchar_t *path, uint32_t securid)
{
    ntfs_inode *dir = create_simple(fs, path, S_IFDIR, securid);
    if (!dir) {
        return -1;
    }
    ntfs_inode_close(dir);
    return 0;
}

static inline
const wchar_t *last_slash(const wchar_t *path)
{
    const wchar_t *last = NULL;
    const wchar_t *c = path;
    while (*c) {
        if (*c == '/') {
            last = c;
        }
        ++c;
    }
    return last;
}

int disklib_write_simple(ntfs_fs_t fs, const wchar_t *path, void *buffer,
        uint64_t size, uint64_t offset, int force_non_resident, uint32_t securid)
{
    int64_t r;
    ntfs_attr *na;

    ntfs_inode *ni = create_simple(fs, path, S_IFREG, securid);
    if (!ni) {
        printf("no inode for %ls\n", path);
        return -1;
    }

    na = ntfs_attr_open(ni, AT_DATA, AT_UNNAMED, 0);
    if (!na) {
        ntfs_inode_close(ni);
        printf("no data attr for %ls\n", path);
        return -1;
    }

    if (offset == 0) {
        ntfs_attr_truncate(na, 0);
    }

    if (force_non_resident) {
        ntfs_attr_force_non_resident(na);
    }

    r = size ? ntfs_attr_pwrite(na, offset, size, buffer) : 0;
    ntfs_attr_close(na);
    ntfs_inode_close(ni);
    return r;
}

int disklib_mklink_simple(ntfs_fs_t fs, const wchar_t *target,
        const wchar_t *path)
{
    int r;
    wchar_t *dup = wcsdup(path);
    wchar_t *last = NULL;
    wchar_t *c = dup;
    while (*c) {
        if (*c == '/') {
            last = c;
        }
        ++c;
    }
    if (last) {
        *last = '\0';
    }
    ntfs_inode *t = create_simple(fs, target, 0, 0);
    if (!t) {
        printf("mklink: cannot resolve target %ls\n", target);
        return -1;
    }
    /* We expect the target dir to have been created, so we
     * pass in mode == 0. */
    ntfs_inode *d = create_simple(fs, dup, 0, 0);
    if (!d) {
        ntfs_inode_close(t);
        printf("mklink: cannot resolve link directory %ls\n", dup);
        return -1;
    }
    //printf("linking %ls SLASH %ls\n", dup, last + 1);
    r = ntfs_link(t, d, last + 1, wcslen(last + 1));
    ntfs_inode_close(d);
    ntfs_inode_close(t);
    free(dup);
    return r;
}

#define LONG_PATH_PREFIX L"\\??\\"
#define LONG_PATH_PREFIX_BYTES (sizeof(LONG_PATH_PREFIX) - sizeof(wchar_t))
_STATIC_ASSERT(LONG_PATH_PREFIX_BYTES == 8);

int disklib_symlink_simple(ntfs_fs_t fs, const wchar_t *link_path,
        const wchar_t *path, uint32_t securid)
{
    int r = -1;
    ntfs_inode *ni = NULL;
    REPARSE_POINT *rp = NULL;
    struct SYMLINK_REPARSE_DATA *sd = NULL;

    uint16_t path_len = wcslen(path) * sizeof(wchar_t); /* in bytes */
    int is_long = wcsncmp(path, LONG_PATH_PREFIX,
                          LONG_PATH_PREFIX_BYTES / sizeof(wchar_t)) == 0;
    int is_abs = is_long || (path_len > 6 && (path[0] == L'\\'
                         || (path[1] == L':' && path[2] == L'\\')));
    int add_long = is_abs && !is_long; /* always add for abs paths */
    uint16_t subst_name_len = path_len + (add_long ? LONG_PATH_PREFIX_BYTES : 0);
    uint16_t sd_len = sizeof(struct SYMLINK_REPARSE_DATA)
                      + path_len + subst_name_len;
    size_t reparse_len = sizeof(REPARSE_POINT) + sd_len;
    rp = malloc(reparse_len);

    rp->reparse_tag = IO_REPARSE_TAG_SYMLINK;
    rp->reparse_data_length = sd_len;
    rp->reserved = 0;
    sd = (struct SYMLINK_REPARSE_DATA *)rp->reparse_data;
    sd->flags = is_abs ? 0 : 1;
    /* In keeping with what ntfs-3g seems to always expect, put printable name
     * first and "subst" name second */
    sd->print_name_offset = 0;
    sd->print_name_length = path_len;
    memcpy(sd->path_buffer, path, path_len);
    sd->subst_name_offset = path_len;
    sd->subst_name_length = subst_name_len;
    if (add_long) {
        memcpy(sd->path_buffer + path_len,
            LONG_PATH_PREFIX, LONG_PATH_PREFIX_BYTES);
        memcpy(sd->path_buffer + path_len + LONG_PATH_PREFIX_BYTES,
            path, path_len);
    } else {
        memcpy(sd->path_buffer + path_len, path, path_len);
    }

    ni = create_simple(fs, link_path, S_IFREG, securid);
    if (!ni) {
        printf("no inode for %ls\n", link_path);
        goto out;
    }

    r = ntfsx_set_reparse_data(ni, (const char *)rp, reparse_len, 1);

out:
    free(rp);
    if (ni) ntfs_inode_close(ni);
    return r;
}

/* Get runlist for a file */
int disklib_ntfs_file_extents(ntfs_fd_t fd,
                                struct disklib_extent **extents,
                                unsigned int *cnt)
{
    runlist_element *rl;
    struct disklib_extent *e;
    unsigned int nr_extents;
    uint64_t b;
    int rc = -1;
    int err = DISKLIB_ERR_CORRUPT;

    if ( !NAttrNonResident(fd->na) ||
        (fd->na->data_flags & (ATTR_COMPRESSION_MASK|ATTR_IS_ENCRYPTED)) ) {
        err = DISKLIB_ERR_INVAL;
        goto out;
    }

    ntfs_attr_map_whole_runlist(fd->na);

    rl = ntfs_attr_find_vcn(fd->na, 0);
    if ( NULL == rl ) {
        err = generic_error(ntfs_get_errno());
        goto out;
    }

    for(b = 0, nr_extents = 0; b < fd->na->initialized_size; rl++) {
        if ( rl->lcn == LCN_RL_NOT_MAPPED) {
            rl = ntfs_attr_find_vcn(fd->na, rl->vcn);
            if ( NULL == rl ) {
                err = generic_error(ntfs_get_errno());
                goto out;
            }
        }
        if ( rl->length == 0 ) {
            goto out;
        }
        if ( rl->lcn < (LCN)0 ) {
            if ( rl->lcn != (LCN)LCN_HOLE )
                goto out;
            /* hole, ignore */
            b += (rl->length << fd->fs->vol->cluster_size_bits);
            nr_extents++;
            continue;
        }

        /* got a real lcn */
        //RTPrintf("%d: off = 0x%"PRIx64" len = %"PRId64"\n", nr_extents,
        //        rl->lcn << fd->fs->vol->cluster_size_bits,
        //        rl->length << fd->fs->vol->cluster_size_bits);
        nr_extents++;
        b += (rl->length << fd->fs->vol->cluster_size_bits);
    }
    //RTPrintf("\n");

    if ( NULL == extents )
        goto done;

    e = RTMemAlloc(nr_extents * sizeof(*e));
    if ( NULL == e ) {
        err = DISKLIB_ERR_NOMEM;
        goto out;
    }

    rl = ntfs_attr_find_vcn(fd->na, 0);
    if ( NULL == rl ) {
        err = generic_error(ntfs_get_errno());
        goto out;
    }

    for(b = 0, nr_extents = 0; b < fd->na->initialized_size; rl++) {
        if ( rl->lcn == LCN_RL_NOT_MAPPED) {
            rl = ntfs_attr_find_vcn(fd->na, rl->vcn);
            //RTPrintf("unmapped\n");
            if ( NULL == rl ) {
                err = generic_error(ntfs_get_errno());
                goto out;
            }
        }
        if ( rl->length == 0 ) {
            goto out;
        }
        if ( rl->lcn < (LCN)0 ) {
            if ( rl->lcn != (LCN)LCN_HOLE )
                goto out;
            /* hole, ignore */
            e[nr_extents].off = DISKLIB_EXTENT_HOLE;
            e[nr_extents].len = rl->length << fd->fs->vol->cluster_size_bits;
            b += e[nr_extents].len;
            nr_extents++;
            continue;
        }

        /* got a real lcn */
        e[nr_extents].off = rl->lcn << fd->fs->vol->cluster_size_bits;
        e[nr_extents].len = rl->length << fd->fs->vol->cluster_size_bits;
        if ( b + e[nr_extents].len > fd->na->initialized_size) {
            //RTPrintf("truncating last extent %"PRId64" -> %"PRId64"\n",
            //         e[nr_extents].len, fd->na->initialized_size - b);
            e[nr_extents].len = fd->na->initialized_size- b;
        }
        b += e[nr_extents].len;
        //RTPrintf("%d: off = 0x%"PRIx64" len = %"PRId64"\n", nr_extents,
        //        rl->lcn << fd->fs->vol->cluster_size_bits,
        //        rl->length << fd->fs->vol->cluster_size_bits);
        nr_extents++;
    }


    *extents = e;

done:
    *cnt = nr_extents;
    rc = 0;
out:
    disklib__set_errno(err);;
    return rc;
}

static char *do_readlink(const void *rp_data, size_t attr_size,
                         unsigned int *type)
{
    const struct MOUNT_POINT_REPARSE_DATA *mnt;
    const struct SYMLINK_REPARSE_DATA *sym;
    const REPARSE_POINT *r;
    const char *ptr, *end;
    unsigned int flags;
    size_t buflen;
    char *ret = NULL, *buf = NULL;

    r = rp_data;
    ptr = (char *)r + sizeof(*r);
    end = (char *)r + attr_size;

    switch(r->reparse_tag) {
    case IO_REPARSE_TAG_MOUNT_POINT: /* aka. junction */
        mnt = (struct MOUNT_POINT_REPARSE_DATA *)ptr;
        ptr += sizeof(*mnt) + mnt->subst_name_offset;
        buflen = mnt->subst_name_length;
        flags = DISKLIB_LINK_JUNCTION;
        break;
    case IO_REPARSE_TAG_SYMLINK:
        sym = (struct SYMLINK_REPARSE_DATA *)ptr;
        ptr += sizeof(*sym) + sym->subst_name_offset;
        buflen = sym->subst_name_length;
        if ( sym->flags & 1 )
            flags = DISKLIB_LINK_SYMBOLIC;
        else
            flags = DISKLIB_LINK_SYM_FULL;
        break;
    default:
        disklib__set_errno(DISKLIB_ERR_INVAL);
        goto out;
    }

    /* buffer overrun */
    if ( ptr + buflen > end )
        goto out;

    if ( ntfs_ucstombs((ntfschar *)ptr, (buflen + 1)/2, &buf, 0) < 0 ) {
        disklib__set_errno(DISKLIB_ERR_INVAL);
        goto out;
    }

    ret = RTStrDup(buf);
    ntfs_ucsfree((void *)buf);
    if ( NULL == ret ) {
        disklib__set_errno(DISKLIB_ERR_NOMEM);
        goto out;
    }

    if ( type )
        *type = flags;

    disklib__set_errno(DISKLIB_ERR_SUCCESS);

out:
    return ret;
}

static int reparse_handled(ntfs_inode *ni)
{
    REPARSE_POINT *r;
    s64 attr_size;
    int ret;

    if (!(ni->flags & FILE_ATTR_REPARSE_POINT)) {
        return 0;
    }

    attr_size = 0;
    r = (REPARSE_POINT*)ntfs_attr_readall(ni,
        AT_REPARSE_POINT,(ntfschar*)NULL, 0, &attr_size);
    if ( NULL == r || attr_size < sizeof(*r) ) {
        LogRel((" - ouch, unable to get reparse data for reparse point\n"));
        return 0;
    }

    switch(r->reparse_tag) {
    case IO_REPARSE_TAG_MOUNT_POINT: /* aka. junction */
    case IO_REPARSE_TAG_SYMLINK:
        ret = 1;
        break;
    default:
        ret = 0;
        break;
    }

    ntfs_ucsfree((void *)r);
    return ret;
}

static void fill_stat(ntfs_inode *ni, ntfs_attr *na, struct disklib_stat *st)
{
    uint8_t isdir, isrep, islnk, ispec, iscmp;
    uint8_t fmode;
    uint8_t amode;

    fmode = 0;
    isdir = !!(ni->mrec->flags & MFT_RECORD_IS_DIRECTORY);
    isrep = !!(ni->flags & FILE_ATTR_REPARSE_POINT);
    islnk = reparse_handled(ni);
    ispec = ntfsx_is_special_file(ni);
    iscmp = !!(ni->flags & FILE_ATTR_COMPRESSED);

    fmode |= (isdir) ? DISKLIB_ISDIR : 0;
    fmode |= (isrep) ? DISKLIB_ISREPARSE : 0;
    fmode |= (islnk) ? DISKLIB_ISLNK : 0;
    fmode |= (ispec) ? DISKLIB_ISSPECIAL: 0;
    (void)iscmp;

    amode = 0;
    if ( na ) {
        uint8_t isres, isspa;

        isres = !NAttrNonResident(na) &&
                    !(na->data_flags & ATTR_COMPRESSION_MASK);
        isspa = !!(na->data_flags & ATTR_IS_SPARSE);

        amode |= DISKLIB_ISATTR;
        amode |= (isres) ? DISKLIB_ISRESIDENT : 0;
        amode |= (isspa) ? DISKLIB_ISSPARSE : 0;
    }

    st->f_ino = ni->mft_no;
    st->f_size = ni->data_size;
    st->f_mode = fmode;
    st->a_mode = amode;
}

int disklib_ntfs_fstat(ntfs_fd_t fd, struct disklib_stat *st)
{
    fill_stat(fd->ni, fd->na, st);
    disklib__set_errno(DISKLIB_ERR_SUCCESS);
    return 0;
}

int disklib_ntfs_stat(ntfs_fs_t fs, const char *path, struct disklib_stat *st)
{
    ntfs_inode *ni;
    ntfs_attr *na;

    ni = ntfs_pathname_to_inode(fs->vol, NULL, path);
    if ( NULL == ni ) {
        disklib__set_errno(generic_error(ntfs_get_errno()));
        return -1;
    }

    na = ntfs_attr_open(ni, AT_DATA, AT_UNNAMED, 0);

    fill_stat(ni, na, st);
    if ( na )
        ntfs_attr_close(na);
    ntfs_inode_close(ni);
    disklib__set_errno(DISKLIB_ERR_SUCCESS);
    return 0;
}

char *disklib_ntfs_readlink(ntfs_fs_t fs, const char *path, unsigned int *type)
{
    ntfs_inode *ni;
    const void *r;
    s64 attr_size;
    char *ret = NULL;

    ni = ntfs_pathname_to_inode(fs->vol, NULL, path);
    if ( NULL == ni ) {
        disklib__set_errno(generic_error(ntfs_get_errno()));
        goto out;
    }

    if (!(ni->flags & FILE_ATTR_REPARSE_POINT)) {
        disklib__set_errno(DISKLIB_ERR_INVAL);
        goto out_close;
    }

    attr_size = 0;
    r = (REPARSE_POINT *)ntfs_attr_readall(ni,
            AT_REPARSE_POINT, (ntfschar *)NULL, 0, &attr_size);
    if ( NULL == r || attr_size < sizeof(*r) ) {
        disklib__set_errno(generic_error(ntfs_get_errno()));
        goto out_close;
    }

    ret = do_readlink(r, attr_size, type);

    ntfs_ucsfree((void *)r);
out_close:
    ntfs_inode_close(ni);
out:
    return ret;
}

int disklib_ntfs_link(ntfs_fs_t fs, const char *target, const char *link)
{
    ntfs_inode *ni, *ni2, *dir_ni;
    ntfschar *ufilename;
    int ufilename_len;
    char *dir, *file;
    int err;

    if ( !fs->write ) {
        err = DISKLIB_ERR_ROFS;
        goto out;
    }

    ni = ntfs_pathname_to_inode(fs->vol, NULL, target);
    if ( NULL == ni ) {
        err = generic_error(ntfs_get_errno());
        goto out;
    }

    ni2 = ntfs_pathname_to_inode(fs->vol, NULL, link);
    if ( ni2 ) {
        LogRel(("%s: link already exists, bad juju\n", link));
        err = DISKLIB_ERR_EXIST;
        ntfs_inode_close(ni2);
        goto out_close_target;
    }

    if ( !filename_split(link, &dir, &file) ) {
        err = disklib_errno();
        goto out_close_target;
    }

    dir_ni = ntfs_pathname_to_inode(fs->vol, NULL, dir);
    if ( NULL == dir_ni ) {
        err = generic_error(ntfs_get_errno());
        goto out_free_split;
    }

    ufilename = NULL;
    ufilename_len = ntfs_mbstoucs(file, &ufilename);
    if (ufilename_len == -1) {
        ntfs_log_perror("ERROR: Failed to convert '%s' to unicode",
                    file);
        err = DISKLIB_ERR_INVAL;
        goto out_close_dir;
    }

    if ( ntfs_link(ni, dir_ni, ufilename, ufilename_len) ) {
        err = generic_error(ntfs_get_errno());
        goto out_free_name;
    }

    err = DISKLIB_ERR_SUCCESS;

out_free_name:
    ntfs_ucsfree((void *)ufilename);
out_close_dir:
    ntfs_inode_close(dir_ni);
out_free_split:
    RTMemFree(dir);
    RTMemFree(file);
out_close_target:
    ntfs_inode_close(ni);
out:
    disklib__set_errno(err);;
    return (err == DISKLIB_ERR_SUCCESS) ? 0 : -1;
}

int disklib_ntfs_unlink(ntfs_fs_t fs, const char *path)
{
    ntfs_inode *parent, *parent2, *ni, *ni2;
    ntfschar *ufilename;
    int ufilename_len;
    char *dir, *file;
    int ret = -1;
    int err;

    if ( !fs->write ) {
        err = DISKLIB_ERR_ROFS;
        goto out;
    }

    /* 1. split dir + name */
    if ( !filename_split(path, &dir, &file) ) {
        err = disklib_errno();
        goto out;
    }

    /* 2. get parent dir inode */
    parent = ntfs_pathname_to_inode(fs->vol, NULL, dir);
    if ( NULL == parent ) {
        err = generic_error(ntfs_get_errno());
        goto out_free_split;
    }

    /* 3. get inode of file to delete */
    ni = ntfs_pathname_to_inode(fs->vol, parent, file);
    if ( NULL == ni ) {
        err = generic_error(ntfs_get_errno());
        goto out_free_parent;
    }

    if ( ntfsx_is_special_file(ni) ) {
        err = DISKLIB_ERR_IS_SPECIAL;
        goto out_free_inode;
    }

    /* 4 convert name string?? */
    ufilename = NULL;
    ufilename_len = ntfs_mbstoucs(file, &ufilename);
    if (ufilename_len == -1) {
        ntfs_log_perror("ERROR: Failed to convert '%s' to unicode",
                    file);
        err = DISKLIB_ERR_INVAL;
        goto out_free_inode;
    }

    /* 5. ntfs_delete, ni is always closed after ntfs_delete() */
    ni2 = ni, ni = NULL;
    parent2 = parent, parent = NULL;
    if ( ntfs_delete(fs->vol, NULL, ni2, parent2,
            ufilename, ufilename_len) ) {
        err = generic_error(ntfs_get_errno());
        goto out_free_all;
    }

    err = DISKLIB_ERR_SUCCESS;
    ret = 0;

out_free_all:
    ntfs_ucsfree((void *)ufilename);
out_free_inode:
    if ( ni )
        ntfs_inode_close(ni);
out_free_parent:
    if ( parent )
        ntfs_inode_close(parent);
out_free_split:
    RTMemFree(dir);
    RTMemFree(file);
out:
    disklib__set_errno(err);;
    return ret;
}

static int copy_one_attr(ntfs_fs_t src_fs, ntfs_fs_t dst_fs,
                         ntfs_inode *src_ni, ntfs_inode *dst_ni,
                         const ATTR_TYPES type, ntfschar *name, u32 name_len,
                         void **cont, const char *src_path)
{
    ntfs_volume *svol = src_ni->vol;
    ntfs_attr *src, *dst;
    size_t buf_sz;
    char *buf;
    s64 cur_ofs, br, bw;
    int err = DISKLIB_ERR_GENERAL;
    void *file = NULL;

    src = ntfs_attr_open(src_ni, type, name, name_len);
    if ( NULL == src ) {
        err = generic_error(ntfs_get_errno());
        goto out;
    }

    dst = ntfs_attr_open(dst_ni, type, name, name_len);
    if ( NULL == dst ) {
        err = generic_error(ntfs_get_errno());
        goto out_close_src;
    }

    /* If it's a non-sparse file, try and up-truncate it right away to
     * get the block allocation done with in one step...
     *
     * For sparse files, buffer size must be cluster size or we might
     * miss a hole...
    */
    if ( !(src->data_flags & ATTR_IS_SPARSE) ) {
        //ntfs_attr_truncate_solid(dst, src->data_size);
        buf_sz = 4 << 20;
    }else{
        /* FIXME: probably need to make dst be sparse */
        buf_sz = svol->cluster_size;
    }

    if ( cont && NAttrNonResident(src) &&
            !(src->data_flags & (ATTR_COMPRESSION_MASK|ATTR_IS_ENCRYPTED)) &&
            src->data_size ) {
        *cont = dst;
        err = DISKLIB_ERR_SUCCESS;
        goto out_close_src;
    }

    buf = RTMemAlloc(buf_sz);
    if ( NULL == buf ) {
        err = DISKLIB_ERR_NOMEM;
        goto out_close_dst;
    }

    ptbl_enable_cache_bypass(src_fs->pt);
    ptbl_enable_cache_bypass(dst_fs->pt);

    if (use_vss_logical_reads()) {
        file = open_vss_logical_file(src_path, 0);
        if (!file) {
            LogAlways(("unable to open %s for read\n", src_path));
            goto nofile;
        }
    }

    for(cur_ofs = 0; cur_ofs < src->data_size; cur_ofs += br ) {
        s64 this_time;

        this_time = src->data_size - cur_ofs;
        if ( this_time > buf_sz )
            this_time = buf_sz;

        if ( (src->data_flags & ATTR_IS_SPARSE) &&
                ntfsx_is_hole(src, cur_ofs >> svol->cluster_size_bits) ) {
            LogRel(("got hole @ %"PRId64"\n", cur_ofs));
            br = this_time;
            continue;
        }

        if (use_vss_logical_reads()) {

            br = read_vss_logical_file(file, buf, this_time, NULL);
            if ( br <= 0 ) {
                LogAlways(("%s: read failed!\n", src_path));
                err = generic_error(ntfs_get_errno());
                goto out_free_buf;
            }

        } else {

            br = ntfs_attr_pread(src, cur_ofs, this_time, buf);
            if ( br <= 0 ) {
                err = generic_error(ntfs_get_errno());
                goto out_free_buf;
            }
        }

        bw = ntfs_attr_pwrite(dst, cur_ofs, br, buf);
        if ( bw <= 0 ) {
            err = generic_error(ntfs_get_errno());
            goto out_free_buf;
        }

        /* do we need to handle this and re-try the read? */
        if ( bw < br ) {
            LogRel(("Short write: %"PRId64" < %"PRId64"\n", bw, br));
            goto out_free_buf;
        }
    }

    if (use_vss_logical_reads()) {
        close_vss_logical_file(file);
    }

nofile:

    /* success */
    err = DISKLIB_ERR_SUCCESS;

out_free_buf:
    ptbl_disable_cache_bypass(src_fs->pt);
    ptbl_disable_cache_bypass(dst_fs->pt);
    RTMemFree(buf);
out_close_dst:
    ntfs_attr_close(dst);
out_close_src:
    ntfs_attr_close(src);
out:
    return err;
}

static int copy_attributes(ntfs_fs_t src, ntfs_fs_t dst,
                            ntfs_inode *src_ni, ntfs_inode *dst_ni,
                            void **cont, const char *src_path)
{
    /* TODO: enumerate and copy other named attributes too */
#if 1
    return copy_one_attr(src, dst, src_ni, dst_ni,
                         AT_DATA, AT_UNNAMED, 0, cont, src_path);
#else
    return DISKLIB_ERR_SUCCESS;
#endif
}

static int set_reparse_data(ntfs_inode *ni, void *buf, size_t sz)
{
    if ( !ntfsx_set_reparse_data(ni, buf, sz, 1) )
        return DISKLIB_ERR_SUCCESS;
    return generic_error(ntfs_get_errno());
}

static void *get_reparse_data(ntfs_inode *ni, size_t *sz)
{
    REPARSE_POINT *r;
    unsigned int type;
    s64 attr_size;
    char *fn, *tstr;

    if (!(ni->flags & FILE_ATTR_REPARSE_POINT)) {
        return NULL;
    }

    attr_size = 0;
    r = (REPARSE_POINT*)ntfs_attr_readall(ni,
        AT_REPARSE_POINT,(ntfschar*)NULL, 0, &attr_size);
    if ( NULL == r || attr_size < sizeof(*r) ) {
        LogRel((" - ouch, unable to get reparse data for reparse point\n"));
        return NULL;
    }

    fn = do_readlink(r, attr_size, &type);
    switch(type) {
    case DISKLIB_LINK_SYMBOLIC:
        tstr = "SYMLINK";
        break;
    case DISKLIB_LINK_SYM_FULL:
        tstr = "SYMLINK-FULL";
        break;
    case DISKLIB_LINK_JUNCTION:
        tstr = "JUNCTION";
        break;
    default:
        tstr = "REPARSE";
        break;
    }
    LogRel((" - %s to: %s\n", tstr, fn));
    RTMemFree(fn);

    *sz = attr_size;

    return r;
}

static ntfs_inode *do_copy(ntfs_fs_t src, ntfs_fs_t dst,
                           const char *src_path, const char *dst_path,
                           void **cont)
{
    int err = DISKLIB_ERR_GENERAL, ret;
    ntfs_inode *src_ni, *dst_ni = NULL;
    void *rpdata;
    size_t rpsz;
    int mode;
    char *attrs = NULL;

    if ( cont )
        *cont = NULL;

    src_ni = ntfs_pathname_to_inode(src->vol, NULL, src_path);
    if ( NULL == src_ni ) {
        err = generic_error(ntfs_get_errno());
        goto out;
    }

    if ( ntfsx_is_special_file(src_ni) ) {
        err = DISKLIB_ERR_IS_SPECIAL;
        goto out_close_src_ni;
    }

    /* TODO: Make this optional with a NUKE flag? */
    dst_ni = ntfs_pathname_to_inode(dst->vol, NULL, dst_path);
    if ( dst_ni ) {
        LogRel((" EEK, target: %s already exists, keeping old\n", dst_path));
        ntfs_inode_close(dst_ni);
        //disklib_ntfs_unlink(dst, dst_path);
        err = DISKLIB_ERR_EXIST;
        goto out_close_src_ni;
    }

    /* create the target inode */
    if ( src_ni->mrec->flags & MFT_RECORD_IS_DIRECTORY ) {
        mode = S_IFDIR;
    }else{
        mode = S_IFREG;
    }

    dst_ni = new_file(dst, dst_path, mode, 1, src);
    if ( NULL == dst_ni ) {
        err = generic_error(ntfs_get_errno());
        goto out_close_src_ni;
    }

    /* copy over contents for all user attributes, only for
     * regular files
     */
    switch(mode) {
    case S_IFREG:
        ret = copy_attributes(src, dst, src_ni, dst_ni, cont, src_path);
        if ( ret != DISKLIB_ERR_SUCCESS ) {
            err = ret;
            goto out_close_dst_ni;
        }
        break;
    case S_IFDIR:
        break;
    default:
        break;
    }

    /* copy over reparse info */
    rpdata = get_reparse_data(src_ni, &rpsz);
    if ( rpdata ) {
        err = set_reparse_data(dst_ni, rpdata, rpsz);
        ntfs_ucsfree(rpdata);
        if ( err != DISKLIB_ERR_SUCCESS )
            goto out_close_dst_ni;
    }

    ret = ntfs_get_acl(src_ni->vol, src_ni, NULL, 0);
    if (ret > 0) {
        attrs = malloc(ret + 1);
        if (attrs) {
            ret = ntfs_get_acl(src_ni->vol, src_ni, attrs, ret + 1);
            if (ret > 0) {
                le32 securid = ntfs_setsecurityattr(dst->vol,
                    (const SECURITY_DESCRIPTOR_RELATIVE*)attrs, ret);
                ntfs_updatesecurityattr(dst->vol, dst_ni, securid);
            }
        }
    }

    err = DISKLIB_ERR_SUCCESS;
    goto out_close_src_ni;

out_close_dst_ni:
    ntfs_inode_close(dst_ni);
out_close_src_ni:
    ntfs_inode_close(src_ni);
out:
    free(attrs);
    disklib__set_errno(err);
    if ( err != DISKLIB_ERR_SUCCESS )
        return NULL;
    return dst_ni;
}

int disklib_ntfs_copy(ntfs_fs_t src, ntfs_fs_t dst,
                        const char *src_path, const char *dst_path,
                        void **cont)
{
    ntfs_inode *dst_ni;

    dst_ni = do_copy(src, dst, src_path, dst_path, cont);
    if ( NULL == dst_ni )
        return -1;

    if ( NULL == cont || NULL == *cont )
        ntfs_inode_close(dst_ni);
    return 0;
}

int disklib_ntfs_copy_cont(void *cont, char *buf, size_t len, uint64_t off, int force_non_resident)
{
    ntfs_attr *na = cont;
    int ret;

    if (force_non_resident) {
        ntfs_attr_force_non_resident(na);
    }

    ret = ntfs_attr_pwrite(na, off, len, buf);
    if ( ret < 0 ) {
        disklib__set_errno(generic_error(ntfs_get_errno()));
        return -1;
    }

    disklib__set_errno(DISKLIB_ERR_SUCCESS);
    return 0;
}

void disklib_ntfs_copy_finish(void *cont)
{
    ntfs_attr *na = cont;
    ntfs_inode *ni = na->ni;
    ntfs_attr_close(na);
    ntfs_inode_close(ni);
}
