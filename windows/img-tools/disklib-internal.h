/*
 * Copyright 2011-2015, Bromium, Inc.
 * Author: Gianni Tedesco
 * SPDX-License-Identifier: ISC
 */
#ifndef _DISKLIB_INTERNAL_H
#define _DISKLIB_INTERNAL_H

void disklib__set_errno(int e);

struct fsops {
    /* ctor/dtor */
    void *(*fs_mount)(partition_t part, unsigned rw);
    void (*fs_umount)(void *fs);

    /* open files */
    void *(*fs_open)(void *fs, const char *path, unsigned flags);
    void *(*fs_open_bitmap)(void *fs);
    void *(*fs_open_mft)(void *fs);

    /* directories */
    int (*fs_readdir)(void *fs, const char *path,
                    int(*cb)(void *priv, const char *path),
                    void *priv, unsigned int flags);
    int (*fs_unlink)(void *fs, const char *path);
    int (*ntfs_mkdir)(void *fs, const char *path);

    /* volume attributes/characteristics */
    uint32_t (*fs_cluster_size)(void *fs);
    uint64_t (*fs_nr_clusters)(void *fs);
    const char *(*fs_volname)(void *fs);
};

struct fdops {
    ssize_t (*fd_read)(void *fd, void *buf, size_t len);
    ssize_t (*fd_write)(void *fd, const void *buf, size_t len);
    void (*fd_close)(void *fd);

    uint64_t (*fd_filesize)(void *fd);
    int (*fd_truncate)(void *fd, uint64_t sz);
    int (*fd_seek_set)(void *fd, uint64_t ofs);

    /* Get runlist for a file */
    int (*fd_extents)(void *,
                        struct disklib_extent **rl,
                        unsigned int *cnt);
};

extern const struct fsops _ntfs_fsops;
extern const struct fdops _ntfs_fdops;

#endif /* _DISKLIB_INTERNAL_H */
