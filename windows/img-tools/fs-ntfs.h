/*
 * Copyright 2011-2016, Bromium, Inc.
 * Author: Gianni Tedesco
 * SPDX-License-Identifier: ISC
 */
#ifndef _DISKLIB_NTFS_H
#define _DISKLIB_NTFS_H

#ifdef __cplusplus
extern "C" {
#endif

typedef struct _ntfs_fs *ntfs_fs_t;
typedef struct _ntfs_fd *ntfs_fd_t;
typedef struct _ntfs_dir *ntfs_dir_t;

/* returns 1 if type is expected to contain NTFS filesystem */
int disklib_ntfs_partition(uint8_t type);

/* offline (ie. unmounted) volume operations */
int disklib_ntfsfix(partition_t part);

/* volumes */
ntfs_fs_t disklib_ntfs_mount(partition_t part, unsigned rw);
void disklib_ntfs_umount(ntfs_fs_t fs);
uint32_t disklib_ntfs_cluster_size(ntfs_fs_t fs);
uint64_t disklib_ntfs_nr_clusters(ntfs_fs_t fs);
uint64_t disklib_ntfs_free_clusters(ntfs_fs_t fs);
const char *disklib_ntfs_volname(ntfs_fs_t fs);

/* Regular file I/O */
ntfs_fd_t disklib_ntfs_open(ntfs_fs_t fs, const char *path, unsigned flags);
int disklib_ntfs_fs_truncate(ntfs_fd_t fd, uint64_t sz);
int disklib_ntfs_seek_set(ntfs_fd_t fd, uint64_t ofs);
ssize_t disklib_ntfs_read(ntfs_fd_t fd, void *buf, size_t len);
ssize_t disklib_ntfs_write(ntfs_fd_t fd, const void *buf, size_t len);
uint64_t disklib_ntfs_filesize(ntfs_fd_t fd);
void disklib_ntfs_close(ntfs_fd_t fd);
int disklib_ntfs_fstat(ntfs_fd_t fd, struct disklib_stat *st);

/* directories and names */
ntfs_dir_t disklib_ntfs_opendir(ntfs_fs_t fs,
                                const char *path,
                                unsigned int flags);
unsigned int disklib_ntfs_szdir(ntfs_dir_t dir);
const char *disklib_ntfs_readdir(ntfs_dir_t dir, unsigned int index);
void disklib_ntfs_closedir(ntfs_dir_t dir);

int disklib_ntfs_unlink(ntfs_fs_t fs, const char *path);
int disklib_ntfs_mkdir(ntfs_fs_t fs, const char *path, int mkp);
int disklib_ntfs_stat(ntfs_fs_t fs, const char *path, struct disklib_stat *st);
int disklib_ntfs_link(ntfs_fs_t fs, const char *target, const char *link);
char *disklib_ntfs_readlink(ntfs_fs_t fs, const char *path, unsigned int *type);

/* Simple & fast versions working on wide chars. */
int disklib_mkdir_simple(ntfs_fs_t fs, const wchar_t *path);
int disklib_write_simple(ntfs_fs_t fs, const wchar_t *path, void *buffer,
        uint64_t size, uint64_t offset, int force_non_resident);
int disklib_mklink_simple(ntfs_fs_t fs, const wchar_t *target, const wchar_t *name);

/* exactly copy an element (file/dir) from one filesystem to another,
 * note that in the case of a directory this is not recursive, giving
 * the caller complete control over what gets copied.
 *
 * All attributes, data streams etc. are to be copied as accurately as
 * possible.
*/
int disklib_ntfs_copy(ntfs_fs_t src, ntfs_fs_t dst,
                        const char *src_path, const char *dst_path,
                        void **cont);
int disklib_ntfs_copy_cont(void *cont, char *buf, size_t len, uint64_t off,
        int force_non_resident);
void disklib_ntfs_copy_finish(void *cont);

/* Open block allocation bitmap special file */
ntfs_fd_t disklib_ntfs_open_bitmap(ntfs_fs_t fs);

/* Open MFT special file */
ntfs_fd_t disklib_ntfs_open_mft(ntfs_fs_t fs);

/* Get runlist for a file */
int disklib_ntfs_file_extents(ntfs_fd_t,
                                struct disklib_extent **rl,
                                unsigned int *cnt);

#ifdef __cplusplus
}
#endif

#endif /* _DISKLIB_NTFS_H */
