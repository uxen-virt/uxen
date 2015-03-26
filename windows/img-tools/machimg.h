/*
 * Copyright 2011-2015, Bromium, Inc.
 * Author: Gianni Tedesco
 * SPDX-License-Identifier: ISC
 *
 * Machine image level library
 */
#ifndef _DISKLIB_MACHIMG_H
#define _DISKLIB_MACHIMG_H

#ifdef __cplusplus
extern "C" {
#endif

typedef struct _mach *mach_t;

#define DISKLIB_MACHIMG_READ_ONLY   0
#define DISKLIB_MACHIMG_READ_WRITE  1

/* lifetime */
mach_t machimg_new(int flags);
int machimg_disk_push(mach_t m, disk_handle_t hdd);
int machimg_ready(mach_t m);
void machimg_free(mach_t m);

/* files */
disklib_fd_t disklib_open(mach_t m, const char *path, unsigned flags);
int disklib_readdir(mach_t m, const char *path,
                int(*cb)(void *priv, const char *path),
                void *priv, unsigned int flags);
int disklib_unlink(mach_t m, const char *path);
int disklib_mkdir(mach_t m, const char *path);

#ifdef __cplusplus
}
#endif

#endif /* _DISKLIB_MACHIMG_H */
