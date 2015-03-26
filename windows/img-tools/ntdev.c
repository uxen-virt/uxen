/*
 * Copyright 2011-2015, Bromium, Inc.
 * Author: Gianni Tedesco
 * SPDX-License-Identifier: ISC
 */
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <sys/param.h>
#include <sys/time.h>
#include <ntfs-3g/compat.h>
#include <ntfs-3g/device.h>

#include "disklib.h"
#include "partition.h"

#include "ntdev.h"

#if 0
#define dprintf RTPrintf
#else
#define dprintf(x...) do {}while(0);
#endif

/* pseudo file descriptor for partition */
struct part_fd {
    partition_t part;
    int rdonly;
    s64 ofs;
};

static int io_open(struct ntfs_device *dev, int flags)
{
    struct part_fd *pfd;

    dprintf("%s: called\n", __func__);

    pfd = RTMemAllocZ(sizeof(*pfd));
    if ( NULL == pfd ) {
        ntfs_set_errno(ENOMEM);
        return -1;
    }

    pfd->part = dev->d_private;
    if ( flags & MS_RDONLY )
        pfd->rdonly = 1;

    dev->d_private = pfd;
    return 0;
}

static int io_close(struct ntfs_device *dev)
{
    struct part_fd *pfd = dev->d_private;
    dprintf("%s: called\n", __func__);
    RTMemFree(pfd);
    dev->d_private = NULL;
    return -1;
}

static s64 io_seek(struct ntfs_device *dev, s64 offset, int whence)
{
    struct part_fd *pfd = dev->d_private;
    s64 tmp;

    switch(whence) {
    case SEEK_SET:
        tmp = offset;
        return 0;
    case SEEK_CUR:
        tmp = pfd->ofs + offset;
        return 0;
    case SEEK_END:
        tmp = part_num_sectors(pfd->part) * SECTOR_SIZE + offset;
        return 0;
    default:
        ntfs_set_errno(EINVAL);
        return -1;
    }

    if ( tmp < 0 ) {
        ntfs_set_errno(EINVAL);
        return -1;
    }
    if ( tmp > part_num_sectors(pfd->part) * SECTOR_SIZE ) {
        ntfs_set_errno(EINVAL);
        return -1;
    }

    pfd->ofs = tmp;
    return 0;
}

static s64 io_read(struct ntfs_device *dev, void *buf, s64 count)
{
    //struct part_fd *pfd = dev->d_private;
    RTPrintf("%s: called\n", __func__);
    ntfs_set_errno(ENOSYS);
    return -1;
}

static s64 io_write(struct ntfs_device *dev, const void *buf, s64 count)
{
    struct part_fd *pfd = dev->d_private;
    RTPrintf("%s: called\n", __func__);
    if ( pfd->rdonly ) {
        ntfs_set_errno(EROFS);
        return 1;
    }
    ntfs_set_errno(ENOSYS);
    return -1;
}

static s64 io_pread(struct ntfs_device *dev, void *buf, s64 count, s64 offset)
{
    struct part_fd *pfd = dev->d_private;
    unsigned int num_sec;
    uint64_t sec;
    int bounce;
    void *ptr;
    s64 ret = -1;

    dprintf("%s: called: %"PRIu64" @ %"PRIu64"\n", __func__, count, offset);

    sec = offset / SECTOR_SIZE;
    if ( (count % SECTOR_SIZE) || (offset % SECTOR_SIZE) ) {
        uint64_t last_sec;

        last_sec = (offset + count + SECTOR_SIZE - 1) / SECTOR_SIZE;
        num_sec = last_sec - sec;

        dprintf(" - reading %u sectors from %"PRIu64" to %"PRIu64"\n",
            num_sec, sec, last_sec);

        ptr = RTMemAlloc(num_sec * SECTOR_SIZE);
        if ( NULL == ptr ) {
            ntfs_set_errno(ENOMEM);
            return ret;
        }

        bounce = 1;
    }else{
        sec = offset / SECTOR_SIZE;
        num_sec = count / SECTOR_SIZE;
        ptr = buf;
        bounce = 0;
    }

    if ( !part_read_sectors(pfd->part, ptr, sec, num_sec) ) {
        ntfs_set_errno(EIO);
        ret = -1;
        goto out;
    }

    ret = count;

    /* de-bounce the data in to users buffer */
    if ( bounce ) {
        size_t off_begin;

        off_begin = offset - (sec * SECTOR_SIZE);
        dprintf(" - Calculated de-bounce offset as %"PRIuS"\n", off_begin);
        memcpy(buf, ptr + off_begin, count);

        RTMemFree(ptr);
    }

out:
    return ret;
}

static s64 io_pwrite(struct ntfs_device *dev, const void *buf, s64 count,
             s64 offset)
{
    struct part_fd *pfd = dev->d_private;
    uint64_t sec, num_sec;
    int bounce = 0;
    void *ptr;
    s64 ret = -1;

    dprintf("%s: called: %"PRIu64" @ %"PRIu64"\n", __func__, count, offset);

    if ( pfd->rdonly ) {
        ntfs_set_errno(EROFS);
        return -1;
    }

    sec = offset / SECTOR_SIZE;
    if ( (count % SECTOR_SIZE) || (offset % SECTOR_SIZE) ) {
        uint64_t last_sec;
        size_t off_begin;

        last_sec = (offset + count + SECTOR_SIZE - 1) / SECTOR_SIZE;
        num_sec = last_sec - sec;

        dprintf(" - reading/writing %"PRIuS" sectors from %"PRIu64
                " to %"PRIu64"\n", num_sec, sec, last_sec);

        ptr = RTMemAlloc(num_sec * SECTOR_SIZE);
        if ( NULL == ptr ) {
            ntfs_set_errno(ENOMEM);
            return -1;
        }

        bounce = 1;

        /* read in whole sectors */
        if ( !part_read_sectors(pfd->part, ptr, sec, num_sec) ) {
            ret = -1;
            goto out;
        }

        /* modify the part we're writing */
        off_begin = offset - (sec * SECTOR_SIZE);
        dprintf(" - Calculated bounce offset as %"PRIuS"\n", off_begin);
        memcpy(ptr + off_begin, buf, count);
    }else{
        sec = offset / SECTOR_SIZE;
        num_sec = count / SECTOR_SIZE;
        ptr = (void *)buf;
    }

    if ( !part_write_sectors(pfd->part, ptr, sec, num_sec)) {
        ntfs_set_errno(EIO);
        goto out;
    }

    ret = count;

out:
    if ( bounce )
        RTMemFree(ptr);

    return ret;
}

static int io_sync(struct ntfs_device *dev)
{
#if 0
    struct part_fd *pfd = dev->d_private;
    if ( part_fsync(pfd->part) )
        return 0;

    ntfs_set_errno(EIO);
    return -1;
#else
    return 0;
#endif
}

static int io_stat(struct ntfs_device *dev, struct stat *buf)
{
    //struct part_fd *pfd = dev->d_private;
    dprintf("%s: called\n", __func__);
    return -1;
}

static int io_ioctl(struct ntfs_device *dev, int request, void *argp)
{
    switch(request) {
#ifdef HDIO_GETGEO
    case HDIO_GETGEO:
        dprintf("%s: HDIO_GETGEO called\n", __func__);
        ntfs_set_errno(EINVAL);
        return -1;
#endif
#ifdef BLKBSZSET
    case BLKBSZSET:
        dprintf("%s: BLKSSZSET(%d) called\n", __func__, *(int *)argp);
        if ( *(int *)argp != SECTOR_SIZE ) {
            ntfs_set_errno(EINVAL);
            return -1;
        }
        return 0;
#endif
#ifdef BLKSSZGET
    case BLKSSZGET:
        dprintf("%s: BLKSSZGET called\n", __func__);
        *(int *)argp = SECTOR_SIZE;
        return 0;
#endif
#ifdef BLKGETSIZE64
    case BLKGETSIZE64:
        struct part_fd *pfd = dev->d_private;
        dprintf("%s: BLKGETSIZE64 called\n", __func__);
        *(uint64_t *)argp = part_num_sectors(pfd->part) * SECTOR_SIZE;
        return 0;
#endif
#ifdef BLKGETSIZE
    case BLKGETSIZE:
        struct part_fd *pfd = dev->d_private;
        dprintf("%s: BLKGETSIZE called\n", __func__);
        *(unsigned long *)argp =
            part_num_sectors(pfd->part) * SECTOR_SIZE;
        return 0;
#endif
    default:
        dprintf("%s: UNKNOWN request\n", __func__);
        break;
    }
    ntfs_set_errno(EINVAL);
    return -1;
}


struct ntfs_device_operations part_io_ops = {
    .open = io_open,
    .close = io_close,
    .seek = io_seek,
    .read = io_read,
    .write = io_write,
    .pread = io_pread,
    .pwrite = io_pwrite,
    .sync = io_sync,
    .stat = io_stat,
    .ioctl = io_ioctl,
};
