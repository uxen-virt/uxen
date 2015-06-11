/*
 * Block driver for RAW files (win32)
 *
 * Copyright (c) 2006 Fabrice Bellard
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */
/*
 * uXen changes:
 *
 * Copyright 2012-2015, Bromium, Inc.
 * Author: Christian Limpach <Christian.Limpach@gmail.com>
 * SPDX-License-Identifier: ISC
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
 * SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION
 * OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
 * CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include "config.h"

#define WIN32_AIO 1

#include <err.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "aio.h"
#include "block.h"
#include "block-int.h"
#include "clock.h"
#include "console.h"
#include "os.h"
#include "timer.h"

#include <winioctl.h>

// #define LOG_COMPLETION_TIMES

#define FTYPE_FILE 0
#define FTYPE_CD     1
#define FTYPE_HARDDISK 2

typedef struct BDRVRawState {
    HANDLE hfile;
    int type;
    int64_t cached_size;
    char drive_path[16]; /* format: "d:\" */
} BDRVRawState;

struct BlockDriverAIOCB_win32 {
    BlockDriverAIOCB common;
    BH *bh;
    int ret;
    HANDLE hEvent;
    OVERLAPPED ov;
    int count;
#ifdef LOG_COMPLETION_TIMES
    int64_t start_time;
#endif
};

typedef struct BlockDriverAIOCB_win32 RawAIOCB;

int ftruncate64(int fd, int64_t length)
{
    LARGE_INTEGER li;
    LONG high;
    HANDLE h;
    BOOL res;

    if ((GetVersion() & 0x80000000UL) && (length >> 32) != 0)
	return -1;

    h = (HANDLE)_get_osfhandle(fd);

    /* get current position, ftruncate do not change position */
    li.HighPart = 0;
    li.LowPart = SetFilePointer (h, 0, &li.HighPart, FILE_CURRENT);
    if (li.LowPart == 0xffffffffUL && GetLastError() != NO_ERROR)
	return -1;

    high = length >> 32;
    if (!SetFilePointer(h, (DWORD) length, &high, FILE_BEGIN))
	return -1;
    res = SetEndOfFile(h);

    /* back to old position */
    SetFilePointer(h, li.LowPart, &li.HighPart, FILE_BEGIN);
    return res ? 0 : -1;
}

static int set_sparse(int fd)
{
    DWORD returned;
    return (int) DeviceIoControl((HANDLE)_get_osfhandle(fd), FSCTL_SET_SPARSE,
				 NULL, 0, NULL, 0, &returned, NULL);
}

static int raw_open(BlockDriverState *bs, const char *filename, int flags)
{
    BDRVRawState *s = bs->opaque;
    int access_flags, create_flags;
    DWORD overlapped;

    if (!strncmp(filename, "raw:", 4))
	filename = &filename[4];

    s->cached_size = 0;
    s->type = FTYPE_FILE;

    if ((flags & BDRV_O_RDWR) == BDRV_O_RDWR) {
        access_flags = GENERIC_READ | GENERIC_WRITE;
    } else {
        access_flags = GENERIC_READ;
    }
#if 0
    if (flags & BDRV_O_CREAT)
        create_flags = CREATE_ALWAYS;
    else
#endif
        create_flags = OPEN_EXISTING;
    overlapped = FILE_ATTRIBUTE_NORMAL | FILE_FLAG_RANDOM_ACCESS;
    overlapped |= FILE_FLAG_OVERLAPPED;
    if ((flags & BDRV_O_NOCACHE))
        overlapped |= FILE_FLAG_NO_BUFFERING | FILE_FLAG_WRITE_THROUGH;
    else if (!(flags & BDRV_O_CACHE_WB))
        overlapped |= FILE_FLAG_WRITE_THROUGH;
    s->hfile = CreateFile(filename, access_flags,
                          FILE_SHARE_READ, NULL,
                          create_flags, overlapped, NULL);
    if (s->hfile == INVALID_HANDLE_VALUE) {
        int err = GetLastError();

        if (err == ERROR_ACCESS_DENIED)
            return -EACCES;
        return -1;
    }
    return 0;
}

static int raw_pread(BlockDriverState *bs, int64_t offset,
                     uint8_t *buf, int count)
{
    BDRVRawState *s = bs->opaque;
    OVERLAPPED ov;
    DWORD ret_count;
    int ret;
#ifdef LOG_COMPLETION_TIMES
    int64_t start_time;
#endif

    memset(&ov, 0, sizeof(ov));
    ov.Offset = offset;
    ov.OffsetHigh = offset >> 32;
#ifdef LOG_COMPLETION_TIMES
    start_time = os_get_clock();
    debug_printf("%016"PRIx64" %"PRIu64"/%d sync read\n",
                 start_time, offset / 512, count / 512);
#endif
    ret = ReadFile(s->hfile, buf, count, NULL, &ov);
    if (!ret) {
	int err = GetLastError();
	if (err != ERROR_IO_PENDING) {
	    return -EIO;
	}
    }
    ret = GetOverlappedResult(s->hfile, &ov, &ret_count, TRUE);
    if (ret_count != count) {
      debug_printf("count not met %lx != %x\n", ret_count, count);
      // asm("int $3\n");
    }
#ifdef LOG_COMPLETION_TIMES
    debug_printf("%016"PRIx64" %"PRIu64"/%d sync read done in %"PRIu64"\n",
                 os_get_clock(), offset / 512, count / 512,
                 os_get_clock() - start_time);
#endif
    if (!ret)
	return -EIO;
    else
	return ret_count;
}

static int raw_pwrite(BlockDriverState *bs, int64_t offset,
                      const uint8_t *buf, int count)
{
    BDRVRawState *s = bs->opaque;
    OVERLAPPED ov;
    DWORD ret_count;
    int ret;
#ifdef LOG_COMPLETION_TIMES
    int64_t start_time;
#endif

    memset(&ov, 0, sizeof(ov));
    ov.Offset = offset;
    ov.OffsetHigh = offset >> 32;
#ifdef LOG_COMPLETION_TIMES
    start_time = os_get_clock();
    debug_printf("%016"PRIx64" %"PRIu64"/%d sync write\n",
                 start_time, offset / 512, count / 512);
#endif
    ret = WriteFile(s->hfile, buf, count, NULL, &ov);
    if (!ret) {
	int err = GetLastError();
	if (err != ERROR_IO_PENDING) {
	    return -EIO;
	}
    }
    ret = GetOverlappedResult(s->hfile, &ov, &ret_count, TRUE);
    if (ret_count != count) {
        error_printf("count not met %lx != %x\n", ret_count, count);
        // asm("int $3\n");
    }
#ifdef LOG_COMPLETION_TIMES
    debug_printf("%016"PRIx64" %"PRIu64"/%d sync write done in %"PRIu64"\n",
                 os_get_clock(), offset / 512, count / 512,
                 os_get_clock() - start_time);
#endif
    if (!ret)
	return -EIO;
    else
	return ret_count;
}

#ifdef WIN32_AIO
/* static */ void raw_aio_cb(void *opaque)
{
    RawAIOCB *acb = opaque;
    BlockDriverState *bs = acb->common.bs;
    BDRVRawState *s = bs->opaque;
    DWORD ret_count;
    int ret;
#ifdef LOG_COMPLETION_TIMES
    int64_t c1, c2, c3;
#endif

#ifdef LOG_COMPLETION_TIMES
#if 0
    c1 = os_get_clock();
    debug_printf("%p %012"PRId64" aio cb in %"PRId64"\n",
                 acb, c1 % 10000000000, c1 - acb->start_time);
#endif
    c1 = os_get_clock();
#endif
    ret = GetOverlappedResult(s->hfile, &acb->ov, &ret_count, TRUE);
#ifdef LOG_COMPLETION_TIMES
    c2 = os_get_clock();
#endif
    if (!ret || ret_count != acb->count) {
        acb->common.cb(acb->common.opaque, -EIO);
    } else {
        acb->common.cb(acb->common.opaque, 0);
    }
#ifdef LOG_COMPLETION_TIMES
    c3 = os_get_clock();
    debug_printf("%p %012"PRId64" aio %04d in %"PRId64"/%"PRId64
                 "/%"PRId64"\n", acb, acb->start_time % 10000000000,
                 acb->count >> 9, c1 - acb->start_time, c2 - c1, c3 - c1);
#endif
    aio_del_wait_object(&acb->ov.hEvent);
    aio_release(acb);
}

static void raw_aio_cancel(BlockDriverAIOCB *blockacb);

static AIOPool raw_aio_pool = {
    .aiocb_size         = sizeof(RawAIOCB),
    .cancel             = raw_aio_cancel,
};

static RawAIOCB *raw_aio_setup(BlockDriverState *bs,
        int64_t sector_num, uint8_t *buf, int nb_sectors,
        BlockDriverCompletionFunc *cb, void *opaque)
{
    RawAIOCB *acb;

    acb = aio_get(&raw_aio_pool, bs, cb, opaque);
    if (!acb->hEvent) {
        acb->hEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
        if (!acb->hEvent) {
            aio_release(acb);
            return NULL;
        }
    }
    memset(&acb->ov, 0, sizeof(acb->ov));
    acb->ov.Offset = sector_num << 9;
    acb->ov.OffsetHigh = sector_num >> (32 - 9);
    acb->ov.hEvent = acb->hEvent;
    acb->count = nb_sectors << 9;
    return acb;
}

static BlockDriverAIOCB *raw_aio_read(BlockDriverState *bs,
        int64_t sector_num, uint8_t *buf, int nb_sectors,
        BlockDriverCompletionFunc *cb, void *opaque)
{
    BDRVRawState *s = bs->opaque;
    RawAIOCB *acb;
    int ret;

    acb = raw_aio_setup(bs, sector_num, buf, nb_sectors, cb, opaque);
    if (!acb)
        return NULL;
#ifdef LOG_COMPLETION_TIMES
    acb->start_time = os_get_clock();
#if 0
    debug_printf("%p %012"PRId64" %"PRIu64"/%d aio read\n",
                 acb, acb->start_time % 10000000000, sector_num, nb_sectors);
#endif
#endif
    ret = ReadFile(s->hfile, buf, acb->count, NULL, &acb->ov);
    if (!ret && GetLastError() != ERROR_IO_PENDING) {
        aio_release(acb);
        return NULL;
    }
    aio_add_wait_object(&acb->ov.hEvent, raw_aio_cb, acb);
    return (BlockDriverAIOCB *)acb;
}

static BlockDriverAIOCB *raw_aio_write(BlockDriverState *bs,
        int64_t sector_num, const uint8_t *buf, int nb_sectors,
        BlockDriverCompletionFunc *cb, void *opaque)
{
    BDRVRawState *s = bs->opaque;
    RawAIOCB *acb;
    int ret;

    acb = raw_aio_setup(bs, sector_num, (uint8_t *)buf, nb_sectors, cb, opaque);
    if (!acb)
        return NULL;
#ifdef LOG_COMPLETION_TIMES
    acb->start_time = os_get_clock();
#if 0
    debug_printf("%p %012"PRId64" %"PRIu64"/%d aio write\n",
                 acb, acb->start_time % 10000000000, sector_num, nb_sectors);
#endif
#endif
    ret = WriteFile(s->hfile, buf, acb->count, NULL, &acb->ov);
    if (!ret && GetLastError() != ERROR_IO_PENDING) {
        aio_release(acb);
        return NULL;
    }
    aio_add_wait_object(&acb->ov.hEvent, raw_aio_cb, acb);
    return (BlockDriverAIOCB *)acb;
}

static void raw_aio_cancel(BlockDriverAIOCB *blockacb)
{
    RawAIOCB *acb = (RawAIOCB *)blockacb;
    BlockDriverState *bs = acb->common.bs;
    BDRVRawState *s = bs->opaque;

    aio_del_wait_object(&acb->ov.hEvent);
    /* XXX: if more than one async I/O it is not correct */
    CancelIo(s->hfile);
    aio_release(acb);
}
#endif /* #if WIN32_AIO */

static int raw_flush(BlockDriverState *bs)
{
    BDRVRawState *s = bs->opaque;
    int ret;
    ret = FlushFileBuffers(s->hfile);
    if (!ret)
	return -EIO;
    return 0;
}

static void raw_close(BlockDriverState *bs)
{
    BDRVRawState *s = bs->opaque;
    CloseHandle(s->hfile);
}

static int raw_truncate(BlockDriverState *bs, int64_t offset)
{
    BDRVRawState *s = bs->opaque;
    LONG low, high;

    low = offset;
    high = offset >> 32;
    if (!SetFilePointer(s->hfile, low, &high, FILE_BEGIN))
	return -EIO;
    if (!SetEndOfFile(s->hfile))
        return -EIO;
    return 0;
}

static int64_t raw_getlength(BlockDriverState *bs)
{
    BDRVRawState *s = bs->opaque;
    LARGE_INTEGER l;
    ULARGE_INTEGER available, total, total_free;
    DISK_GEOMETRY_EX dg;
    DWORD count;
    BOOL status;

    if (s->cached_size)
	return s->cached_size;

    switch(s->type) {
    case FTYPE_FILE:
        status = GetFileSizeEx(s->hfile, &l);
        if (!status)
            return -EIO;
        break;
    case FTYPE_CD:
        if (!GetDiskFreeSpaceEx(s->drive_path, &available, &total, &total_free))
            return -EIO;
        l.QuadPart = total.QuadPart;
        break;
    case FTYPE_HARDDISK:
        status = DeviceIoControl(s->hfile, IOCTL_DISK_GET_DRIVE_GEOMETRY_EX,
                                 NULL, 0, &dg, sizeof(dg), &count, NULL);
        if (status != 0) {
            l = dg.DiskSize;
        }
        break;
    default:
        return -EIO;
    }
    s->cached_size = l.QuadPart;
    return l.QuadPart;
}

static int
raw_create(const char *filename, int64_t total_size, int flags)
{
    int fd;

    if (flags & ~BDRV_O_SPARSE)
        return -ENOTSUP;

    fd = open(filename, O_WRONLY | O_CREAT | O_TRUNC | O_BINARY, 0644);
    if (fd < 0)
        return -EIO;
    if (flags & BDRV_O_SPARSE)
        set_sparse(fd);
    ftruncate64(fd, total_size * 512);
    close(fd);
    return 0;
}

BlockDriver bdrv_raw = {
    .format_name = "raw",
    .protocol_name = "raw",
    .instance_size = sizeof(BDRVRawState),
    .bdrv_probe = NULL, /* no probe for protocols */
    .bdrv_open = raw_open,
    .bdrv_close = raw_close,
    .bdrv_create = raw_create,
    .bdrv_flush = raw_flush,

#ifdef WIN32_AIO
    .bdrv_aio_read = raw_aio_read,
    .bdrv_aio_write = raw_aio_write,
#endif
    .bdrv_pread = raw_pread,
    .bdrv_pwrite = raw_pwrite,
    .bdrv_truncate = raw_truncate,
    .bdrv_getlength = raw_getlength,

    .bdrv_flags = BLOCK_DRIVER_FLAG_EXTENDABLE,
};

/***********************************************/
/* host device */

static int find_cdrom(char *cdrom_name, int cdrom_name_size)
{
    char drives[256], *pdrv = drives;
    UINT type;

    memset(drives, 0, sizeof(drives));
    GetLogicalDriveStrings(sizeof(drives), drives);
    while(pdrv[0] != '\0') {
        type = GetDriveType(pdrv);
        switch(type) {
        case DRIVE_CDROM:
            snprintf(cdrom_name, cdrom_name_size, "\\\\.\\%c:", pdrv[0]);
            return 0;
            break;
        }
        pdrv += lstrlen(pdrv) + 1;
    }
    return -1;
}

static int find_device_type(BlockDriverState *bs, const char *filename)
{
    BDRVRawState *s = bs->opaque;
    UINT type;
    const char *p;

    if (strstart(filename, "\\\\.\\", &p) ||
        strstart(filename, "//./", &p)) {
        if (stristart(p, "PhysicalDrive", NULL))
            return FTYPE_HARDDISK;
        snprintf(s->drive_path, sizeof(s->drive_path), "%c:\\", p[0]);
        type = GetDriveType(s->drive_path);
        switch (type) {
        case DRIVE_REMOVABLE:
        case DRIVE_FIXED:
            return FTYPE_HARDDISK;
        case DRIVE_CDROM:
            return FTYPE_CD;
        default:
            return FTYPE_FILE;
        }
    } else {
        return FTYPE_FILE;
    }
}

static int hdev_open(BlockDriverState *bs, const char *filename, int flags)
{
    BDRVRawState *s = bs->opaque;
    int access_flags, create_flags;
    DWORD overlapped;
    char device_name[64];

    if (strstart(filename, "/dev/cdrom", NULL)) {
        if (find_cdrom(device_name, sizeof(device_name)) < 0)
            return -ENOENT;
        filename = device_name;
    } else {
        /* transform drive letters into device name */
        if (((filename[0] >= 'a' && filename[0] <= 'z') ||
             (filename[0] >= 'A' && filename[0] <= 'Z')) &&
            filename[1] == ':' && filename[2] == '\0') {
            snprintf(device_name, sizeof(device_name), "\\\\.\\%c:", filename[0]);
            filename = device_name;
        }
    }
    s->type = find_device_type(bs, filename);

    if ((flags & BDRV_O_RDWR) == BDRV_O_RDWR) {
        access_flags = GENERIC_READ | GENERIC_WRITE;
    } else {
        access_flags = GENERIC_READ;
    }
    create_flags = OPEN_EXISTING;

#ifdef WIN32_AIO
    overlapped = FILE_FLAG_OVERLAPPED;
#else
    overlapped = FILE_ATTRIBUTE_NORMAL;
#endif
    if ((flags & BDRV_O_NOCACHE))
        overlapped |= FILE_FLAG_NO_BUFFERING | FILE_FLAG_WRITE_THROUGH;
    else if (!(flags & BDRV_O_CACHE_WB))
        overlapped |= FILE_FLAG_WRITE_THROUGH;
    s->hfile = CreateFile(filename, access_flags,
                          FILE_SHARE_READ, NULL,
                          create_flags, overlapped, NULL);
    if (s->hfile == INVALID_HANDLE_VALUE) {
        int err = GetLastError();

        if (err == ERROR_ACCESS_DENIED)
            return -EACCES;
        return -1;
    }
    return 0;
}

#if 0
/***********************************************/
/* removable device additional commands */

static int raw_is_inserted(BlockDriverState *bs)
{
    return 1;
}

static int raw_media_changed(BlockDriverState *bs)
{
    return -ENOTSUP;
}

static int raw_eject(BlockDriverState *bs, int eject_flag)
{
    DWORD ret_count;

    if (s->type == FTYPE_FILE)
        return -ENOTSUP;
    if (eject_flag) {
        DeviceIoControl(s->hfile, IOCTL_STORAGE_EJECT_MEDIA,
                        NULL, 0, NULL, 0, &lpBytesReturned, NULL);
    } else {
        DeviceIoControl(s->hfile, IOCTL_STORAGE_LOAD_MEDIA,
                        NULL, 0, NULL, 0, &lpBytesReturned, NULL);
    }
}

static int raw_set_locked(BlockDriverState *bs, int locked)
{
    return -ENOTSUP;
}
#endif

BlockDriver bdrv_host_device = {
    .format_name = "host_device",
    .instance_size = sizeof(BDRVRawState),
    .bdrv_probe = NULL, /* no probe for protocols */
    .bdrv_open = hdev_open,
    .bdrv_close = raw_close,
    .bdrv_flush = raw_flush,

#ifdef WIN32_AIO
    .bdrv_aio_read = raw_aio_read,
    .bdrv_aio_write = raw_aio_write,
#endif
    .bdrv_pread = raw_pread,
    .bdrv_pwrite = raw_pwrite,
    .bdrv_getlength = raw_getlength,
};
