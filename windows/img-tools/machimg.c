/*
 * Copyright 2011-2015, Bromium, Inc.
 * Author: Gianni Tedesco
 * SPDX-License-Identifier: ISC
 *
 * Boot Configuration Database
 * For Windows Vista and above
 */

#define LOG_GROUP LOG_GROUP_DISKLIB
#include <VBox/vd.h>
#include <VBox/disklib/disklib.h>
#include <VBox/disklib/partition.h>
#include <VBox/disklib/reghive.h>
#include <VBox/disklib/fs-ntfs.h>
#include <VBox/disklib/bcd.h>
#include <VBox/disklib/machimg.h>

/* we're only using one at the moment, maybe two are planned
 * so 4 is generous */
#define MACH_MAX_DISKS          4

struct _disklib_fs {
    struct _mach        *f_owner;
    const struct fsops  *f_ops;
    void                *f_priv;
};

struct _disklib_fd {
    struct _mach        *f_owner;
    const struct fdops  *f_ops;
    void                *f_priv;
};

struct _mach {
    ptbl_t              m_ptbl[MACH_MAX_DISKS];
    disk_handle_t       m_disk[MACH_MAX_DISKS];
    unsigned int        m_num_disks;
    int                 m_flags;
};

mach_t machimg_new(int flags)
{
    struct _mach *m;

    m = RTMemAllocZ(sizeof(*m));
    if ( NULL == m )
        return NULL;

    m->m_flags = flags;

    return m;
}

int machimg_disk_push(mach_t m, disk_handle_t hdd)
{
    if ( m->m_num_disks >= MACH_MAX_DISKS )
        return 0;

    m->m_disk[m->m_num_disks] = hdd;
    m->m_ptbl[m->m_num_disks] = ptbl_open(hdd);

    if ( NULL == m->m_ptbl[m->m_num_disks] )
        return 0;

    m->m_num_disks++;
    return 1;
}

int machimg_ready(mach_t m)
{
    unsigned int i;

    /* 1. for each disk, mount boot partition */
    for(i = 0; i < m->m_num_disks; i++) {
        /* 2. for each boot partition attempt to read BCD */
        /* 3. once we got BCD, read windows dir and OSdevice */
        /* 4. map OSdevice to C: */
        /* 5. read system hive from C: */
        /* 6. map mountedevices keys and mount them */
    }

    return 0;
}

void disklib_free(mach_t m)
{
    if ( m ) {
        unsigned int i;
        for(i = 0; i < m->m_num_disks; i++) {
            disklib_close_image(m->m_disk[i]);
            ptbl_close(m->m_ptbl[i]);
        }
        RTMemFree(m);
    }

    return;
}

/* filesystem */
int disklib_readdir(mach_t m, const char *path,
                int(*cb)(void *priv, const char *path),
                void *priv, unsigned int flags)
{
    return 0;
}

int disklib_unlink(mach_t m, const char *path)
{
    return 0;
}

int disklib_mkdir(mach_t m, const char *path)
{
    return 0;
}


disklib_fd_t disklib_open(mach_t m, const char *path, unsigned flags)
{
    return NULL;
}

/* file descriptors */
int disklib_truncate(disklib_fd_t fd, uint64_t sz)
{
    return 1;
}

int disklib_seek_set(disklib_fd_t fd, uint64_t ofs)
{
    return 1;
}

ssize_t disklib_read(disklib_fd_t fd, void *buf, size_t len)
{
    return 1;
}

ssize_t disklib_write(disklib_fd_t fd, const void *buf, size_t len)
{
    return 1;
}

uint64_t disklib_filesize(disklib_fd_t fd)
{
    return 1;
}

void disklib_close(disklib_fd_t fd)
{
    return;
}
