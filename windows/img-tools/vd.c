/*
 * Copyright 2012-2015, Bromium, Inc.
 * Author: Christian Limpach <Christian.Limpach@gmail.com>
 * SPDX-License-Identifier: ISC
 */

#include <assert.h>
#include <ctype.h>
#include <err.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "vbox-compat.h"
#include "queue.h"
#include "vd.h"

#include "libimg.h"

static int vd_initialized = 0;

static LIST_HEAD(, vd) vd_all =
    LIST_HEAD_INITIALIZER(vd_all);

void
vd_close_all(void)
{
    struct vd *vd, *n;

    LIST_FOREACH_SAFE(vd, &vd_all, entry, n)
        vd_destroy(vd);
}

static void
vd_init(void)
{

    ioh_init();
    bh_init();
    aio_init();
    bdrv_init();
}

struct vd *
vd_new(void)
{
    struct vd *vd;

    if (!vd_initialized)
        vd_init();
    vd_initialized = 1;

    vd = calloc(1, sizeof(struct vd));
    if (!vd)
        return NULL;

    LIST_INSERT_HEAD(&vd_all, vd, entry);

    return vd;
}

void
vd_destroy(struct vd *vd)
{

    if (vd->bs) {
        bdrv_flush(vd->bs);
        bdrv_delete(vd->bs);
    }
    LIST_REMOVE(vd, entry);
    free(vd);
}

static int
fmt_name(char **name, const char *_fmt, const char *filename)
{
    char *fmt, *l;
    int ret;

    fmt = strdup(_fmt);
    if (!fmt)
        return -errno;

    for (l = fmt; *l; l++)
        *l = tolower(*l);

    ret = asprintf(name, "%s:%s", fmt, filename);
    if (ret < 0)
        ret = -errno;

    free(fmt);

    return ret;
}

static int
_vd_open(struct vd *vd, const char *name, int _flags)
{
    int flags;
    int ret;

    if (_flags & VD_OPEN_FLAGS_READ_ONLY)
        flags = 0;
    else
        flags = BDRV_O_RDWR;

    vd->bs = bdrv_new("");
    if (!vd->bs) {
        ret = -errno;
        goto out;
    }

    ret = bdrv_open(vd->bs, name, flags);

  out:
    if (ret) {
        if (vd->bs)
            bdrv_delete(vd->bs);
        vd->bs = NULL;
    }
    return ret;
}

int
vd_open(struct vd *vd, const char *fmt, const char *filename, int _flags)
{
    char *name;
    int ret;

    ret = fmt_name(&name, fmt, filename);
    if (ret < 0)
        return ret;

    ret = _vd_open(vd, name, _flags);

    if (name)
        free(name);
    return ret;
}

int
vd_create(struct vd *vd, const char *fmt, const char *filename, uint64_t size,
          int _create_flags, int _open_flags)
{
    char *name;
    int create_flags;
    int ret;

    ret = fmt_name(&name, fmt, filename);
    if (ret < 0)
        return ret;

    create_flags = 0;

    ret = bdrv_create(name, size, create_flags);
    if (ret < 0)
        goto out;

    ret = _vd_open(vd, name, _open_flags);

  out:
    if (name)
        free(name);
    return ret;
}

int
vd_get_format(const char *filename, char **fmt)
{
    char *ext;

    ext = strrchr(filename, '.');
    if (!ext)
        return -EINVAL;

    ext++;
    if (*ext == 0)
        return -EINVAL;

    assert(fmt);
    *fmt = strdup(ext);
    if (!*fmt)
        return -errno;

    return 0;
}

int
vd_get_lchs_geometry(struct vd *vd, uint32_t *cylinders, uint32_t *heads,
                     uint32_t *sectors)
{
    int c, h, s;

    if (!vd->bs)
        return -EINVAL;

    bdrv_guess_geometry(vd->bs, &c, &h, &s);

    *cylinders = c;
    *heads = h;
    *sectors = s;

    return 0;
}

uint64_t
vd_getsize(struct vd *vd)
{

    if (!vd->bs)
        return 0;

    return bdrv_getlength(vd->bs);
}

int
vd_read(struct vd *vd, uint64_t offset, uint8_t *buf, size_t count)
{

    if (!vd->bs)
        return -EINVAL;

    assert(!(offset & ~BDRV_SECTOR_MASK));
    assert(!(count & ~BDRV_SECTOR_MASK));

    return bdrv_read(vd->bs, offset >> BDRV_SECTOR_BITS, buf,
                     count >> BDRV_SECTOR_BITS);
}

int
vd_write(struct vd *vd, uint64_t offset, const uint8_t *buf, size_t count)
{

    if (!vd->bs)
        return -EINVAL;

    assert(!(offset & ~BDRV_SECTOR_MASK));
    assert(!(count & ~BDRV_SECTOR_MASK));

    return bdrv_write(vd->bs, offset >> BDRV_SECTOR_BITS, buf,
                     count >> BDRV_SECTOR_BITS);
}
