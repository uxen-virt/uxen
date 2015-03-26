/*
 * Copyright 2012-2015, Bromium, Inc.
 * Author: Christian Limpach <Christian.Limpach@gmail.com>
 * SPDX-License-Identifier: ISC
 */

#ifndef _VD_H_
#define _VD_H_

#include <libimg.h>

#include "queue.h"

struct vd {
    BlockDriverState *bs;
    LIST_ENTRY(vd) entry;
};

struct vd *vd_new(void);
void vd_destroy(struct vd *vd);

int vd_open(struct vd *vd, const char *fmt, const char *filename, int flags);
int vd_create(struct vd *vd, const char *fmt, const char *filename,
              uint64_t size, int create_flags, int open_flags);
int vd_get_format(const char *filename, char **fmt);
int vd_get_lchs_geometry(struct vd *vd, uint32_t *cylinders, uint32_t *heads,
                         uint32_t *sectors);
uint64_t vd_getsize(struct vd *vd);

int vd_read(struct vd *vd, uint64_t offset, uint8_t *buf, size_t count);
int vd_write(struct vd *vd, uint64_t offset, const uint8_t *buf, size_t count);

#endif  /* _VD_H_ */
