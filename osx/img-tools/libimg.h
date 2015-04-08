/*
 * Copyright 2013-2015, Bromium, Inc.
 * Author: Jacob Gorm Hansen <jacobgorm@gmail.com>
 * SPDX-License-Identifier: ISC
 */

#ifndef _LIBIMG_H_
#define _LIBIMG_H_

#include <stdint.h>

typedef struct BlockDriverState BlockDriverState;

#define BDRV_O_RDWR        0x0002

#define BDRV_SECTOR_BITS   9
#define BDRV_SECTOR_SIZE   (1ULL << BDRV_SECTOR_BITS)
#define BDRV_SECTOR_MASK   ~(BDRV_SECTOR_SIZE - 1)

void ioh_init(void);
void bh_init(void);
void aio_init(void);
void bdrv_init(void);

BlockDriverState *bdrv_new(const char *device_name);
void bdrv_delete(BlockDriverState *bs);
int bdrv_create(const char* filename, int64_t total_size, int flags);
int bdrv_open(BlockDriverState *bs, const char *filename, int flags);

int64_t bdrv_getlength(BlockDriverState *bs);
void bdrv_guess_geometry(BlockDriverState *bs, int *pcyls, int *pheads, int *psecs);

int bdrv_read(BlockDriverState *bs, int64_t sector_num,
              uint8_t *buf, int nb_sectors);
int bdrv_write(BlockDriverState *bs, int64_t sector_num,
               const uint8_t *buf, int nb_sectors);
int bdrv_flush(BlockDriverState *bs);
int bdrv_close(BlockDriverState *bs);
int bdrv_remove(BlockDriverState *bs);

#endif  /* _LIBIMG_H_ */
