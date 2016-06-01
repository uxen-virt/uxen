/*
 * Copyright 2012-2016, Bromium, Inc.
 * SPDX-License-Identifier: ISC
 */

#ifndef _LIBIMG_H_
#define _LIBIMG_H_

typedef struct BlockDriverState BlockDriverState;

#define BDRV_O_RDWR        0x0002

#define BDRV_SECTOR_BITS   9ULL
#define BDRV_SECTOR_SIZE   (1ULL << BDRV_SECTOR_BITS)
#define BDRV_SECTOR_MASK   ~(BDRV_SECTOR_SIZE - 1ULL)

void ioh_init(void);
void bh_init(void);
void aio_init(void);
void bdrv_init(void);

BlockDriverState *bdrv_new(const char *device_name);
void bdrv_delete(BlockDriverState *bs);
int bdrv_create(const char* filename, int64_t total_size, int flags);
int bdrv_remove(BlockDriverState *bs);
int bdrv_open(BlockDriverState *bs, const char *filename, int flags);
void bdrv_flush(BlockDriverState *bs);

int64_t bdrv_getlength(BlockDriverState *bs);
void bdrv_guess_geometry(BlockDriverState *bs, int *pcyls, int *pheads, int *psecs);

int bdrv_read(BlockDriverState *bs, int64_t sector_num,
              uint8_t *buf, int nb_sectors);
int bdrv_write(BlockDriverState *bs, int64_t sector_num,
               const uint8_t *buf, int nb_sectors);

int bdrv_snapshot_delete(BlockDriverState *bs, const char *id);

#endif  /* _LIBIMG_H_ */
