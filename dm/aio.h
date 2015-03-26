/*
 * Copyright 2012-2015, Bromium, Inc.
 * Author: Christian Limpach <Christian.Limpach@gmail.com>
 * SPDX-License-Identifier: ISC
 */

#ifndef _AIO_H_
#define _AIO_H_

#include "block.h"
#include "ioh.h"

void aio_flush();
void *aio_get(AIOPool *pool, BlockDriverState *bs,
	      BlockDriverCompletionFunc *cb, void *opaque);
void aio_release(void *p);

BlockDriverAIOCB *
bdrv_aio_read(BlockDriverState *bs, int64_t sector_num,
              uint8_t *buf, int nb_sectors,
              BlockDriverCompletionFunc *cb, void *opaque);
BlockDriverAIOCB *
bdrv_aio_write(BlockDriverState *bs, int64_t sector_num,
               const uint8_t *buf, int nb_sectors,
               BlockDriverCompletionFunc *cb, void *opaque);

void aio_setup_em(BlockDriver *bdrv);

void aio_init(void);
void aio_poll(void);
void aio_flush(void);
void aio_wait_start(void);
void aio_wait(void);
void aio_wait_end(void);
int aio_add_wait_object(ioh_event *event, WaitObjectFunc *func, void *opaque);
void aio_del_wait_object(ioh_event *event);

#endif	/* _AIO_H_ */
