/*
 * Copyright 2012-2015, Bromium, Inc.
 * Author: Christian Limpach <Christian.Limpach@gmail.com>
 * SPDX-License-Identifier: ISC
 */

#ifndef _DMA_H_
#define _DMA_H_

#include "block.h"
#include "sg.h"

typedef uint64_t dma_addr_t;

typedef enum {
    DMA_DIRECTION_TO_DEVICE = 0,
    DMA_DIRECTION_FROM_DEVICE = 1,
} DMADirection;

typedef BlockDriverAIOCB *DMAIOFunc(BlockDriverState *bs, int64_t sector_num,
				    IOVector *iov, int nb_sectors,
				    BlockDriverCompletionFunc *cb, void *opaque);

BlockDriverAIOCB *dma_bdrv_io(BlockDriverState *bs,
			      SGList *sg, uint64_t sector,
			      DMAIOFunc *io_func, BlockDriverCompletionFunc *cb,
			      void *opaque, bool to_dev);
BlockDriverAIOCB *dma_bdrv_read(BlockDriverState *bs,
                                SGList *sg, uint64_t sector,
                                void (*cb)(void *opaque, int ret),
				void *opaque);
BlockDriverAIOCB *dma_bdrv_write(BlockDriverState *bs,
                                 SGList *sg, uint64_t sector,
                                 void (*cb)(void *opaque, int ret),
				 void *opaque);

#endif	/* _DMA_H_ */
