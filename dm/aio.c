/*
 * Copyright 2012-2015, Bromium, Inc.
 * Author: Christian Limpach <Christian.Limpach@gmail.com>
 * SPDX-License-Identifier: ISC
 */

#include "config.h"

#include <err.h>
#include <stdbool.h>
#include <stdint.h>

#if defined(__APPLE__)
#include <unistd.h>
#include <sys/types.h>
#include <sys/event.h>
#include <sys/time.h>
#endif

#include "aio.h"
#include "block.h"
#include "block-int.h"
#include "introspection.h"
#include "ioh.h"
#include "iovec.h"

/* XXX per device */
WaitObjects aio_wait_objects = WAITOBJECTS_INITIALIZER;

void *
aio_get(AIOPool *pool, BlockDriverState *bs,
        BlockDriverCompletionFunc *cb, void *opaque)
{
    BlockDriverAIOCB *acb;

    if (pool->free_aiocb) {
        acb = pool->free_aiocb;
        pool->free_aiocb = acb->next;
    } else {
        acb = calloc(1, pool->aiocb_size);
        acb->pool = pool;
    }

    acb->bs = bs;
    acb->cb = cb;
    acb->opaque = opaque;

    return acb;
}

void
aio_release(void *p)
{
    BlockDriverAIOCB *acb = (BlockDriverAIOCB *)p;
    AIOPool *pool = acb->pool;

    acb->next = pool->free_aiocb;
    pool->free_aiocb = acb;
}

void
aio_init(void)
{
}

void
aio_poll(void)
{

    bh_poll();
}

void
aio_wait_start(void)
{
}

#if defined(_WIN32)
static void
wait_for_objects(int timeout, WaitObjects *w)
{
    int ret, obj, num;

    num = w->num;
    if (num >=  MAXIMUM_WAIT_EVENTS)
        num = MAXIMUM_WAIT_EVENTS;
    ret = MsgWaitForMultipleObjectsEx(num, w->events, timeout,
                                      0, MWMO_ALERTABLE | 
                                      MWMO_INPUTAVAILABLE);
    if (ret >= WAIT_OBJECT_0 && ret < WAIT_OBJECT_0 + num) {
        obj = ret - WAIT_OBJECT_0;
        ResetEvent(w->events[obj]);
        if (w->desc[obj].func)
            w->desc[obj].func(w->desc[obj].opaque);
    } else if (ret == WAIT_TIMEOUT || ret == WAIT_IO_COMPLETION) {
        /* ok, ignore */
    } else {
        Wwarn("WaitForMultipleObjectsEx");
    }
}
#elif defined(__APPLE__)
static void
wait_for_objects(int timeout, WaitObjects *w)
{
    ioh_event_queue events = TAILQ_HEAD_INITIALIZER(events);
    ioh_event *event, *next;
    struct kevent kev[64];
    struct timespec ts;
    int num;
    int ev;

    if (timeout >= 0) {
        ts.tv_sec = timeout / 1000;
        ts.tv_nsec = (timeout % 1000) * 1000000;
    }

    do {
        num = kevent(w->queue_fd, NULL, 0, kev, 64, (timeout < 0) ? NULL : &ts);
        if (num == -1)
            err(1, "%s: kevent failed", __FUNCTION__);

        for (ev = 0; ev < num; ev++) {
            event = kev[ev].udata;
            if (event->processq)
                TAILQ_REMOVE(event->processq, event, link);
            event->processq = &events;
            TAILQ_INSERT_TAIL(&events, event, link);
        }

        ts.tv_sec = 0;
        ts.tv_nsec = 0;
        timeout = 0;
    } while (num == 64);

    TAILQ_FOREACH_SAFE(event, &events, link, next) {
        TAILQ_REMOVE(&events, event, link);
        event->processq = NULL;
        ioh_event_reset(event);
        if (event->func)
            event->func(event->opaque);
    }
}
#endif

void
aio_wait(void)
{

    wait_for_objects(1000, &aio_wait_objects);
}

void
aio_wait_end(void)
{
}

int
aio_add_wait_object(ioh_event *event, WaitObjectFunc *func, void *opaque)
{
    int ret;

    ret = ioh_add_wait_object(event, func, opaque, NULL);
    if (ret)
        return ret;
    ret = ioh_add_wait_object(event, func, opaque, &aio_wait_objects);
    if (ret)
        return ret;
    return 0;
}

void
aio_del_wait_object(ioh_event *event)
{

    ioh_del_wait_object(event, NULL);
    ioh_del_wait_object(event, &aio_wait_objects);
}

void aio_flush(void)
{
    aio_wait_start();
    aio_poll();
#if defined(__APPLE__)
    while (aio_wait_objects.queue_len) {
#else
    while (aio_wait_objects.num) {
#endif
        aio_wait();
    }
    aio_wait_end();
}

BlockDriverAIOCB *
bdrv_aio_read(BlockDriverState *bs, int64_t sector_num,
              uint8_t *buf, int nb_sectors,
              BlockDriverCompletionFunc *cb, void *opaque)
{
    BlockDriver *drv = bs->drv;
    BlockDriverAIOCB *ret;

    if (!drv)
        return NULL;
    if (bdrv_check_request(bs, sector_num, nb_sectors))
        return NULL;

    ret = drv->bdrv_aio_read(bs, sector_num, buf, nb_sectors, cb, opaque);

    if (ret) {
	/* Update stats even though technically transfer has not happened. */
	bs->nr_bytes[BDRV_ACCT_READ] += nb_sectors * BDRV_SECTOR_SIZE;
	bs->nr_ops[BDRV_ACCT_READ]++;
    }

    return ret;
}

BlockDriverAIOCB *
bdrv_aio_write(BlockDriverState *bs, int64_t sector_num,
               const uint8_t *buf, int nb_sectors,
               BlockDriverCompletionFunc *cb, void *opaque)
{
    BlockDriver *drv = bs->drv;
    BlockDriverAIOCB *ret;

    if (!drv)
        return NULL;
    if (bs->read_only)
        return NULL;
    if (bdrv_check_request(bs, sector_num, nb_sectors))
        return NULL;

#ifndef LIBIMG
    if (bs->device_name[0]) /* So, guest device, not backing file */
        lava_check_mbr_vbr_write(sector_num);
#endif

    ret = drv->bdrv_aio_write(bs, sector_num, buf, nb_sectors, cb, opaque);

    if (ret) {
	/* Update stats even though technically transfer has not happened. */
	bs->nr_bytes[BDRV_ACCT_WRITE] += nb_sectors * BDRV_SECTOR_SIZE;
	bs->nr_ops[BDRV_ACCT_WRITE]++;
    }

    return ret;
}

void
bdrv_aio_cancel(BlockDriverAIOCB *acb)
{

    acb->pool->cancel(acb);
}

BlockDriverAIOCB *
bdrv_aio_flush(BlockDriverState *bs, BlockDriverCompletionFunc *cb,
               void *opaque)
{
    BlockDriver *drv = bs->drv;

    if (!drv)
        return NULL;

    return drv->bdrv_aio_flush(bs, cb, opaque);
}

typedef struct VectorTranslationAIOCB {
    BlockDriverAIOCB common;
    IOVector *qiov;
    uint8_t *bounce;
    int is_write;
    BlockDriverAIOCB *aiocb;
} VectorTranslationAIOCB;

static void
bdrv_aio_cancel_vector(BlockDriverAIOCB *_acb)
{
    VectorTranslationAIOCB *acb
        = container_of(_acb, VectorTranslationAIOCB, common);

    bdrv_aio_cancel(acb->aiocb);
}

static AIOPool bdrv_vector_aio_pool = {
    .aiocb_size         = sizeof(VectorTranslationAIOCB),
    .cancel             = bdrv_aio_cancel_vector,
};

static void
bdrv_aio_rw_vector_cb(void *opaque, int ret)
{
    VectorTranslationAIOCB *s = (VectorTranslationAIOCB *)opaque;

    if (!s->is_write)
        iovec_from_buffer(s->qiov, s->bounce, 0, s->qiov->size);

    align_free(s->bounce);

    s->common.cb(s->common.opaque, ret);

    aio_release(s);
}

static BlockDriverAIOCB *
bdrv_aio_rw_vector(BlockDriverState *bs,
                   int64_t sector_num,
                   IOVector *qiov,
                   int nb_sectors,
                   BlockDriverCompletionFunc *cb,
                   void *opaque,
                   int is_write)
{
    VectorTranslationAIOCB *acb;

#if 0
    BlockDriver *drv = bs->drv;
    if (is_write && drv->bdrv_aio_writev)
        return drv->bdrv_aio_writev(bs, sector_num, qiov, nb_sectors, cb,
                                    opaque);
    else if (!is_write && drv->bdrv_aio_readv)
        return drv->bdrv_aio_readv(bs, sector_num, qiov, nb_sectors, cb,
                                   opaque);
#endif

    acb = aio_get(&bdrv_vector_aio_pool, bs, cb, opaque);
    acb->is_write = is_write;
    acb->qiov = qiov;
    acb->bounce = bdrv_blockalign(bs, qiov->size);
    if (!acb->bounce) {
        warn("Failed to allocate bounce buffer size=%"PRId64" align=%"PRId64,
             (uint64_t)qiov->size, (uint64_t)bs->buffer_alignment);
        aio_release(acb);
        return NULL;
    }

    if (is_write) {
        iovec_to_buffer(acb->qiov, acb->bounce, 0, qiov->size);
        acb->aiocb = bdrv_aio_write(bs, sector_num, acb->bounce, nb_sectors,
				    bdrv_aio_rw_vector_cb, acb);
    } else {
        acb->aiocb = bdrv_aio_read(bs, sector_num, acb->bounce, nb_sectors,
				   bdrv_aio_rw_vector_cb, acb);
    }

    if (!acb->aiocb) {
        align_free(acb->bounce);
        aio_release(acb);
        return NULL;
    }

    return &acb->common;
}

BlockDriverAIOCB *
bdrv_aio_readv(BlockDriverState *bs, int64_t sector_num,
               IOVector *iov, int nb_sectors,
               BlockDriverCompletionFunc *cb, void *opaque)
{

    if (bdrv_check_request(bs, sector_num, nb_sectors))
        return NULL;

    return bdrv_aio_rw_vector(bs, sector_num, iov, nb_sectors,
                              cb, opaque, 0);
}

BlockDriverAIOCB *
bdrv_aio_writev(BlockDriverState *bs, int64_t sector_num,
                IOVector *iov, int nb_sectors,
                BlockDriverCompletionFunc *cb, void *opaque)
{

    if (bdrv_check_request(bs, sector_num, nb_sectors))
        return NULL;

    return bdrv_aio_rw_vector(bs, sector_num, iov, nb_sectors,
                              cb, opaque, 1);
}

#if 0
typedef struct BlockDriverAIOCB_em_with_v {
    BlockDriverAIOCB common;
    IOVector qiov;
    BlockDriverAIOCB *aiocb;
} BlockDriverAIOCB_em_with_v;

static BlockDriverAIOCB *
bdrv_aio_read_em_with_v(BlockDriverState *bs,
                        int64_t sector_num,
                        uint8_t *buf,
                        int nb_sectors,
                        BlockDriverCompletionFunc *cb,
                        void *opaque)
{

    return NULL;
}

static BlockDriverAIOCB *
bdrv_aio_write_em_with_v(BlockDriverState *bs,
                         int64_t sector_num,
                         const uint8_t *buf,
                         int nb_sectors,
                         BlockDriverCompletionFunc *cb,
                         void *opaque)
{

    return NULL;
}
#endif

typedef struct BlockDriverAIOCB_sync BlockDriverAIOCB_sync;

static void bdrv_aio_cancel_em(BlockDriverAIOCB *blockacb);

static AIOPool bdrv_em_aio_pool = {
    .aiocb_size         = sizeof(BlockDriverAIOCB_sync),
    .cancel             = bdrv_aio_cancel_em,
};

static void
bdrv_aio_bh_cb(void *opaque)
{
    BlockDriverAIOCB_sync *acb = opaque;

    acb->common.cb(acb->common.opaque, acb->ret);

    bh_delete(acb->bh);
    acb->bh = NULL;

    aio_release(acb);
}

BlockDriverAIOCB *
bdrv_aio_read_em(BlockDriverState *bs,
                 int64_t sector_num, uint8_t *buf, int nb_sectors,
                 BlockDriverCompletionFunc *cb, void *opaque)
{
    BlockDriverAIOCB_sync *acb;

    acb = aio_get(&bdrv_em_aio_pool, bs, cb, opaque);

    if (!acb->bh)
        acb->bh = bh_new(bdrv_aio_bh_cb, acb);

    acb->ret = bdrv_read(bs, sector_num, buf, nb_sectors);

    bh_schedule(acb->bh);

    return &acb->common;
}

BlockDriverAIOCB *
bdrv_aio_write_em(BlockDriverState *bs,
                  int64_t sector_num, const uint8_t *buf, int nb_sectors,
                  BlockDriverCompletionFunc *cb, void *opaque)
{
    BlockDriverAIOCB_sync *acb;

    acb = aio_get(&bdrv_em_aio_pool, bs, cb, opaque);

    if (!acb->bh)
        acb->bh = bh_new(bdrv_aio_bh_cb, acb);

    acb->ret = bdrv_write(bs, sector_num, buf, nb_sectors);

    bh_schedule(acb->bh);

    return &acb->common;
}

static void
bdrv_aio_cancel_em(BlockDriverAIOCB *blockacb)
{
    BlockDriverAIOCB_sync *acb = (BlockDriverAIOCB_sync *)blockacb;

    bh_delete(acb->bh);

    acb->bh = NULL;

    aio_release(acb);
}

static void
bdrv_rw_em_cb(void *opaque, int ret)
{

    *(int *)opaque = ret;
}

#define NOT_DONE 0x7fffffff

static int bdrv_read_em(BlockDriverState *bs, int64_t sector_num,
                        uint8_t *buf, int nb_sectors)
{
    int async_ret;
    BlockDriverAIOCB *acb;

    async_ret = NOT_DONE;
    acb = bdrv_aio_read(bs, sector_num, buf, nb_sectors,
                        bdrv_rw_em_cb, &async_ret);
    if (acb == NULL)
        return -1;

    while (async_ret == NOT_DONE)
        aio_flush();

    return async_ret;
}

static int bdrv_write_em(BlockDriverState *bs, int64_t sector_num,
                         const uint8_t *buf, int nb_sectors)
{
    int async_ret;
    BlockDriverAIOCB *acb;

    async_ret = NOT_DONE;
    acb = bdrv_aio_write(bs, sector_num, buf, nb_sectors,
                         bdrv_rw_em_cb, &async_ret);
    if (acb == NULL)
        return -1;

    while (async_ret == NOT_DONE)
        aio_flush();

    return async_ret;
}

static BlockDriverAIOCB *
bdrv_aio_flush_em(BlockDriverState *bs,
                  BlockDriverCompletionFunc *cb, void *opaque)
{
    BlockDriverAIOCB_sync *acb;

    acb = aio_get(&bdrv_em_aio_pool, bs, cb, opaque);

    if (!acb->bh)
        acb->bh = bh_new(bdrv_aio_bh_cb, acb);

    acb->ret = bdrv_flush(bs);

    bh_schedule(acb->bh);

    return &acb->common;
}

void
aio_setup_em(BlockDriver *bdrv)
{

#if 0
    if (bdrv->bdrv_aio_readv && !bdrv->bdrv_aio_read) {
        /* add non-v AIO emulation layer */
        bdrv->bdrv_aio_read = bdrv_aio_read_em_with_v;
        bdrv->bdrv_aio_write = bdrv_aio_write_em_with_v;
    }
#endif
    if (!bdrv->bdrv_aio_read) {
        /* add AIO emulation layer */
        bdrv->bdrv_aio_read = bdrv_aio_read_em;
        bdrv->bdrv_aio_write = bdrv_aio_write_em;
    } else if (!bdrv->bdrv_read && !bdrv->bdrv_pread) {
        /* add synchronous IO emulation layer */
        bdrv->bdrv_read = bdrv_read_em;
        bdrv->bdrv_write = bdrv_write_em;
    }

    if (!bdrv->bdrv_aio_flush)
        bdrv->bdrv_aio_flush = bdrv_aio_flush_em;
}

