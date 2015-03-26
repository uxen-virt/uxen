/*
 * DMA helper functions
 *
 * Copyright (c) 2009 Red Hat
 *
 * This work is licensed under the terms of the GNU General Public License
 * (GNU GPL), version 2 or later.
 */

#include <dm/qemu_glue.h>
#include <dm/dma.h>
#include <dm/block.h>
#include <dm/block-int.h>

#define SANE_NALLOC_COST (1<<30)
void qemu_sglist_init(QEMUSGList *qsg, int alloc_hint)
{
    if (alloc_hint < 0 ||
        alloc_hint > SANE_NALLOC_COST/sizeof(ScatterGatherEntry))
        err(1, "Insane alloc_hint=0x%x in qemu_sglist_init", alloc_hint);
    qsg->sg = g_malloc(alloc_hint * sizeof(ScatterGatherEntry));
    if (!qsg->sg)
        err(1, "malloc failure in qemu_sglist_init");
    qsg->nsg = 0;
    qsg->nalloc = alloc_hint;
    qsg->size = 0;
}

/* We need MAX_IOVEC_SIZE, because we do not want the guest force us allocate
almost arbitrary amount of memory. We do not expect DMA request for more than
1G, do we ? There is no good way to gracefully fail,
so we just abort with err().
Also, at least on 32bit build, allocation sizes close to 4G (prone to integer
overflow) make me nervous - see e.g. bdrv_aio_rw_vector() when we
linearize iovec, it is just dumb luck that bdrv_blockalign cannot alloc 0 bytes
if passed e.g. 0xfffff000 as size.
*/
#define MAX_IOVEC_SIZE (1<<30)

void qemu_sglist_add_completion(QEMUSGList *qsg,
                                dma_addr_t base,
                                dma_addr_t len,
                                SGEntryCompletion cb,
                                void *opaque)
{
    if (len > MAX_IOVEC_SIZE || qsg->size > MAX_IOVEC_SIZE ||
        len + qsg->size > MAX_IOVEC_SIZE)
        err(1, "Cowardly refusing to create an insanely large QEMUSGList, len=0x%"PRIx64" qsg->size=0x%"PRIx64, (uint64_t)len, (uint64_t)qsg->size);

    if (qsg->nsg == qsg->nalloc) {
        if (qsg->nalloc >= SANE_NALLOC_COST/sizeof(ScatterGatherEntry))
            err(1, "Insane qsg->nalloc=0x%x in sglist_add", qsg->nalloc);
        qsg->nalloc = 2 * qsg->nalloc + 1;
        qsg->sg = g_realloc(qsg->sg, qsg->nalloc * sizeof(ScatterGatherEntry));
        if (!qsg->sg)
            err(1, "Malloc fail in sglist_add");
    }
    qsg->sg[qsg->nsg].base = base;
    qsg->sg[qsg->nsg].len = len;
    qsg->sg[qsg->nsg].completion_cb = cb;
    qsg->sg[qsg->nsg].opaque = opaque;
    qsg->size += len;
    ++qsg->nsg;
}

void qemu_sglist_add(QEMUSGList *qsg, dma_addr_t base, dma_addr_t len)
{
    qemu_sglist_add_completion(qsg, base, len, NULL, NULL);
}

void qemu_sglist_destroy(QEMUSGList *qsg)
{
    g_free(qsg->sg);
}

typedef struct {
    BlockDriverAIOCB common;
    BlockDriverState *bs;
    BlockDriverAIOCB *acb;
    QEMUSGList *sg;
    uint64_t sector_num;
    bool to_dev;
    bool in_cancel;
    int sg_cur_index;
    dma_addr_t sg_cur_byte;
    QEMUIOVector iov;
#if 0
    QEMUBH *bh;
#endif
    DMAIOFunc *io_func;
} DMAAIOCB;

static void dma_bdrv_cb(void *opaque, int ret);

#if 0
static void reschedule_dma(void *opaque)
{
    DMAAIOCB *dbs = (DMAAIOCB *)opaque;

    qemu_bh_delete(dbs->bh);
    dbs->bh = NULL;
    dma_bdrv_cb(dbs, 0);
}

static void continue_after_map_failure(void *opaque)
{
    DMAAIOCB *dbs = (DMAAIOCB *)opaque;

    dbs->bh = qemu_bh_new(reschedule_dma, dbs);
    qemu_bh_schedule(dbs->bh);
}
#endif

static void dma_bdrv_unmap(DMAAIOCB *dbs)
{
    int i;

    for (i = 0; i < dbs->iov.niov; ++i) {
        vm_memory_unmap(dbs->iov.ioaddr[i],
                        dbs->iov.iov[i].iov_len, !dbs->to_dev, 0,
                        dbs->iov.iov[i].iov_base,
                        dbs->iov.iov[i].iov_len);
    }
    qemu_iovec_reset(&dbs->iov);
}

static void dma_complete(DMAAIOCB *dbs, int ret)
{
    if (dbs->sg) {
        uint32_t i, sgcount;
        ScatterGatherEntry *cur_prd;

        cur_prd = dbs->sg->sg;
        sgcount = dbs->sg->nsg;

        for (i = 0; i < sgcount; i++) {
            if (cur_prd->completion_cb)
                cur_prd->completion_cb(cur_prd, cur_prd->opaque);
            cur_prd++;
        }
    }

    dma_bdrv_unmap(dbs);
    if (dbs->common.cb) {
        dbs->common.cb(dbs->common.opaque, ret);
    }
    qemu_iovec_destroy(&dbs->iov);
#if 0
    if (dbs->bh) {
        qemu_bh_delete(dbs->bh);
        dbs->bh = NULL;
    }
#endif
    if (!dbs->in_cancel) {
        /* Requests may complete while dma_aio_cancel is in progress.  In
         * this case, the AIOCB should not be released because it is still
         * referenced by dma_aio_cancel.  */
        qemu_aio_release(dbs);
    }
}

static void dma_bdrv_cb(void *opaque, int ret)
{
    DMAAIOCB *dbs = (DMAAIOCB *)opaque;
    target_phys_addr_t cur_addr, cur_len;
    void *mem;

    dbs->acb = NULL;
    dbs->sector_num += dbs->iov.size / 512;
    dma_bdrv_unmap(dbs);

    if (dbs->sg_cur_index == dbs->sg->nsg || ret < 0) {
        dma_complete(dbs, ret);
        return;
    }

    if (dbs->iov.size == 0 && dbs->sg_cur_index >= dbs->sg->nsg) {
        debug_printf("%s: SG list error cur=%d nsg=%d\n",
                     __FUNCTION__, dbs->sg_cur_index, dbs->sg->nsg);
        return;
    }

    while (dbs->sg_cur_index < dbs->sg->nsg) {
        cur_addr = dbs->sg->sg[dbs->sg_cur_index].base + dbs->sg_cur_byte;
        cur_len = dbs->sg->sg[dbs->sg_cur_index].len - dbs->sg_cur_byte;
        if (!cur_len) {
            debug_printf("%s: Attempting to map zero bytes ! idx=%d "
                         "cur_byte=%"PRId64" base=%"PRIx64" len=%"PRId64"\n",
                         __FUNCTION__, dbs->sg_cur_index, dbs->sg_cur_byte,
                         dbs->sg->sg[dbs->sg_cur_index].base,
                         dbs->sg->sg[dbs->sg_cur_index].len);
            break;
        }
        mem = vm_memory_map(cur_addr, &cur_len, !dbs->to_dev, 0);
        if (!mem) {
            debug_printf("%s: vm_memory_map failed. addr=%"PRIx64
                         " len=%"PRId64"\n", __FUNCTION__, cur_addr, cur_len);
            break;
        }
        iovec_add(&dbs->iov, mem, cur_len, cur_addr);
        dbs->sg_cur_byte += cur_len;
        if (dbs->sg_cur_byte == dbs->sg->sg[dbs->sg_cur_index].len) {
            dbs->sg_cur_byte = 0;
            ++dbs->sg_cur_index;
        }
    }

    if (dbs->iov.size == 0) {
        err(1, "%s: unexpected null iov size", __FUNCTION__);
    }

    dbs->acb = dbs->io_func(dbs->bs, dbs->sector_num, &dbs->iov,
                            dbs->iov.size / 512, dma_bdrv_cb, dbs);
    if (!dbs->acb) {
        dma_complete(dbs, -EIO);
    }
}

static void dma_aio_cancel(BlockDriverAIOCB *acb)
{
    DMAAIOCB *dbs = container_of(acb, DMAAIOCB, common);

    if (dbs->acb) {
        BlockDriverAIOCB *acb = dbs->acb;
        dbs->acb = NULL;
        dbs->in_cancel = true;
        bdrv_aio_cancel(acb);
        dbs->in_cancel = false;
    }
    dbs->common.cb = NULL;
    dma_complete(dbs, 0);
}

static AIOPool dma_aio_pool = {
    .aiocb_size         = sizeof(DMAAIOCB),
    .cancel             = dma_aio_cancel,
};

BlockDriverAIOCB *dma_bdrv_io(
    BlockDriverState *bs, QEMUSGList *sg, uint64_t sector_num,
    DMAIOFunc *io_func, BlockDriverCompletionFunc *cb,
    void *opaque, bool to_dev)
{
    DMAAIOCB *dbs = qemu_aio_get(&dma_aio_pool, bs, cb, opaque);

    dbs->acb = NULL;
    dbs->bs = bs;
    dbs->sg = sg;
    dbs->sector_num = sector_num;
    dbs->sg_cur_index = 0;
    dbs->sg_cur_byte = 0;
    dbs->to_dev = to_dev;
    dbs->io_func = io_func;
#if 0
    dbs->bh = NULL;
#endif
    qemu_iovec_init(&dbs->iov, sg->nsg);
    dma_bdrv_cb(dbs, 0);
    return &dbs->common;
}


BlockDriverAIOCB *dma_bdrv_read(BlockDriverState *bs,
                                QEMUSGList *sg, uint64_t sector,
                                void (*cb)(void *opaque, int ret), void *opaque)
{
    return dma_bdrv_io(bs, sg, sector, bdrv_aio_readv, cb, opaque, false);
}

BlockDriverAIOCB *dma_bdrv_write(BlockDriverState *bs,
                                 QEMUSGList *sg, uint64_t sector,
                                 void (*cb)(void *opaque, int ret), void *opaque)
{
    return dma_bdrv_io(bs, sg, sector, bdrv_aio_writev, cb, opaque, true);
}
