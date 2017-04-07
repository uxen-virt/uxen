/* 
 *  block-vhd.c
 *  uxen
 *
 * Copyright 2012-2017, Bromium, Inc.
 * Author: Christian Limpach <Christian.Limpach@gmail.com>
 * SPDX-License-Identifier: ISC
 * 
 */

/*
 * Todo:
 * - cancel: interrupt in progress requests
 * - td_prep_{read,write}: on error, add bh to run cb with failure code
 * - aio read/write win32: handle case where there's no wait objects
 *   + qemu_add_wait_object failure needs to be propagated
 *   + td_prep_{read,write} should put tiocb on queue
 *   + try to re-issue from cb or add bh for re-issue
 * - aio flush: implement
 *   + queue incoming requests
 *   + put callback into a bh
 *   + schedule bh when in_progress goes to 0
 */
#include "config.h"

#include <err.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#if defined(_WIN32)
#include <intrin.h>
#include <malloc.h>
#endif

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "aio.h"
#include "bh.h"
#include "block.h"
#include "block-int.h"
#include "console.h"

#include <libvhd.h>
#include <mm_malloc.h>

#include <tapdisk.h>
#include <tapdisk-driver.h>
#include <tapdisk-log.h>

// #define DEBUG_DPRINTF
// #define DEBUG_APRINTF
// #define DEBUG_PPRINTF

#undef dprintf
#ifdef DEBUG_DPRINTF
#define dprintf(fmt, args...) debug_printf(fmt, ##args)
#else
#define dprintf(fmt, args...)
#endif
#ifdef DEBUG_APRINTF
#define aprintf(fmt, args...) debug_printf(fmt, ##args)
#else
#define aprintf(fmt, args...)
#endif
#ifdef DEBUG_PPRINTF
#define pprintf(fmt, args...) debug_printf(fmt, ##args)
#else
#define pprintf(fmt, args...)
#endif
#define eprintf(fmt, args...) error_printf(fmt, ##args)

// #define TRACK_TRUE_DATA
// #define VHD_TLOG
// #define VHD_NO_AIO

#define SECTOR_SHIFT 9

typedef struct VhdState {
#ifdef VHD_NO_AIO
    vhd_context_t ctx;
#else
    td_driver_t td_driver;
    BlockDriverState *parent_bs;
    int has_parent;
#endif
    int in_progress;
} VhdState;

typedef struct VhdAIOCB {
    BlockDriverAIOCB common;
    BH *bh;
    int ret;
    int nsecs_remaining;
    int cancelled;
} VhdAIOCB;

#ifndef VHD_NO_AIO
static void bdrv_vhd_aio_cancel(BlockDriverAIOCB *_acb);
#endif

#ifdef TRACK_TRUE_DATA
static char **true_data;
#endif

struct libvhd_stub_handle {
    BlockDriverState *hd;
    off64_t pos;
    off64_t size;
};

static struct libvhd_stub_handle *h = NULL;
static int nrh = 0;
static int libvhd_stub_setup = 0;

static int
bad_handle(int fd)
{
    return fd >= nrh || h[fd].hd == NULL;
}

static int
libvhd_open_stub(const char *pathname, int flags, ...)
{
    int fd, ret;
    int bdrv_flags = BDRV_O_CACHE_WB;

    if (flags & O_CREAT) {
        ret = bdrv_create(pathname, 0, 0);
        if (ret)
            return ret;
    }

    bdrv_flags &= ~BDRV_O_RDWR;
    if (flags & (O_WRONLY | O_RDWR))
	bdrv_flags |= BDRV_O_RDWR;

    for (fd = 0; fd < nrh; fd++)
	if (h[fd].hd == NULL)
	    break;

    if (fd == nrh) {
	struct libvhd_stub_handle *nh = h;
	int nnrh = 1 + nrh * 2;
	nh = realloc(h, nnrh * sizeof(struct libvhd_stub_handle));
	if (nh == NULL) {
	    error_printf("Could not realloc BlockDriverState array\n");
	    return -1;
	}
	h = nh;
	while (nrh < nnrh) {
	    h[nrh].hd = NULL;
	    nrh++;
	}
    }

    ret = bdrv_file_open(&h[fd].hd, pathname, bdrv_flags);
    if (ret < 0) {
	error_printf("bdrv_file_open %s failed\n", pathname);
	h[fd].hd = NULL;
	errno = -ret;
	return -1;
    }
    h[fd].pos = 0;
    h[fd].size = (off64_t)h[fd].hd->total_sectors << SECTOR_SHIFT;

    return fd;
}

static int
libvhd_close_stub(int fd)
{
    if (bad_handle(fd)) {
	errno = EBADF;
	return -1;
    }
    bdrv_delete(h[fd].hd);
    h[fd].hd = NULL;
    return 0;
}

static read_return_t
libvhd_read_stub(int fd, void *buf, read_write_size_t count)
{
    int ret;

    if (bad_handle(fd)) {
	errno = EBADF;
	return -1;
    }
    if (count & ((1 << SECTOR_SHIFT) - 1)) {
	eprintf("libvhd_read_stub count %"PRIx_rw_size" not multiple of "
		"sector size\n", count);
	errno = EINVAL;
	return -1;
    }
    if ((h[fd].pos + count) > h[fd].size) {
	eprintf("libvhd_read_stub read past end\n");
	errno = EINVAL;
	return -1;
    }
    ret = bdrv_read(h[fd].hd, h[fd].pos >> SECTOR_SHIFT, buf,
		    count >> SECTOR_SHIFT);
    if (ret) {
	eprintf("libvhd_read_stub failed %"PRIx_rw_size"@%"PRIx64"\n", count,
		h[fd].pos);
	errno = EIO;
	return -1;
    }

    h[fd].pos += count;
    return count;
}

static write_return_t
libvhd_write_stub(int fd, const void *buf, read_write_size_t count)
{
    int ret;

    if (bad_handle(fd)) {
	errno = EBADF;
	return -1;
    }
    if (count & ((1 << SECTOR_SHIFT) - 1)) {
	eprintf("libvhd_write_stub count %"PRIx_rw_size" not multiple of "
		"sector size\n", count);
	errno = EINVAL;
	return -1;
    }
    if (h[fd].pos > h[fd].size) {
	static char *zbuf = NULL;
	static int zbufsize = 4 * 4096;
	int zcount;
	if (zbuf == NULL) {
	    zbuf = _mm_malloc(zbufsize, 4096);
	    if (zbuf == NULL) {
		errno = EINVAL;
		return -1;
	    }
	    memset(zbuf, 0, zbufsize);
	}
	while (h[fd].pos > h[fd].size) {
	    zcount = h[fd].pos - h[fd].size;
	    if (zcount > zbufsize)
		zcount = zbufsize;
	    ret = bdrv_write(h[fd].hd, h[fd].size >> SECTOR_SHIFT,
			     (void *)zbuf, zcount >> SECTOR_SHIFT);
	    if (ret) {
		eprintf("libvhd_write_stub extend failed %x@%"PRIx64" -> %d\n",
			zcount, h[fd].pos, ret);
		errno = EIO;
		return -1;
	    }
	    h[fd].size += zcount;
	}
    }
    ret = bdrv_write(h[fd].hd, h[fd].pos >> SECTOR_SHIFT, buf,
		     count >> SECTOR_SHIFT);
    if (ret) {
	eprintf("libvhd_write_stub failed %"PRIx_rw_size"@%"PRIx64" -> %d\n",
		count, h[fd].pos, ret);
	errno = EIO;
	return -1;
    }

    h[fd].pos += count;
    if (h[fd].pos > h[fd].size)
	h[fd].size = h[fd].pos;
    return count;
}

static off64_t
libvhd_lseek64_stub(int fd, off64_t offset, int whence)
{

    if (bad_handle(fd)) {
	errno = EBADF;
	return -1;
    }

    switch (whence) {
    case SEEK_SET:
	h[fd].pos = offset;
	break;
    case SEEK_CUR:
	h[fd].pos += offset;
	break;
    case SEEK_END:
	h[fd].pos = h[fd].size + offset;
	break;
    default:
	errno = EINVAL;
	return -1;
	break;
    }
    return h[fd].pos;
}

static int
libvhd_fsync_stub(int fd)
{
    int ret;

    if (bad_handle(fd)) {
	errno = EBADF;
	return -1;
    }

    ret = bdrv_flush(h[fd].hd);
    if (ret) {
	errno = -ret;
	ret = -1;
    }
    return ret;
}

#ifndef VHD_NO_AIO
typedef void (*libvhd_aio_stub_cb)(void *, int);

static BlockDriverAIOCB *
libvhd_aio_read_stub(int fd, uint8_t *buf, off64_t offset, size_t bytes,
		      libvhd_aio_stub_cb cb, void *arg)
{
    BlockDriverAIOCB *aiocb;

    if (bad_handle(fd)) {
	errno = EBADF;
	return NULL;
    }
    aiocb = bdrv_aio_read(h[fd].hd, offset >> SECTOR_SHIFT, buf,
			   bytes >> SECTOR_SHIFT, cb, arg);
    dprintf("issued aio read for %"PRIxS"@%"PRIx64" buf %p => %p\n",
	    bytes >> SECTOR_SHIFT, offset >> SECTOR_SHIFT, buf, aiocb);
    return aiocb;
}

static BlockDriverAIOCB *
libvhd_aio_write_stub(int fd, const uint8_t *buf, off64_t offset, size_t bytes,
		      libvhd_aio_stub_cb cb, void *arg)
{
    BlockDriverAIOCB *aiocb;

    if (bad_handle(fd)) {
	errno = EBADF;
	return NULL;
    }
    aiocb = bdrv_aio_write(h[fd].hd, offset >> SECTOR_SHIFT, buf,
			   bytes >> SECTOR_SHIFT, cb, arg);
    dprintf("issued aio write for %"PRIxS"@%"PRIx64" buf %p => %p\n",
	    bytes >> SECTOR_SHIFT, offset >> SECTOR_SHIFT, buf, aiocb);
    return aiocb;
}
#endif

static int bdrv_vhd_probe(const uint8_t *buf, int buf_size,
			  const char *filename)
{
    eprintf("bdrv_vhd_probe %s\n", filename);

    return -100;
}

#ifdef VHD_NO_AIO
static int bdrv_vhd_open(BlockDriverState *bs, const char *filename, int flags)
{
    VhdState *s = bs->opaque;
    int ret;

    dprintf("bdrv_vhd_open %s\n", filename);

    if (!libvhd_stub_setup) {
	vhd_set_fops(libvhd_open_stub, libvhd_close_stub,
		     libvhd_read_stub, libvhd_write_stub, libvhd_lseek64_stub);
	libvhd_stub_setup = 1;
#ifdef TRACK_TRUE_DATA
	true_data = calloc(1, 0x1000000 * sizeof(char *));
	if (true_data == NULL)
	    return -1;
#endif
    }

    if (!strncmp(filename, "vhd:", 4))
	filename = &filename[4];

    ret = vhd_open(&s->ctx, filename, VHD_OPEN_RDWR);
    if (ret < 0)
	return ret;

    bs->total_sectors = s->ctx.footer.curr_size >> SECTOR_SHIFT;

    return 0;
}

static int bdrv_vhd_read(BlockDriverState *bs, int64_t sector_num,
                    uint8_t *buf, int nb_sectors)
{
    VhdState *s = bs->opaque;
    int ret;

    ret = vhd_io_read(&s->ctx, (char *)buf, sector_num, nb_sectors);
#ifdef TRACK_TRUE_DATA
    if (ret == 0) {
	int i;
	for (i = sector_num; i < sector_num + nb_sectors; i++) {
	    int failed;
	    if (true_data[i] == NULL) {
		int j;
		failed = 0;
		for (j = 0; j < (1 << SECTOR_SHIFT); j++)
		    if (buf[((i - sector_num) << SECTOR_SHIFT) + j]) {
			failed = 1;
			break;
		    }
	    } else {
		failed = memcmp(true_data[i],
				&buf[(i - sector_num) << SECTOR_SHIFT],
				1 << SECTOR_SHIFT);
	    }
	    if (failed) {
		eprintf("vhd read verify failed for sector %"PRIx64" td %p\n",
			sector_num, true_data[i]);
		asm ("int3");
	    }
	}
    }
#endif
    dprintf("bdrv_vhd_read %x@%"PRIx64" => %d\n", nb_sectors, sector_num, ret);
    return ret;
}

static int bdrv_vhd_write(BlockDriverState *bs, int64_t sector_num,
                     const uint8_t *buf, int nb_sectors)
{
    VhdState *s = bs->opaque;
    int ret;

#ifdef TRACK_TRUE_DATA
    {
	int i;
	for (i = sector_num; i < sector_num + nb_sectors; i++) {
	    if (true_data[i] == NULL) {
		true_data[i] = malloc(1 << SECTOR_SHIFT);
		if (true_data[i] == NULL)
		    return -errno;
	    }
	    memcpy(true_data[i], &buf[(i - sector_num) << SECTOR_SHIFT],
		   1 << SECTOR_SHIFT);
	}
    }
#endif
    ret = vhd_io_write(&s->ctx, (const char *)buf, sector_num, nb_sectors);
    dprintf("bdrv_vhd_write %x@%"PRIx64" => %d\n", nb_sectors, sector_num, ret);
    return ret;
}
#endif

static int
bdrv_vhd_create(const char *filename, int64_t size, int flags)
{

    if (!strncmp(filename, "vhd:", 4))
	filename = &filename[4];

    return vhd_create(filename, size, HD_TYPE_DYNAMIC, 0, 0);
}

#ifdef VHD_NO_AIO
static void bdrv_vhd_close(BlockDriverState *bs)
{
    VhdState *s = bs->opaque;

    dprintf("bdrv_vhd_close\n");

    vhd_close(&s->ctx);
}
#endif

static int bdrv_vhd_is_allocated(BlockDriverState *bs, int64_t sector_num,
			    int nb_sectors, int *pnum)
{
    dprintf("bdrv_vhd_is_allocated\n");

    return 1;
}

#ifdef VHD_NO_AIO
static int bdrv_vhd_flush(BlockDriverState *bs)
{
    VhdState *s = bs->opaque;

    dprintf("bdrv_vhd_flush\n");

    return libvhd_fsync_stub(s->ctx.fd);
}
#endif

#ifndef VHD_NO_AIO
static int bdrv_vhd_aio_open(BlockDriverState *bs, const char *filename,
			     int flags)
{
    VhdState *s = bs->opaque;
    td_disk_id_t parent_id;
    int ret;

    dprintf("bdrv_vhd_aio_open %s\n", filename);

    if (!libvhd_stub_setup) {
	vhd_set_fops(libvhd_open_stub, libvhd_close_stub,
		     libvhd_read_stub, libvhd_write_stub, libvhd_lseek64_stub);
	libvhd_stub_setup = 1;
#ifdef TRACK_TRUE_DATA
	true_data = calloc(1, 0x1000000 * sizeof(char *));
	if (true_data == NULL)
	    return -1;
#endif
#ifdef VHD_TLOG
	open_tlog("tapdisk.%d.log", (64 << 10), TLOG_DBG, 1);
	atexit(tlog_flush);
#endif
    }

    if (!strncmp(filename, "vhd:", 4))
	filename = &filename[4];

    ret = _vhd_open(&s->td_driver, filename,
		    (flags & BDRV_O_RDWR) ? 0 : TD_OPEN_RDONLY);
    if (ret < 0)
	return ret;

    bs->total_sectors = s->td_driver.info.size;

    s->in_progress = 0;

    ret = vhd_get_parent_id(&s->td_driver, &parent_id);
    if (ret == 0) {
	char *parent;

	if (parent_id.drivertype == DISK_TYPE_VHD) {
	    ret = asprintf(&parent, "vhd:%s", parent_id.name);
	    if (ret == -1) {
		_vhd_close(&s->td_driver);
		return -ENOMEM;
	    }
	} else
	    parent = parent_id.name;

	flags &= ~BDRV_O_RDWR;
        s->parent_bs = bdrv_new("");
	ret = bdrv_open(s->parent_bs, parent, flags);
	if (ret < 0)
	    _vhd_close(&s->td_driver);
        else
            s->has_parent = 1;

	if (parent_id.drivertype == DISK_TYPE_VHD)
	    free(parent);
    }

    return ret;
}

static void bdrv_vhd_aio_close(BlockDriverState *bs)
{
    VhdState *s = bs->opaque;

    dprintf("bdrv_vhd_aio_close\n");

    _vhd_close(&s->td_driver);
    if (s->has_parent)
	bdrv_delete(s->parent_bs);
#ifdef VHD_TLOG
    close_tlog();
#endif
}

static int bdrv_vhd_flush(BlockDriverState *bs)
{
    VhdState *s = bs->opaque;

    dprintf("bdrv_vhd_flush\n");

#ifdef VHD_TLOG
    tlog_flush();
#endif

    aio_wait_start();
    aio_poll();
    while (s->in_progress)
	aio_wait();
    aio_wait_end();

    return libvhd_fsync_stub(vhd_fd(&s->td_driver));
}

/* XXX per fd */
struct queued_treq {
    STAILQ_ENTRY(queued_treq) next;
    td_request_t treq;
};
STAILQ_HEAD(, queued_treq) unused_queued_treqs =
    STAILQ_HEAD_INITIALIZER(unused_queued_treqs);
STAILQ_HEAD(queued_treq_stailq, queued_treq) queued_treqs =
    STAILQ_HEAD_INITIALIZER(queued_treqs);

static int bdrv_vhd_aio_queue_blocked(td_request_t *treq)
{
    struct queued_treq *qt;
#ifdef DEBUG_APRINTF
    VhdAIOCB *acb = (VhdAIOCB *)treq->cb_data;
#endif

    aprintf("bdrv_vhd_aio_queue_blocked %p: %x of %x\n", acb, treq->secs,
	    acb->nsecs_remaining);

    if (!STAILQ_EMPTY(&unused_queued_treqs)) {
	qt = STAILQ_FIRST(&unused_queued_treqs);
	STAILQ_REMOVE_HEAD(&unused_queued_treqs, next);
    } else {
	qt = malloc(sizeof(struct queued_treq));
	if (qt == NULL)
	    return -EIO;
	memset(qt, 0, sizeof(struct queued_treq));
    }

    qt->treq = *treq;

    STAILQ_INSERT_TAIL(&queued_treqs, qt, next);

    return -EBUSY;
}

static void bdrv_vhd_aio_queue_reissue(void)
{
    struct queued_treq *qt;
    struct queued_treq_stailq q;

    if (STAILQ_EMPTY(&queued_treqs))
	return;

    q = queued_treqs;
    STAILQ_INIT(&queued_treqs);

    while (!STAILQ_EMPTY(&q)) {
	td_driver_t *driver;
#ifdef DEBUG_APRINTF
	VhdAIOCB *acb;
#endif

	qt = STAILQ_FIRST(&q);
	STAILQ_REMOVE_HEAD(&q, next);

	driver = qt->treq.private;

#ifdef DEBUG_APRINTF
	acb = (VhdAIOCB *)qt->treq.cb_data;
#endif
	aprintf("bdrv_vhd_aio_queue_reissue %p: %x of %x\n", acb,
		qt->treq.secs, acb->nsecs_remaining);

	switch (qt->treq.op) {
	case TD_OP_READ:
	    vhd_queue_read(driver, qt->treq);
	    break;
	case TD_OP_WRITE:
	    vhd_queue_write(driver, qt->treq);
	    break;
	}

        free(qt);
    }
}

static void bdrv_vhd_aio_cb(td_request_t treq, int res)
{
    VhdAIOCB *acb = (VhdAIOCB *)treq.cb_data;

    if (res && res != -EBUSY)
	eprintf("bdrv_vhd_aio_cb %p failed: %x of %x: res %d\n", acb,
		treq.secs, acb->nsecs_remaining, -res);

    dprintf("bdrv_vhd_aio_cb %p: %x of %x: res %d\n", acb, treq.secs,
	    acb->nsecs_remaining, -res);
    if (acb->cancelled)
	res = 0;
    if (res == 0)
	acb->nsecs_remaining -= treq.secs;
    if (res == -EBUSY)
	res = bdrv_vhd_aio_queue_blocked(&treq);

    if (acb->nsecs_remaining == 0 || (res && res != -EBUSY)) {
	((VhdState *)acb->common.bs->opaque)->in_progress--;
	pprintf("acb %p returned (%d outstanding)\n", acb,
		((VhdState *)acb->common.bs->opaque)->in_progress);
	if (acb->cancelled == 0)
	    acb->common.cb(acb->common.opaque, -res);
	aio_release(acb);
    }

    if (!STAILQ_EMPTY(&queued_treqs) && res != -EBUSY)
	bdrv_vhd_aio_queue_reissue();
}

static AIOPool vhd_aio_pool = {
    .aiocb_size = sizeof(VhdAIOCB),
    .cancel = bdrv_vhd_aio_cancel,
};

static VhdAIOCB *
bdrv_vhd_aio_setup(BlockDriverState *bs, td_driver_t *driver,
		   td_request_t *treq, int64_t sector_num, uint8_t *buf,
		   int nb_sectors, BlockDriverCompletionFunc *cb, void *opaque)
{
    VhdAIOCB *acb;
    static int id = 0;

    acb = aio_get(&vhd_aio_pool, bs, cb, opaque);
    if (acb == NULL)
	return NULL;
    memset(treq, 0, sizeof(*treq));
    treq->id = id++;
    treq->sidx = 0;
    treq->blocked = 0;
    treq->buf = (char *)buf;
    treq->sec = sector_num;
    treq->secs = nb_sectors;
    treq->image = NULL/* image */;
    treq->cb = bdrv_vhd_aio_cb;
    treq->cb_data = acb;
    treq->private = driver;

    acb->nsecs_remaining = nb_sectors;

    return acb;
}

static BlockDriverAIOCB *
bdrv_vhd_aio_read(BlockDriverState *bs,
		  int64_t sector_num, uint8_t *buf, int nb_sectors,
		  BlockDriverCompletionFunc *cb, void *opaque)
{
    VhdState *s = bs->opaque;
    VhdAIOCB *acb;
    td_request_t treq;

    acb = bdrv_vhd_aio_setup(bs, &s->td_driver, &treq, sector_num, buf,
			     nb_sectors, cb, opaque);
    if (acb == NULL)
	goto out;
    s->in_progress++;
    dprintf("bdrv_vhd_aio_read %x@%"PRIx64" buf %p => %p\n", nb_sectors,
	    sector_num, buf, acb);
    treq.op = TD_OP_READ;
    vhd_queue_read(&s->td_driver, treq);
    pprintf("read acb %p submitted (%d outstanding)\n", acb,
	    ((VhdState *)acb->common.bs->opaque)->in_progress);
  out:
    return (BlockDriverAIOCB *)acb;
}

static BlockDriverAIOCB *bdrv_vhd_aio_write(BlockDriverState *bs,
        int64_t sector_num, const uint8_t *buf, int nb_sectors,
        BlockDriverCompletionFunc *cb, void *opaque)
{
    VhdState *s = bs->opaque;
    VhdAIOCB *acb;
    td_request_t treq;

    acb = bdrv_vhd_aio_setup(bs, &s->td_driver, &treq, sector_num,
			     (uint8_t *)buf, nb_sectors, cb, opaque);
    if (acb == NULL)
	goto out;
    s->in_progress++;
    dprintf("bdrv_vhd_aio_write %x@%"PRIx64" buf %p => %p\n", nb_sectors,
	    sector_num, buf, acb);
    treq.op = TD_OP_WRITE;
    vhd_queue_write(&s->td_driver, treq);
    pprintf("write acb %p submitted (%d outstanding)\n", acb,
	    ((VhdState *)acb->common.bs->opaque)->in_progress);
  out:
    return (BlockDriverAIOCB *)acb;
}

static void bdrv_vhd_aio_cancel(BlockDriverAIOCB *_acb)
{
    VhdAIOCB *acb = (VhdAIOCB *)_acb;

    eprintf("bdrv_vhd_aio_cancel %p\n", acb);
    acb->cancelled = 1;
    bdrv_vhd_flush(acb->common.bs);
}

#include "tapdisk-interface.h"

static void
td_forward_request_cb(void *opaque, int ret)
{
    td_request_t *treq = (td_request_t *)opaque;

    td_complete_request(*treq, ret);
    free(treq);
}

void
td_forward_request(td_request_t treq)
{
    VhdAIOCB *acb = (VhdAIOCB *)treq.cb_data;
    VhdState *s = (VhdState *)acb->common.bs->opaque;
    td_request_t *ptreq;

    if (s->has_parent == 0) {
	memset(treq.buf, 0, treq.secs << SECTOR_SHIFT);
	td_complete_request(treq, 0);
    } else {
	BlockDriverAIOCB *aiocb;

	if (treq.op != TD_OP_READ) {
	    eprintf("td_forward_request: non-read request\n");
	    td_complete_request(treq, -EINVAL);
	    return;
	}
	ptreq = malloc(sizeof(td_request_t));
	if (ptreq == NULL) {
	    eprintf("td_forward_request: out of memory\n");
	    td_complete_request(treq, -ENOMEM);
	    return;
	}
	*ptreq = treq;
	aiocb = bdrv_aio_read(s->parent_bs, treq.sec,
			      (unsigned char *)treq.buf, treq.secs,
			      td_forward_request_cb, ptreq);
	if (aiocb == NULL) {
	    eprintf("td_forward_request: bdrv_aio_read failed\n");
	    td_complete_request(treq, -ENOMEM);
	    return;
	}
    }
}

void
td_complete_request(td_request_t treq, int res)
{
    ((td_callback_t)treq.cb)(treq, res);
}

void
td_queue_tiocb(td_driver_t *driver, struct tiocb *tiocb)
{
}

static void
td_tiocb_complete_cb(void *opaque, int ret)
{
    struct tiocb *tiocb = opaque;

    tiocb->cb(tiocb->arg, tiocb, ret);
}

void
td_prep_read(struct tiocb *tiocb, int fd, char *buf, size_t bytes,
	     long long offset, td_queue_callback_t cb, void *arg)
{
 
    // asm("int3");
    tiocb->cb = cb;
    tiocb->arg = arg;

    tiocb->opaque = libvhd_aio_read_stub(fd, (unsigned char *)buf, offset,
					 bytes, td_tiocb_complete_cb, tiocb);
    if (tiocb->opaque == NULL) {
	/* Add bh to run cb with failure code */
	eprintf("td_prep_read: libvhd_aio_read_stub failed\n");
    }
}

void
td_prep_write(struct tiocb *tiocb, int fd, char *buf, size_t bytes,
	      long long offset, td_queue_callback_t cb, void *arg)
{

    // asm("int3");
    tiocb->cb = cb;
    tiocb->arg = arg;

    tiocb->opaque = libvhd_aio_write_stub(fd, (unsigned char *)buf, offset,
					  bytes, td_tiocb_complete_cb, tiocb);
    if (tiocb->opaque == NULL) {
	/* Add bh to run cb with failure code */
	eprintf("td_prep_write: libvhd_aio_write_stub failed\n");
    }
}
#endif

#ifdef VHD_NO_AIO
BlockDriver bdrv_vhd = {
    "vhd",
    sizeof(VhdState),
    bdrv_vhd_probe,
    bdrv_vhd_open,
    bdrv_vhd_read,
    bdrv_vhd_write,
    bdrv_vhd_close,
    bdrv_vhd_create,
    NULL,
    bdrv_vhd_flush,
    bdrv_vhd_is_allocated,
    .protocol_name = "vhd",
};
#else
BlockDriver bdrv_vhd = {
    "vhd",
    sizeof(VhdState),
    bdrv_vhd_probe,
    bdrv_vhd_aio_open,
    NULL,
    NULL,
    bdrv_vhd_aio_close,
    bdrv_vhd_create,
    NULL,
    bdrv_vhd_flush,
    bdrv_vhd_is_allocated,

    .bdrv_aio_read = bdrv_vhd_aio_read,
    .bdrv_aio_write = bdrv_vhd_aio_write,

    .protocol_name = "vhd",
};
#endif
