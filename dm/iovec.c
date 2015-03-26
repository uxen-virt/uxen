/*
 * Copyright 2012-2015, Bromium, Inc.
 * Author: Christian Limpach <Christian.Limpach@gmail.com>
 * SPDX-License-Identifier: ISC
 */

#include "config.h"

#include <err.h>
#include <stdint.h>
#include <string.h>

#include "iovec.h"

#define SANE_NALLOC_COST (1<<30)
void iovec_init(IOVector *qiov, int alloc_hint)
{
    if (alloc_hint < 0 || alloc_hint > SANE_NALLOC_COST/sizeof(struct iovec))
        err(1, "Insane alloc_hint=0x%x in iovec_init", alloc_hint);
    qiov->iov = malloc(alloc_hint * sizeof(struct iovec));
    qiov->ioaddr = malloc(alloc_hint * sizeof(uint64_t));
    if (!qiov->iov || !qiov->ioaddr)
        err(1, "malloc failure in iovec_init");
    qiov->niov = 0;
    qiov->nalloc = alloc_hint;
    qiov->size = 0;
}

void iovec_init_external(IOVector *qiov, struct iovec *iov, int niov)
{
    int i;

    qiov->iov = iov;
    qiov->ioaddr = NULL;	/* XXX */
    qiov->niov = niov;
    qiov->nalloc = -1;
    qiov->size = 0;
    for (i = 0; i < niov; i++)
        qiov->size += iov[i].iov_len;
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
void iovec_add(IOVector *qiov, void *base, size_t len, uint64_t addr)
{
    if (len > MAX_IOVEC_SIZE || qiov->size > MAX_IOVEC_SIZE ||
        len + qiov->size > MAX_IOVEC_SIZE)
        err(1, "Cowardly refusing to create an insanely large iovec, len=0x%"PRIx64" qiov->size=0x%"PRIx64, (uint64_t)len, (uint64_t)qiov->size);

    if (qiov->niov == qiov->nalloc) {
        if (qiov->nalloc >= SANE_NALLOC_COST/sizeof(struct iovec))
            err(1, "Insane qiov->nalloc=0x%x in iovec_add", qiov->niov);
        qiov->nalloc = 2 * qiov->nalloc + 1;
        qiov->iov = realloc(qiov->iov, qiov->nalloc * sizeof(struct iovec));
        if (!qiov->iov)
            err(1, "Realloc failure in iovec_add");
        if (qiov->ioaddr) {
	        qiov->ioaddr = realloc(qiov->ioaddr,
                qiov->nalloc * sizeof(uint64_t));
            if (!qiov->ioaddr)
                err(1, "Realloc failure in iovec_add");
        }
    }
    qiov->iov[qiov->niov].iov_base = base;
    qiov->iov[qiov->niov].iov_len = len;
    if (qiov->ioaddr)
	qiov->ioaddr[qiov->niov] = addr;
    qiov->size += len;
    ++qiov->niov;
}

void iovec_destroy(IOVector *qiov)
{
    free(qiov->iov);
    if (qiov->ioaddr)
	free(qiov->ioaddr);
}

void iovec_reset(IOVector *qiov)
{
    qiov->niov = 0;
    qiov->size = 0;
    if (qiov->ioaddr)
        memset(qiov->ioaddr, 0, qiov->nalloc * sizeof(uint64_t));
}

size_t iov_to_buf(const struct iovec *iov, const unsigned int niov,
                  void *buf, ssize_t offset, size_t count)
{
    uint8_t *p = (uint8_t *)buf;
    int i;

    for (i = 0; i < niov && count; i++) {
        if (offset < iov[i].iov_len) {
            size_t s;
            s = count;
            if (s > iov[i].iov_len - offset) 
                s = iov[i].iov_len - offset;
            memcpy(p, iov[i].iov_base + offset, s);
            p += s;
            count -= s;
        }
        if (offset) {
            offset -= iov[i].iov_len;
            if (offset < 0)
                offset = 0;
        }
    }

    return p - (uint8_t *)buf;
}

size_t iovec_to_buffer(IOVector *qiov, void *buf, ssize_t offset, size_t count)
{

    return iov_to_buf(qiov->iov, qiov->niov, buf, offset, count);
}

size_t iov_from_buf(struct iovec *iov, const unsigned int niov,
                    const void *buf, ssize_t offset, size_t count)
{
    const uint8_t *p = (const uint8_t *)buf;
    int i;

    for (i = 0; i < niov && count; i++) {
        if (offset < iov[i].iov_len) {
            size_t s;
            s = count;
            if (s > iov[i].iov_len - offset)
                s = iov[i].iov_len - offset;
            memcpy(iov[i].iov_base + offset, p, s);
            p += s;
            count -= s;
        }
        if (offset) {
            offset -= iov[i].iov_len;
            if (offset < 0)
                offset = 0;
        }
    }

    return p - (const uint8_t *)buf;
}

size_t iovec_from_buffer(IOVector *qiov, const void *buf, ssize_t offset,
                         size_t count)
{

    return iov_from_buf(qiov->iov, qiov->niov, buf, offset, count);
}

size_t iov_size(const struct iovec *iov, const unsigned int niov)
{
    size_t len = 0;
    int i;

    for (i = 0; i < niov; i++)
        len += iov[i].iov_len;

    return len;
}

size_t iov_clear(struct iovec *iov, const unsigned int niov,
                 ssize_t offset, size_t count)
{
    size_t done = 0;
    int i;

    for (i = 0; i < niov && count; i++) {
        if (offset < iov[i].iov_len) {
            size_t s;
            s = count;
            if (s > iov[i].iov_len - offset)
                s = iov[i].iov_len - offset;
            memset(iov[i].iov_base + offset, 0, s);
            done += s;
            count -= s;
        }
        if (offset) {
            offset -= iov[i].iov_len;
            if (offset < 0)
                offset = 0;
        }
    }

    return done;
}

void iov_hexdump(const struct iovec *iov, const unsigned int niov,
                 FILE *fp, const char *prefix, size_t limit)
{
    unsigned int i, j, p;
    uint8_t *c;

    p = 0;
    for (i = 0; i < niov && p < limit; i++) {
        c = iov[i].iov_base;
        for (j = 0; j < iov[i].iov_len && p < limit; j++) {
            if ((p % 16) == 0)
                fprintf(fp, "%s: %04x:", prefix, p);
            if ((p % 4) == 0)
                fprintf(fp, " ");
            fprintf(fp, " %02x", c[j]);
            if ((p % 16) == 15)
                fprintf(fp, "\n");
            p++;
        }
    }
    if ((p % 16) != 0)
        fprintf(fp, "\n");
}
