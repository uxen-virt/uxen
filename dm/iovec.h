/*
 * Copyright 2012-2015, Bromium, Inc.
 * Author: Christian Limpach <Christian.Limpach@gmail.com>
 * SPDX-License-Identifier: ISC
 */

#ifndef _IOVEC_H_
#define _IOVEC_H_

#include "os.h"

struct iovec {
    void *iov_base;
    size_t iov_len;
};
#define IOV_MAX 1024

typedef struct IOVector {
    struct iovec *iov;
    uint64_t *ioaddr;
    int niov;
    int nalloc;
    size_t size;
} IOVector;

void iovec_init(IOVector *qiov, int alloc_hint);
void iovec_init_external(IOVector *qiov, struct iovec *iov, int niov);
void iovec_add(IOVector *qiov, void *base, size_t len, uint64_t addr);
void iovec_destroy(IOVector *qiov);
void iovec_reset(IOVector *qiov);
size_t iovec_to_buffer(IOVector *qiov, void *buf, ssize_t offset, size_t count);
size_t iovec_from_buffer(IOVector *qiov, const void *buf, ssize_t offset,
                         size_t count);
size_t iov_to_buf(const struct iovec *iov, const unsigned int niov,
                  void *buf, ssize_t offset, size_t count);
size_t iov_from_buf(struct iovec *iov, unsigned int niov,
                    const void *buf, ssize_t offset, size_t size);
size_t iov_size(const struct iovec *iov, const unsigned int niov);
size_t iov_clear(struct iovec *iov, const unsigned int niov,
                 ssize_t offset, size_t count);
void iov_hexdump(const struct iovec *iov, const unsigned int niov,
                 FILE *fp, const char *prefix, size_t limit);

#endif	/* _IOVEC_H_ */
