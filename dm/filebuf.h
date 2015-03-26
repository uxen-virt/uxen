/*
 * Copyright 2014-2015, Bromium, Inc.
 * Author: Jacob Gorm Hansen <jacobgorm@gmail.com>
 * SPDX-License-Identifier: ISC
 */

#ifndef _FILEBUF_H_
#define _FILEBUF_H_

struct filebuf {
#ifdef _WIN32
    HANDLE file;
#else
    int file;
#endif
    uint8_t *buffer;
    size_t buffered;
    size_t consumed;
    int writable;
    int eof;
};

struct filebuf *filebuf_open(const char *fn, const char *mode);
int filebuf_flush(struct filebuf *fb);
int filebuf_read(struct filebuf *fb, void *buf, size_t size);
int filebuf_write(struct filebuf *fb, void *buf, size_t size);
void filebuf_close(struct filebuf *fb);

#endif  /* __FILEBUF_H_ */
