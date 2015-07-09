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
    char *filename;
    int delete_on_close;
#endif
    int users;
    uint8_t *buffer;
    off_t offset;
    size_t buffered;
    size_t consumed;
    int writable;
    int eof;
    size_t buffer_max;
};

struct filebuf *filebuf_open(const char *fn, const char *mode);
int filebuf_set_readable(struct filebuf *fb);
int filebuf_flush(struct filebuf *fb);
int filebuf_read(struct filebuf *fb, void *buf, size_t size);
int filebuf_write(struct filebuf *fb, void *buf, size_t size);
void filebuf_close(struct filebuf *fb);
struct filebuf *filebuf_openref(struct filebuf *fb);
int filebuf_skip(struct filebuf *fb, size_t size);
off_t filebuf_tell(struct filebuf *fb);
off_t filebuf_seek(struct filebuf *fb, off_t offset, int whence);
#define FILEBUF_SEEK_SET 0
#define FILEBUF_SEEK_CUR 1
#define FILEBUF_SEEK_END 2
void filebuf_buffer_max(struct filebuf *fb, size_t new_buffer_max);
int filebuf_delete_on_close(struct filebuf *fb, int delete);

#endif  /* __FILEBUF_H_ */
