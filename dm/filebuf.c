/*
 * Copyright 2014-2015, Bromium, Inc.
 * Author: Jacob Gorm Hansen <jacobgorm@gmail.com>
 * SPDX-License-Identifier: ISC
 */

#include "config.h"
#include "filebuf.h"

#include <errno.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

const size_t buffer_max = 1 << 20;

struct filebuf *
filebuf_open(const char *fn, const char *mode)
{
    struct filebuf *fb;
    int no_buffering = 0;
#ifdef _WIN32
    int sequential = 0;
    int write_through = 0;
#endif  /* _WIN32 */

    fb = calloc(1, sizeof(struct filebuf));
    if (!fb)
        return NULL;

    fb->buffer = page_align_alloc(buffer_max);
    if (!fb->buffer) {
        free(fb);
        return NULL;
    }

    while (*mode) {
        switch (*mode) {
            case 'n':
                no_buffering = 1;
                break;
#ifdef _WIN32
            case 's':
                sequential = 1;
                break;
            case 't':
                write_through = 1;
                break;
#endif  /* _WIN32 */
            case 'w':
                fb->writable = 1;
                break;
            default:
                break;
        }
        mode++;
    }

#ifdef _WIN32
    fb->file = CreateFile(fn,
          (fb->writable ? GENERIC_WRITE : 0) | GENERIC_READ,
          fb->writable ? 0 :
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
          NULL,
          fb->writable ? CREATE_ALWAYS : OPEN_EXISTING,
          FILE_ATTRIBUTE_NORMAL |
          (sequential ? FILE_FLAG_SEQUENTIAL_SCAN : 0) |
          (write_through ? FILE_FLAG_WRITE_THROUGH : 0) |
          (no_buffering ? FILE_FLAG_NO_BUFFERING : 0),
          NULL);
#else  /* _WIN32 */
    fb->file = open(fn, fb->writable ? O_RDWR | O_CREAT : O_RDONLY, 0644);
#endif  /* _WIN32 */

#ifdef _WIN32
    if (fb->file == INVALID_HANDLE_VALUE)
#else  /* _WIN32 */
    if (fb->file < 0)
#endif  /* _WIN32 */
    {
        align_free(fb->buffer);
        free(fb);
        fb = NULL;
    }
#ifdef __APPLE__
    if (no_buffering)
        fcntl(fb->file, F_NOCACHE, 1);
#endif  /* __APPLE__ */
    return fb;
}

int
filebuf_flush(struct filebuf *fb)
{
#ifdef _WIN32
    DWORD wrote;

    if (!WriteFile(fb->file, fb->buffer, fb->buffered, &wrote, NULL)) {
        Wwarn("%s: WriteFile failed", __FUNCTION__);
        return -1;
    }
#else  /* _WIN32 */
    ssize_t ret;

    do {
        ret = write(fb->file, fb->buffer, fb->buffered);
    } while (ret < 0 && errno == EINTR);
    if (ret < 0) {
        warn("%s: write failed", __FUNCTION__);
        return -1;
    }
#endif  /* _WIN32 */
    fb->buffered = 0;
    return 0;
}

void
filebuf_close(struct filebuf *fb)
{

    if (fb->writable)
        filebuf_flush(fb);
#ifdef _WIN32
    CloseHandle(fb->file);
#else  /* _WIN32 */
    close(fb->file);
#endif  /* _WIN32 */
    align_free(fb->buffer);
    free(fb);
}

int
filebuf_write(struct filebuf *fb, void *buf, size_t size)
{
    uint8_t *b = buf;

    while (size) {
        size_t n = size;

        if (n > buffer_max - fb->buffered)
            n = buffer_max - fb->buffered;
        memcpy(fb->buffer + fb->buffered, b, n);
        fb->buffered += n;
        b += n;
        size -= n;

        if (fb->buffered == buffer_max) {
            if (filebuf_flush(fb) < 0)
                return -1;
        }
    }
    return b - (uint8_t *) buf;
}

int
filebuf_read(struct filebuf *fb, void *buf, size_t size)
{
    uint8_t *b = buf;

    while (size) {
        size_t n = size;

        if (n > fb->buffered - fb->consumed)
            n = fb->buffered - fb->consumed;
        memcpy(b, fb->buffer + fb->consumed, n);
        fb->consumed += n;
        b += n;
        size -= n;

        if (fb->consumed == fb->buffered && fb->eof)
            return b - (uint8_t *)buf;

        if (fb->consumed == fb->buffered) {
#ifdef _WIN32
            DWORD ret;

            if (!ReadFile(fb->file, fb->buffer, (DWORD)buffer_max, &ret,
                          NULL)) {
                Wwarn("%s: ReadFile failed", __FUNCTION__);
                return -1;
            }
#else
            ssize_t ret;

            do {
                ret = read(fb->file, fb->buffer, buffer_max);
            } while (ret < 0 && errno == EINTR);
            if (ret < 0) {
                warn("%s: read failed", __FUNCTION__);
                return -1;
            }
#endif
            fb->buffered = ret;
            fb->eof = (fb->buffered < buffer_max);
            fb->consumed = 0;
        }
    }

    return b - (uint8_t *)buf;
}

