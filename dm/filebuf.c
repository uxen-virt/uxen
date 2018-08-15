/*
 * Copyright 2014-2018, Bromium, Inc.
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

#ifdef _WIN32
#include <winioctl.h>
#endif

#ifdef __APPLE__
#include <sys/mman.h>
#endif  /* __APPLE__ */

static const size_t default_buffer_max = 1 << 20;

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

    fb->buffer_max = default_buffer_max;
    fb->buffer = page_align_alloc(fb->buffer_max);
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

    fb->users = 1;

#ifdef _WIN32
    fb->file = CreateFile(
        fn, GENERIC_READ | (fb->writable ? GENERIC_WRITE | DELETE : 0),
        fb->writable ? 0 :
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        NULL,
        fb->writable ? CREATE_ALWAYS : OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OVERLAPPED |
        (sequential ? FILE_FLAG_SEQUENTIAL_SCAN : 0) |
        (write_through ? FILE_FLAG_WRITE_THROUGH : 0) |
        (no_buffering ? FILE_FLAG_NO_BUFFERING : 0),
        NULL);
#else  /* _WIN32 */
    fb->file = open(fn, fb->writable ? O_RDWR | O_CREAT | O_TRUNC : O_RDONLY,
                    0644);
#endif  /* _WIN32 */

#ifdef _WIN32
    if (fb->file == INVALID_HANDLE_VALUE) {
        _set_errno(GetLastError());
        Wwarn("%s: open %s failed", __FUNCTION__, fn);
#else  /* _WIN32 */
    if (fb->file < 0) {
        warn("%s: open %s failed", __FUNCTION__, fn);
#endif  /* _WIN32 */
        align_free(fb->buffer);
        free(fb);
        fb = NULL;
    }
#ifdef __APPLE__
    else {
        if (no_buffering)
            fcntl(fb->file, F_NOCACHE, 1);
        if (fb->file >= 0)
            fb->filename = strdup(fn);
    }
#endif  /* __APPLE__ */
    return fb;
}

int
filebuf_set_readable(struct filebuf *fb)
{

    if (!fb->writable)
        return -1;

    filebuf_flush(fb);

    fb->offset = 0;
    fb->writable = 0;

    return 0;
}

int
filebuf_flush(struct filebuf *fb)
{
#ifdef _WIN32
    DWORD ret;
    OVERLAPPED o = { };
#else  /* _WIN32 */
    ssize_t ret, o = 0;
#endif  /* _WIN32 */

    if (!fb->writable) {
        /* flush buffered data for read files */
        fb->offset = filebuf_tell(fb);
        fb->buffered = fb->consumed = 0;
        return 0;
    }

#ifdef _WIN32
    o.Offset = fb->offset;
    o.OffsetHigh = fb->offset >> 32ULL;

    if (!WriteFile(fb->file, fb->buffer, fb->buffered, &ret, &o) &&
        GetLastError() != ERROR_IO_PENDING) {
        Wwarn("%s: WriteFile failed", __FUNCTION__);
        return -1;
    }
    if (!GetOverlappedResult(fb->file, &o, &ret, TRUE) ||
        ret != fb->buffered) {
        Wwarn("%s: GetOverlappedResult failed", __FUNCTION__);
        return -1;
    }
#else  /* _WIN32 */
    do {
        ret = pwrite(fb->file, fb->buffer + o, fb->buffered - o,
                     fb->offset + o);
        if (ret > 0)
            o += ret;
    } while (ret < 0 && errno == EINTR);
    if (ret < 0) {
        warn("%s: pwrite failed", __FUNCTION__);
        return -1;
    }
    ret = o;
#endif  /* _WIN32 */
    fb->offset += ret;
    fb->buffered = 0;
    return 0;
}

void
filebuf_close(struct filebuf *fb)
{

    --fb->users;
    if (fb->users)
        return;

#ifdef __APPLE__
    if (fb->delete_on_close)
        unlink(fb->filename);
    else                        /* only flush if the file isn't deleted */
#endif  /* __APPLE__ */
    if (fb->writable)
        filebuf_flush(fb);
#ifdef _WIN32
    CloseHandle(fb->file);
    if (fb->mapping)
        UnmapViewOfFile(fb->mapping);
#else  /* _WIN32 */
    close(fb->file);
    if (fb->mapping)
        munmap(fb->mapping, fb->mapping_len);
    free(fb->filename);
#endif  /* _WIN32 */
    align_free(fb->buffer);
    free(fb);
}

struct filebuf *
filebuf_openref(struct filebuf *fb)
{

    ++fb->users;
    return fb;
}

int
filebuf_write(struct filebuf *fb, void *buf, size_t size)
{
    uint8_t *b = buf;

    while (size) {
        size_t n = size;

        if (n > fb->buffer_max - fb->buffered)
            n = fb->buffer_max - fb->buffered;
        memcpy(fb->buffer + fb->buffered, b, n);
        fb->buffered += n;
        b += n;
        size -= n;

        if (fb->buffered == fb->buffer_max) {
            if (filebuf_flush(fb) < 0)
                return -1;
        }
    }
    return b - (uint8_t *) buf;
}

static int
filebuf_fill(struct filebuf *fb)
{
    if (fb->consumed == fb->buffered) {
#ifdef _WIN32
        DWORD ret = 0;
        OVERLAPPED o = { };

        fb->consumed = fb->offset & (ALIGN_PAGE_ALIGN - 1);
        fb->offset -= fb->consumed;

        o.Offset = fb->offset;
        o.OffsetHigh = fb->offset >> 32ULL;

        if (!ReadFile(fb->file, fb->buffer, (DWORD)fb->buffer_max, &ret, &o)) {
            if (GetLastError() != ERROR_IO_PENDING) {
                _set_errno(GetLastError());
                Wwarn("%s: ReadFile failed", __FUNCTION__);
                return -1;
            }
            if (!GetOverlappedResult(fb->file, &o, &ret, TRUE) &&
                GetLastError() != ERROR_HANDLE_EOF) {
                _set_errno(GetLastError());
                Wwarn("%s: GetOverlappedResult failed", __FUNCTION__);
                return -1;
            }
        }
#else  /* _WIN32 */
        ssize_t ret, o = 0;

        do {
            ret = pread(fb->file, fb->buffer + o, fb->buffer_max - o,
                        fb->offset + o);
            if (ret > 0)
                o += ret;
        } while (ret < 0 && errno == EINTR);
        if (ret < 0) {
            warn("%s: pread failed", __FUNCTION__);
            return -1;
        }
        ret = o;
        fb->consumed = 0;
#endif  /* _WIN32 */
        fb->offset += ret;
        fb->buffered = ret;
        fb->eof = (fb->buffered < fb->buffer_max);
    }
    return 0;
}

int
filebuf_read(struct filebuf *fb, void *buf, size_t size)
{
    uint8_t *b = buf;
    int ret;

    while (size) {
        size_t n = size;

        ret = filebuf_fill(fb);
        if (ret < 0)
            return ret;

        if (fb->consumed == fb->buffered && fb->eof)
            break;

        if (n > fb->buffered - fb->consumed)
            n = fb->buffered - fb->consumed;
        memcpy(b, fb->buffer + fb->consumed, n);
        fb->consumed += n;
        b += n;
        size -= n;
    }

    return b - (uint8_t *)buf;
}

int
filebuf_skip(struct filebuf *fb, size_t size)
{
    void *buf = NULL;
    uint8_t *b = buf;
    int ret;

    while (size) {
        size_t n = size;

        ret = filebuf_fill(fb);
        if (ret < 0)
            return ret;

        if (fb->consumed == fb->buffered && fb->eof)
            break;

        if (n > fb->buffered - fb->consumed)
            n = fb->buffered - fb->consumed;
        fb->consumed += n;
        b += n;
        size -= n;
    }

    return b - (uint8_t *)buf;
}

off_t
filebuf_tell(struct filebuf *fb)
{

    if (fb->writable)
        return fb->offset + fb->buffered;
    else
        return fb->offset - fb->buffered + fb->consumed;
}

off_t
filebuf_seek(struct filebuf *fb, off_t offset, int whence)
{

    filebuf_flush(fb);
    fb->eof = 0;
    switch (whence) {
    case FILEBUF_SEEK_SET:
        fb->offset = offset;
        break;
    case FILEBUF_SEEK_CUR:
        fb->offset += offset;
        break;
    case FILEBUF_SEEK_END: {
#ifdef _WIN32
        LARGE_INTEGER size;
        if (!GetFileSizeEx(fb->file, &size))
            Werr(1, "%s: GetFileSizeEx failed", __FUNCTION__);
        fb->end = size.QuadPart;
#else  /* _WIN32 */
        fb->end = lseek(fb->file, 0, SEEK_END);
        if (fb->end == -1)
            err(1, "%s: lseek(SEEK_END) failed", __FUNCTION__);
#endif /* _WIN32 */
        fb->offset = fb->end + offset;
    }
        break;
    }
    return fb->offset;
}

void
filebuf_buffer_max(struct filebuf *fb, size_t new_buffer_max)
{

    filebuf_flush(fb);

    fb->buffer_max = new_buffer_max;
    do {
        align_free(fb->buffer);
        fb->buffer = page_align_alloc(fb->buffer_max);
        if (!fb->buffer) {
            fb->buffer_max /= 2; /* try half sized buffer */
            if (fb->buffer_max < ALIGN_PAGE_ALIGN)
                errx(1, "%s: out of memory", __FUNCTION__);
        }
    } while (!fb->buffer);
}

int
filebuf_delete_on_close(struct filebuf *fb, int delete)
{
#ifdef _WIN32
    FILE_DISPOSITION_INFO fdi = { delete };
    int ret;

    ret = SetFileInformationByHandle(fb->file, FileDispositionInfo, &fdi,
                                     sizeof(fdi));
    if (!ret)
        Wwarn("%s", __FUNCTION__);
    return ret ? 0 : -1;
#else  /* _WIN32 */
    fb->delete_on_close = delete;
    return 0;
#endif  /* _WIN32 */
}

static void *
_filebuf_mmap(struct filebuf *fb, off_t offset, size_t len,
              bool cow, void *tgt_va)
{
    static uint64_t align_mask = 0;
    uint64_t aligned_offset;
#ifdef _WIN32
    HANDLE h = INVALID_HANDLE_VALUE;
    SYSTEM_INFO si;

    if (!align_mask) {
        GetSystemInfo(&si);
        align_mask = ~(si.dwAllocationGranularity - 1);
    }
    aligned_offset = offset & align_mask;

    h = CreateFileMapping(fb->file, NULL, PAGE_READONLY, 0, 0, NULL);
    if (!h)
        Werr(1, "%s: CreateFileMapping failed", __FUNCTION__);

    fb->mapping = MapViewOfFileEx(h, !cow ? FILE_MAP_READ : FILE_MAP_COPY,
                                (uint32_t)(aligned_offset >> 32),
                                (uint32_t)aligned_offset,
                                len + offset - aligned_offset,
                                tgt_va);
    if (!fb->mapping)
        Werr(1, "%s: MapViewOfFile failed", __FUNCTION__);

    if (h)
        CloseHandle(h);

#else  /* _WIN32 */

    if (!align_mask)
        align_mask = ~((uint64_t) sysconf(_SC_PAGESIZE) - 1);
    aligned_offset = offset & align_mask;

    fb->mapping_len = len + offset - aligned_offset;
    fb->mapping = mmap(NULL, fb->mapping_len, PROT_READ,
                       MAP_SHARED, fb->file, aligned_offset);
    if (fb->mapping == MAP_FAILED)
        err(1, "%s: mmap failed", __FUNCTION__);

#endif /* _WIN32 */

    return fb->mapping + offset - aligned_offset;
}

void *
filebuf_mmap(struct filebuf *fb, off_t offset, size_t len)
{
    return _filebuf_mmap(fb, offset, len, false, NULL);
}

void *
filebuf_mmap_cow(struct filebuf *fb, off_t offset, size_t len, void *tgt_va)
{
    return _filebuf_mmap(fb, offset, len, true, tgt_va);
}

int
filebuf_set_sparse(struct filebuf *fb, bool sparse_flag)
{
#ifdef _WIN32
    FILE_SET_SPARSE_BUFFER fssb = { };

    fssb.SetSparse = sparse_flag;
    if (!DeviceIoControl(fb->file, FSCTL_SET_SPARSE,
            &fssb, sizeof(fssb), NULL, 0, NULL, NULL)) {
        _set_errno(GetLastError());
        Wwarn("%s: failed to FSCTL_SET_SPARSE: %d", __FUNCTION__, GetLastError());
        return -1;
    }

    return 0;
#else /* _WIN32 */
    return -1;
#endif
}

int
filebuf_set_zero_data(struct filebuf *fb, off_t offset, size_t len)
{
#ifdef _WIN32
    FILE_ZERO_DATA_INFORMATION fzdi = { };

    fzdi.FileOffset.QuadPart = offset;
    fzdi.BeyondFinalZero.QuadPart = offset + len + 1;
    if (!DeviceIoControl(fb->file, FSCTL_SET_ZERO_DATA,
            &fzdi, sizeof(fzdi), NULL, 0, NULL, NULL)) {
        _set_errno(GetLastError());
        Wwarn("%s: failed to FSCTL_SET_ZERO_DATA: %d", __FUNCTION__, GetLastError());
        return -1;
    }

    return 0;
#else /* _WIN32 */
    return -1;
#endif
}

