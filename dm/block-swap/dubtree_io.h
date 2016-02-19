/*
 * Copyright 2013-2016, Bromium, Inc.
 * Author: Jacob Gorm Hansen <jacobgorm@gmail.com>
 * SPDX-License-Identifier: ISC
 */

#ifndef __DUBTREE_IO_H__
#define __DUBTREE_IO_H__

#ifdef _WIN32
#define DUBTREE_INVALID_HANDLE INVALID_HANDLE_VALUE
typedef HANDLE dubtree_handle_t;
#else
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#ifndef O_NOATIME
#define O_NOATIME 01000000
#endif


#define DUBTREE_INVALID_HANDLE -1
typedef int dubtree_handle_t;
#endif

/* Expand path using fullpath/realpath. Caller must
 * free returned result. */
static inline char *dubtree_realpath(const char *in)
{
#ifdef _WIN32
    return _fullpath(NULL, in, 0);
#else
    return realpath(in, NULL);
#endif
}

static inline dubtree_handle_t
dubtree_open_existing(const char *fn)
{
#ifdef _WIN32
    return CreateFile(fn, GENERIC_READ | GENERIC_WRITE | DELETE,
            0, NULL,
            OPEN_EXISTING, FILE_FLAG_OVERLAPPED, NULL);
#else
    int f = open(fn, O_RDWR | O_NOATIME);
    return f < 0 ? DUBTREE_INVALID_HANDLE : f;
#endif
}

static inline dubtree_handle_t
dubtree_open_existing_readonly(const char *fn)
{
#ifdef _WIN32
    return CreateFile(fn, GENERIC_READ,
            FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
            OPEN_EXISTING, FILE_FLAG_OVERLAPPED |
                FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM,
            NULL);
#else
    int f = open(fn, O_RDONLY | O_NOATIME);
    return f < 0 ? DUBTREE_INVALID_HANDLE : f;
#endif
}

static inline dubtree_handle_t
dubtree_open_new(const char *fn, int temp)
{
#ifdef _WIN32
    DWORD flags = FILE_FLAG_OVERLAPPED;
    if (temp) {
        flags |= FILE_ATTRIBUTE_TEMPORARY;
    }
    return CreateFile(fn, GENERIC_READ | GENERIC_WRITE | DELETE,
            0, NULL,
            OPEN_ALWAYS, flags, NULL);
#else
    int f = open(fn, O_RDWR | O_CREAT | O_NOATIME, 0644);
    return f < 0 ? DUBTREE_INVALID_HANDLE : f;
#endif
}

static inline void dubtree_set_file_size(dubtree_handle_t f, size_t sz)
{
#ifdef _WIN32
    SetFilePointer(f, (DWORD)sz, 0, FILE_BEGIN);
    SetEndOfFile(f);
#else
    if (ftruncate(f, sz)) {
        perror("truncate");
        exit(-1);
    }
#endif
}

static inline int64_t dubtree_get_file_size(dubtree_handle_t f)
{
#ifdef _WIN32
    return GetFileSize(f, NULL); // XXX on 32b
#else
    struct stat st;
    if (fstat(f, &st) < 0) {
        //warn("unable to stat %s", s->filename);
        assert(0);
        return -1;
    }
    return st.st_size;
#endif
}

static inline void dubtree_close_file(dubtree_handle_t f)
{
#ifdef _WIN32
    CloseHandle(f);
#else
    close(f);
#endif
}

static inline
int dubtree_pread(dubtree_handle_t f, void *buf, size_t sz, uint64_t offset)
{
#ifdef _WIN32
    OVERLAPPED o = {};
    DWORD got = 0;
    o.OffsetHigh = offset >>32ULL;
    o.Offset = offset & 0xffffffff;

    if (!ReadFile(f, buf, (DWORD)sz, NULL, &o)) {
        if (GetLastError() != ERROR_IO_PENDING) {
            printf("%s: ReadFile fails with error %u\n",
                    __FUNCTION__, (uint32_t)GetLastError());
            return -1;
        }
    }
    if (!GetOverlappedResult(f, &o, &got, TRUE)) {
        printf("GetOverlappedResult fails on line %d with error %u\n",
                __LINE__, (uint32_t)GetLastError());
        got = -1;
    }
    return (int) got;
#else
    int r;
    do {
        r = pread(f, buf, sz, offset);
    } while (r < 0 && errno == EINTR);
    return r;
#endif
}

static inline int
dubtree_pwrite(dubtree_handle_t f, const void *buf, size_t sz, uint64_t offset)

{
#ifdef _WIN32
    DWORD wrote = 0;
    OVERLAPPED o = {};
    o.OffsetHigh = offset >>32ULL;
    o.Offset = offset & 0xffffffff;

    if (!WriteFile(f, buf, sz, NULL, &o)) {
        if (GetLastError() != ERROR_IO_PENDING) {
            printf("%s: WriteFile fails with error %u\n",
                    __FUNCTION__, (uint32_t)GetLastError());
            return -1;
        }
    }
    if (!GetOverlappedResult(f, &o, &wrote, TRUE)) {
        printf("GetOverlappedResult fails on line %d with error %u\n",
                __LINE__, (uint32_t)GetLastError());
        wrote = -1;
    }
    return (int) wrote;
#else
    int r;
    do {
        r = pwrite(f, buf, sz, offset);
    } while (r < 0 && errno == EINTR);
    return (r == sz) ? r : -1;
#endif
}

static inline int dubtree_mkdir(const char *dn)
{
#ifdef _WIN32
    return CreateDirectory(dn, NULL) ? 0 : -1;
#else
    return mkdir(dn, 0700);
#endif

}

#endif /* __DUBTREE_IO_H__ */
