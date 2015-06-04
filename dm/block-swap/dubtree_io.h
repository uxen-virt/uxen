/*
 * Copyright 2013-2015, Bromium, Inc.
 * Author: Jacob Gorm Hansen <jacobgorm@gmail.com>
 * SPDX-License-Identifier: ISC
 */

#ifndef __DUBTREE_IO_H__
#define __DUBTREE_IO_H__

#ifdef _WIN32
#define DUBTREE_INVALID_HANDLE INVALID_HANDLE_VALUE
typedef HANDLE DUBTREE_FILE_HANDLE;
#else
#include <unistd.h>
#include <errno.h>
#include <sys/stat.h>
#define DUBTREE_INVALID_HANDLE -1
typedef int DUBTREE_FILE_HANDLE;
#endif

/* Expand path using fullpath/realpath. Caller must
 * free returned result. */
static inline char *dubtreeRealPath(const char *in)
{
#ifdef _WIN32
    return _fullpath(NULL, in, 0);
#else
    return realpath(in, NULL);
#endif
}

static inline DUBTREE_FILE_HANDLE
dubtreeOpenExistingFile(const char *fn)
{
#ifdef _WIN32
    return CreateFile(fn, GENERIC_READ | GENERIC_WRITE,
            FILE_SHARE_READ| FILE_SHARE_WRITE, NULL, 
            OPEN_EXISTING, FILE_FLAG_OVERLAPPED, NULL);
#else
    int f = open(fn, O_RDWR);
    return f < 0 ? DUBTREE_INVALID_HANDLE : f;
#endif
}

static inline DUBTREE_FILE_HANDLE
dubtreeOpenExistingFileReadOnly(const char *fn)
{
#ifdef _WIN32
    return CreateFile(fn, GENERIC_READ,
            FILE_SHARE_READ| FILE_SHARE_WRITE, NULL, OPEN_EXISTING,
            FILE_FLAG_OVERLAPPED | FILE_ATTRIBUTE_HIDDEN |
            FILE_ATTRIBUTE_SYSTEM , NULL);
#else
    int f = open(fn, O_RDONLY);
    return f < 0 ? DUBTREE_INVALID_HANDLE : f;
#endif
}

static inline DUBTREE_FILE_HANDLE
dubtreeOpenNewFile(const char *fn, int temp)
{
#ifdef _WIN32
    DWORD flags = FILE_FLAG_OVERLAPPED;
    if (temp) {
        flags |= FILE_ATTRIBUTE_TEMPORARY;
    }
    return CreateFile(fn, GENERIC_READ | GENERIC_WRITE,
            FILE_SHARE_READ| FILE_SHARE_WRITE, NULL, 
            OPEN_ALWAYS, flags, NULL);
#else
    int f = open(fn, O_RDWR | O_CREAT, 0644);
    return f < 0 ? DUBTREE_INVALID_HANDLE : f;
#endif
}

static inline void dubtreeSetFileSize(DUBTREE_FILE_HANDLE f, size_t sz)
{
#ifdef _WIN32
    SetFilePointer(f, (DWORD)sz, 0, FILE_BEGIN);
    SetEndOfFile(f);
#else
    off_t use_sz = (off_t)sz;
    if (sz != (size_t)use_sz) {
        perror("dubtreeSetFileSize bad offset");
        exit(-1);
    }
    if (ftruncate(f, use_sz)) {
        perror("dubtreeSetFileSize truncate");
        exit(-1);
    }
#endif
}

static inline void dubtreeCloseFile(DUBTREE_FILE_HANDLE f)
{
#ifdef _WIN32
    CloseHandle(f);
#else
    close(f);
#endif
}

static inline
int dubtreeReadFileAt(DUBTREE_FILE_HANDLE f, void *buf, size_t sz,
        uint64_t offset, void *context)

{
#ifdef _WIN32
    OVERLAPPED ovl = {0,};
    OVERLAPPED *o = context ? context : &ovl;
    DWORD got = 0;
    o->OffsetHigh = offset >>32ULL;
    o->Offset = offset & 0xffffffff;

    if (!ReadFile(f, buf, (DWORD)sz, NULL, o)) {
        if (GetLastError() != ERROR_IO_PENDING) {
            printf("%s: ReadFile fails with error %u\n",
                    __FUNCTION__, (uint32_t)GetLastError());
            return -1;
        }
    }
    if (!context) {
        if (!GetOverlappedResult(f, o, &got, TRUE)) {
            printf("swap: GetOverlappedResult fails on line %d with error %u\n",
                    __LINE__, (uint32_t)GetLastError());
            got = -1;
        }
    }
    return (int) got;
#else
    off_t use_offset = (off_t)offset;
    if (offset != (uint64_t)use_offset) {
        perror("dubtreeReadFileAt bad offset");
        return -1;
    }
    ssize_t r;
    do {
        r = pread(f, buf, sz, use_offset);
    } while (r < 0 && errno == EINTR);
    return (int)r;
#endif
}

static inline int
dubtreeWriteFileAt(DUBTREE_FILE_HANDLE f, const void *buf, size_t sz,
        uint64_t offset, void *context)

{
#ifdef _WIN32
    DWORD wrote = 0;
    OVERLAPPED ovl = {0,};
    OVERLAPPED *o = context ? context : &ovl;
    o->OffsetHigh = offset >>32ULL;
    o->Offset = offset & 0xffffffff;

    if (!WriteFile(f, buf, sz, NULL, o)) {
        if (GetLastError() != ERROR_IO_PENDING) {
            printf("%s: WriteFile fails with error %u\n",
                    __FUNCTION__, (uint32_t)GetLastError());
            return -1;
        }
    }
    if (!context) {
        if (!GetOverlappedResult(f, o, &wrote, TRUE)) {
            printf("swap: GetOverlappedResult fails on line %d with error %u\n",
                    __LINE__, (uint32_t)GetLastError());
            assert(0);
            wrote = -1;
        }
    }
    return (int) wrote;
#else
    off_t use_offset = (off_t)offset;
    if (offset != (uint64_t)use_offset) {
        perror("dubtreeWriteFileAt bad offset");
        return -1;
    }
    ssize_t r;
    do {
        r = pwrite(f, buf, sz, use_offset);
    } while (r < 0 && errno == EINTR);
    return (r == (ssize_t)sz) ? (int)r : -1;
#endif
}

static inline int dubtreeCreateDirectory(const char *dn)
{
#ifdef _WIN32
    return CreateDirectory(dn, NULL) ? 0 : -1;
#else
    return mkdir(dn, 0700);
#endif

}

#endif /* __DUBTREE_IO_H__ */
