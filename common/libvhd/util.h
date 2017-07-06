/*
 * Copyright 2012-2017, Bromium, Inc.
 * Author: Christian Limpach <Christian.Limpach@gmail.com>
 * SPDX-License-Identifier: ISC
 */

#ifndef _LIBVHD_UTIL_H_
#define _LIBVHD_UTIL_H_

#include <mm_malloc.h>
#include <stdarg.h>
#include <sys/param.h>
#include <stdlib.h>
#include <errno.h>

#define syslog(level, _f, _a...) fprintf(stderr, _f, ##_a)
// #define syslog(level, _f, _a...) term_printf(_f, ##_a)

#if 1
#define DPRINTF(_f, _a...) syslog(LOG_INFO, _f, ##_a)
#else
#define DPRINTF(_f, _a...) ((void)0)
#endif

#if 0
#define EPRINTF(_f, _a...) syslog(LOG_ERR, "tap-err:%s: " _f, __func__, ##_a)
#else
#define EPRINTF(_f, _a...) fprintf(stderr, "tap-err:%s: " _f, __func__, ##_a)
#endif

#if defined(_WIN32)
#define O_DIRECT 0
#define O_LARGEFILE 0
#define O_NONBLOCK 0
#ifndef _WINBASE_
void __stdcall Sleep(unsigned int);
#endif
#define sleep(x) Sleep((x) * 1000)
#ifndef fsync
#define fsync(fd) _commit(fd)
#endif
#define FMT_SIZE "I"
#define read_return_t int
#define write_return_t int
#define read_write_size_t unsigned int
#define PRIx_rw_size "x"
#define PRIdS "Id"
#define PRIuS "Iu"
#elif defined(__APPLE__)
#define O_DIRECT 0
#define O_LARGEFILE 0
#define O_BINARY 0
typedef off_t off64_t;
#define FMT_SIZE "l"
#define read_return_t ssize_t
#define write_return_t ssize_t
#define read_write_size_t size_t
#define PRIx_rw_size "zx"
#define PRIdS "zd"
#define PRIuS "zu"
#define lseek64 lseek
#else
#define PRIdS "zd"
#define PRIuS "zu"
#endif

#if defined(_WIN32)
#define PATHSEP_STR    "\\"
#else
#define PATHSEP_STR    "/"
#endif
#define PATHSEP (PATHSEP_STR[0])

static inline void
internalize_path(char *p)
{
    for (; *p; p++)
	if (*p == PATHSEP)
	    *p = '/';
}

#if defined(_WIN32)
static inline char *
realpath(const char *path, char *resolved_path)
{
    char *p;
    p = _fullpath(resolved_path, path, _MAX_PATH);
    if (p == NULL)
	errno = EIO;
    else
	internalize_path(p);
    return p;
}
#endif

static inline char *
realpath_null(const char *path)
{
    char *resolved_path;

    resolved_path = malloc(PATH_MAX);
    if (resolved_path == NULL)
	return NULL;
    return realpath(path, resolved_path);
}

#ifndef asprintf
#define asprintf _asprintf
static __inline__ int
_asprintf(char **strp, const char *fmt, ...)
{
    va_list ap;
    size_t buflen = 512;
    int ret;

    *strp = malloc(buflen);
    if (*strp == NULL)
	return -1;
    va_start(ap, fmt);
    while (1) {
	ret = vsnprintf(*strp, buflen, fmt, ap);
	if (ret >= 0 && ret < buflen)
	    break;
	if (ret > 0 && ret > buflen)
	    buflen = ret;
	else
	    buflen *= 2;
	*strp = realloc(*strp, buflen);
	if (*strp == NULL) {
	    ret = -1;
	    break;
	}
    }
    va_end(ap);
    return ret;
}
#endif

#define getpagesize() 4096

static inline int
_posix_memalign(void **memptr, size_t alignment, size_t size)
{
    void *ptr;

    ptr = _mm_malloc(size, alignment);
    if (ptr == NULL)
	return ENOMEM;
    *memptr = (char *)ptr;
    return 0;
}

#define posix_memalign(ptr, al, s) ({				\
		void *_x = (ptr);				\
		_posix_memalign(_x, al, s);			\
	    })

static inline void 
posix_memfree(void *ptr)
{
    if (ptr)
	_mm_free(ptr);
}

#define __STR(...) #__VA_ARGS__
#define STR(...) __STR(__VA_ARGS__)

static inline char *
basename(char *path)
{
    char *r;

    if (path == NULL || *path == 0)
	return ".";

    r = &path[strlen(path) - 1];

    while (*r == '/') {
	if (r == path)
	    return "/";
	*r-- = 0;
    }

    while (*r != '/') {
	if (r == path)
	    return r;
	r--;
    }

    return r + 1;
}

static inline char *
dirname(char *path)
{
    char *r;

    if (path == NULL || *path == 0)
	return ".";

    r = &path[strlen(path) - 1];

    while (*r == '/') {
	if (r == path)
	    return "/";
	*r-- = 0;
    }

    while (*r != '/') {
	if (r == path)
	    return ".";
	r--;
    }

    if (r == path)
	return "/";

    *r = 0;
    return path;
}

#endif
