/*
 * Copyright 2012-2015, Bromium, Inc.
 * SPDX-License-Identifier: ISC
 */

#ifndef _DISKLIB_VBOX_COMPAT_H
#define _DISKLIB_VBOX_COMPAT_H

#include <err.h>

#define warn_use(fn) warnx("%s:%d %s:%s", __FILE__, __LINE__, __FUNCTION__, fn)

#include "vd.h"

typedef struct vd *PVBOXHDD;

typedef struct VDGEOMETRY {
    /** Number of cylinders. */
    uint32_t    cCylinders;
    /** Number of heads. */
    uint32_t    cHeads;
    /** Number of sectors. */
    uint32_t    cSectors;
} VDGEOMETRY;

typedef struct VDTYPE {
    uint32_t vdtype_canary;
} VDTYPE;

#include <assert.h>
#include <inttypes.h>
#include <stdarg.h>

#define Assert(v) assert(v)
#define AssertFailed() assert(0)

#define RTPrintf(...) fprintf(logfile, __VA_ARGS__)
#define printf(...) fprintf(logfile, __VA_ARGS__)
extern FILE *logfile;
#define error_printf_for_people_who_dont_know_how_to_use_va_args(...) \
    do {fprintf(logfile, __VA_ARGS__); fflush(logfile);} while(0)
#define Log(l) do {} while(0)
#define LogAlways(l) error_printf_for_people_who_dont_know_how_to_use_va_args l
#define LogRel(l) error_printf_for_people_who_dont_know_how_to_use_va_args l

#define RTMemAlloc(size) malloc(size)
#define RTMemAllocZ(size) calloc(1, size)
#define RTMemFree(ptr) free(ptr)
#define RTMemRealloc(ptr, size) realloc(ptr, size)

typedef struct RTMEMCACHE {
    size_t size;
} RTMEMCACHE;
#define RTMemCacheCreate(cache, _size, align, max, ctor, dtor, opaque, flags) \
    (({                                                                 \
            assert((align) == 0);                                       \
            assert((ctor) == NULL);                                     \
            assert((dtor) == NULL);                                     \
            (cache)->size = (_size);                                   \
            0;                                                          \
        }))
#define RTMemCacheAlloc(cache)                  \
    malloc((cache).size)
#define RTMemCacheFree(cache, p)                \
    free(p)
#define RTMemCacheDestroy(cache) do { /* */ } while (0)

#define RTR3Init() do { /* */ } while (0)

#include "sha1.h"
typedef SHA1_CTX RTSHA1CONTEXT;
#define RTSHA1_HASH_SIZE SHA1_DIGEST_SIZE
#define RTSha1Init(context) SHA1_Init(context)
#define RTSha1Update(context, data, len)                \
    SHA1_Update(context, (const uint8_t *)data, len)
#define RTSha1Final(context, digest) SHA1_Final(context, digest)
static inline int
RTSha1ToString(const uint8_t *digest, char *buf, int maxlen) {
    const char hexdigits[] = "0123456789abcdef";
    int i;
    if (RTSHA1_HASH_SIZE * 2 > maxlen)
        return -ENOMEM;
    for (i = 0; i < RTSHA1_HASH_SIZE; i++) {
        buf[i * 2] = hexdigits[digest[i] >> 4];
        buf[i * 2 + 1] = hexdigits[digest[i] & 0xf];
    }
    if (RTSHA1_HASH_SIZE * 2 + 1 < maxlen)
        buf[RTSHA1_HASH_SIZE * 2] = 0;
    return 0;
}

#define RTStrCmp(s1, s2) strcmp(s1, s2)
#define RTStrNCmp(s1, s2, n) strncmp(s1, s2, n)
#define RTStrICmp(s1, s2) stricmp(s1, s2)
#define RTStrNICmp(s1, s2, n) strnicmp(s1, s2, n)
#define RTStrDup(s) strdup(s)
#define RTStrFree(s) free(s)
#define RTStrPrintf(buf, max, ...) snprintf(buf, max, __VA_ARGS__)
#define RTStrAPrintf(buf, ...) asprintf(buf, __VA_ARGS__)

#define RT_SUCCESS(v) ((v) == 0)
#define RT_FAILURE(v) ((v) != 0)

typedef struct RTTIMESPEC {
    int64_t     i64NanosecondsRelativeToUnixEpoch;
} RTTIMESPEC;
typedef struct RUNTIME_ENTRY RUNTIME_ENTRY;
typedef struct RUNTIMES RUNTIMES;
#define RTTimeNow(spec) do {                    \
        uint64_t t;                                     \
        FILETIME ft;                                    \
        GetSystemTimeAsFileTime(&ft);                   \
        t = (uint64_t)ft.dwHighDateTime << 32 | ft.dwLowDateTime;       \
        t -= 116444736000000000ULL;                     \
        t *= 100;                                       \
        (spec)->i64NanosecondsRelativeToUnixEpoch = t;  \
    } while (0)
#define RTTimeSpecToString(spec, buf, len) (({                          \
                FILETIME ft;                                            \
                SYSTEMTIME st;                                          \
                uint64_t t = (spec)->i64NanosecondsRelativeToUnixEpoch; \
                t /= 100;                                               \
                t += 116444736000000000ULL;                             \
                ft.dwHighDateTime = t >> 32;                            \
                ft.dwLowDateTime = t;                                   \
                FileTimeToSystemTime(&ft, &st);                         \
                snprintf((buf), (len), "%u-%02u-%02uT%02u:%02u:%02u.%03u", \
                         st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, \
                         st.wSecond, st.wMilliseconds);                 \
                buf;                                                    \
            }))

#include <direct.h>

static inline void
RTPathStripFilename(char *path) {
    char *l = path, *p = l;
    assert(p);
    if (!*p)
        return;
    while (*p) {
        switch (*p) {
        case ':':
            if (l == path)
                l = p;
            break;
        case '\\':
        case '/':
            l = p;
            break;
        }
        p++;
    }
    if (l == path)
        *(l++) = '.';
    *l = 0;
}
static inline int
RTPathAppend(char *path, int maxlen, const char *append) {
    int len, alen;
    len = strlen(path);
    while (path[len - 1] == '/' || path[len - 1] == '\\')
        len--;
    (path)[len] = 0;
    while (*append == '/' || *append == '\\')
        append++;
    alen = strlen(append);
    assert(len + 1 + alen + 1 < maxlen);
    strcat(path, "/");
    strcat(path, append);
    return len + 1 + alen;
}
#define RTDirCreate(path, mode) (({             \
                assert((mode) == 0);            \
                _mkdir((path));                 \
            }))
#define RTPathAbs(path, abspath, maxlen) _fullpath(abspath, path, maxlen)

typedef FILE *PRTSTREAM;
#define RTStrmOpen(filename, mode, strm) (({    \
                FILE *f;                        \
                f = fopen(filename, mode);      \
                *(strm) = f;                    \
                f ? VINF_SUCCESS : -errno;      \
            }))
#define RTStrmClose(strm) fclose(strm)
#define RTStrmGetLine(strm, buf, maxlen) (({                            \
                char *l;                                                \
                while (maxlen) {                                        \
                    buf[0] = 0;                                         \
                    l = fgets(buf, maxlen, strm);                       \
                    if (l) {                                            \
                        int len = strlen(l);                            \
                        if (len && l[len - 1] == '\n')                  \
                            l[--len] = 0;                               \
                        if (!len)                                       \
                            continue;                                   \
                    }                                                   \
                    break;                                              \
                }                                                       \
                l ? VINF_SUCCESS : (feof(strm) ? VERR_EOF : -errno);    \
            }))

#define VERR_FILE_IO_ERROR -EIO
#define VERR_INVALID_PARAMETER -EINVAL
#define VERR_NO_MEMORY -ENOMEM
#define VERR_EOF -3999
#define VERR_PDM_MEDIA_NOT_MOUNTED -3998
#define VINF_SUCCESS 0

#define VD_OPEN_FLAGS_NORMAL 0x0
#define VD_OPEN_FLAGS_READ_ONLY 0x1

#define VD_IMAGE_FLAGS_NONE 0x0

#define VDTYPE_HDD 0x12344321

#define VDCreate(iflist, type, disk) (({        \
                int _ret = 0;                   \
                struct vd *vd = NULL;           \
                assert((iflist) == NULL);       \
                assert((type) == VDTYPE_HDD);   \
                vd = vd_new();                  \
                if (vd == NULL)                 \
                    _ret = -errno;              \
                else                            \
                    *(disk) = vd;               \
                _ret;                           \
            }))
#define VDCreateBase(disk, format, filename, size, image_flags, ident,  \
                     geom1, geom2, uuid, open_flags, if_image, if_op) (({ \
                                 assert(!memcmp((geom1), &((VDGEOMETRY){0}), \
                                                sizeof(VDGEOMETRY)));   \
                                 assert(!memcmp((geom2), &((VDGEOMETRY){0}), \
                                                sizeof(VDGEOMETRY)));   \
                                 assert((uuid) == NULL);                \
                                 assert((if_image) == NULL);            \
                                 assert((if_op) == NULL);               \
                                 vd_create(disk, format, filename, size, \
                                           image_flags, open_flags);    \
                             }))
#define VDDestroy(disk) vd_destroy(disk)
#define VDTYPE_CANARY 0x12341234
#define VDGetFormat(if_disk, if_image, filename, format, type) (({      \
                assert((if_disk) == NULL);                              \
                assert((if_image) == NULL);                             \
                (type)->vdtype_canary = VDTYPE_CANARY;                  \
                vd_get_format(filename, format);                        \
            }))
#define VDGetLCHSGeometry(disk, image, geom) (({                        \
                VDGEOMETRY *g = (geom);                                 \
                assert((image) == 0);                                   \
                vd_get_lchs_geometry(disk, &g->cCylinders, &g->cHeads,  \
                                     &g->cSectors);                     \
            }))
#define VDGetSize(disk, image) (({              \
                assert((image) == 0);           \
                vd_getsize(disk);               \
            }))
#define VDFlush(disk) (({ warn_use("VDFlush"); 0; }))
#define VDOpen(disk, backend, filename, flags, if_image) (({    \
                assert((if_image) == NULL);                     \
                vd_open(disk, backend, filename, flags);        \
            }))
#define VDRead(disk, offset, buffer, n) \
    vd_read(disk, offset, buffer, n)
#define VDSetOpenFlags(handle, image, flags) \
    (({ warn_use("VDSetOpenFlags"); -EINVAL; }))
extern void vd_close_all(void);
#define VDShutdown() do { vd_close_all(); } while (0)
#define VDWrite(disk, offset, buffer, n) \
    vd_write(disk, offset, buffer, n)

#define DECLCALLBACK(type) type
#define DECLINLINE(type) type

int asprintf(char **strp, const char *fmt, ...);

#endif  /* _DISKLIB_VBOX_COMPAT_H */
