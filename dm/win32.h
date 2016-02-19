/*
 * Copyright 2012-2016, Bromium, Inc.
 * Author: Christian Limpach <Christian.Limpach@gmail.com>
 * SPDX-License-Identifier: ISC
 */

#ifndef _WIN32_H_
#define _WIN32_H_

#define WIN32_LEAN_AND_MEAN
#ifndef WINVER
#define WINVER 0x0601
#endif
#define _WIN32_WINNT 0x0601
#include <mm_malloc.h>
#include <windows.h>
#include <wincrypt.h>
#include <winsock2.h>
#undef POLLIN
#undef POLLOUT
#undef POLLERR
#define poll WSAPoll

#define ERR_WINDOWS
#include <err.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>

#ifdef SLIST_ENTRY
#undef SLIST_ENTRY
#endif

extern uint64_t process_shutdown_priority;

/* Prototype for the actual main() in dm.c, make the compiler check
   that the signatures match. */
int main(int argc, char **argv);

#define        ENODATA         61      /* No data available */

static inline void *
align_alloc(size_t alignment, size_t size)
{
    return _aligned_malloc(size, alignment);
}

static inline void
align_free(void *ptr)
{
    _aligned_free(ptr);
}

#define ALIGN_PAGE_ALIGN 0x1000
#define page_align_alloc(size) align_alloc(ALIGN_PAGE_ALIGN, size)

int inet_aton(const char *cp, struct in_addr *ia);
WINSOCK_API_LINKAGE int WSAAPI inet_pton(int family, const char *cp, void *ia);

int vasprintf(char **strp, const char *fmt, va_list ap)
    __attribute__ ((__format__ (printf, 2, 0)));
int asprintf(char **strp, const char *fmt, ...)
    __attribute__ ((__format__ (printf, 2, 3)));

extern HINSTANCE g_instance;
extern int g_showwindow;

#ifdef __x86_64__
#define PRIdSIZE PRId64
#define PRIxSIZE PRIx64
#define PRIuSIZE PRIu64
#else
#define PRIdSIZE PRId32
#define PRIxSIZE PRIx32
#define PRIuSIZE PRIu32
#endif

typedef CRITICAL_SECTION critical_section;
#define critical_section_init InitializeCriticalSection
#define critical_section_enter EnterCriticalSection
#define critical_section_leave LeaveCriticalSection
#define critical_section_free DeleteCriticalSection

/* -1 for MsgWaitForMultipleObjectsEx */
#define MAXIMUM_WAIT_EVENTS (MAXIMUM_WAIT_OBJECTS - 1)
typedef HANDLE ioh_handle;
typedef HANDLE ioh_event;
typedef HANDLE ioh_wait_event;

#define ioh_event_init(ev) do {                                     \
        *(ev) = CreateEvent(NULL, TRUE, FALSE, NULL);               \
        if (!*(ev))                                                 \
            Werr(1, "%s: ioh_event_init: CreateEvent failed: %d",   \
                 __FUNCTION__, GetLastError());                     \
    } while(0)
#define ioh_event_set(ev) SetEvent(*(ev))
#define ioh_event_reset(ev) ResetEvent(*(ev))
#define ioh_event_wait(ev) WaitForSingleObject(*(ev), INFINITE)
#define ioh_event_close(ev) do {                                    \
        CloseHandle(*(ev)); *(ev) = NULL;                           \
    } while(0)
#define ioh_event_valid(ev) (*(ev) != NULL)

typedef HANDLE uxen_notification_event;
typedef HANDLE uxen_user_notification_event;
#define uxen_notification_event_init(ev) ioh_event_init(ev)
#define uxen_user_notification_event_init(ev) ioh_event_init(ev)
#define uxen_user_notification_event_set(ev) ioh_event_set(ev)
#define uxen_notification_add_wait_object(ev, fn, arg, wo) \
    ioh_add_wait_object(ev, fn, arg, wo)

typedef HWND window_handle;

typedef HANDLE uxen_thread;

#define create_thread(thread, fn, arg) (({                              \
                int ret = 0;                                            \
                *(thread) = CreateThread(NULL, 0, fn, arg, 0, NULL);    \
                if (!*(thread))                                         \
                    ret = -1;                                           \
                ret;                                                    \
            }))
#define cancel_thread(thread) do { } while(0)
#define setcancel_thread() do { } while(0)
#define elevate_thread(thread) SetThreadPriority(thread, THREAD_PRIORITY_ABOVE_NORMAL)
#define wait_thread(thread) WaitForSingleObject(thread, INFINITE)
#define detach_thread(thread) do { } while(0)
#define close_thread_handle(thread) CloseHandle(thread)

#undef assert
#define assert(cond) do {                                       \
        if (!(cond)) {                                          \
            debug_printf("%s:%d: assertion failed: %s\n",       \
                         __FUNCTION__, __LINE__, # cond);       \
            *(uint32_t *)0 = 0;                                 \
        }                                                       \
    } while (0)

#define assert_always(cond) assert(cond)

/* Sabotage <assert.h> to prevent direct includes. The correct thing
 * to is to include "config.h" from dm or <dm/qemu_glue.h> from qemu. */
#define __ASSERT_H_

void windows_time_update(void);

static inline wchar_t *_utf8_to_wide(const char *s)
{
    int sz;
    wchar_t *ws;
    
    /* First figure out buffer size needed and malloc it. */
    sz = MultiByteToWideChar(CP_UTF8, 0, s, -1, NULL, 0);
    if (!sz)
        return NULL;

    ws = (wchar_t *)malloc(sizeof(wchar_t) * (sz + 1));
    if (!ws)
        return NULL;
    ws[sz] = 0;

    /* Now perform the actual conversion. */
    sz = MultiByteToWideChar(CP_UTF8, 0, s, -1, ws, sz);
    if (!sz) {
        free(ws);
        ws = NULL;
    }

    return ws;
}

/* UTF-8 compatible wrapper for fopen(). */
static inline FILE *fopen_utf8(const char *path, const char *mode)
{
    FILE *r = NULL;
    wchar_t *path_w = NULL;
    wchar_t *mode_w = NULL;

    mode_w = _utf8_to_wide(mode);
    if (!mode_w) {
        errno = ENOMEM;
        goto out;
    }

    path_w = _utf8_to_wide(path);
    if (!path_w) {
        errno = ENOMEM;
        goto out;
    }

    r = _wfopen(path_w, mode_w);

  out:
    free(mode_w);
    free(path_w);

    return r;
}

/* UTF-8 compatible wrapper for unlink(). */
static inline int unlink_utf8(const char *path)
{
    int r = 0;
    wchar_t *path_w;

    path_w = _utf8_to_wide(path);
    if (!path_w) {
        errno = ENOMEM;
        return -1;
    }

    if (!DeleteFileW(path_w)) {
        if (GetLastError() == ERROR_FILE_NOT_FOUND)
            errno = ENOENT;
        else if (GetLastError() == ERROR_ACCESS_DENIED)
            errno = EACCES;
        else
            errno = EINVAL;
        r = -1;
    }

    free(path_w);

    return r;
}

/* UTF-8 compatible wrapper for unlink(). */
static inline int rmdir_utf8(const char *path)
{
    int r = 0;
    wchar_t *path_w;

    path_w = _utf8_to_wide(path);
    if (!path_w) {
        errno = ENOMEM;
        return -1;
    }

    if (!RemoveDirectoryW(path_w)) {
        if (GetLastError() == ERROR_FILE_NOT_FOUND)
            errno = ENOENT;
        else if (GetLastError() == ERROR_ACCESS_DENIED)
            errno = EACCES;
        else
            errno = EINVAL;
        r = -1;
    }

    free(path_w);

    return r;
}

/* UTF-8 compatible wrapper for open(). */
static inline int open_utf8(const char *path, int flags, ...)
{
    int r = 0;
    wchar_t *path_w;
    int mode;

    path_w = _utf8_to_wide(path);
    if (!path_w) {
        errno = ENOMEM;
        return -1;
    }

    if (flags & O_CREAT) {
        va_list ap;
        va_start(ap, flags);
        mode = va_arg(ap, int);
        va_end(ap);
        r = _wopen(path_w, flags, mode);
    } else
        r = _wopen(path_w, flags);

    free(path_w);

    return r;
}

/* UTF-8 compatible wrapper around GetFileAttributes() to not have to use stat()
 * on Windows. */
static inline int file_exists(const char *path)
{
    wchar_t *path_w = _utf8_to_wide(path);
    DWORD attr;
    int ret;

    if (!path_w) {
        /* For sake of convenience we treat OOM here as 'no such file'. */
        return 0;
    }

    attr = GetFileAttributesW(path_w);
    if (attr == INVALID_FILE_ATTRIBUTES &&
            (GetLastError() == ERROR_FILE_NOT_FOUND ||
            GetLastError() == ERROR_PATH_NOT_FOUND)) {
        ret = 0;
    } else {
        ret = 1;
    }
    free(path_w);

    return ret;
}

/* UTF-8 compatible wrapper for CreateFile(). */
static inline HANDLE CreateFile_utf8(
        const char *path,
        DWORD dwDesiredAccess,
        DWORD dwShareMode,
        LPSECURITY_ATTRIBUTES lpSecurityAttributes,
        DWORD dwCreationDisposition,
        DWORD dwFlagsAndAttributes,
        HANDLE hTemplateFile
        )
{
    HANDLE hFile;
    wchar_t *path_w;

    path_w = _utf8_to_wide(path);
    if (!path_w) {
        SetLastError(ERROR_NOT_ENOUGH_MEMORY);
        return INVALID_HANDLE_VALUE;
    }

    hFile = CreateFileW(path_w, dwDesiredAccess, dwShareMode,
            lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes,
            hTemplateFile);

    free(path_w);

    return hFile;
}

/* UTF-8 compatible wrapper for CreateDirectory(). */
static inline BOOL CreateDirectory_utf8(
        const char *path,
        LPSECURITY_ATTRIBUTES lpSecurityAttributes
        )
{
    wchar_t *path_w;
    BOOL r;

    path_w = _utf8_to_wide(path);
    if (!path_w) {
        SetLastError(ERROR_NOT_ENOUGH_MEMORY);
        return 0;
    }

    r = CreateDirectoryW(path_w, lpSecurityAttributes);

    free(path_w);

    return r;
}

/* UTF-8 compatible wrapper for fullpath(). */
static inline char *_fullpath_utf8(char *_abs, const char *path, size_t sz)
{
    char *r = NULL;
    char *abs = _abs;
    wchar_t *path_w;
    wchar_t abs_w[MAX_PATH];

    path_w = _utf8_to_wide(path);
    if (!path_w)
        return NULL;

    if (!_wfullpath(abs_w, path_w, MAX_PATH))
        goto out;

    if (abs == NULL) {
        sz = WideCharToMultiByte(CP_UTF8, 0, abs_w, -1, NULL, 0, NULL, 0);
        if (!sz)
            goto out;

        abs = (char *)malloc(sz + 1);
        if (!abs)
            goto out;

        abs[sz] = 0;
    }

    if (WideCharToMultiByte(CP_UTF8, 0, abs_w, -1, abs, sz, NULL, 0))
        r = abs;

  out:
    free(path_w);
    if (r == NULL && _abs == NULL) /* free allocated abs on failure */
        free(abs);

    return r;
}

int c99_vsnprintf(char *buf, size_t len, const char *fmt, va_list ap);
int c99_snprintf(char *buf, size_t len, const char *fmt, ...);

#undef fopen
#define fopen fopen_utf8
#undef open
#define open open_utf8
#undef unlink
#define unlink unlink_utf8
#undef rmdir
#define rmdir rmdir_utf8
#undef CreateFile
#define CreateFile CreateFile_utf8
#undef CreateDirectory
#define CreateDirectory CreateDirectory_utf8
#undef _fullpath
#define _fullpath _fullpath_utf8
#undef snprintf
#define snprintf c99_snprintf
#undef vsnprintf
#define vsnprintf c99_vsnprintf

void uxenclipboard_gdi_startup_with_atexit();

int generate_random_bytes(void *buf, size_t len);
void cpu_usage(float *user, float *kernel, uint64_t *user_total_sec,
               uint64_t *kernel_total_sec);
#ifdef QEMU_UXEN
void *__wrap_VirtualAlloc(void *addr, size_t size, DWORD type, DWORD protect);
void *__wrap_HeapAlloc(HANDLE heap, DWORD flags, size_t size);
void *__wrap_HeapReAlloc(HANDLE heap, DWORD flags, void *ptr, size_t size);
#define VirtualAlloc __wrap_VirtualAlloc
#define HeapAlloc __wrap_HeapAlloc
#define HeapReAlloc __wrap_HeapReAlloc
#endif

#endif	/* _WIN32_H_ */
