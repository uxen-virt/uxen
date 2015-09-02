/*
 *  err.h
 *
 * Copyright 2015, Bromium, Inc.
 * Author: Christian Limpach <Christian.Limpach@gmail.com>
 * SPDX-License-Identifier: ISC
 *
 */

#ifndef _ERR_H_
#define _ERR_H_

#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#if defined(ERR_WINDOWS) && defined(_WIN32)
#define _ERR_WINDOWS
#endif

#ifdef _ERR_WINDOWS
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#endif

#ifndef ERR_NO_PROGNAME
extern const char *_progname;

#define DECLARE_PROGNAME const char *_progname
#else
#define _progname "err"
#endif  /* ERR_NO_PROGNAME */

#if defined(_ERR_WINDOWS) && defined(ERR_AUTO_CONSOLE)
#include <fcntl.h>
#include <io.h>
#include <stdio.h>

static inline void
_err_auto_console(void)
{
    static int once = 0;
    int hCrt;
    FILE *hf;

    if (once)
        return;

    once = 1;
    AllocConsole();
    hCrt = _open_osfhandle((intptr_t)GetStdHandle(STD_ERROR_HANDLE),
                           _O_TEXT);
    hf = _fdopen(hCrt, "w");
    if (!hf)
        return;
    *stderr = *hf;
    setvbuf(stderr, NULL, _IONBF, 0);
}
static inline void
open_stderr_console(void)
{

    _err_auto_console();
}
#else
static inline void
_err_auto_console(void)
{
}
static inline void
open_stderr_console(void)
{
}
#endif  /* ERR_AUTO_CONSOLE */

#ifndef ERR_STDERR
#define ERR_STDERR stderr
#else
extern FILE *ERR_STDERR;
#endif  /* ERR_STDERR */

#if !defined(_WIN32) || defined(__MINGW_H)
#define _get_errno(e) *(e) = errno
#define _set_errno(e) errno = (e)
#endif

#if defined(_WIN32)
static inline const char *
getprogname(void)
{
    return _progname;
}

static inline void
setprogname(const char *name)
{
#ifndef ERR_NO_PROGNAME
    _progname = strrchr(name, '/');
    if (!_progname)
        _progname = strrchr(name, '\\');
    if (_progname) {
        _progname++;
        return;
    }
    _progname = name;
#endif
}
#endif

#ifndef _err_vprintf
__attribute__ ((__format__ (printf, 6, 0)))
static inline void
_err_vprintf(const char *function, int line,
             const char *type,
             int errval, const char *errdesc,
             const char *fmt, va_list ap)
{
    if (!ERR_STDERR)
        return;

    fprintf(ERR_STDERR, "%s: ", getprogname());
    if (fmt) {
        vfprintf(ERR_STDERR, fmt, ap);
        if (errdesc)
            fprintf(ERR_STDERR, ": %s (%08X)", errdesc, errval);
        else if (errval)
            fprintf(ERR_STDERR, ": (%08X)", errval);
    }
    fprintf(ERR_STDERR, "\n");
}
#else
extern void _err_vprintf(const char *function, int line,
                         const char *type,
                         int errval, const char *errdesc,
                         const char *fmt, va_list ap);
#endif

#ifndef _err_flush
static inline void
_err_flush(void)
{
    if (!ERR_STDERR)
        return;

    fflush(ERR_STDERR);
}
#else
extern void _err_flush(void);
#endif

static inline void
_err_printf(const char *function, int line,
            const char *type,
            int errval, const char *errdesc,
            const char *fmt, ...)
{
    va_list ap;

    va_start(ap, fmt);
    _err_vprintf(function, line, type, errval, errdesc, fmt, ap);
    va_end(ap);
}


static inline void
__attribute__ ((__format__ (printf, 3, 0)))
_vwarn(const char *function, int line, const char *fmt, va_list ap)
{
    int saved_errno;

    _get_errno(&saved_errno);

    _err_auto_console();

    _err_vprintf(function, line, "warn", saved_errno, strerror(saved_errno),
                 fmt, ap);

    _set_errno(saved_errno);
}

static inline void
__attribute__ ((__format__ (printf, 3, 0)))
_vwarnx(const char *function, int line, const char *fmt, va_list ap)
{
    int saved_errno;

    _get_errno(&saved_errno);

    _err_auto_console();

    _err_vprintf(function, line, "warn", 0, NULL,
                 fmt, ap);

    _set_errno(saved_errno);
}

static inline void
__attribute__ ((__format__ (printf, 3, 4)))
_warn(const char *function, int line, const char *fmt, ...)
{
    va_list ap;

    va_start(ap, fmt);
    _vwarn(function, line, fmt, ap);
    va_end(ap);
}

static inline void
__attribute__ ((__format__ (printf, 3, 4)))
_warnx(const char *function, int line, const char *fmt, ...)
{
    va_list ap;

    va_start(ap, fmt);
    _vwarnx(function, line, fmt, ap);
    va_end(ap);
}

static inline void
__attribute__ ((__noreturn__, __format__ (printf, 4, 0)))
_verr(const char *function, int line, int eval, const char *fmt, va_list ap)
{
    int saved_errno;

    _get_errno(&saved_errno);

    _err_auto_console();

    _err_vprintf(function, line, "err", saved_errno, strerror(saved_errno),
                 fmt, ap);

    _err_flush();
    if (eval)
        _exit(eval);
    exit(0);
    /* NOTREACHED */
}

static inline void
__attribute__ ((__noreturn__, __format__ (printf, 4, 0)))
_verrx(const char *function, int line, int eval, const char *fmt, va_list ap)
{
    int saved_errno;

    _get_errno(&saved_errno);

    _err_auto_console();

    _err_vprintf(function, line, "err", 0, NULL,
                 fmt, ap);

    _err_flush();
    if (eval)
        _exit(eval);
    exit(0);
    /* NOTREACHED */
}

static inline void
__attribute__ ((__noreturn__, __format__ (printf, 4, 5)))
_err(const char *function, int line, int eval, const char *fmt, ...)
{
    va_list ap;

    va_start(ap, fmt);
    _verr(function, line, eval, fmt, ap);
    /* NOTREACHED */
}

static inline void
__attribute__ ((__noreturn__, __format__ (printf, 4, 5)))
_errx(const char *function, int line, int eval, const char *fmt, ...)
{
    va_list ap;

    va_start(ap, fmt);
    _verrx(function, line, eval, fmt, ap);
    /* NOTREACHED */
}

#define vwarn(fmt, ap) _vwarn(__FUNCTION__, __LINE__, fmt, ap)
#define warn(fmt, ...) _warn(__FUNCTION__, __LINE__, fmt, ##__VA_ARGS__)
#define vwarnx(fmt, ap) _vwarnx(__FUNCTION__, __LINE__, fmt, ap)
#define warnx(fmt, ...) _warnx(__FUNCTION__, __LINE__, fmt, ##__VA_ARGS__)
#define verr(eval, fmt, ap) _verr(__FUNCTION__, __LINE__, eval, fmt, ap)
#define err(eval, fmt, ...) _err(__FUNCTION__, __LINE__, eval, fmt, ##__VA_ARGS__)
#define verrx(eval, fmt, ap) _verrx(__FUNCTION__, __LINE__, eval, fmt, ap)
#define errx(eval, fmt, ...) _errx(__FUNCTION__, __LINE__, eval, fmt, ##__VA_ARGS__)

#ifdef _ERR_WINDOWS
#define _err_trim_format_message(buf) if ((buf)) {           \
        if ((buf)[strlen((buf)) - 1] == '\n')           \
            (buf)[strlen((buf)) - 1] = 0;               \
        if ((buf)[strlen((buf)) - 1] == '\r')           \
            (buf)[strlen((buf)) - 1] = 0;               \
    }

static inline void
_Wwarnv(const char *function, int line, const char *fmt, va_list ap)
{
    long last_error;
    int saved_errno;
    char *lpMsgBuf;

    _get_errno(&saved_errno);
    last_error = GetLastError();

    _err_auto_console();

    FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM |
		  FORMAT_MESSAGE_IGNORE_INSERTS, NULL, last_error,
		  MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (LPTSTR)&lpMsgBuf,
		  0, NULL);
    _err_trim_format_message(lpMsgBuf);

    _err_vprintf(function, line, "warn", last_error, lpMsgBuf, fmt, ap);

    LocalFree(lpMsgBuf);
    _err_flush();
    _set_errno(saved_errno);
}

static inline void
_Wwarn(const char *function, int line, const char *fmt, ...)
{
    va_list ap;

    va_start(ap, fmt);
    _Wwarnv(function, line, fmt, ap);
    va_end(ap);
}

static inline void
__attribute__ ((__noreturn__))
_Werrv(const char *function, int line, int eval, const char *fmt, va_list ap)
{
    long last_error;
    char *lpMsgBuf;

    last_error = GetLastError();

    _err_auto_console();

    FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM |
		  FORMAT_MESSAGE_IGNORE_INSERTS, NULL, last_error,
		  MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (LPTSTR)&lpMsgBuf,
		  0, NULL);
    _err_trim_format_message(lpMsgBuf);

    _err_vprintf(function, line, "err", last_error, lpMsgBuf, fmt, ap);

    _err_flush();
    if (eval)
        _exit(eval);
    exit(0);
    /* NOTREACHED */
}

static inline void
__attribute__ ((__noreturn__))
_Werr(const char *function, int line, int eval, const char *fmt, ...)
{
    va_list ap;

    va_start(ap, fmt);
    _Werrv(function, line, eval, fmt, ap);
    /* NOTREACHED */
}

#define Wwarnv(fmt, ap) _Wwarnv(__FUNCTION__, __LINE__, fmt, ap)
#define Wwarn(fmt, ...) _Wwarn(__FUNCTION__, __LINE__, fmt, ##__VA_ARGS__)
#define Werrv(fmt, ap) _Werrv(__FUNCTION__, __LINE__, fmt, ap)
#define Werr(fmt, ...) _Werr(__FUNCTION__, __LINE__, fmt, ##__VA_ARGS__)

#endif  /* _ERR_WINDOWS */


#endif
