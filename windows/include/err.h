/*
 *  err.h
 *
 * Copyright 2011-2015, Bromium, Inc.
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

#ifdef __MINGW_H
#define _get_errno(e) *(e) = errno
#define _set_errno(e) errno = (e)
#endif

static inline void
__attribute__ ((__format__ (printf, 1, 0)))
_err_vprintf(const char *fmt, va_list ap)
{

    if (!ERR_STDERR)
        return;

    (void)vfprintf(ERR_STDERR, fmt, ap);
}

static inline void
__attribute__ ((__format__ (printf, 1, 2)))
_err_printf(const char *fmt, ...)
{
    va_list ap;

    va_start(ap, fmt);
    _err_vprintf(fmt, ap);
    va_end(ap);
}

static inline void
__attribute__ ((__format__ (printf, 1, 0)))
vwarn(const char *fmt, va_list ap)
{
    int saved_errno;

    _get_errno(&saved_errno);

    _err_auto_console();

    _err_printf("%s: ", _progname);
    if (fmt) {
        _err_vprintf(fmt, ap);
        _err_printf(": %s", strerror(saved_errno));
    }
    _err_printf("\n");
    _set_errno(saved_errno);
}

static inline void
__attribute__ ((__format__ (printf, 1, 0)))
vwarnx(const char *fmt, va_list ap)
{
    int saved_errno;

    _get_errno(&saved_errno);

    _err_auto_console();

    _err_printf("%s: ", _progname);
    if (fmt)
        _err_vprintf(fmt, ap);
    _err_printf("\n");
    _set_errno(saved_errno);
}

static inline void
__attribute__ ((__format__ (printf, 1, 2)))
warn(const char *fmt, ...)
{
    va_list ap;

    va_start(ap, fmt);
    vwarn(fmt, ap);
    va_end(ap);
}

static inline void
__attribute__ ((__format__ (printf, 1, 2)))
warnx(const char *fmt, ...)
{
    va_list ap;

    va_start(ap, fmt);
    vwarnx(fmt, ap);
    va_end(ap);
}

static inline void
__attribute__ ((__noreturn__, __format__ (printf, 2, 0)))
verr(int eval, const char *fmt, va_list ap)
{

    vwarn(fmt, ap);
    fflush(ERR_STDERR);
    exit(eval);
    /* NOTREACHED */
}

static inline void
__attribute__ ((__noreturn__, __format__ (printf, 2, 0)))
verrx(int eval, const char *fmt, va_list ap)
{

    vwarnx(fmt, ap);
    fflush(ERR_STDERR);
    exit(eval);
    /* NOTREACHED */
}

static inline void
__attribute__ ((__noreturn__, __format__ (printf, 2, 3)))
err(int eval, const char *fmt, ...)
{
    va_list ap;

    va_start(ap, fmt);
    verr(eval, fmt, ap);
    /* NOTREACHED */
}

static inline void
__attribute__ ((__noreturn__, __format__ (printf, 2, 3)))
errx(int eval, const char *fmt, ...)
{
    va_list ap;

    va_start(ap, fmt);
    verrx(eval, fmt, ap);
    /* NOTREACHED */
}

#ifdef _ERR_WINDOWS
static inline void
Wwarnv(const char *fmt, va_list ap)
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

    _err_printf("%s: ", _progname);
    if (fmt)
        _err_vprintf(fmt, ap);
    if (lpMsgBuf) {
        if (lpMsgBuf[strlen(lpMsgBuf) - 1] == '\n')
            lpMsgBuf[strlen(lpMsgBuf) - 1] = 0;
        if (lpMsgBuf[strlen(lpMsgBuf) - 1] == '\r')
            lpMsgBuf[strlen(lpMsgBuf) - 1] = 0;
        _err_printf(": %s (%08lX)\n", lpMsgBuf, last_error);
    } else
        _err_printf(" (%08lX)\n", last_error);

    LocalFree(lpMsgBuf);
    _set_errno(saved_errno);
}

static inline void
Wwarn(const char *fmt, ...)
{
    va_list ap;

    va_start(ap, fmt);
    Wwarnv(fmt, ap);
    va_end(ap);
}

static inline void
__attribute__ ((__noreturn__))
Werr(int eval, const char *fmt, ...)
{
    va_list ap;

    va_start(ap, fmt);
    Wwarnv(fmt, ap);
    fflush(ERR_STDERR);
    exit(eval);
    /* NOTREACHED */
}
#endif  /* _ERR_WINDOWS */

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

