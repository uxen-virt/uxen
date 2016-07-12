/*
 * Copyright 2012-2016, Bromium, Inc.
 * Author: Christian Limpach <Christian.Limpach@gmail.com>
 * SPDX-License-Identifier: ISC
 */

#include "config.h"

#include <err.h>
#include <fcntl.h>
#include <signal.h>
#include <stdint.h>

#include <shellapi.h>
#include <wincrypt.h>

#include "dm.h"
#include "vm.h"
#include "guest-agent.h"

int initcall_logging = 0;

#ifndef LIBIMG

DECLARE_PROGNAME = "uxendm";

/* Global instance handle, set by WinMain(). */
HINSTANCE g_instance;
int g_showwindow;

uint64_t process_shutdown_priority = 0x280;

void
socket_cleanup(void)
{

    WSACleanup();
}

int
socket_init(void)
{
    WSADATA Data;
    int ret;

    ret = WSAStartup(MAKEWORD(2,2), &Data);
    if (ret)
        Werr(1, "WSAStartup: %d", ret);

    return 0;
}

void
socket_set_block(int fd)
{
    unsigned long opt = 0;

    ioctlsocket(fd, FIONBIO, &opt);
}

void
socket_set_nonblock(int fd)
{
    unsigned long opt = 1;

    ioctlsocket(fd, FIONBIO, &opt);
}

int
get_timeoffset(void)
{
    TIME_ZONE_INFORMATION tz;
    int ret;

    ret = GetTimeZoneInformation(&tz);
    return -60 * (tz.Bias + ((ret==2) ? tz.DaylightBias : 0));
}

void
windows_time_update(void)
{
    DYNAMIC_TIME_ZONE_INFORMATION dtzi;

    GetDynamicTimeZoneInformation(&dtzi);

    guest_agent_set_dynamic_time_zone(&dtzi);
}

int
inet_aton(const char *cp, struct in_addr *ia)
{
    uint32_t addr = inet_addr(cp);

    if (addr == 0xffffffff)
	return 0;
    ia->s_addr = addr;
    return 1;
}
#endif  /* LIBIMG */

static HCRYPTPROV crypt_provider = 0;

static void __attribute__((constructor))
os_early_init(void)
{
    BOOL rc;

    rc = CryptAcquireContext(&crypt_provider, NULL, NULL, PROV_RSA_FULL,
                             CRYPT_VERIFYCONTEXT | CRYPT_SILENT);
    if (!rc) {
        errx(1, "CryptAcquireContext");
    }
}

int
generate_random_bytes(void *buf, size_t len)
{
    BOOL rc;

    rc = CryptGenRandom(crypt_provider, len, buf);
    if (!rc)
        return -1;

    return 0;
}

int
c99_vsnprintf(char *buf, size_t len, const char *fmt, va_list ap)
{
    int ret;

    if(buf) {
        ret = _vsnprintf(buf, len, fmt, ap);
        if (ret != -1 && ret < len)
            return ret;
        buf[len - 1] = '\0';
    }

    return _vscprintf(fmt, ap);
}

int
c99_snprintf(char *buf, size_t len, const char *fmt, ...)
{
    va_list ap;
    int ret;

    va_start(ap, fmt);
    ret = c99_vsnprintf(buf, len, fmt, ap);
    va_end(ap);
    return ret;
}


int
vasprintf(char **strp, const char *fmt, va_list ap)
{
    size_t buflen = 512;
    int ret;
    va_list cp;

    *strp = malloc(buflen);
    if (*strp == NULL)
        return -1;
    while (1) {
        char *tmp;

        /* Work on a copy of ap in case we need to realloc. */
        va_copy(cp, ap);
        ret = _vsnprintf(*strp, buflen, fmt, cp);
        if (ret != -1 && ret < buflen) {
            va_end(cp);
            break;
        }
        if (ret == -1 && errno != ERANGE) {
            free(*strp);
            *strp = NULL;
            va_end(cp);
            break;
        }
        buflen *= 2;
        assert(buflen <= 16777216);

        tmp = realloc(*strp, buflen);
        if (tmp == NULL) {
            ret = -1;
            free(*strp);
            *strp = NULL;
            va_end(cp);
            break;
        }
        *strp = tmp;
        va_end(cp);
    }

    assert(ret == -1 || (*strp)[ret] == '\0');

    return ret;
}

int
asprintf(char **strp, const char *fmt, ...)
{
    va_list ap;
    int ret;

    va_start(ap, fmt);
    ret = vasprintf(strp, fmt, ap);
    va_end(ap);
    return ret;
}

#ifndef LIBIMG
/* XXX RtlSecureZeroMemory is missing on -O0 builds */
#ifdef __CRT__NO_INLINE
    /* __CRT_INLINE */ PVOID WINAPI RtlSecureZeroMemory(PVOID ptr,SIZE_T cnt) {
      volatile char *vptr =(volatile char *)ptr;
#ifdef __x86_64
      __stosb((PBYTE)((DWORD64)vptr),0,cnt);
#else
      while(cnt) {
	*vptr = 0;
	vptr++;
	cnt--;
      }
#endif /* __x86_64 */
      return ptr;
    }
#endif /* __CRT__NO_INLINE */
#endif  /* LIBIMG */

#ifndef LIBIMG
/* Convert a wide string to UTF8. */
static char *
utf8(const wchar_t *ws)
{
    int sz;
    char *s;

    /* First figure out buffer size needed and malloc it. */
    sz = WideCharToMultiByte(CP_UTF8, 0, ws, -1, NULL, 0, NULL, 0);
    if (!sz)
        return NULL;

    s = (char *)malloc(sz + sizeof(char));
    if (s == NULL)
        return NULL;
    s[sz] = 0;

    /* Now perform the actual conversion. */
    sz = WideCharToMultiByte(CP_UTF8, 0, ws, -1, s, sz, NULL, 0);
    if (!sz) {
        free(s);
        s = NULL;
    }

    return s;
}

static void
exit_handler(int signo)
{

    vm_shutdown_sync();
    warnx("%s: exiting", __FUNCTION__);

    fflush(stderr);
}

/* The actual entry point, since this is a Win32 GUI application.
 * The actual main() is in dm.c. */
int WINAPI
WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance,
        LPSTR szCmdLine, int iCmdShow)
{
    wchar_t **argv_w;
    int argc;
    char **argv;
    wchar_t *s;
    int i;
    int status;

    /* Not sure why we need this, but squirrel it for hard times. */
    g_instance = hInstance;
    g_showwindow = iCmdShow;

    /* Get wide-char argv and set program name. */
    argv_w = CommandLineToArgvW(GetCommandLineW(), &argc);
    if (!argv_w)
        Werr(1, "CommandLineToArgvW");
    setprogname(utf8(argv_w[0]));

    signal(SIGINT, exit_handler);
    signal(SIGTERM, exit_handler);
    signal(SIGBREAK, exit_handler);

    /* Create non-wide-char argv */
    argv = (char **)malloc(sizeof(char *) * argc);
    if (argv == NULL)
        err(1, "malloc");

    for (i = 0; i < argc; i++) {
        argv[i] = utf8(argv_w[i]);
        if (!argv[i])
            errx(1, "utf8(arg %d)", i);
    }

    i = GetFullPathNameW(argv_w[0], 0, NULL, NULL);
    if (!i)
        Werr(1, "GetFullPathName");
    s = calloc(1, sizeof(wchar_t) * i);
    if (!s)
        err(1, "calloc(full dm_path)");
    i = GetFullPathNameW(argv_w[0], i, s, NULL);
    if (!i)
        Werr(1, "GetFullPathName");

    dm_path = utf8(s);
    if (!dm_path)
        err(1, "utf8(dm_path)");
    free(s);

    strip_filename(dm_path);

    status = dm_main(argc, argv);

    /* exit() so that atexit runs */
    exit(status);
}

void
cpu_usage(float *user, float *kernel, uint64_t *user_total_ms,
          uint64_t *kernel_total_ms)
{
    static uint64_t last_kernel_time = 0;
    static uint64_t last_user_time = 0;
    static uint64_t last_time = 0;
    uint64_t current_time;
    uint64_t kernel_time;
    uint64_t user_time;
    FILETIME dummy1, dummy2;
    BOOL rc;

    rc = GetProcessTimes(GetCurrentProcess(),
                         &dummy1,
                         &dummy2,
                         (FILETIME *)&kernel_time,
                         (FILETIME *)&user_time);
    if (!rc)
        return;

    current_time = GetTickCount64() * 10000ULL;

    if (!last_time || (last_time == current_time)) {
        if (user) *user = .0;
        if (kernel) *kernel = .0;
    } else {
        if (user) *user = (float)(user_time - last_user_time) /
                          (float)(current_time - last_time);
        if (kernel) *kernel = (float)(kernel_time - last_kernel_time) /
                              (float)(current_time - last_time);
    }

    if (user_total_ms) *user_total_ms = user_time / 10000;
    if (kernel_total_ms) *kernel_total_ms = kernel_time / 10000;

    last_kernel_time = kernel_time;
    last_user_time = user_time;
    last_time = current_time;
}

#endif  /* LIBIMG */
