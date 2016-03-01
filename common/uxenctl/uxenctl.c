/*
 *  uxenctl.c
 *  uxen
 *
 * Copyright 2012-2016, Bromium, Inc.
 * Author: Christian Limpach <Christian.Limpach@gmail.com>
 * SPDX-License-Identifier: ISC
 *
 */

#ifdef _WIN32
#define ERR_WINDOWS
#endif
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <signal.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <limits.h>
#include <inttypes.h>
#ifdef __APPLE__
#include <libgen.h>
#endif
#if defined(_WIN32)
#define _POSIX
#endif
#include <time.h>
#include <sys/time.h>

#include <uuid/uuid.h>

#include "uxenctllib.h"

#ifdef _WIN32
DECLARE_PROGNAME;
#endif  /* _WIN32 */

static void exit_handler(int signo);
static void redir_stderr(const char *logfile);
static int fork_exec(const char *path, char *const argv[]);

static UXEN_HANDLE_T handle;
static int uxen_connection_open = FALSE;

#define LOG_SIZE 16384

static void
usage(const char *progname)
{
    fprintf(stderr, "usage: %s [-R] [-L] [--load file] [-i] "
            "[-s] [-w] [--unload] [-U] [-I arg] [-I arg] ...\n", progname);
    fprintf(stderr, "       %s [-v]\n", progname);
    fprintf(stderr, "       %s [-d uuid]\n", progname);
    fprintf(stderr, "       %s [-k keys]\n", progname);
    fprintf(stderr, "       %s [-p {suspend,resume}]\n", progname);
    fprintf(stderr, "       %s [-P path]\n", progname);
    fprintf(stderr, "       %s [-x] [-X] [--logfile file]\n", progname);
    fprintf(stderr, "       %s [--log-daemon]\n", progname);
    fprintf(stderr, "       %s [--log-ratelimit-ms arg]\n", progname);
    fprintf(stderr, "       %s [--log-ratelimit-burst arg]\n", progname);
    exit(1);
}

static void __attribute__ ((noreturn))
do_unload_driver(void)
{
    int ret;

    ret = uxen_manage_driver(FALSE, FALSE, NULL);
    if (ret)
        warnx("unload driver failed");

    exit(0);
}

static int
list_vm_cb(struct uxen_queryvm_desc *uqd, void *opaque)
{
    FILE *f = (FILE *)opaque;
    char uuid_str[37];

    uuid_unparse_lower(uqd->uqd_vmuuid, uuid_str);
    fprintf(f, "uuid %s domid %d\n", uuid_str, uqd->uqd_domid);

    return 0;
}

static void
set_path(const char *progname, char **out_path)
{
#ifdef __APPLE__
    char buf[PATH_MAX];

    realpath(progname, buf);
    if (out_path)
        *out_path = strdup(dirname(buf));
#else
    if (out_path)
        *out_path = NULL;
#endif
}

int
main(int argc, char **argv, char **envp)
{
    int ret;
    int init = 0;
    int shutdown = 0;
    int wait_vm_exit = 0;
    char *load = NULL;
    int unload = 0;
    int version = 0;
    char *keys = NULL;
    int power = -1;
    int load_driver = 0;
    int reload_driver = 0;
    int unload_driver = 0;
    char *destroy_vm = NULL;
    int list_vms = 0;
    int log = 0;
    int log_daemon = 0;
    int log_dump = 0;
    xen_domain_handle_t vm_uuid;
    struct uxen_logging_buffer *logbuf;
    int logbuf_size = LOG_SIZE - sizeof(struct uxen_logging_buffer);
    UXEN_EVENT_HANDLE_T logging_event = NULL;
    char *logfile = NULL;
    char *path = NULL;
    struct uxen_init_desc init_args;
    int show_physinfo = 0;
    uxen_physinfo_t physinfo = { };
    uint64_t log_ratelimit_ms = 0;
    uint64_t log_ratelimit_burst = 0;

#ifdef _WIN32
    setprogname(argv[0]);
    uxen_set_logfile(stderr);
#endif  /* _WIN32 */

    set_path(argv[0], &path);

#ifdef SIGHUP
    signal(SIGHUP, exit_handler);
#endif
    signal(SIGINT, exit_handler);
    signal(SIGTERM, exit_handler);
#ifdef SIGQUIT
    signal(SIGQUIT, exit_handler);
#endif
#ifdef SIGBREAK
    signal(SIGBREAK, exit_handler);
#endif

    memset(&init_args,0,sizeof(init_args));

    while (1) {
        int c, index = 0;

        enum { LI_LOAD, LI_UNLOAD, LI_LOGFILE, LI_LOGDAEMON, LI_PHYSINFO,
               LI_LRMS, LI_LRBURST };

        static int long_index;
        static struct option long_options[] = {
            {"help",          no_argument,       NULL,       'h'},
            {"load",          required_argument, &long_index, LI_LOAD},
            {"init",          no_argument,       NULL,       'i'},
            {"init-args",     required_argument, NULL,       'I'},
            {"shutdown",      no_argument,       NULL,       's'},
            {"wait-vm-exit",  no_argument,       NULL,       'w'},
            {"unload",        no_argument,       &long_index, LI_UNLOAD},
            {"version",       no_argument,       NULL,       'v'},
            {"keys",          required_argument, NULL,       'k'},
            {"power",         required_argument, NULL,       'p'},
            {"load-driver",   no_argument,       NULL,       'L'},
            {"reload-driver", no_argument,       NULL,       'R'},
            {"unload-driver", no_argument,       NULL,       'U'},
            {"destroy-vm",    required_argument, NULL,       'd'},
            {"list-vms",      no_argument,       NULL,       'l'},
            {"log",           no_argument,       NULL,       'x'},
            {"logfile",       required_argument, &long_index, LI_LOGFILE},
            {"log-daemon",    no_argument,       &long_index, LI_LOGDAEMON},
            {"log-dump",      no_argument,       NULL,       'X'},
            {"path",          required_argument, NULL,       'P'},
            {"physinfo",      no_argument,       &long_index, LI_PHYSINFO},
            {"log-ratelimit-ms", required_argument, &long_index, LI_LRMS},
            {"log-ratelimit-burst", required_argument, &long_index, LI_LRBURST},
            {NULL,   0,                 NULL, 0}
        };

        long_index = 0;
        c = getopt_long(argc, argv, "hiI:swvk:p:LRUd:lxXP:", long_options,
                        &index);
        if (c == -1)
            break;

        switch (c) {
        case 0:
            switch (long_index) {
            case LI_LOAD:
                load = optarg;
                break;
            case LI_UNLOAD:
                unload = 1;
                break;
            case LI_LOGFILE:
                logfile = optarg;
                break;
            case LI_LOGDAEMON:
                log_daemon = 1;
                break;
            case LI_PHYSINFO:
                show_physinfo = 1;
                break;
            case LI_LRMS:
                sscanf(optarg, "%" SCNu64, &log_ratelimit_ms);
                break;
            case LI_LRBURST:
                sscanf(optarg, "%" SCNu64, &log_ratelimit_burst);
                break;
            }
            break;
        case 'h':
            usage(argv[0]);
            /* NOTREACHED */
        case 'I':
	    if (uxen_parse_init_arg(&init_args,optarg)) 
            	errx(1, "failed to parse init argument");
            /*Fall through*/
        case 'i':
            init = 1;
            break;
        case 's':
            shutdown = 1;
            break;
        case 'w':
            wait_vm_exit = 1;
            break;
        case 'v':
            version = 1;
            break;
        case 'k':
            keys = optarg;
            break;
        case 'p':
            if (!strcmp(optarg, "suspend"))
                power = 1;
            else if (!strcmp(optarg, "resume"))
                power = 0;
            else
                usage(argv[0]);
            break;
        case 'L':
            load_driver = 1;
            break;
        case 'R':
            reload_driver = 1;
            load_driver = 1;
            break;
        case 'U':
            unload_driver = 1;
            break;
        case 'd':
            destroy_vm = optarg;
            break;
        case 'l':
            list_vms = 1;
            break;
        case 'x':
            log = 1;
            break;
        case 'X':
            log_dump = 1;
            break;
        case 'P':
            path = optarg;
            break;
        }
    }

    if (log || log_dump || (!log_daemon && !getenv("UXENCTL_LOGDAEMON")))
        redir_stderr(logfile);

    if (reload_driver) {
        ret = uxen_manage_driver(FALSE, TRUE, path);
        if (ret)
            errx(1, "reload driver unload failed");
    }

    if (load_driver) {
        ret = uxen_manage_driver(TRUE, FALSE, path);
        if (ret)
            errx(1, "load driver failed");
    }

    if (init == 0 && shutdown == 0 && load == NULL && unload == 0 &&
        version == 0 && keys == NULL && destroy_vm == NULL && list_vms == 0 &&
        log == 0 && log_dump == 0 && show_physinfo == 0 && power == -1 &&
        wait_vm_exit == 0 && log_ratelimit_ms == 0 &&
        log_ratelimit_burst == 0) {
        if (load_driver)
            exit(0);
        if (unload_driver) {
            do_unload_driver();
            /* NOTREACHED */
        }
        usage(argv[0]);
        /* NOTREACHED */
    }

    handle = uxen_open(0, load != NULL, NULL);
    if (handle == INVALID_HANDLE_VALUE)
        errx(1, "uxen_open failed");
    uxen_connection_open = TRUE;

    if (!log && !log_dump && (log_daemon || getenv("UXENCTL_LOGDAEMON"))) {
        char *logdaemon_args[] = { argv[0], "--logfile", logfile,
                                   "-x", NULL };
        if (!logfile)
            logdaemon_args[2] = argv[0];
        ret = uxen_logging(handle, logbuf_size, NULL, &logbuf);
        if (ret)
            errx(1, "logging setup failed");
        ret = fork_exec(argv[0], logfile ? logdaemon_args : &logdaemon_args[2]);
        if (ret)
            err(1, "re-exec as logging daemon failed");
    }

    if (log || log_dump) {
        if (!log_dump) {
            ret = uxen_event_init(&logging_event);
            if (ret)
                errx(1, "logging event init failed");
        }
        ret = uxen_logging(handle, logbuf_size, logging_event, &logbuf);
        if (ret)
            errx(1, "logging setup failed");
    }

    if (load) {
        ret = uxen_load(handle, load);
        if (ret)
            errx(1, "load failed");
    }

    if (init) {
        ret = uxen_init(handle, &init_args);
        if (ret)
            errx(1, "init failed");
    }

    if (version) {
        ret = uxen_output_version_info(handle, stdout);
        if (ret)
            errx(1, "version failed");
    }

    if (keys) {
        ret = uxen_trigger_keyhandler(handle, keys);
        if (ret)
            errx(1, "trigger keyhandler failed");
    }

    if (power != -1) {
        ret = uxen_power(handle, power);
        if (ret)
            errx(1, "power failed");
    }

    if (log_ratelimit_ms || log_ratelimit_burst) {
        ret = uxen_log_ratelimit(handle, log_ratelimit_ms,
                                 log_ratelimit_burst);
        if (ret)
            errx(1, "log_ratelimit failed");
    }

    if (show_physinfo) {
        ret = uxen_physinfo(handle, &physinfo);
        if (ret)
            errx(1, "physinfo failed");
        fprintf(stdout, "nr_cpus: %u\n", physinfo.nr_cpus);
        fprintf(stdout, "cpu_khz: %u\n", physinfo.cpu_khz);
        fprintf(stdout, "total_pages: %lu\n",
                (unsigned long)physinfo.total_pages);
        fprintf(stdout, "used_pages: %lu\n",
                (unsigned long)physinfo.used_pages);
        fprintf(stdout, "free_pages: %lu\n",
                (unsigned long)physinfo.free_pages);
        fprintf(stdout, "total_hidden_pages: %lu\n",
                (unsigned long)physinfo.total_hidden_pages);
        fprintf(stdout, "used_hidden_pages: %lu\n",
                (unsigned long)physinfo.used_hidden_pages);
        fprintf(stdout, "free_hidden_pages: %lu\n",
                (unsigned long)physinfo.free_hidden_pages);
    }

    if (shutdown) {
        ret = uxen_shutdown(handle);
        if (ret && errno != EEXIST)
            errx(1, "shutdown failed");
    }

    if (destroy_vm) {
        ret = uuid_parse(destroy_vm, vm_uuid);
        if (ret)
            errx(1, "uuid_parse failed");

        ret = uxen_destroy_vm(handle, vm_uuid);
        if (ret)
            errx(1, "uxen_destroy_vm failed");
    }

    if (list_vms) {
        ret = uxen_enum_vms(handle, list_vm_cb, stdout);
        if (ret)
            errx(1, "list_vms failed");
    }

    if (wait_vm_exit) {
        ret = uxen_wait_vm_exit(handle);
        if (ret)
            errx(1, "wait_vm_exit failed");
    }

    if (unload) {
        ret = uxen_unload(handle);
        if (ret)
            errx(1, "unload failed");
    }

    if (log || log_dump) {
        char *buf;
        uint64_t pos;
        uint32_t incomplete;

        pos = 0;
        while (1) {
            buf = uxen_logging_read(logbuf, &pos, &incomplete);
            if (buf) {
                static int had_newline = 1;
                struct tm _tm, *tm = &_tm;
                struct timeval tv;
                time_t ltime;

                if (logfile) {
                    gettimeofday(&tv, NULL);
                    ltime = (time_t)tv.tv_sec;
                    tm = localtime_r(&ltime, &_tm);
                }

                if (incomplete) {
                    if (!logfile)
                        warnx("[logbuf overflow -- output incomplete]");
                    else
                        warnx("%s%03d-%02d:%02d:%02d.%03d"
                              " [logbuf overflow -- output incomplete]",
                              had_newline ? "" : "\n",
                              tm->tm_yday, tm->tm_hour, tm->tm_min, tm->tm_sec,
                              (int)(tv.tv_usec / 1000));
                    had_newline = 1;
                }
                if (!logfile)
                    fputs(buf, stderr);
                else {
                    char *b = buf, *e;

                    while (*b) {
                        e = strchr(b, '\n');
                        if (e) {
                            e[0] = 0;
                            e++;
                        }
                        if (!had_newline)
                            fprintf(stderr, "%s%s", b, e ? "\n" : "");
                        else
                            fprintf(stderr, "%03d-%02d:%02d:%02d.%03d %s%s",
                                    tm->tm_yday, tm->tm_hour, tm->tm_min,
                                    tm->tm_sec,
                                    (int)(tv.tv_usec / 1000), b,
                                    e ? "\n" : "");
                        if (e) {
                            had_newline = 1;
                            b = e;
                        } else {
                            had_newline = 0;
                            break;
                        }
                    }
                }
                free(buf);
            }
            if (log_dump)
                break;
            ret = uxen_event_wait(handle, logging_event, -1);
            if (ret != 1)
                break;
        }
    }

    uxen_close(handle);
    uxen_connection_open = FALSE;

    if (unload_driver) {
        do_unload_driver();
        /* NOTREACHED */
    }

    return 0;
}

static void
exit_handler(int signo)
{

    if (uxen_connection_open) {
        uxen_close(handle);
        uxen_connection_open = FALSE;
    }
    exit(0);
}

#if defined(_WIN32)
static void
redir_stderr(const char *logfile)
{
    int append;
    FILE *hf = NULL;
    int hCrt;

    append = getenv("UXENCTL_LOGFILE_APPEND") != NULL;

    /* If unable to open the selected file, open console. */
    if (logfile)
        hf = fopen(logfile, append ? "a" : "w");
    else {
        wchar_t *name;
        name = _wgetenv(L"UXENCTL_LOGFILE");
        if (name)
            hf = _wfopen(name, append ? L"a" : L"w");
    }
    if (!hf) {
        AllocConsole();
        hCrt = _open_osfhandle((intptr_t)GetStdHandle(STD_ERROR_HANDLE),
                               _O_TEXT);
        hf = _fdopen(hCrt, "w");
    }
    if (hf) {
        *stderr = *hf;
        setvbuf(stderr, NULL, _IONBF, 0);
    }
}

static int
fork_exec(const char *path, char *const args[])
{
    int n, len;
    char *buf, *bufp;
    STARTUPINFO si;
    PROCESS_INFORMATION pi;

    len = strlen(path) + 1;     /* path + terminating NUL */
    for (n = 1; args[n]; n++)
        len += 1 + strlen(args[n]); /* space + arg */

    buf = calloc(1, len);
    if (!buf)
        err(1, "%s: calloc failed", __FUNCTION__);

    bufp = buf;
    sprintf(bufp, "%s", path);
    bufp += strlen(bufp);
    for (n = 1; args[n]; n++) {
        sprintf(bufp, " %s", args[n]);
        bufp += strlen(bufp);
    }

    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    ZeroMemory(&pi, sizeof(pi));

    if (!CreateProcess(NULL, buf, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi))
        Werr(1, "%s: CreateProcess failed", __FUNCTION__);

    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);

    free(buf);

    return 0;
}
#elif defined(__APPLE__)
static void
redir_stderr(const char *logfile)
{
    const char *name;
    int append;
    FILE *f;

    if (logfile)
        name = logfile;
    else
        name = getenv("UXENCTL_LOGFILE");

    append = getenv("UXENCTL_LOGFILE_APPEND") != NULL;

    if (name) {
        f = freopen(name, append ? "a" : "w", stderr);
        if (!f)
            stderr = fdopen(2, "w");
    }

    setlinebuf(stderr);
}

static int
fork_exec(const char *path, char *const args[])
{
    pid_t pid;
    int ret;

    pid = fork();
    switch (pid) {
    case 0:
        break;
    case -1:
        err(1, "%s: fork failed", __FUNCTION__);
        /* NOTREACHED */
        break;
    default:
        setsid();
        close(0);
        close(1);
        /* leave stderr open */
        ret = execv(path, args);
        if (ret)
            err(1, "%s: execv failed", __FUNCTION__);
        errx(1, "%s: execv returned without error", __FUNCTION__);
        /* NOTREACHED */
    }

    return 0;
}
#endif
