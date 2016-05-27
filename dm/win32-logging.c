/*
 * Copyright 2015-2016, Bromium, Inc.
 * Author: Christian Limpach <Christian.Limpach@gmail.com>
 * SPDX-License-Identifier: ISC
 */

#include "config.h"
#include "dm.h"

/* Set to default if NULL and set to NULL if "-", to select console */
static void
redir_stderr(wchar_t *name, wchar_t *defname, int append)
{
    FILE* f;
    int fd;
    int open_fail_fatal = 0;
    HANDLE h = INVALID_HANDLE_VALUE;

    if (!name)
        name = defname;
    else if (!wcscmp(name, L"-"))
        name = NULL;

    /* ! prefix disables fallback if logfile can't be opened */
    if (name && name[0] == '!') {
        open_fail_fatal = 1;
        name++;
    }
    /* + prefix enables append mode */
    if (name && name[0] == '+') {
        append = 1;
        name++;
    }

    /* Get Win32 HANDLE for stderr file. If '-' argument set, or unable to open
     * the default/selected file, open handle on console. */
    if (name) {
        h = CreateFileW(name,
                        append ? FILE_APPEND_DATA : GENERIC_WRITE,
                        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                        NULL,
                        append ? OPEN_ALWAYS : CREATE_ALWAYS,
                        FILE_ATTRIBUTE_NORMAL, NULL);
        if (h == INVALID_HANDLE_VALUE && open_fail_fatal)
            Werr(1, "unable to open log file %ls", name);
    }
    if (h == INVALID_HANDLE_VALUE) {
        AllocConsole();
        h = GetStdHandle(STD_ERROR_HANDLE);
    }
    if (h != INVALID_HANDLE_VALUE) {
        fd = _open_osfhandle((intptr_t) h, _O_TEXT);
        if (fd != -1 && fd != -2) {
            f = _fdopen(fd, "w");
            if (f != NULL) {
                /* flush old stderr */
                fflush(stderr);
                *stderr = *f;
                setvbuf(stderr, NULL, _IONBF, 0);
            }
        }
    }
}

void early_init_win32_logging(void)
{
    redir_stderr(_wgetenv(L"UXENDM_LOGFILE"), L"uxendm.log",
                 getenv("UXENDM_LOGFILE_APPEND") != NULL);
    logstyle_set(getenv("UXENDM_LOGSTYLE"));
}
