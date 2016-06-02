/*
 * Copyright 2016, Bromium, Inc.
 * Author: Tomasz Wroblewski <tomasz.wroblewski@gmail.com>
 * SPDX-License-Identifier: ISC
 */

#include "config.h"
#include <fcntl.h>

/* Set to default if NULL and set to NULL if "-", to select console */
void
redir_stderr(const char *name, const char *defname, int append)
{
    int fd;

    if (!name)
        name = defname;
    else if (!strcmp(name, "-"))
        name = NULL;

    if (name) {
        fd = open(name, O_CREAT | O_RDWR | (append ? O_APPEND : O_TRUNC), 0666);
        if (fd != -1)
            dup2(fd, 2);
    }

    setlinebuf(stderr);
}

initcall(logging_prepare)
{
#ifdef DEBUG_INITCALLS
    initcall_logging = 1;
#else
    char *str;
    str = getenv("UXENDM_INITCALL_LOG");
    initcall_logging = str ? atoi(str) : 0;
#endif
    logstyle_set(getenv("UXENDM_LOGSTYLE"));
    redir_stderr(getenv("UXENDM_LOGFILE"), "uxendm.log",
                 getenv("UXENDM_LOGFILE_APPEND") != NULL);
 }
