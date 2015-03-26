/*
 * Copyright 2013-2015, Bromium, Inc.
 * Author: Jacob Gorm Hansen <jacobgorm@gmail.com>
 * SPDX-License-Identifier: ISC
 */

#include <err.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

FILE *logfile = NULL;

static void __attribute__((constructor))
disklib_init(void) {
    char *logname;
    char l[256];

    /* Check for BRHV_LOG_DEST first to be compatible with Krypton. */
    logname = getenv("BRHV_LOG_DEST");
    if (logname && !strncmp(logname, "dir=", 4)) {
        logname += 4;
        strcpy(l, logname);
        strcat(l, "\\img-tools.log");
        logname = l;
    }

    /* Else check IMGTOOLS_LOGFILE. */
    if (!logname)
        logname = getenv("IMGTOOLS_LOGFILE");

    if (logname)
        logfile = fopen(logname, "a");

    if (!logfile)
        logfile = stderr;
}
