/*
 * Copyright 2012-2015, Bromium, Inc.
 * Author: Christian Limpach <Christian.Limpach@gmail.com>
 * SPDX-License-Identifier: ISC
 */

#include "config.h"

#include <ctype.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

int
strstart(const char *str, const char *val, const char **ptr)
{

    while (*val != '\0') {
        if (*val != *str)
            return 0;
        val++;
        str++;
    }
    if (ptr)
        *ptr = str;
    return 1;
}

int
stristart(const char *str, const char *val, const char **ptr)
{

    while (*val != '\0') {
        if (toupper(*val) != toupper(*str))
            return 0;
        val++;
        str++;
    }
    if (ptr)
        *ptr = str;
    return 1;
}

void
strip_filename(char *path) {
    char *l = path, *p = l;
    assert(p);
    if (!*p)
        return;
    while (*p) {
        switch (*p) {
#ifdef _WIN32
        case ':':
            if (l == path)
                l = p;
            break;
#endif
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
