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


static int xdtoa(char c)
{
    switch (c)
    {
        case '0':
        case '1':
        case '2':
        case '3':
        case '4':
        case '5':
        case '6':
        case '7':
        case '8':
        case '9':
                return c - '0';
        case 'a':
        case 'b':
        case 'c':
        case 'd':
        case 'e':
        case 'f':
                return 0xa + c - 'a';
        case 'A':
        case 'B':
        case 'C':
        case 'D':
        case 'E':
        case 'F':
                return 0xA + c - 'A';
        default:
                return -1;
    }
}

size_t urldecode(const char *str, char *output, size_t len)
{
    char *p, *end;

    p = output;
    end = p + len;

    while (*str && p < end) {
        if (str[0] == '%' && isxdigit(str[1]) && isxdigit(str[2])) {
            str++;
            *p = xdtoa(*str++) << 4;
            *p |= xdtoa(*str++);
            p++;
        } else
            *p++ = *str++;
    }

    return p - output;
}
