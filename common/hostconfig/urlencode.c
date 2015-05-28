/*
 * Copyright 2015, Bromium, Inc.
 * SPDX-License-Identifier: ISC
 */

#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <ctype.h>

char *
urlencode(const unsigned char *data, size_t len)
{
    size_t out_len;
    size_t i, o;
    char *output;
    int c;

    out_len = (len * 3) + 1;
    output = calloc(1, out_len);
    if (!output)
        return NULL;

    i = 0;
    o = 0;
    while (i < len) {
        c = data[i++];
#define atoxd(v) (((v) >= 0xA) ? (((v) - 0xA) + 'A') : ((v) + '0'))
        if (!isprint(c)) {
            output[o++] = '%';
            output[o++] = atoxd(c >> 4);
            output[o++] = atoxd(c & 0xF);
        } else
            output[o++] = c;
    }

    output[o++] = '\0';

    return output;
}
