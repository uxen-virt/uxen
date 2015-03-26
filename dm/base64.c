/*
 * Copyright 2012-2015, Bromium, Inc.
 * SPDX-License-Identifier: ISC
 */

#include <string.h>
#include <stdlib.h>
#include <sys/types.h>

static const char digit_table[] = {
    'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H',
    'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
    'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X',
    'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f',
    'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n',
    'o', 'p', 'q', 'r', 's', 't', 'u', 'v',
    'w', 'x', 'y', 'z', '0', '1', '2', '3',
    '4', '5', '6', '7', '8', '9', '+', '/'
};

static char
digit_decode(char c)
{
    if (c >= 'A' && c <= 'Z')
        return c - 'A';
    else if (c >= 'a' && c <= 'z')
        return c - 'a' + 26;
    else if (c >= '0' && c <= '9')
        return c - '0' + 52;
    else if (c == '+')
        return 62;
    else if (c == '/')
        return 63;
    else if (c == '=')
        return 0;
    else
        return -1;
}

unsigned char *
base64_decode(const char *input, size_t *output_len)
{
    unsigned char *output;
    size_t in_len, len;
    size_t i = 0;
    size_t o = 0;

    in_len = strlen(input);
    if (!in_len || in_len % 4)
        return NULL;
    len = (in_len / 4) * 3;
    if (input[in_len - 1] == '=') {
        len--;
        if (input[in_len - 2] == '=')
            len--;
    }

    output = calloc(1, len);
    if (!output)
        return NULL;

    i = 0;
    o = 0;
    while (o < len) {
        int r = len - o;
        char a, b, c, d;

        if (r > 3)
            r = 3;

        a = digit_decode(input[i]);
        b = digit_decode(input[i + 1]);
        c = digit_decode(input[i + 2]);
        d = digit_decode(input[i + 3]);

        switch (r) {
        case 3: output[o + 2] = d | ((c & 0x3) << 6);
        case 2: output[o + 1] = (c >> 2) | ((b & 0xf) << 4);
        case 1: output[o + 0] = (b >> 4) | (a << 2);
        case 0:
            break;
        }

        o += r;
        i += 4;
    }

    *output_len = o;
    return output;
}


char *
base64_encode(const unsigned char *data, size_t len)
{
    size_t out_len;
    size_t i, o;
    char *output;

    out_len = ((len + 2) / 3) * 4 + 1;
    output = calloc(1, out_len);
    if (!output)
        return NULL;

    i = 0;
    o = 0;
    while (i < len) {
        unsigned int r = len - i;
        unsigned char i0;
        unsigned char i1 = 0;
        unsigned char i2 = 0;
        char o0, o1;
        char o2 = '=';
        char o3 = '=';

        if (r > 3)
            r = 3;

        switch (r) {
        case 3: i2 = data[i + 2];
                o3 = digit_table[i2 & 0x3f];
        case 2: i1 = data[i + 1];
                o2 = digit_table[((i1 & 0xf) << 2) | (i2 >> 6)];
        case 1: i0 = data[i];
                o1 = digit_table[((i0 & 0x3) << 4) | (i1 >> 4)];
                o0 = digit_table[i0 >> 2];
                break;
        case 0: goto out;    /* XXX gcc -O2 can't figure out that r != 0 */
        }

        output[o++] = o0;
        output[o++] = o1;
        output[o++] = o2;
        output[o++] = o3;

        i += r;
    }

  out:
    output[o++] = '\0';

    return output;
}

