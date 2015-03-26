/*
 * Copyright 2011-2015, Bromium, Inc.
 * Author: Gianni Tedesco
 * SPDX-License-Identifier: ISC
 */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "disklib.h"

#include <ctype.h>

void hex_dump(const uint8_t *tmp, size_t len, size_t llen, int depth)
{
    size_t i, j;
    size_t line;

    if ( 0 == len )
        return;

    for(j = 0; j < len; j += line, tmp += line) {
        if ( j + llen > len ) {
            line = len - j;
        }else{
            line = llen;
        }

        RTPrintf("%*c%05"PRIxS" : ", depth, ' ', j);

        for(i = 0; i < line; i++) {
            if ( isprint(tmp[i]) && !(tmp[i] & 0x80) && tmp[i] > 0x19) {
                RTPrintf("%c", tmp[i]);
            }else{
                RTPrintf(".");
            }
        }

        for(; i < llen; i++)
            RTPrintf(" ");

        for(i = 0; i < line; i++)
            RTPrintf(" %02x", tmp[i]);

        RTPrintf("\n");
    }
    RTPrintf("\n");
}
