/*
 * Copyright 2013-2015, Bromium, Inc.
 * Author: Kris Uchronski <kuchronski@gmail.com>
 * SPDX-License-Identifier: ISC
 */

#include "storflt.h"


#ifdef LOGGING_ENABLED

VOID StorfltLogHex(__in PVOID pData, __in const ULONG cbDataSize)
{
#define COLUMNS 16

    char line[COLUMNS + 2 + COLUMNS * 3 + COLUMNS + 1];
    char *pPos = line;
    size_t i, j;

    /* Make sure we're not eating too much of kernel stack */
    C_ASSERT(sizeof(line) < 84);

    ASSERT_IRQL(CLOCK_LEVEL - 1);
    ASSERT(NULL != pData);

    for (i = 0;
         i < (cbDataSize + ((cbDataSize % COLUMNS) ?
                            (COLUMNS - cbDataSize % COLUMNS) : 0));
         i++)
    {
        if (i % COLUMNS == 0) {
            /* Print address of current line content */
            pPos += sprintf_s(pPos, sizeof(line) - (pPos - line),
                              "%p: ",
                              (char *)pData + i);
        }

        if (i < cbDataSize) {
            /* Print data as hex */
            pPos += sprintf_s(pPos, sizeof(line) - (pPos - line),
                              "%02x ",
                              0xFF & ((char *)pData)[i]);
        } else {
            pPos += sprintf_s(pPos, sizeof(line) - (pPos - line), "   ");
        }

        if (i % COLUMNS == (COLUMNS - 1)) {
            /* Print char representation of all bytes contained in the line */
            for (j = i - (COLUMNS - 1); j <= i; j++) {
                if (j >= cbDataSize) {
                    pPos += sprintf_s(pPos, sizeof(line) - (pPos - line), " ");
                } else if (isprint(((char *)pData)[j])) {
                    pPos += sprintf_s(pPos, sizeof(line) - (pPos - line),
                                      "%c",
                                      0xFF & ((char*)pData)[j]);
                } else {
                    pPos += sprintf_s(pPos, sizeof(line) - (pPos - line), ".");
                }
            }
            uxen_debug("%s\n", line);
            pPos = line;
        }
    }
}

#endif /* LOGGING_ENABLED */