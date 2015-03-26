/*
 * Copyright 2013-2015, Bromium, Inc.
 * Author: Julian Pidancet <julian@pidancet.net>
 * SPDX-License-Identifier: ISC
 */

#include <stdlib.h>
#include <stdint.h>

#include "smbios.h"

void *
__smbios_get_struct(char *start, char *end,
                    int type_start, int type_end,
                    size_t *out_len)
{
    struct smbios_struct_header *hdr;

    hdr = (void *)start;

    while ((char *)(hdr + 1) < end) {
        char *p = (void *)hdr;
        size_t len;

        p += hdr->length;
        if (p >= end)
            break;

        /* Lookup the end of the non-formated section */
        while(p < end - 1) {
            if (p[0] == '\0' && p[1] == '\0') {
                p += 2;
                break;
            }
            p++;
        }

        len = p - (char *)hdr;

        if (type_start <= hdr->type && hdr->type <= type_end) {
            *out_len = len;
            return hdr;
        }

        hdr = (struct smbios_struct_header *)p;
    }

    return NULL;
}

