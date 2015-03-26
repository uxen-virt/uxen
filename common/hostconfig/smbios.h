/*
 * Copyright 2013-2015, Bromium, Inc.
 * Author: Julian Pidancet <julian@pidancet.net>
 * SPDX-License-Identifier: ISC
 */

#ifndef _SMBIOS_H_
#define _SMBIOS_H_

struct smbios_struct_header {
    uint8_t     type;
    uint8_t     length;
    uint16_t    handle;
};

void *
__smbios_get_struct(char *start, char *end,
                    int type_start, int type_end,
                    size_t *out_len);

#endif /* _SMBIOS_H_ */
