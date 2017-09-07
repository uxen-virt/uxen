/*
 * Copyright 2013-2017, Bromium, Inc.
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

struct smbios_header {
    uint8_t     calling_method;
    uint8_t     major_version;
    uint8_t     minor_version;
    uint8_t     dmi_revision;
    uint32_t    length;
};

void *
__smbios_get_struct(char *start, char *end,
                    int type_start, int type_end,
                    size_t *out_len);

#endif /* _SMBIOS_H_ */
