/*
 * Copyright 2015, Bromium, Inc.
 * SPDX-License-Identifier: ISC
 */

#ifndef _SMBIOS_H_
#define _SMBIOS_H_

struct smbios_struct_header {
    uint8_t type;
    uint8_t length;
    uint16_t handle;
};

int smbios_find_struct_table(char *range, size_t range_len,
                             uint64_t *smbios_structure_table,
                             size_t *smbios_structure_table_len);

void * smbios_get_struct(char *smbios_data, size_t smbios_data_len,
                         uint8_t type, uint16_t handle,
                         size_t *out_len);

#endif /* _SMBIOS_H_ */
