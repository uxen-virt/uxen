/*
 * Copyright 2015, Bromium, Inc.
 * SPDX-License-Identifier: ISC
 */

#include "uxenstor.h"
#include "smbios.h"

struct smbios_entry_point_structure {
    char        anchor_string[4];
    uint8_t     checksum;
    uint8_t     length;
    uint8_t     smbios_major_version;
    uint8_t     smbios_minor_version;
    uint16_t    max_structure_size;
    uint8_t     entry_point_revision;
    uint8_t     formatted_area[5];
    char        intermediate_anchor_string[5];
    uint8_t     intermediate_checksum;
    uint16_t    structure_table_length;
    uint32_t    structure_table_address;
    uint16_t    number_of_structures;
    uint8_t     smbios_bcd_revision;
};

static 
uint8_t checksum(char *buffer, size_t len)
{
    size_t i;
    uint8_t checksum = 0;

    ASSERT(0 == len || buffer);

    for (i = 0; i < len; i++)
        checksum += buffer[i];

    return checksum;
}

int smbios_find_struct_table(char *range, size_t range_len,
                             uint64_t *smbios_structure_table,
                             size_t *smbios_structure_table_len)
{
    const char anchor_str[] = {0x5F, 0x53, 0x4D, 0x5F};
    struct smbios_entry_point_structure *eps = NULL;
    int found = 0;
    char *range_end = NULL;
    uint8_t eps_len = 0;

    ASSERT(range && range_len >= sizeof(struct smbios_entry_point_structure));
    ASSERT(smbios_structure_table && smbios_structure_table_len);

    range_end = range + range_len - sizeof(struct smbios_entry_point_structure);

    while (range <= range_end) {
        if (anchor_str[0] == range[0] && anchor_str[1] == range[1] &&
            anchor_str[2] == range[2] && anchor_str[3] == range[3])
        {
            eps = (struct smbios_entry_point_structure *)range;
            eps_len = min(eps->length,
                          sizeof(struct smbios_entry_point_structure));
            if (0 == checksum((char *)eps, eps_len)) {
                *smbios_structure_table = eps->structure_table_address;
                *smbios_structure_table_len = eps->structure_table_length;
                found = 1;
                break;
            }
        }
        range += 2;
    }

    return found;
}

static
void * __smbios_get_struct(char *start, char *end,
                           uint8_t type, uint16_t handle,
                           size_t *out_len)
{
    struct smbios_struct_header *hdr;

    ASSERT(start && end);
    ASSERT(out_len);

    hdr = (void *)start;

    while ((char *)(hdr + 1) < end) {
        char *p = (void *)hdr;
        size_t len;

        p += hdr->length;
        if (p >= end)
            break;

        /* Lookup the end of the non-formated section */
        while (p < end - 1) {
            if (p[0] == '\0' && p[1] == '\0') {
                p += 2;
                break;
            }
            p++;
        }

        len = p - (char *)hdr;

        if (type == hdr->type && handle == hdr->handle) {
            *out_len = len;
            return hdr;
        }

        hdr = (struct smbios_struct_header *)p;
    }

    return NULL;
}

void * smbios_get_struct(char *smbios_data, size_t smbios_data_len,
                         uint8_t type, uint16_t handle,
                         size_t *out_len)
{
    char *start, *end;

    ASSERT(smbios_data);
    ASSERT(smbios_data_len >= sizeof(struct smbios_struct_header));

    start = smbios_data;
    end = smbios_data + smbios_data_len;

    return __smbios_get_struct(start, end, type, handle, out_len);
}
