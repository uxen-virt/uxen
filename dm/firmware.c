/*
 * Copyright 2012-2015, Bromium, Inc.
 * Author: Julian Pidancet <julian@pidancet.net>
 * SPDX-License-Identifier: ISC
 */

#include "config.h"

#include <err.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

#include "firmware.h"

struct fw_list_head acpi_modules = TAILQ_HEAD_INITIALIZER(acpi_modules);
struct fw_list_head smbios_modules = TAILQ_HEAD_INITIALIZER(smbios_modules);

struct smbios_struct_header {
    uint8_t     type;
    uint8_t     length;
    uint16_t    handle;
};

struct smc_data {
    char key[4];
    uint8_t *data;
    size_t len;
    TAILQ_ENTRY(smc_data) link;
};

static TAILQ_HEAD(, smc_data) smc_keys = TAILQ_HEAD_INITIALIZER(smc_keys);

int
smc_enabled(void)
{
    return !TAILQ_EMPTY(&smc_keys);
}

int
smc_key_add(const char *key, void *data, size_t len)
{
    struct smc_data *d;

    if (strlen(key) != 4)
        return -1;

    d = calloc(1, sizeof(*d));
    if (!d)
        return -1;

    memcpy(d->key, key, 4);
    d->data = data;
    d->len = len;
    TAILQ_INSERT_TAIL(&smc_keys, d, link);

    return 0;
}

void *
smc_key_lookup(const char *key, size_t *len)
{
    struct smc_data *d;

    TAILQ_FOREACH(d, &smc_keys, link) {
        if (!strncmp(d->key, key, 4)) {
            *len = d->len;
            return d->data;
        }
    }

    return NULL;
}

int
acpi_module_add(void *data, size_t len)
{
    struct firmware_info *fi;

    fi = calloc(1, sizeof(*fi));
    if (!fi)
        return -1;

    fi->data = data;
    fi->len = len;
    TAILQ_INSERT_TAIL(&acpi_modules, fi, link);

    return 0;
}

int
smbios_module_add(void *data, size_t len)
{
    struct firmware_info *fi;

    fi = calloc(1, sizeof(*fi));
    if (!fi)
        return -1;

    fi->data = data;
    fi->len = len;
    TAILQ_INSERT_TAIL(&smbios_modules, fi, link);

    return 0;
}

int
smbios_add_drive_property(void *data, size_t len)
{
    static uint16_t handle = 0xF080; /* Must be unique for each table */
    struct smbios_struct_header *table;
    int ret = 0;

    while (len) {
        size_t l = len;

        if (l > (255 - sizeof (*table)))
            l = (255 - sizeof (*table));

        table = calloc(1, sizeof(*table) + l + 2);
        if (!table)
            return -1;
        memcpy(table + 1, data, l);
        memset((char *)(table + 1) + l, 0x0, 2);

        table->type = 0xE9; /* OEM-type */
        table->handle = handle++;
        table->length = sizeof(*table) + l;

        ret = smbios_module_add(table, sizeof(*table) + l + 2);
        if (ret) {
            free(table);
            break;
        }

        len -= l;
        data += l;
    }

    return ret;
}


