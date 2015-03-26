/*
 * Copyright 2012-2015, Bromium, Inc.
 * Author: Julian Pidancet <julian@pidancet.net>
 * SPDX-License-Identifier: ISC
 */

#ifndef _FIRMWARE_H_
#define _FIRMWARE_H_

#include "queue.h"

struct firmware_info {
    void *data;
    size_t len;
    TAILQ_ENTRY(firmware_info) link;
};

TAILQ_HEAD(fw_list_head, firmware_info);
extern struct fw_list_head acpi_modules;
extern struct fw_list_head smbios_modules;

int acpi_module_add(void *data, size_t len);
int smbios_module_add(void *data, size_t len);
int smbios_add_drive_property(void *data, size_t len);

int smc_key_add(const char *key, void *data, size_t len);
void *smc_key_lookup(const char *key, size_t *len);
int smc_enabled(void);

#endif /* _FIRMWARE_H_ */
