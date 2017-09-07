/*
 * Copyright 2017, Bromium, Inc.
 * Author: Piotr Foltyn <piotr.foltyn@gmail.com>
 * SPDX-License-Identifier: ISC
 */

#ifndef _WMI_H_
#define _WMI_H_

int get_raw_smb_table_using_wmi(struct smbios_header **table, size_t *size);

#endif /* _WMI_H_ */
