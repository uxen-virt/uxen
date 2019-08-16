/******************************************************************************
 * xenguest.h
 *
 * A library for guest domain management in Xen.
 *
 * Copyright (c) 2003-2004, K A Fraser.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation;
 * version 2.1 of the License.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */
/*
 * uXen changes:
 *
 * Copyright 2012-2019, Bromium, Inc.
 * Author: Christian Limpach <Christian.Limpach@gmail.com>
 * SPDX-License-Identifier: ISC
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
 * SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION
 * OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
 * CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#ifndef XENGUEST_H
#define XENGUEST_H

enum xc_hvm_module_type {
    XC_HVM_MODULE_ACPI = 0,
    XC_HVM_MODULE_SMBIOS,
};

struct xc_hvm_mod_entry {
    int flags;
    size_t len;
    void *base;
};

struct xc_hvm_module {
    int type;
    size_t nent; /* Number of entries in the module */
    struct xc_hvm_mod_entry *entries;
};

#define XC_HVM_OEM_ID           (1 << 0)
#define XC_HVM_OEM_TABLE_ID     (1 << 1)
#define XC_HVM_OEM_REVISION     (1 << 2)
#define XC_HVM_CREATOR_ID       (1 << 3)
#define XC_HVM_CREATOR_REVISION (1 << 4)
#define XC_HVM_SMBIOS_MAJOR     (1 << 5)
#define XC_HVM_SMBIOS_MINOR     (1 << 6)

struct xc_hvm_oem_info {
    int flags;
    char oem_id[6];
    char oem_table_id[8];
    uint32_t oem_revision;
    char creator_id[4];
    uint32_t creator_revision;
    uint8_t smbios_version_major;
    uint8_t smbios_version_minor;
};

int xc_hvm_build(xc_interface *xch,
                 uint32_t domid,
                 int memsize,
                 uint32_t nr_vcpus,
                 uint32_t nr_ioreq_servers,
                 const char *image_name,
                 struct xc_hvm_module *modules,
                 size_t mod_count,
                 struct xc_hvm_oem_info *oem_info);

/* attovm build flags */

#endif /* XENGUEST_H */
