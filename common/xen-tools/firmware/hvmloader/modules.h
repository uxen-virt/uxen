/*
 * modules.h: Defs for HVM firmware modules support.
 *
 * Copyright (c) 2012 Ross Philipson, Citrix Systems Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 59 Temple
 * Place - Suite 330, Boston, MA 02111-1307 USA.
 */
/*
 * uXen changes:
 *
 * Copyright 2012-2015, Bromium, Inc.
 * Author: Julian Pidancet <julian@pidancet.net>
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

#ifndef __HVMLOADER_MODULES_H__
#define __HVMLOADER_MODULES_H__

struct hvm_modules_iterator {
    uint32_t flags;
    uint32_t module_index;
    uint32_t entry_index;
    struct hvm_module *curr_module;
    struct hvm_module_entry *curr_entry;
    
    union {
        struct {
            uint8_t range_start;
            uint8_t range_end;
        } smbios;
        struct {
            char signature[4];
            int iterate_all;
        } acpi;
    } type;
};

void init_hvm_modules(uint32_t paddr);

void init_smbios_module_iterator(struct hvm_modules_iterator *iter,
                                 uint8_t smbios_type_start,
                                 uint8_t smbios_type_end);

void init_acpi_module_iterator(struct hvm_modules_iterator *iter,
                               const char *signature,
                               int iterate_all);

void *hvm_find_module_entry(struct hvm_modules_iterator *iter,
                            uint32_t *length_out);

#endif /* __HVMLOADER_MODULES_H__ */
/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
