/*
 * modules.c: HVM firmware modules support.
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

#include <stdint.h>
#include <xen/xen.h>
#include <xen/version.h>
#include <xen/hvm/hvm_info_table.h>
#include "config.h"
#include "util.h"
#include "modules.h"

#define MODULE_ITERATOR_FLAG_SMBIOS 0x00000001
#define MODULE_ITERATOR_FLAG_ACPI   0x00000002

#define MODULE_INVALID_INDEX        0xffffffff

static struct hvm_module_info *module_info = NULL;

static int validate_hvm_module(struct hvm_module *module, uint32_t max_val)
{
    uint8_t sum = 0;
    uint8_t *ptr;
    uint32_t i;

    if ( strncmp(module->signature, HVM_MODULE_SIGNATURE, 8) )
        return 0;

    if ( module->length <= 
         (sizeof(struct hvm_module) + sizeof(struct hvm_module_entry)) )
        return 0;

    if ( module->length >= max_val )
        return 0;

    ptr = (uint8_t *)module;
    for ( i = 0; i < module->length; i++ )
        sum += ptr[i];

    if ( sum != 0 )
        return 0;

    return 1;
}

static int check_current_module_match(struct hvm_modules_iterator *iter)
{
    if ( (iter->flags & MODULE_ITERATOR_FLAG_SMBIOS)&&
         (iter->curr_module->type == HVM_MODULE_SMBIOS) )
        return 1;

    if ( (iter->flags & MODULE_ITERATOR_FLAG_ACPI)&&
         (iter->curr_module->type == HVM_MODULE_ACPI) )
        return 1;

    return 0;
}

static int check_current_table_match(struct hvm_modules_iterator *iter)
{
    uint8_t *ptr = (uint8_t*)(iter->curr_entry + 1);

    if ( iter->flags & MODULE_ITERATOR_FLAG_SMBIOS )
    {
        if ( iter->type.smbios.range_end != 0 )
        {
            if ( (iter->type.smbios.range_start <= ptr[0])&&
                 (ptr[0] <= iter->type.smbios.range_end) )
                return 1;
        }
        else if ( iter->type.smbios.range_start == ptr[0] )
            return 1;
    }

    if ( iter->flags & MODULE_ITERATOR_FLAG_ACPI )
    {
        if ( iter->type.acpi.iterate_all )
            return 1;
        if ( memcmp(ptr, iter->type.acpi.signature, 4) == 0 )
            return 1;
    }

    return 0;
}

static int find_next_module_match(struct hvm_modules_iterator *iter)
{
    int bval = 0;
    uint64_t *offsets = (uint64_t*)(module_info + 1);
    uint8_t *ptr = (uint8_t*)module_info;

    while ( iter->module_index < module_info->count )
    {        
        iter->curr_module =
            (struct hvm_module*)(ptr + offsets[iter->module_index]);

        iter->module_index++;

        /* Match the type of module requested or go on looking... */
        if ( !check_current_module_match(iter) )
            continue;

        /* Else another matching module was found. */
        iter->curr_entry = (struct hvm_module_entry*)(iter->curr_module + 1);
        iter->entry_index = 0;
        bval = 1;
        break;
    }

    /* If it reaches here and no next module is found the iteration
     * cannot continue.
     */
    if ( !bval )
    {
        iter->module_index = MODULE_INVALID_INDEX;
        iter->entry_index = MODULE_INVALID_INDEX;
        iter->curr_module = NULL;
        iter->curr_entry = NULL;
    }

    return bval;
}

static int find_next_entry_match(struct hvm_modules_iterator *iter)
{
    int bval = 0;
    uint8_t *ptr;
    uint32_t length;

    while ( iter->entry_index < iter->curr_module->count )
    {
        /* Already iterating through the module. */
        if ( iter->entry_index > 0 )
        {
            ptr = (uint8_t*)iter->curr_entry + sizeof(struct hvm_module_entry);
            length = iter->curr_entry->length;
            iter->curr_entry = (struct hvm_module_entry*)(ptr + length);
        }
        /* Else the module was just entered */

        iter->entry_index++;

        /* Match the type of table requested or go on looking... */
        if ( !check_current_table_match(iter) )
            continue;

        /* Else this is what was sought so leave the iterator
         * in the current state and let the caller process the table.
         */
        bval = 1;
        break;
    }

    /* If it reaches here then the iterator needs to move to the
     * next module.
     */
    if ( !bval )
    {        
        iter->entry_index = MODULE_INVALID_INDEX;
        iter->curr_module = NULL;
    }

    return bval;
}

void init_hvm_modules(uint32_t paddr)
{
    struct hvm_module_info *hmi;
    uint8_t *ptr;
    uint8_t sum = 0;
    uint32_t i, max_val;
    uint64_t *offsets;

    /* If firmware modules were passed in then there will be a modules
     * information table at the base address. This address will be in the
     * in the low RAM region just after the HVMLOADER image.
     */
    max_val = (hvm_info->low_mem_pgend << PAGE_SHIFT) - 
               sizeof(struct hvm_module_info);
    if ( (paddr < 0x100000)||(paddr >= max_val) )
        return;

    max_val -= 0x100000; /* adjust as a reasonable max length for modules */

    /* Valid address, test if it is a module info structure. */
    hmi = (struct hvm_module_info *)((uintptr_t)paddr);

    if ( strncmp(hmi->signature, HVM_MODULE_INFO_SIGNATURE, 8) ) {
        printf("Bad signature\n");
        goto error_out;
    }

    if ( hmi->count == 0 ) {
        printf("No modules\n");
        goto error_out;
    }

    if ( hmi->length < (sizeof(struct hvm_module_info) + sizeof(uint64_t))) {
        printf("Module info structure too short\n");
        goto error_out;
    }

    ptr = (uint8_t *)hmi;
    for ( i = 0; i < hmi->length; i++ )
        sum += ptr[i];

    if ( sum != 0 ) {
        printf("Module info checksum mismatch\n");
        goto error_out;
    }

    offsets = (uint64_t*)(hmi + 1);
    for ( i = 0, ptr = (uint8_t*)hmi; i < hmi->count; i++, offsets++ )
    {
        if ( !validate_hvm_module((struct hvm_module*)(ptr + *offsets),
                                  max_val) )
        {
            printf("Invalid HVM module at index: %d\n", i);
            goto error_out;
        }
    }

    /* If validation is successful set the global pointer indicating
     * the presence of a modules.
     */
    module_info = hmi;
    printf("HVM modules found at: %08x\n", paddr);

    return;
error_out:
    printf("HVM modules not validated, exiting module init.\n");
}

void init_smbios_module_iterator(struct hvm_modules_iterator *iter,
                                 uint8_t smbios_type_start,
                                 uint8_t smbios_type_end)
{
    if ( module_info == NULL )
        return;

    if ( iter == NULL )
        return;

    if ( (smbios_type_end != 0)&&
         (smbios_type_end <= smbios_type_start) )
        return;

    memset(iter, 0, sizeof(struct hvm_modules_iterator));
    iter->flags = MODULE_ITERATOR_FLAG_SMBIOS;
    iter->type.smbios.range_start = smbios_type_start;
    iter->type.smbios.range_end = smbios_type_end;

    /* Move to the first module (if there is one) */
    find_next_module_match(iter);
}

void init_acpi_module_iterator(struct hvm_modules_iterator *iter,
                               const char *signature,
                               int iterate_all)
{
    if ( module_info == NULL )
        return;

    if ( iter == NULL )
        return;

    if ( !iterate_all )
    {
        if ( (signature == NULL)||(strlen(signature) != 4) )
            return;
    }

    memset(iter, 0, sizeof(struct hvm_modules_iterator));
    iter->flags = MODULE_ITERATOR_FLAG_ACPI;
    if ( !iterate_all )    
        memcpy(iter->type.acpi.signature, signature, 4);
    else
        iter->type.acpi.iterate_all = 1;

    /* Move to the first module (if there is one) */
    find_next_module_match(iter);
}

void *hvm_find_module_entry(struct hvm_modules_iterator *iter,
                            uint32_t *length_out)
{
    void *entry = NULL;
    int bval;

    if ( (module_info == NULL)||(iter == NULL)||(length_out == NULL) )
        return NULL;

    *length_out = 0;

    while ( iter->module_index != MODULE_INVALID_INDEX )
    {
        bval = find_next_entry_match(iter);
        if ( bval )
        {
            /* Match found, get entry from current iterator state */
            entry = (iter->curr_entry + 1);
            *length_out = iter->curr_entry->length;
            break;
        }

        /* Else attempt to move on to the next module. */
        bval = find_next_module_match(iter);
        if ( !bval ) /* at the end, no more module matches */
            break;
    }

    return entry;
}

/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
