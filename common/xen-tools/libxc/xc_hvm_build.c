/******************************************************************************
 * xc_hvm_build.c
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

#include "xc_private.h"

#include <stddef.h>
#include <inttypes.h>
#include <stdlib.h>
#include <unistd.h>

#include "xg_private.h"
#include "xc_attovm.h"
#include "xc_attovm_private.h"

#if !defined(QEMU_UXEN)
#include <xen/foreign/x86_32.h>
#include <xen/foreign/x86_64.h>
#endif  /* QEMU_UXEN */
#include <xen/hvm/hvm_info_table.h>
#include <xen/hvm/params.h>
#include <xen/hvm/e820.h>
#include <xen/attovm.h>

#if !defined(QEMU_UXEN)
#include <xen/libelf/libelf.h>
#else   /* QEMU_UXEN */
#define NO_XEN_ELF_NOTE
#include <libelf/libelf.h>
#endif  /* QEMU_UXEN */

#include <attoxen-api/ax_attovm.h>

#define SUPERPAGE_2MB_SHIFT   9
#define SUPERPAGE_2MB_NR_PFNS (1UL << SUPERPAGE_2MB_SHIFT)
#define SUPERPAGE_1GB_SHIFT   18
#define SUPERPAGE_1GB_NR_PFNS (1UL << SUPERPAGE_1GB_SHIFT)

#define SPECIALPAGE_IDENT_PT 0

#if !defined(QEMU_UXEN)
#define SPECIALPAGE_IOREQ    X
#define SPECIALPAGE_BUFIOREQ X
#define SPECIALPAGE_XENSTORE X
#define SPECIALPAGE_CONSOLE  X
#endif  /* QEMU_UXEN */

#define SPECIALPAGE_DMREQ      (SPECIALPAGE_IDENT_PT + 1)
#define SPECIALPAGE_DMREQ_VCPU (SPECIALPAGE_DMREQ + 1 + nr_vcpus + 1)

/* reverse first/last since special_pfn's indexes allocate in reverse order */
#define SPECIALPAGE_IOREQ_LAST (SPECIALPAGE_DMREQ_VCPU + 1)
#define SPECIALPAGE_IOREQ_FIRST                                         \
    (SPECIALPAGE_IOREQ_LAST + (nr_ioreq_servers * NR_IO_PAGES_PER_SERVER) + 1)

#define NR_SPECIAL_PAGES     SPECIALPAGE_IOREQ_FIRST

/* special_pfn indexes start at 0, index 0 == 0xfefff */
#define special_pfn(x) (0xff000u - 1 - (x))

static void build_hvm_info(void *hvm_info_page, uint64_t mem_size,
                           uint32_t nr_vcpus, uint32_t nr_ioreq_servers,
                           uint32_t modules_base,
                           struct xc_hvm_oem_info *oem_info)
{
    struct hvm_info_table *hvm_info = (struct hvm_info_table *)
        (((unsigned char *)hvm_info_page) + HVM_INFO_OFFSET);
    uint64_t lowmem_end = mem_size, highmem_end = 0;
    uint8_t sum;
    int i;

    if ( lowmem_end > HVM_BELOW_4G_RAM_END )
    {
        highmem_end = lowmem_end + HVM_BELOW_4G_MMIO_LENGTH;
        lowmem_end = HVM_BELOW_4G_RAM_END;
    }

    memset(hvm_info_page, 0, PAGE_SIZE);

    /* Fill in the header. */
    strncpy(hvm_info->signature, "HVM INFO", 8);
    hvm_info->length = sizeof(struct hvm_info_table);

    /* Sensible defaults: these can be overridden by the caller. */
    hvm_info->apic_mode = 1;
    hvm_info->nr_vcpus = 1;
    memset(hvm_info->vcpu_online, 0xff, sizeof(hvm_info->vcpu_online));

    /* Memory parameters. */
    hvm_info->low_mem_pgend = lowmem_end >> PAGE_SHIFT;
    hvm_info->high_mem_pgend = highmem_end >> PAGE_SHIFT;
    hvm_info->reserved_mem_pgstart = special_pfn(NR_SPECIAL_PAGES);

    /* Modules */
    hvm_info->mod_base = modules_base;

    /* OEM info */
    if (oem_info && (oem_info->flags & XC_HVM_OEM_ID))
        memcpy(hvm_info->oem_info.oem_id, oem_info->oem_id, 6);
    else
        strncpy(hvm_info->oem_info.oem_id, "Xen", 6);

    if (oem_info && (oem_info->flags & XC_HVM_OEM_TABLE_ID))
        memcpy(hvm_info->oem_info.oem_table_id, oem_info->oem_table_id, 8);
    else
        strncpy(hvm_info->oem_info.oem_table_id, "HVM", 8);

    if (oem_info && (oem_info->flags & XC_HVM_OEM_REVISION))
        hvm_info->oem_info.oem_revision  = oem_info->oem_revision;
    else
        hvm_info->oem_info.oem_revision = 0;

    if (oem_info && (oem_info->flags & XC_HVM_CREATOR_ID))
        memcpy(hvm_info->oem_info.creator_id, oem_info->creator_id, 4);
    else
        strncpy(hvm_info->oem_info.creator_id, "HVML", 4);

    if (oem_info && (oem_info->flags & XC_HVM_CREATOR_REVISION))
        hvm_info->oem_info.creator_revision  = oem_info->creator_revision;
    else
        hvm_info->oem_info.creator_revision = 0;

    if (oem_info && (oem_info->flags & XC_HVM_SMBIOS_MAJOR))
        hvm_info->oem_info.smbios_version_major = oem_info->smbios_version_major;
    else
        hvm_info->oem_info.smbios_version_major = 2;

    if (oem_info && (oem_info->flags & XC_HVM_SMBIOS_MINOR))
        hvm_info->oem_info.smbios_version_minor = oem_info->smbios_version_minor;
    else
        hvm_info->oem_info.smbios_version_minor = 4;

    /* Finish with the checksum. */
    for ( i = 0, sum = 0; i < hvm_info->length; i++ )
        sum += ((uint8_t *)hvm_info)[i];
    hvm_info->checksum = -sum;
}

static int loadelfimage(
    xc_interface *xch,
    struct elf_binary *elf, uint32_t dom, xen_pfn_t *parray)
{
    int rc = -1;
    privcmd_mmap_entry_t *entries = NULL;
    unsigned long pfn_start = elf->pstart >> PAGE_SHIFT;
    unsigned long pfn_end = (elf->pend + PAGE_SIZE - 1) >> PAGE_SHIFT;
    size_t pages = pfn_end - pfn_start;
    int i;

    /* Map address space for initial elf image. */
    entries = calloc(pages, sizeof(privcmd_mmap_entry_t));
    if ( entries == NULL )
        goto err;

    for ( i = 0; i < pages; i++ )
        entries[i].mfn = parray[(elf->pstart >> PAGE_SHIFT) + i];

    elf->dest = xc_map_foreign_ranges(
        xch, dom, pages << PAGE_SHIFT, PROT_READ | PROT_WRITE, 1 << PAGE_SHIFT,
        entries, pages);
    if ( elf->dest == NULL )
        goto err;

    elf->dest += elf->pstart & (PAGE_SIZE - 1);

    /* Load the initial elf image. */
    elf_load_binary(elf);
    rc = 0;

    xc_munmap(xch, dom, elf->dest, pages << PAGE_SHIFT);
    elf->dest = NULL;

 err:
    free(entries);

    return rc;
}

/*
 * Check whether there exists mmio hole in the specified memory range.
 * Returns 1 if exists, else returns 0.
 */
static int check_mmio_hole(uint64_t start, uint64_t memsize)
{
    if ( start + memsize <= HVM_BELOW_4G_MMIO_START ||
         start >= HVM_BELOW_4G_MMIO_START + HVM_BELOW_4G_MMIO_LENGTH )
        return 0;
    else
        return 1;
}

static struct hvm_module_info *modules_init(struct xc_hvm_module *modules,
                                            size_t mod_count,
                                            size_t *out_len)
{
    struct hvm_module_info *hmi;
    struct xc_hvm_module *m;
    size_t len;
    int i, j;
    uint64_t *offsets;
    uint8_t sum;

    len = sizeof(*hmi);

    m = modules;
    for (i = 0; i < mod_count; i++) {
        len += sizeof(uint64_t); /* Offset */
        len += sizeof(struct hvm_module); /* Module Descriptor */
        for (j = 0; j < m->nent; j++) {
            len += sizeof (struct hvm_module_entry);
            len += m->entries[j].len;
        }
        m++;
    }

    hmi = calloc(1, (len + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1));
    if (!hmi)
        return NULL;

    offsets = (uint64_t *)(hmi + 1);
    len = sizeof(*hmi) + mod_count * sizeof(uint64_t);

    for (i = 0; i < mod_count; i++) {
        struct hvm_module *mod = (void *)((uint8_t *)hmi + len);
        struct hvm_module_entry *entry = (void *)(mod + 1);

        offsets[i] = len;
        strncpy(mod->signature, "_HVMMOD_", 8);
        switch (modules[i].type) {
        case XC_HVM_MODULE_ACPI:
            mod->type = HVM_MODULE_ACPI;
            break;
        case XC_HVM_MODULE_SMBIOS:
            mod->type = HVM_MODULE_SMBIOS;
            break;
        default:
            goto out;
        }

        mod->length = sizeof(*mod);
        for (j = 0; j < modules[i].nent; j++) {
            entry->length = modules[i].entries[j].len;
            entry->flags = modules[i].entries[j].flags;

            memcpy(entry + 1, modules[i].entries[j].base, entry->length);
            mod->length += sizeof(*entry) + entry->length;

            entry = (void *)((uint8_t *)(entry + 1) + entry->length);
        }

        mod->count = j;
        mod->revision = 0;
        mod->checksum = 0;

        sum = 0;
        for (j = 0; j < mod->length; j++)
            sum += ((uint8_t *)mod)[j];
        mod->checksum = -sum;

        len += mod->length;
    }

    strncpy(hmi->signature, "_HVM_MI_", 8);
    hmi->length = sizeof(*hmi) + mod_count * sizeof(uint64_t);
    hmi->count = i;
    hmi->revision = 0;
    hmi->checksum = 0;

    sum = 0;
    for (j = 0; j < hmi->length; j++)
        sum += ((uint8_t *)hmi)[j];
    hmi->checksum = -sum;

    *out_len = (len + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1);

    return hmi;
out:
    free(hmi);
    return NULL;
}

static int load_modules(xc_interface *xch, struct hvm_module_info *hmi,
                        uint32_t mod_base, size_t mod_len,
                        uint32_t dom, xen_pfn_t *parray)
{
    unsigned long pfn_start, nr_pages;
    privcmd_mmap_entry_t *entries = NULL;
    unsigned long i;
    void *dest;
    int rc = -1;

    pfn_start = (unsigned long)(mod_base >> PAGE_SHIFT);
    nr_pages = (mod_len + PAGE_SIZE - 1) >> PAGE_SHIFT;

    entries = calloc(nr_pages, sizeof(*entries));
    if (!entries)
        return -1;

    for (i = 0; i < nr_pages; i++)
        entries[i].mfn = parray[pfn_start + i];

    dest = xc_map_foreign_ranges(xch, dom, nr_pages * PAGE_SIZE,
                                 PROT_READ | PROT_WRITE, PAGE_SIZE,
                                 entries, nr_pages);
    if (!dest)
        goto out;

    memcpy(dest, hmi, nr_pages * PAGE_SIZE);
    xc_munmap(xch, dom, dest, nr_pages * PAGE_SIZE);
    rc = 0;
out:
    free(entries);
    return rc;
}

static void
elf_log_cb(struct elf_binary *elf, void *called_data, int iserr,
           const char *fmt, va_list ap)
{

    vfprintf(stderr, fmt, ap);
}

static int check_write_works(void *page, int o, uint32_t v)
{
    volatile uint32_t *a = (uint32_t *) (page + o);

    *a=v;

    asm( "" : : : "memory" );

    if (*a == v) return 0;

    fprintf(stderr,"PAGE canary hvm_info_page mapped at %p: wrote 0x%08x to %p and read back 0x%08x\n",
		page, v, a, *a);

    return -1;
}

static int check_page_works(void *p)
{
    if (check_write_works(p, 0, 0x55aa55aa) ||
        check_write_works(p, 0, 0xaa55aa55) ||
        check_write_works(p, (PAGE_SIZE - sizeof(uint32_t)), 0x55aa55aa) ||
        check_write_works(p, (PAGE_SIZE - sizeof(uint32_t)), 0xaa55aa55))
		return -1;

    return 0;
}

static int setup_guest(xc_interface *xch,
                       uint32_t dom, int memsize, int target,
                       uint32_t nr_vcpus, uint32_t nr_ioreq_servers,
                       char *image, unsigned long image_size,
                       struct xc_hvm_module *modules,
                       size_t mod_count,
                       struct xc_hvm_oem_info *oem_info,
                       const char *attovm_image_file,
                       struct attovm_definition_v1 *out_attovm_def)
{
    xen_pfn_t *page_array = NULL;
    unsigned long i;
    unsigned long nr_pages = (unsigned long)memsize << (20 - PAGE_SHIFT);
    unsigned long entry_eip;
    unsigned long cur_pages, cur_pfn;
    void *hvm_info_page;
    uint32_t *ident_pt;
    struct elf_binary elf;
    uint64_t v_start, v_end;
    int rc;
    xen_capabilities_info_t caps;
    unsigned long stat_normal_pages = 0, stat_2mb_pages = 0, 
        stat_1gb_pages = 0;
    int pod_mode = 0;
    struct hvm_module_info *hmi = NULL;
    size_t modules_len = 0;
    uint32_t modules_base = 0;
    int attovm = attovm_image_file != NULL;

    /* An HVM guest must be initialised with at least 2MB memory. */
    if ( memsize < 2 || target < 2 )
        goto error_out;

    if ( memsize > target )
        pod_mode = 1;

    if (!attovm) {
        memset(&elf, 0, sizeof(elf));
        if ( elf_init(&elf, image, image_size) != 0 )
            goto error_out;

#if !defined(QEMU_UXEN)
        xc_elf_set_logfile(xch, &elf, 1);
#else   /* QEMU_UXEN */
        elf_set_log(&elf, elf_log_cb, NULL, 1);
#endif  /* QEMU_UXEN */

        elf_parse_binary(&elf);
    }

    v_start = 0;
    v_end = (unsigned long long)memsize << 20;

    if ( xc_version(xch, XENVER_capabilities, &caps) != 0 )
    {
        PERROR("Could not get Xen capabilities");
        goto error_out;
    }

    if (!attovm) {
        if (mod_count && modules) {
            /* Align to the next Megabyte */
            uint32_t base = (elf.pend + (1 << 20) - 1) & ~((1 << 20) - 1);

            hmi = modules_init(modules, mod_count, &modules_len);

            if (hmi && (base + modules_len) > v_end) {
                PERROR("Insufficient space to load modules");
                goto error_out;
            }
            if (hmi)
                modules_base = base;
        }

        IPRINTF("VIRTUAL MEMORY ARRANGEMENT:\n"
                "  Loader:        %016"PRIx64"->%016"PRIx64"\n"
                "  Modules:       %016"PRIx64"->%016"PRIx64"\n"
                "  TOTAL:         %016"PRIx64"->%016"PRIx64"\n"
                "  ENTRY ADDRESS: %016"PRIx64"\n",
                elf.pstart, elf.pend,
                (uint64_t)modules_base, (uint64_t)modules_base + modules_len,
                v_start, v_end,
                elf_uval(&elf, elf.ehdr, e_entry));
    } else {
        IPRINTF("VIRTUAL MEMORY ARRANGEMENT:\n"
            "  TOTAL:         %016"PRIx64"->%016"PRIx64"\n",
            v_start, v_end);
    }

    if ( (page_array = malloc(nr_pages * sizeof(xen_pfn_t))) == NULL )
    {
        PERROR("Could not allocate memory.");
        goto error_out;
    }

    for ( i = 0; i < nr_pages; i++ )
        page_array[i] = i;
    for ( i = HVM_BELOW_4G_RAM_END >> PAGE_SHIFT; i < nr_pages; i++ )
        page_array[i] += HVM_BELOW_4G_MMIO_LENGTH >> PAGE_SHIFT;

    /*
     * Allocate memory for HVM guest, skipping VGA hole 0xA0000-0xC0000.
     *
     * We attempt to allocate 1GB pages if possible. It falls back on 2MB
     * pages if 1GB allocation fails. 4KB pages will be used eventually if
     * both fail.
     * 
     * Under 2MB mode, we allocate pages in batches of no more than 8MB to 
     * ensure that we can be preempted and hence dom0 remains responsive.
     */
    rc = xc_domain_populate_physmap_exact(
        xch, dom, 0xa0, 0, pod_mode ? XENMEMF_populate_on_demand : 0, &page_array[0x00]);
    cur_pages = 0xc0;
    stat_normal_pages = 0xc0;
    while ( (rc == 0) && (nr_pages > cur_pages) )
    {
        /* Clip count to maximum 1GB extent. */
        unsigned long count = nr_pages - cur_pages;
        unsigned long max_pages = SUPERPAGE_1GB_NR_PFNS;

        if ( count > max_pages )
            count = max_pages;

        cur_pfn = page_array[cur_pages];

        /* Take care the corner cases of super page tails */
        if ( ((cur_pfn & (SUPERPAGE_1GB_NR_PFNS-1)) != 0) &&
             (count > (-cur_pfn & (SUPERPAGE_1GB_NR_PFNS-1))) )
            count = -cur_pfn & (SUPERPAGE_1GB_NR_PFNS-1);
        else if ( ((count & (SUPERPAGE_1GB_NR_PFNS-1)) != 0) &&
                  (count > SUPERPAGE_1GB_NR_PFNS) )
            count &= ~(SUPERPAGE_1GB_NR_PFNS - 1);

        /* Attemp to allocate 1GB super page. Because in each pass we only
         * allocate at most 1GB, we don't have to clip super page boundaries.
         */
        if ( ((count | cur_pfn) & (SUPERPAGE_1GB_NR_PFNS - 1)) == 0 &&
             /* Check if there exists MMIO hole in the 1GB memory range */
             !check_mmio_hole(cur_pfn << PAGE_SHIFT,
                              SUPERPAGE_1GB_NR_PFNS << PAGE_SHIFT) )
        {
            long done;
            unsigned long nr_extents = count >> SUPERPAGE_1GB_SHIFT;
            xen_pfn_t sp_extents[nr_extents];

            for ( i = 0; i < nr_extents; i++ )
                sp_extents[i] = page_array[cur_pages+(i<<SUPERPAGE_1GB_SHIFT)];

            done = xc_domain_populate_physmap(xch, dom, nr_extents, SUPERPAGE_1GB_SHIFT,
                                              pod_mode ? XENMEMF_populate_on_demand : 0,
                                              sp_extents);

            if ( done > 0 )
            {
                stat_1gb_pages += done;
                done <<= SUPERPAGE_1GB_SHIFT;
                cur_pages += done;
                count -= done;
            }
        }

        if ( count != 0 )
        {
            /* Clip count to maximum 8MB extent. */
            max_pages = SUPERPAGE_2MB_NR_PFNS * 4;
            if ( count > max_pages )
                count = max_pages;
            
            /* Clip partial superpage extents to superpage boundaries. */
            if ( ((cur_pfn & (SUPERPAGE_2MB_NR_PFNS-1)) != 0) &&
                 (count > (-cur_pfn & (SUPERPAGE_2MB_NR_PFNS-1))) )
                count = -cur_pfn & (SUPERPAGE_2MB_NR_PFNS-1);
            else if ( ((count & (SUPERPAGE_2MB_NR_PFNS-1)) != 0) &&
                      (count > SUPERPAGE_2MB_NR_PFNS) )
                count &= ~(SUPERPAGE_2MB_NR_PFNS - 1); /* clip non-s.p. tail */

            /* Attempt to allocate superpage extents. */
            if ( ((count | cur_pfn) & (SUPERPAGE_2MB_NR_PFNS - 1)) == 0 )
            {
                long done;
                unsigned long nr_extents = count >> SUPERPAGE_2MB_SHIFT;
                xen_pfn_t sp_extents[nr_extents];

                for ( i = 0; i < nr_extents; i++ )
                    sp_extents[i] = page_array[cur_pages+(i<<SUPERPAGE_2MB_SHIFT)];

                done = xc_domain_populate_physmap(xch, dom, nr_extents, SUPERPAGE_2MB_SHIFT,
                                                  pod_mode ? XENMEMF_populate_on_demand : 0,
                                                  sp_extents);

                if ( done > 0 )
                {
                    stat_2mb_pages += done;
                    done <<= SUPERPAGE_2MB_SHIFT;
                    cur_pages += done;
                    count -= done;
                }
            }
        }

        /* Fall back to 4kB extents. */
        if ( count != 0 )
        {
            rc = xc_domain_populate_physmap_exact(
                xch, dom, count, 0, pod_mode ? XENMEMF_populate_on_demand : 0, &page_array[cur_pages]);
            cur_pages += count;
            stat_normal_pages += count;
        }
    }

    IPRINTF("PHYSICAL MEMORY ALLOCATION:\n"
            "  4KB PAGES: 0x%016lx\n"
            "  2MB PAGES: 0x%016lx\n"
            "  1GB PAGES: 0x%016lx\n",
            stat_normal_pages, stat_2mb_pages, stat_1gb_pages);

    if (attovm) {
        if ( attovm_setup_guest(xch, dom, page_array, attovm_image_file, out_attovm_def) ) {
            ERROR("attovm_setup_guest failed");
            goto error_out;
        }
    } else {
        if ( loadelfimage(xch, &elf, dom, page_array) != 0 )
            goto error_out;

        if (modules_base && load_modules(xch, hmi, modules_base, modules_len,
                                         dom, page_array)) {
            PERROR("Failed to load hvm modules.");
            goto error_out;
        }
    }

    if ( (hvm_info_page = xc_map_foreign_range(
              xch, dom, PAGE_SIZE, PROT_READ | PROT_WRITE,
              HVM_INFO_PFN)) == NULL )
        goto error_out;

    if ( (rc = check_page_works(hvm_info_page)) )
        goto error_out;

    build_hvm_info(hvm_info_page, v_end, nr_vcpus, nr_ioreq_servers,
                   modules_base, oem_info);
    xc_munmap(xch, dom, hvm_info_page, PAGE_SIZE);

    /* Allocate and clear special pages. */
    for ( i = 0; i <= NR_SPECIAL_PAGES; i++ )
    {
        xen_pfn_t pfn = special_pfn(i);
        rc = xc_domain_populate_physmap_exact(xch, dom, 1, 0, 0, &pfn);
        if ( rc != 0 )
        {
            PERROR("Could not allocate %d'th special page.", i);
            goto error_out;
        }
        if ( xc_clear_domain_page(xch, dom, special_pfn(i)) )
            goto error_out;
    }

#if !defined(QEMU_UXEN)
    xc_set_hvm_param(xch, dom, HVM_PARAM_STORE_PFN,
                     special_pfn(SPECIALPAGE_XENSTORE));
#endif  /* QEMU_UXEN */
#if !defined(QEMU_UXEN)
    xc_set_hvm_param(xch, dom, HVM_PARAM_CONSOLE_PFN,
                     special_pfn(SPECIALPAGE_CONSOLE));
#endif  /* QEMU_UXEN */
    xc_set_hvm_param(xch, dom, HVM_PARAM_IO_PFN_FIRST,
                     special_pfn(SPECIALPAGE_IOREQ_FIRST));
    xc_set_hvm_param(xch, dom, HVM_PARAM_IO_PFN_LAST,
                     special_pfn(SPECIALPAGE_IOREQ_LAST));

    /*
     * Identity-map page table is required for running with CR0.PG=0 when
     * using Intel EPT. Create a 32-bit non-PAE page directory of superpages.
     */
    if ( (ident_pt = xc_map_foreign_range(
              xch, dom, PAGE_SIZE, PROT_READ | PROT_WRITE,
              special_pfn(SPECIALPAGE_IDENT_PT))) == NULL )
        goto error_out;
    for ( i = 0; i < PAGE_SIZE / sizeof(*ident_pt); i++ )
        ident_pt[i] = ((i << 22) | _PAGE_PRESENT | _PAGE_RW | _PAGE_USER |
                       _PAGE_ACCESSED | _PAGE_DIRTY | _PAGE_PSE);
    xc_munmap(xch, dom, ident_pt, PAGE_SIZE);
    xc_set_hvm_param(xch, dom, HVM_PARAM_IDENT_PT,
                     special_pfn(SPECIALPAGE_IDENT_PT) << PAGE_SHIFT);

    if (!attovm) {
        /* Insert JMP <rel32> instruction at address 0x0 to reach entry point. */
        entry_eip = elf_uval(&elf, elf.ehdr, e_entry);
        if ( entry_eip != 0 )
        {
            char *page0 = xc_map_foreign_range(
                xch, dom, PAGE_SIZE, PROT_READ | PROT_WRITE, 0);
            if ( page0 == NULL )
                goto error_out;
            page0[0] = 0xe9;
            *(uint32_t *)&page0[1] = entry_eip - 5;
            xc_munmap(xch, dom, page0, PAGE_SIZE);
        }
    } else {
        /* for attovm execution starts at 0x0 and rest is handled by loaded trampoline */
    }

    xc_set_hvm_param(xch, dom, HVM_PARAM_DMREQ_PFN,
                     special_pfn(SPECIALPAGE_DMREQ));
    xc_set_hvm_param(xch, dom, HVM_PARAM_DMREQ_VCPU_PFN,
                     special_pfn(SPECIALPAGE_DMREQ_VCPU));

    if (hmi)
        free(hmi);
    free(page_array);
    return 0;

 error_out:
    if (hmi)
        free(hmi);
    free(page_array);
    return -1;
}

static int xc_hvm_build_internal(xc_interface *xch,
                                 uint32_t domid,
                                 int memsize,
                                 int target,
                                 uint32_t nr_vcpus,
                                 uint32_t nr_ioreq_servers,
                                 char *image,
                                 unsigned long image_size,
                                 struct xc_hvm_module *modules,
                                 size_t mod_count,
                                 struct xc_hvm_oem_info *oem_info)
{
    if ( (image == NULL) || (image_size == 0) )
    {
        PERROR("Image required");
        return -1;
    }

    target = 8;
    return setup_guest(xch, domid, memsize, target, nr_vcpus, nr_ioreq_servers,
                       image, image_size, modules, mod_count, oem_info, NULL, NULL);
}

/* xc_hvm_build:
 * Create a domain for a virtualized Linux, using files/filenames.
 */
int xc_hvm_build(xc_interface *xch,
                 uint32_t domid,
                 int memsize,
                 uint32_t nr_vcpus,
                 uint32_t nr_ioreq_servers,
                 const char *image_name,
                 struct xc_hvm_module *modules,
                 size_t mod_count,
                 struct xc_hvm_oem_info *oem_info)
{
    char *image;
    int  sts;
    unsigned long image_size;

    if ( (image_name == NULL) ||
         ((image = xc_read_image(xch, image_name, &image_size)) == NULL) ) {
        ERROR("Failed to load image file: \"%s\"", image_name);
        return -1;
    }

    sts = xc_hvm_build_internal(xch, domid, memsize, memsize, nr_vcpus,
                                nr_ioreq_servers, image, image_size,
                                modules, mod_count, oem_info);

    free(image);

    return sts;
}

/* xc_attovm_build:
 * Create a domain for running linux under attoxen */
int xc_attovm_build(xc_interface *xch,
    uint32_t domid,
    uint32_t nr_vcpus,
    uint32_t memsize_mb,
    const char *image_filename,
    int seal)
{
    struct attovm_definition_v1 def;
    int rc;

    memset(&def, 0, sizeof(def));
    rc = setup_guest(xch, domid, memsize_mb, memsize_mb, nr_vcpus,
        2, /*FIXME: ioreq servers */
        NULL, 0, NULL, 0, NULL, image_filename, &def);
    if (rc)
        return rc;
    if (seal) {
        rc = attovm_seal_guest(xch, domid, &def);
        if (rc) {
            ERROR("failed to seal domain %d: rc=%d", domid, rc);
            return rc;
        }
    }

    return 0;
}

#if !defined(QEMU_UXEN)
/* xc_hvm_build_target_mem: 
 * Create a domain for a pre-ballooned virtualized Linux, using
 * files/filenames.  If target < memsize, domain is created with
 * memsize pages marked populate-on-demand, 
 * calculating pod cache size based on target.
 * If target == memsize, pages are populated normally.
 */
int xc_hvm_build_target_mem(xc_interface *xch,
                           uint32_t domid,
                           int memsize,
                           int target,
                           uint32_t nr_vcpus,
                           uint32_t nr_ioreq_servers,
                           const char *image_name)
{
    char *image;
    int  sts;
    unsigned long image_size;

    if ( (image_name == NULL) ||
         ((image = xc_read_image(xch, image_name, &image_size)) == NULL) )
        return -1;

    sts = xc_hvm_build_internal(xch, domid, memsize, target, nr_vcpus,
                                nr_ioreq_servers, image, image_size);

    free(image);

    return sts;
}

/* xc_hvm_build_mem:
 * Create a domain for a virtualized Linux, using memory buffers.
 */
int xc_hvm_build_mem(xc_interface *xch,
                     uint32_t domid,
                     int memsize,
                     uint32_t nr_vcpus,
                     uint32_t nr_ioreq_servers,
                     const char *image_buffer,
                     unsigned long image_size)
{
    int           sts;
    unsigned long img_len;
    char         *img;

    /* Validate that there is a kernel buffer */

    if ( (image_buffer == NULL) || (image_size == 0) )
    {
        ERROR("kernel image buffer not present");
        return -1;
    }

    img = xc_inflate_buffer(xch, image_buffer, image_size, &img_len);
    if ( img == NULL )
    {
        ERROR("unable to inflate ram disk buffer");
        return -1;
    }

    sts = xc_hvm_build_internal(xch, domid, memsize, memsize, nr_vcpus,
                                nr_ioreq_servers, img, img_len);

    /* xc_inflate_buffer may return the original buffer pointer (for
       for already inflated buffers), so exercise some care in freeing */

    if ( (img != NULL) && (img != image_buffer) )
        free(img);

    return sts;
}
#endif  /* QEMU_UXEN */

/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
