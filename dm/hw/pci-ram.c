/*
 * Copyright 2014-2018, Bromium, Inc.
 * Author: Julian Pidancet <julian@pidancet.net>
 * SPDX-License-Identifier: ISC
 */

#include <dm/qemu_glue.h>
#include <dm/dm.h>
#include <dm/mr.h>
#include <dm/qemu/hw/pci.h>
#include <dm/whpx/whpx.h>
#include <xenctrl.h>

#include "pci-ram.h"

/* ------------------ uxen pci ram ------------- */

static int
uxen_unpopulate_ram(pcibus_t addr, size_t len)
{
    return 0;
}

static int
uxen_populate_ram(pcibus_t addr, size_t len)
{
    xen_pfn_t pfn = addr >> TARGET_PAGE_BITS;
    size_t npages = len >> TARGET_PAGE_BITS;
    xen_pfn_t *pfn_list;
    unsigned int i;
    int ret;

    pfn_list = malloc(sizeof(xen_pfn_t) * npages);
    if (!pfn_list)
        return -1;

    for (i = 0; i < npages; ++i)
        pfn_list[i] = pfn + i;

    ret = xc_domain_populate_physmap_exact(xc_handle, vm_id, npages, 0, 0,
                                           pfn_list);
    free(pfn_list);

    return ret;
}

static int
uxen_move_ram(pcibus_t last_addr, pcibus_t new_addr, size_t len)
{
    xen_pfn_t last_pfn = last_addr >> TARGET_PAGE_BITS;
    xen_pfn_t new_pfn = new_addr >> TARGET_PAGE_BITS;
    size_t npages = len >> TARGET_PAGE_BITS;
    unsigned int i;
    int ret;

    for (i = 0; i < npages; ++i) {
        ret = xc_domain_add_to_physmap(xc_handle, vm_id, XENMAPSPACE_gmfn,
                                       last_pfn++, new_pfn++);
        if (ret)
            return ret;
    }

    return 0;
}

static void *
uxen_map_ram(pcibus_t addr, size_t len)
{
    xen_pfn_t pfn = addr >> TARGET_PAGE_BITS;
    size_t npages = len >> TARGET_PAGE_BITS;
    unsigned int i;
    void *ret;
    xen_pfn_t *pfn_list;

    pfn_list = malloc(sizeof(xen_pfn_t) * npages);
    if (!pfn_list)
        return NULL;

    for (i = 0; i < npages; ++i)
        pfn_list[i] = pfn++;

    ret = xc_map_foreign_pages(xc_handle, vm_id, PROT_READ | PROT_WRITE,
                               pfn_list, npages);
    free(pfn_list);

    return ret;
}

static void
uxen_unmap_ram(void *ptr, size_t len)
{
    size_t npages = len >> TARGET_PAGE_BITS;

    xc_munmap(xc_handle, vm_id, ptr, npages);
}

/* -------------- whp pci ram ------------- */

static int
whpx_unpopulate_ram(pcibus_t addr, size_t len)
{
    whpx_ram_depopulate(addr, len, WHPX_RAM_PCI);

    return 0;
}

static int
whpx_populate_ram(pcibus_t addr, size_t len)
{
    whpx_ram_populate(addr, len, WHPX_RAM_PCI);

    return 0;
}

static int
whpx_move_ram(pcibus_t last_addr, pcibus_t new_addr, size_t len)
{
    void *map_new, *map_last;
    uint64_t maplen = len;

    whpx_ram_populate(new_addr, len, WHPX_RAM_PCI);

    map_new = whpx_ram_map(new_addr, &maplen);
    assert(map_new && maplen == len);

    map_last = whpx_ram_map(new_addr, &maplen);
    assert(map_last && maplen == len);

    memmove(map_new, map_last, len);

    whpx_ram_unmap(map_new);
    whpx_ram_unmap(map_last);

    whpx_ram_depopulate(last_addr, len, WHPX_RAM_PCI);

    return 0;
}

static void *
whpx_pci_map_ram(pcibus_t addr, size_t len)
{
    uint64_t maplen = len;
    void *ptr;

    ptr = whpx_ram_map(addr, &maplen);
    assert(ptr && len == maplen);

    return ptr;
}

static void
whpx_pci_unmap_ram(void *ptr, size_t len)
{
    whpx_ram_unmap(ptr);
}

/* ----------------------- uxen/whp wrappers ---------------- */

static int
unpopulate_ram(pcibus_t addr, size_t len)
{
    return whpx_enable
      ? whpx_unpopulate_ram(addr, len)
      : uxen_unpopulate_ram(addr, len);
}

static int
populate_ram(pcibus_t addr, size_t len)
{
    return whpx_enable
      ? whpx_populate_ram(addr, len)
      : uxen_populate_ram(addr, len);
}

static int
move_ram(pcibus_t last_addr, pcibus_t new_addr, size_t len)
{
    return whpx_enable
      ? whpx_move_ram(last_addr, new_addr, len)
      : uxen_move_ram(last_addr, new_addr, len);
}

static void *
map_ram(pcibus_t addr, size_t len)
{
    return whpx_enable ?
        whpx_pci_map_ram(addr, len) : uxen_map_ram(addr, len);
}

static void
unmap_ram(void *ptr, size_t len)
{
    return whpx_enable ?
        whpx_pci_unmap_ram(ptr, len) : uxen_unmap_ram(ptr, len);
}

void
pci_ram_update_region(PCIDevice *d, PCIIORegion *r, pcibus_t last_addr, pcibus_t new_addr)
{
    struct ram_range *range;

    TAILQ_FOREACH(range, &r->memory->ram_map, link) {
        if (last_addr == PCI_BAR_UNMAPPED) {
            populate_ram(new_addr + range->offset, range->length);
            range->ram_ptr = map_ram(new_addr + range->offset, range->length);
        } else if (new_addr == PCI_BAR_UNMAPPED) {
            unmap_ram(range->ram_ptr, range->length);
            unpopulate_ram(last_addr + range->offset, range->length);
            range->ram_ptr = NULL;
        } else {
            unmap_ram(range->ram_ptr, range->length);
            move_ram(last_addr + range->offset, new_addr + range->offset,
                     range->length);
            range->ram_ptr = map_ram(new_addr + range->offset, range->length);
        }

        range->update_ptr(range->ram_ptr, range->opaque);
    }
}

void
pci_ram_config_write(PCIDevice *d, uint32_t addr, uint32_t val, int len)
{
    int region_num = (addr - PCI_BASE_ADDRESS_0) / 4;
    PCIIORegion *r = &d->io_regions[region_num];
    pcibus_t last_addr, new_addr;

    if (len != 4 || region_num < 0 || region_num > 5) {
        pci_default_write_config(d, addr, val, len);
        return;
    }

    last_addr = pci_bar_address(d, region_num, r->type, r->size);
    pci_default_write_config(d, addr, val, len);
    new_addr = pci_bar_address(d, region_num, r->type, r->size);

    if (last_addr == new_addr)
        return;

    pci_ram_update_region(d, r, last_addr, new_addr);
}

void
pci_ram_pre_save(PCIDevice *d)
{
    /* Nothing to do */
}

void
pci_ram_post_save(PCIDevice *d)
{
    PCIIORegion *r;
    int i;
    pcibus_t addr;
    struct ram_range *range;

    for (i = 0; i < PCI_NUM_REGIONS; i++) {
        r = &d->io_regions[i];
        if (!r->size)
            continue;
        addr = pci_bar_address(d, i, r->type, r->size);
        if (addr != PCI_BAR_UNMAPPED) {
            TAILQ_FOREACH(range, &r->memory->ram_map, link) {
                range->update_ptr(NULL, range->opaque);
                unmap_ram(range->ram_ptr, range->length);
                range->ram_ptr = NULL;
            }
        }
    }
}

void
pci_ram_post_load(PCIDevice *d, int version_id)
{
    PCIIORegion *r;
    int i;
    pcibus_t addr;
    struct ram_range *range;

    for(i = 0; i < PCI_NUM_REGIONS; i++) {
        r = &d->io_regions[i];
        if (!r->size)
            continue;
        addr = pci_bar_address(d, i, r->type, r->size);
        if (addr != PCI_BAR_UNMAPPED) {
            TAILQ_FOREACH(range, &r->memory->ram_map, link) {
                range->ram_ptr = map_ram(addr + range->offset, range->length);
                range->update_ptr(range->ram_ptr, range->opaque);
            }
        }
    }
}
