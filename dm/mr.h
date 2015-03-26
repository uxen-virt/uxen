/*
 * Copyright 2012-2015, Bromium, Inc.
 * Author: Christian Limpach <Christian.Limpach@gmail.com>
 * SPDX-License-Identifier: ISC
 */

#ifndef _MR_H_
#define _MR_H_

#include "dev.h"
#include "iomem.h"
#include "ioport.h"
#include "queue.h"

enum device_endian {
    DEVICE_NATIVE_ENDIAN,
    DEVICE_BIG_ENDIAN,
    DEVICE_LITTLE_ENDIAN,
};

struct MemoryRegionOps {
    uint64_t (*read)(void *opaque,
                     uint64_t addr,
                     unsigned size);
    void (*write)(void *opaque,
                  uint64_t addr,
                  uint64_t data,
                  unsigned size);
    enum device_endian endianness;

    struct {
	unsigned min_access_size;
	unsigned max_access_size;
    } impl;
    // const struct ioport_region *old_portio;
    // const struct iomem_region old_mmio;
};

struct ram_range {
    size_t offset;
    size_t length;
    void *ram_ptr;
    void *opaque;
    void (*update_ptr)(void *ptr, void *opaque);
    TAILQ_ENTRY(ram_range) link;
};

struct MemoryRegion {
    uint64_t size;
    // uint64_t addr;
    // uint64_t offset;

    const char *name;

    const MemoryRegionOps *ops;
    void *opaque;
    int mmio_index;
    uint64_t ops_base;
    unsigned int serverid;

    const struct ioport_region_list *ioport_list;
    uint32_t ioport_list_offset;

    uint64_t ram_ptr;

    MemoryRegion *alias;
    uint64_t alias_offset;

    MemoryRegion *parent;
    uint64_t parent_offset;
    TAILQ_ENTRY(MemoryRegion) subregions_link;
    TAILQ_HEAD(subregions, MemoryRegion) subregions;

    TAILQ_HEAD(, ram_range) ram_map;

    void (*map_cb)(void *);
    void *map_opaque;
};

extern MemoryRegion *system_iomem;
extern MemoryRegion *system_ioport;

void memory_region_init(MemoryRegion *mr,
                        const char *name,
                        uint64_t size);

void memory_region_init_io(MemoryRegion *mr,
                           const MemoryRegionOps *ops,
                           void *opaque,
                           const char *name,
                           uint64_t size);
void memory_region_init_ram_ptr(MemoryRegion *mr,
                                DeviceState *dev,
                                const char *name,
                                uint64_t size,
                                void *ptr);
void memory_region_init_alias(MemoryRegion *mr,
                              const char *name,
                              MemoryRegion *orig,
                              uint64_t offset,
                              uint64_t size);

void memory_region_destroy(MemoryRegion *mr);

uint64_t memory_region_size(MemoryRegion *mr);

void memory_region_add_subregion(MemoryRegion *mr,
                                 uint64_t offset,
                                 MemoryRegion *subregion);
void memory_region_add_subregion_overlap(MemoryRegion *mr,
                                         uint64_t offset,
                                         MemoryRegion *subregion,
                                         unsigned priority);
void memory_region_del_subregion(MemoryRegion *mr,
                                 MemoryRegion *subregion);

#define memory_region_add_coalescing(mr, offset, size) do { ; } while(0)
#define memory_region_set_coalescing(mr) do { ; } while(0)

uint64_t memory_region_absolute_offset(MemoryRegion *mr);

void memory_region_set_serverid(MemoryRegion *mr, unsigned int serverid);

void init_memory_region(void);

int memory_region_add_ram_range(MemoryRegion *mr, size_t offset, size_t length,
                                void (*update_ptr)(void *, void *),
                                void *opaque);
void memory_region_del_ram_range(MemoryRegion *mr, size_t offset);

#endif	/* _MR_H_ */
