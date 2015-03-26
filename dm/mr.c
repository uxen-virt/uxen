/*
 * Copyright 2012-2015, Bromium, Inc.
 * Author: Christian Limpach <Christian.Limpach@gmail.com>
 * SPDX-License-Identifier: ISC
 */

#include "config.h"

#include <err.h>
#include <stdint.h>

#include <dm/qemu/range.h>

#include "mr.h"
#include "xen.h"

static void
mr_ioport_ops_1_write(void *opaque, uint32_t address, uint32_t data)
{
    MemoryRegion *mr = opaque;

    if (mr->ops && mr->ops->write)
	mr->ops->write(mr->opaque, address - mr->ops_base, data, 1);
}

static uint32_t
mr_ioport_ops_1_read(void *opaque, uint32_t address)
{
    MemoryRegion *mr = opaque;

    if (mr->ops && mr->ops->read)
	return mr->ops->read(mr->opaque, address - mr->ops_base, 1) & 0xff;
    else
	return 0xff;
}

static IOPortOps mr_ioport_ops_1 = {
    .write = mr_ioport_ops_1_write,
    .read = mr_ioport_ops_1_read,
};

static void
mr_ioport_ops_2_write(void *opaque, uint32_t address, uint32_t data)
{
    MemoryRegion *mr = opaque;

    if (mr->ops && mr->ops->write)
	mr->ops->write(mr->opaque, address - mr->ops_base, data, 2);
}

static uint32_t
mr_ioport_ops_2_read(void *opaque, uint32_t address)
{
    MemoryRegion *mr = opaque;

    if (mr->ops && mr->ops->read)
	return mr->ops->read(mr->opaque, address - mr->ops_base, 2) & 0xffff;
    else
	return 0xffff;
}

static IOPortOps mr_ioport_ops_2 = {
    .write = mr_ioport_ops_2_write,
    .read = mr_ioport_ops_2_read,
};

static void
mr_ioport_ops_4_write(void *opaque, uint32_t address, uint32_t data)
{
    MemoryRegion *mr = opaque;

    if (mr->ops && mr->ops->write)
	mr->ops->write(mr->opaque, address - mr->ops_base, data, 4);
}

static uint32_t
mr_ioport_ops_4_read(void *opaque, uint32_t address)
{
    MemoryRegion *mr = opaque;

    if (mr->ops && mr->ops->read)
	return mr->ops->read(mr->opaque, address - mr->ops_base, 4) & 0xffffffff;
    else
	return 0xffffffff;
}

static IOPortOps mr_ioport_ops_4 = {
    .write = mr_ioport_ops_4_write,
    .read = mr_ioport_ops_4_read,
};

static void
mr_iomem_read_access_fn(MemoryRegion *mr, uint64_t addr, uint32_t *value,
			uint32_t size, uint32_t shift, uint32_t mask)
{
    uint32_t tmp;

    tmp = mr->ops->read(mr->opaque, addr, size);
    *value |= (tmp & mask) << shift;
}

static void
mr_iomem_write_access_fn(MemoryRegion *mr, uint64_t addr, uint32_t *value,
			 uint32_t size, uint32_t shift, uint32_t mask)
{
    uint32_t tmp;

    tmp = (*value >> shift) & mask;
    mr->ops->write(mr->opaque, addr, tmp, size);
}

static void
mr_iomem_access(MemoryRegion *mr, uint64_t addr, uint32_t *value, uint32_t size,
		void (*access_fn)(MemoryRegion *, uint64_t, uint32_t *,
				  uint32_t, uint32_t, uint32_t))
{
    unsigned int i;
    uint32_t access_mask;
    uint32_t access_size;

    access_size = MAX(MIN(size, mr->ops->impl.max_access_size ? : 4),
		      mr->ops->impl.min_access_size ? : 1);
    access_mask = ~0UL >> ((4 - access_size) * 8);
    for (i = 0; i < size; i += access_size)
	access_fn(mr, addr + i, value, access_size, i * 8, access_mask);
}

uint32_t
mr_iomem_read_1(void *opaque, uint64_t addr)
{
    MemoryRegion *mr = opaque;
    uint32_t value = 0;

    if (!mr->ops->read)
	return 0xff;

    mr_iomem_access(mr, addr - mr->ops_base, &value, 1,
		    mr_iomem_read_access_fn);
    return value;
}

uint32_t
mr_iomem_read_2(void *opaque, uint64_t addr)
{
    MemoryRegion *mr = opaque;
    uint32_t value = 0;

    if (!mr->ops->read)
	return 0xffff;

    mr_iomem_access(mr, addr - mr->ops_base, &value, 2,
		    mr_iomem_read_access_fn);
    return value;
}

uint32_t
mr_iomem_read_4(void *opaque, uint64_t addr)
{
    MemoryRegion *mr = opaque;
    uint32_t value = 0;

    if (!mr->ops->read)
	return 0xffffffff;

    mr_iomem_access(mr, addr - mr->ops_base, &value, 4,
		    mr_iomem_read_access_fn);
    return value;
}

static IOMemReadFunc *mr_iomem_read[] = {
    mr_iomem_read_1,
    mr_iomem_read_2,
    mr_iomem_read_4,
};

void
mr_iomem_write_1(void *opaque, uint64_t addr, uint32_t value)
{
    MemoryRegion *mr = opaque;

    if (!mr->ops->write)
	return;

    mr_iomem_access(mr, addr - mr->ops_base, &value, 1,
		    mr_iomem_write_access_fn);
}

void
mr_iomem_write_2(void *opaque, uint64_t addr, uint32_t value)
{
    MemoryRegion *mr = opaque;

    if (!mr->ops->write)
	return;

    mr_iomem_access(mr, addr - mr->ops_base, &value, 2,
		    mr_iomem_write_access_fn);
}

void
mr_iomem_write_4(void *opaque, uint64_t addr, uint32_t value)
{
    MemoryRegion *mr = opaque;

    if (!mr->ops->write)
	return;

    mr_iomem_access(mr, addr - mr->ops_base, &value, 4,
		    mr_iomem_write_access_fn);
}

static IOMemWriteFunc *mr_iomem_write[] = {
    mr_iomem_write_1,
    mr_iomem_write_2,
    mr_iomem_write_4,
};

static void
update_tree_recurse(MemoryRegion *mr, int clear, uint64_t addr, int is_ioport)
{
    MemoryRegion *r;

    TAILQ_FOREACH(r, &mr->subregions, subregions_link)
	update_tree_recurse(r, clear, addr + mr->parent_offset, is_ioport);

    if (mr->ops == NULL && mr->ioport_list == NULL)
	return;

    if (!clear)
	xen_map_iorange(addr + mr->parent_offset, mr->size,
			is_ioport ? 0 : 1, mr->serverid);
    else
	xen_unmap_iorange(mr->ops_base, mr->size, is_ioport ? 0 : 1,
			  mr->serverid);
    if (is_ioport && mr->ioport_list) {
        if (!clear) {
	    mr->ops_base = memory_region_absolute_offset(mr) +
                mr->ioport_list_offset;
            ioport_region_list_map(mr->ioport_list, mr, mr->ioport_list_offset);
        } else {
	    unregister_ioport_ops(mr->ops_base, mr->size);
	    mr->ops_base = 0;
        }
    } else if (is_ioport) {
	if (!clear) {
	    mr->ops_base = addr + mr->parent_offset;
	    register_ioport_ops(mr->ops_base, mr->size, 1,
				&mr_ioport_ops_1, mr);
	    if (mr->size >= 2)
		register_ioport_ops(mr->ops_base, mr->size / 2, 2,
				    &mr_ioport_ops_2, mr);
	    if (mr->size >= 4)
		register_ioport_ops(mr->ops_base, mr->size / 4, 4,
				    &mr_ioport_ops_4, mr);
	} else {
	    unregister_ioport_ops(mr->ops_base, mr->size);
	    mr->ops_base = 0;
	}
    } else {
	if (!clear) {
	    mr->ops_base = addr + mr->parent_offset;
	    if (mr->mmio_index == -1)
		mr->mmio_index = register_iomem(0, mr_iomem_read,
						mr_iomem_write, mr);
	    register_mmio(mr->ops_base, mr->size, mr->mmio_index);
	} else {
	    unregister_mmio(mr->ops_base);
	    mr->ops_base = 0;
	}
    }
}

static void
update_tree(MemoryRegion *mr, int clear)
{
    MemoryRegion *top;
    uint64_t addr;

    top = mr;
    addr = 0;
    while (top->parent) {
	top = top->parent;
	addr += top->parent_offset;
    }
    if (top != system_iomem && top != system_ioport)
	return;			/* not attached to system */

    update_tree_recurse(mr, clear, addr, top == system_ioport);
}

void memory_region_init(MemoryRegion *mr,
                        const char *name,
                        uint64_t size)
{
    memset(mr, 0, sizeof(*mr));
    mr->size = size;
    mr->name = name;
    TAILQ_INIT(&mr->subregions);
    mr->mmio_index = -1;
    mr->serverid = 1;
    TAILQ_INIT(&mr->ram_map);
}


void memory_region_init_io(MemoryRegion *mr,
                           const MemoryRegionOps *ops,
                           void *opaque,
                           const char *name,
                           uint64_t size)
{
    memory_region_init(mr, name, size);
    mr->ops = ops;
    mr->opaque = opaque;
}

void memory_region_init_ram_ptr(MemoryRegion *mr,
                                DeviceState *dev,
                                const char *name,
                                uint64_t size,
                                void *ptr)
{
    memory_region_init(mr, name, size);
    mr->ram_ptr = (uint64_t)(uintptr_t)ptr;
    debug_break();
}

void memory_region_init_alias(MemoryRegion *mr,
                              const char *name,
                              MemoryRegion *orig,
                              uint64_t offset,
                              uint64_t size)
{
    memory_region_init(mr, name, size);
    mr->alias = orig;
    mr->alias_offset = offset;
}

void memory_region_destroy(MemoryRegion *mr)
{
    assert(TAILQ_EMPTY(&mr->subregions));
}

uint64_t
memory_region_size(MemoryRegion *mr)
{
    return mr->size;
}

void memory_region_add_subregion(MemoryRegion *mr,
                                 uint64_t offset,
                                 MemoryRegion *subregion)
{
    subregion->parent = mr;
    subregion->parent_offset = offset;

    TAILQ_INSERT_TAIL(&mr->subregions, subregion, subregions_link);

    update_tree(subregion, 0);

    if (subregion->map_cb)
        subregion->map_cb(subregion->map_opaque);
}

void memory_region_add_subregion_overlap(MemoryRegion *mr,
                                         uint64_t offset,
                                         MemoryRegion *subregion,
                                         unsigned priority)
{
    memory_region_add_subregion(mr, offset, subregion);
}

void memory_region_del_subregion(MemoryRegion *mr,
                                 MemoryRegion *subregion)
{
    assert(subregion->parent == mr);

    update_tree(subregion, 1);

    subregion->parent = NULL;
    TAILQ_REMOVE(&mr->subregions, subregion, subregions_link);
}

uint64_t
memory_region_absolute_offset(MemoryRegion *mr)
{
    uint64_t addr;

    addr = mr->parent_offset;
    while (mr->parent) {
	mr = mr->parent;
	addr += mr->parent_offset;
    }

    return addr;
}

void
memory_region_set_serverid(MemoryRegion *mr, unsigned int serverid)
{

    mr->serverid = serverid;
}

MemoryRegion *system_iomem = NULL;
MemoryRegion *system_ioport = NULL;

void
init_memory_region(void)
{

    system_iomem = malloc(sizeof(*system_iomem));
    memory_region_init(system_iomem, "iomem", INT64_MAX);

    system_ioport = malloc(sizeof(*system_ioport));
    memory_region_init(system_ioport, "ioport", 65536);
}

int
memory_region_add_ram_range(MemoryRegion *mr, size_t offset, size_t length,
                            void (*update_ptr)(void *, void *), void *opaque)
{
    struct ram_range *r, *cur;

    if ((offset + length) > mr->size)
        return -1;

    TAILQ_FOREACH(cur, &mr->ram_map, link) {
        if (ranges_overlap(cur->offset, cur->length, offset, length))
            return -1;
        if (cur->offset > offset)
            break;
    }

    r = malloc(sizeof (*r));
    r->offset = offset;
    r->length = length;
    r->ram_ptr = NULL;
    r->update_ptr = update_ptr;
    r->opaque = opaque;

    if (cur)
        TAILQ_INSERT_BEFORE(cur, r, link);
    else
        TAILQ_INSERT_TAIL(&mr->ram_map, r, link);

    return 0;
}

void
memory_region_del_ram_range(MemoryRegion *mr, size_t offset)
{
    struct ram_range *cur;

    TAILQ_FOREACH(cur, &mr->ram_map, link) {
        if (ranges_overlap(cur->offset, cur->length, offset, 1)) {
            TAILQ_REMOVE(&mr->ram_map, cur, link);
            free(cur);
            break;
        }
    }
}
