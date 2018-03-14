/*
 * Copyright 2012-2018, Bromium, Inc.
 * Author: Christian Limpach <Christian.Limpach@gmail.com>
 * SPDX-License-Identifier: ISC
 */

#include "config.h"

#include <err.h>
#include <stdint.h>

#include "compiler.h"
#include "ioport.h"
#include "lib.h"
#include "mr.h"
#include "xen.h"

#include "rbtree.h"

#include <dm/dm.h>
#include <dm/whpx/whpx.h>

// #define IOPORT_DEBUG_UNUSED
// #define IOPORT_TRACE

#ifdef IOPORT_DEBUG_UNUSED
#define UNUSED_PRINTF(fmt, ...) dprintf(fmt, ## __VA_ARGS__)
#else
#define UNUSED_PRINTF(fmt, ...) do { } while(0)
#endif

#ifdef IOPORT_TRACE
#undef IOPORT_TRACE
#define IOPORT_TRACE(fmt, ...) dprintf(fmt, ## __VA_ARGS__)
#else
#define IOPORT_TRACE(fmt, ...) do { } while(0)
#endif

typedef uint32_t ioport_key;

struct ioport {
    ioport_key ioport;
    IOPortReadFunc *ioport_read_table[3];
    IOPortWriteFunc *ioport_write_table[3];
    void *opaque;
    struct rb_node ioport_rbnode;
};

static int
ioport_compare_key(void *ctx, const void *b, const void *key)
{
    const struct ioport * const pnp = b;
    const ioport_key * const fhp = key;

    return pnp->ioport - *fhp;
}

static int
ioport_compare_nodes(void *ctx, const void *parent, const void *node)
{
    const struct ioport * const np = node;

    return ioport_compare_key(ctx, parent, &np->ioport);
}

static rb_tree_t ioport_rbtree;
static const rb_tree_ops_t ioport_rbtree_ops = {
    .rbto_compare_nodes = ioport_compare_nodes,
    .rbto_compare_key = ioport_compare_key,
    .rbto_node_offset = offsetof(struct ioport, ioport_rbnode),
    .rbto_context = NULL
};

void
ioport_init(void)
{

    rb_tree_init(&ioport_rbtree, &ioport_rbtree_ops);
}

static uint32_t
default_ioport_readb(void *opaque, uint32_t address)
{

    UNUSED_PRINTF("unused inb: port=0x%04x\n", address);
    return 0xff;
}

static void
default_ioport_writeb(void *opaque, uint32_t address, uint32_t data)
{

    UNUSED_PRINTF("unused outb: port=0x%04x data=0x%02x\n", address, data);
}

/* default is to make two byte accesses */
static uint32_t
default_ioport_readw(void *opaque, uint32_t address)
{
    uint32_t data;

    data = ioport_read(0, address);
    address = (address + 1) & (MAX_IOPORTS - 1);
    data |= ioport_read(0, address) << 8;
    return data;
}

static void
default_ioport_writew(void *opaque, uint32_t address, uint32_t data)
{

    ioport_write(0, address, data & 0xff);
    address = (address + 1) & (MAX_IOPORTS - 1);
    ioport_write(0, address, (data >> 8) & 0xff);
}

static uint32_t
default_ioport_readl(void *opaque, uint32_t address)
{

    UNUSED_PRINTF("unused inl: port=0x%04x\n", address);
    return 0xffffffff;
}

static void
default_ioport_writel(void *opaque, uint32_t address, uint32_t data)
{

    UNUSED_PRINTF("unused outl: port=0x%04x data=0x%02x\n", address, data);
}

uint32_t
ioport_read(ioport_width_t width, uint32_t address)
{
    static IOPortReadFunc *default_fn[3] = {
        default_ioport_readb,
        default_ioport_readw,
        default_ioport_readl
    };
    struct ioport *ioport;

    ioport = rb_tree_find_node(&ioport_rbtree, &address);
    if (ioport && ioport->ioport_read_table[width])
	return (ioport->ioport_read_table[width])(ioport->opaque, address);
    return default_fn[width](NULL, address);
}

void
ioport_write(ioport_width_t width, uint32_t address, uint32_t data)
{
    static IOPortWriteFunc *default_fn[3] = {
        default_ioport_writeb,
        default_ioport_writew,
        default_ioport_writel
    };
    struct ioport *ioport;

    ioport = rb_tree_find_node(&ioport_rbtree, &address);
    if (ioport && ioport->ioport_write_table[width])
	return (ioport->ioport_write_table[width])(ioport->opaque, address,
						   data);
    return default_fn[width](NULL, address, data);
}

static int
register_ioport_fn(uint32_t start, uint32_t length, uint32_t size,
		   void *func, void *opaque, int is_write)
{
    int bsize;
    uint32_t address;
    struct ioport *ioport;

    bsize = ioport_width(size, "register_ioport_%s: invalid size",
			 is_write ? "write" : "read");

    for (address = start; address < start + length; address += size) {
	ioport = rb_tree_find_node(&ioport_rbtree, &address);
	if (ioport == NULL) {
	    ioport = calloc(1, sizeof(*ioport));
	    if (ioport == NULL)
		err(1, "calloc");
	    ioport->ioport = address;
	    rb_tree_insert_node(&ioport_rbtree, ioport);
	}
	if (is_write)
	    ioport->ioport_write_table[bsize] = func;
	else
	    ioport->ioport_read_table[bsize] = func;
        if (ioport->opaque != NULL && ioport->opaque != opaque)
            errx(1, "register_ioport_%s: invalid opaque",
		 is_write ? "write" : "read");
        ioport->opaque = opaque;
    }
    return 0;
}

int
register_ioport_ops(uint32_t start, uint32_t length, uint32_t size,
		    IOPortOps *ops, void *opaque)
{
    int ret = 0;

    ret |= register_ioport_fn(start, length, size, ops->read, opaque, 0);
    ret |= register_ioport_fn(start, length, size, ops->write, opaque, 1);

    return ret;
}

void
unregister_ioport_ops(uint32_t start, uint32_t length)
{
    uint32_t address;
    struct ioport *ioport;

    for (address = start; address < start + length; address++) {
	ioport = rb_tree_find_node(&ioport_rbtree, &address);
	if (ioport) {
	    rb_tree_remove_node(&ioport_rbtree, ioport);
	    free(ioport);
	}
    }
}

int
register_ioport_read(uint32_t start, uint32_t length, uint32_t size,
		     IOPortReadFunc func, void *opaque)
{
    if (!whpx_enable)
        xen_map_iorange(start, length * size, 0, 1);
    else
        whpx_register_iorange(start, length * size,  0);

  return register_ioport_fn(start, length, size, func, opaque, 0);
}

int
register_ioport_write(uint32_t start, uint32_t length, uint32_t size,
		      IOPortWriteFunc func, void *opaque)
{
    if (!whpx_enable)
        xen_map_iorange(start, length * size, 0, 1);
    else
        whpx_register_iorange(start, length * size, 0);

    return register_ioport_fn(start, length, size, func, opaque, 1);
}

int
register_ioport_list(uint32_t base, const struct ioport_region *list,
		     void *opaque)
{
    int ret = 0;

    while (list->len) {
        if (!whpx_enable)
            xen_map_iorange(base + list->offset, list->len * list->size, 0, 1);
        else
            whpx_register_iorange(base + list->offset, list->len * list->size, 0);

	if (list->read)
	    ret |= register_ioport_fn(base + list->offset, list->len,
				      list->size, list->read, opaque, 0);
	if (list->write)
	    ret |= register_ioport_fn(base + list->offset, list->len,
				      list->size, list->write, opaque, 1);
	list++;
    }

    return ret;
}

void
unregister_ioport(uint32_t start, uint32_t length)
{
    if (!whpx_enable)
        xen_unmap_iorange(start, length, 0, 1);
    else
        whpx_unregister_iorange(start, length, 0);

    unregister_ioport_ops(start, length);
}

ioport_width_t
ioport_width(int size, char *errmsg, ...)
{
    ioport_width_t width;
    va_list ap;

    switch (size) {
    case 1:
        return IOPORT_WIDTH0;
	break;
    case 2:
        return IOPORT_WIDTH1;
	break;
    case 4:
	return IOPORT_WIDTH2;
	break;
    default:
	va_start(ap, errmsg);
	if (errmsg) {
	    verrx(1, errmsg, ap);
	    /* NOTREACHED */
	}
	width = va_arg(ap, int);
	va_end(ap);
	return width;
	break;
    }
}

void
ioport_region_list_init(struct ioport_region_list *list,
			const struct ioport_region *ports,
			void *opaque, const char *name)
{

    list->ports = ports;
    list->opaque = opaque;
}

void
ioport_region_list_map(const struct ioport_region_list *list,
		       MemoryRegion *space, uint32_t offset)
{
    uint64_t base = memory_region_absolute_offset(space) + offset;

    register_ioport_list(base, list->ports, list->opaque);
}

void
ioport_region_list_set(const struct ioport_region_list *list,
		       MemoryRegion *space, uint32_t offset)
{

    space->ioport_list = list;
    space->ioport_list_offset = offset;
}
