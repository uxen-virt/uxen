/*
 * Copyright 2012-2015, Bromium, Inc.
 * Author: Christian Limpach <Christian.Limpach@gmail.com>
 * SPDX-License-Identifier: ISC
 */

#include "config.h"

#include <err.h>
#include <stdint.h>

#include "compiler.h"
#include "iomem.h"
#include "lib.h"

#include "rbtree.h"

// #define IOMEM_DEBUG_UNUSED
// #define IOMEM_TRACE

#ifdef IOMEM_DEBUG_UNUSED
#define UNUSED_PRINTF(fmt, ...) dprintf(fmt, ## __VA_ARGS__)
#else
#define UNUSED_PRINTF(fmt, ...) do { } while(0)
#endif

#ifdef IOMEM_TRACE
#undef IOMEM_TRACE
#define IOMEM_TRACE(fmt, ...) dprintf(fmt, ## __VA_ARGS__)
#else
#define IOMEM_TRACE(fmt, ...) do { } while(0)
#endif

#define IOMEM_ALLOC_BATCH 4
static int max_iomem = 0;
static int free_iomem = 0;

static struct iomem_region *iomem = NULL;

int
register_iomem(int index, IOMemReadFunc *mem_read[],
	       IOMemWriteFunc *mem_write[], void *opaque)
{
    int i;

    if (index == 0) {
	while (free_iomem < max_iomem && iomem[free_iomem].read[0] != NULL)
	    free_iomem++;
	if (free_iomem == max_iomem) {
	    max_iomem += IOMEM_ALLOC_BATCH;
	    iomem = realloc(iomem, max_iomem * sizeof(*iomem));
	    if (iomem == NULL)
		err(1, "realloc");
	    memset(&iomem[free_iomem], 0, IOMEM_ALLOC_BATCH * sizeof(*iomem));
	}
	index = free_iomem;
	free_iomem++;
    }
    
    for (i = 0; i < 3; i++) {
	iomem[index].read[i] = mem_read[i];
	iomem[index].write[i] = mem_write[i];
    }
    iomem[index].opaque = opaque;

    return index;
}

void
unregister_iomem(int index)
{

    /* XXX clear mmio */
    debug_break();

    memset(&iomem[index], 0, sizeof(*iomem));
    if (index < free_iomem)
	free_iomem = index;
}

IOMemWriteFunc **
get_iomem_write(int index)
{

    assert(index < max_iomem);
    return iomem[index].write;
}

IOMemReadFunc **
get_iomem_read(int index)
{

    assert(index < max_iomem);
    return iomem[index].read;
}

struct mmio_key {
    uint64_t addr;
    uint64_t size;
};

struct mmio {
    struct mmio_key mmio_key;
#define mmio_addr mmio_key.addr
#define mmio_size mmio_key.size
    int mmio_index;
    struct rb_node mmio_rbnode;
};

static int
mmio_compare_key(void *ctx, const void *b, const void *key)
{
    const struct mmio * const pnp = b;
    const struct mmio_key * const fhp = key;

    if ((pnp->mmio_addr >= fhp->addr && 
	 pnp->mmio_addr + pnp->mmio_size < fhp->addr + fhp->size) ||
	(fhp->addr >= pnp->mmio_addr &&
	 fhp->addr + fhp->size < pnp->mmio_addr + pnp->mmio_size))
	return 0;
    return pnp->mmio_addr - fhp->addr;
}

static int
mmio_compare_nodes(void *ctx, const void *parent, const void *node)
{
    const struct mmio * const np = node;

    return mmio_compare_key(ctx, parent, &np->mmio_key);
}

static rb_tree_t mmio_rbtree;
static const rb_tree_ops_t mmio_rbtree_ops = {
    .rbto_compare_nodes = mmio_compare_nodes,
    .rbto_compare_key = mmio_compare_key,
    .rbto_node_offset = offsetof(struct mmio, mmio_rbnode),
    .rbto_context = NULL
};

void
mmio_init(void)
{

    rb_tree_init(&mmio_rbtree, &mmio_rbtree_ops);
}

void
register_mmio(uint64_t addr, uint64_t size, int index)
{
    struct mmio_key mmio_key;
    struct mmio *mmio;

    mmio_key.addr = addr;
    mmio_key.size = size;
    mmio = rb_tree_find_node(&mmio_rbtree, &mmio_key);
    if (mmio == NULL) {
	mmio = calloc(1, sizeof(*mmio));
	if (mmio == NULL)
	    err(1, "calloc");
	mmio->mmio_key = mmio_key;
	rb_tree_insert_node(&mmio_rbtree, mmio);
    }
    if (mmio->mmio_addr != addr)
	errx(1, "register_mmio addr mismatch");
    mmio->mmio_index = index;
}

int
mmio_index(uint64_t addr)
{
    struct mmio_key mmio_key;
    struct mmio *mmio;

    mmio_key.addr = addr;
    mmio_key.size = 0;
    mmio = rb_tree_find_node(&mmio_rbtree, &mmio_key);

    return mmio ? mmio->mmio_index : -1;
}

void
unregister_mmio(uint64_t addr)
{
    struct mmio_key mmio_key;
    struct mmio *mmio;

    mmio_key.addr = addr;
    mmio_key.size = 0;
    mmio = rb_tree_find_node(&mmio_rbtree, &mmio_key);
    if (mmio) {
	rb_tree_remove_node(&mmio_rbtree, mmio);
	free(mmio);
    } else
	warnx("unregister_mmio(%"PRIx64") not found", addr);
}

int
mmio_write(uint64_t addr, uint32_t val, uint32_t width)
{
    struct mmio_key mmio_key;
    struct mmio *mmio;

    mmio_key.addr = addr;
    mmio_key.size = width;
    mmio = rb_tree_find_node(&mmio_rbtree, &mmio_key);
    if (mmio) {
	assert(mmio->mmio_index < max_iomem);
	iomem[mmio->mmio_index].write[width](iomem[mmio->mmio_index].opaque,
					     addr, val);
	return 0;
    } else {
	//warnx("mmio_write(%"PRIx64"/%d, %x) not found", addr, width, val);
	return -1;
    }
}

int
mmio_read(uint64_t addr, uint32_t width, uint32_t *val)
{
    struct mmio_key mmio_key;
    struct mmio *mmio;

    mmio_key.addr = addr;
    mmio_key.size = width;
    mmio = rb_tree_find_node(&mmio_rbtree, &mmio_key);
    if (mmio) {
	assert(mmio->mmio_index < max_iomem);
	*val = iomem[mmio->mmio_index].
	  read[width](iomem[mmio->mmio_index].opaque, addr);
	return 0;
    } else {
	// warnx("mmio_read(%"PRIx64"/%d) not found", addr, width);
	return -1;
    }
}
