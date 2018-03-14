/*
 * Copyright 2018, Bromium, Inc.
 * Author: Tomasz Wroblewski <tomasz.wroblewski@gmail.com>
 * SPDX-License-Identifier: ISC
 */

#include <dm/qemu_glue.h>
#include "whpx.h"
#include "core.h"

#define VM_VA_RANGE_SIZE 0x100000000ULL

/* base for ram allocated by uxendm (won't be used if vm runs off
 * memory mapped file for example */
static uint8_t *vm_ram_base = NULL;

typedef struct pagerange {
    uint64_t start; /* start page */
    uint64_t end; /* end page */
} pagerange_t;

/* vm-mappable block */
typedef struct mb_entry {
    TAILQ_ENTRY(mb_entry) entry;

    pagerange_t r;
    uint64_t page_count;
    void *va;
    int partition_mapped;
    uint32_t flags;
} mb_entry_t;

/* sorted list of blocks */
static TAILQ_HEAD(, mb_entry) mb_entries;

static void
remap_mb(mb_entry_t *mb, int map)
{
    whpx_update_mapping(
        mb->r.start << PAGE_SHIFT,
        mb->page_count << PAGE_SHIFT,
        mb->va,
        map ? 1:0,
        0 /* rom */,
        NULL);
    mb->partition_mapped = map;
}

static void
insert_mb(mb_entry_t *mb)
{
    mb_entry_t *e;
    mb_entry_t *after = NULL;

    TAILQ_FOREACH(e, &mb_entries, entry) {
        if (e->r.start <= mb->r.start)
            after = e;
        else break;
    }

    if (after)
        TAILQ_INSERT_AFTER(&mb_entries, after, mb, entry);
    else
        TAILQ_INSERT_TAIL(&mb_entries, mb, entry);
}

// create memory block at guest physical address
static mb_entry_t *
create_mb(uint64_t phys_addr, uint64_t len, void *va, uint32_t flags)
{
    mb_entry_t *entry;

    debug_printf("WHPX: +++ memory block %016"PRIx64" - %016"PRIx64
                 " (%d pages) va %p\n",
      phys_addr, phys_addr+len-1,
        (int)(len >> PAGE_SHIFT), va);

    assert((phys_addr & ~TARGET_PAGE_MASK) == 0);
    assert((len & ~TARGET_PAGE_MASK) == 0);

    entry = calloc(1, sizeof(mb_entry_t));
    if (!entry)
        whpx_panic("out of memory");
    entry->r.start = phys_addr >> PAGE_SHIFT;
    entry->page_count = len >> PAGE_SHIFT;
    entry->r.end = entry->r.start + entry->page_count-1;
    entry->va = va;
    entry->flags = flags;

    remap_mb(entry, 1);
    insert_mb(entry);

    return entry;
}

static void
destroy_mb(mb_entry_t *mb)
{
    if (mb) {
        uint64_t addr_start = mb->r.start << PAGE_SHIFT;
        uint64_t addr_end = ((mb->r.start + mb->page_count) << PAGE_SHIFT) - 1;

        debug_printf("WHPX: --- memory block %016"PRIx64" - %016"PRIx64
                     " (%d pages) va %p\n",
                     addr_start, addr_end,
                     (int)mb->page_count, mb->va);
        TAILQ_REMOVE(&mb_entries, mb, entry);
        // remove mapping
        remap_mb(mb, 0);

        free(mb);
    }
}

#if 0
static pagerange_t
mk_pr(uint64_t addr, uint64_t len)
{
    pagerange_t r;

    assert((addr & ~TARGET_PAGE_MASK) == 0);
    assert((len & ~TARGET_PAGE_MASK) == 0);

    r.start = addr >> PAGE_SHIFT;
    r.end   = (addr + len - 1) >> PAGE_SHIFT;

    return r;
}
#endif

#if 0
static uint64_t
pr_bytes(pagerange_t *r)
{
    return (r->end - r->start + 1) << PAGE_SHIFT;
}
#endif

static mb_entry_t *
create_mb_from_pr(pagerange_t *pr, void *va, uint32_t flags)
{
    return create_mb(
      pr->start << PAGE_SHIFT,
      (pr->end - pr->start + 1) << PAGE_SHIFT,
      va, flags);
}

static int
intersect_pr(pagerange_t *a, pagerange_t *b, pagerange_t *out)
{
    uint64_t p_start, p_end;

    if (a->start > b->end ||
        b->start > a->end)
        return 0; /* no intersection */

    if (a->start >= b->start && a->start <= b->end)
        p_start = a->start;
    else if (a->start < b->start)
        p_start = b->start;
    else
        return 0;

    if (a->end >= b->start && a->end <= b->end)
        p_end = a->end;
    else if (a->end > b->end)
        p_end = b->end;
    else
        return 0;

    out->start = p_start;
    out->end = p_end;

    return 1;
}

#if 0
// a minus b, returns number of chunks
static int
diff_pr(pagerange_t *a, pagerange_t *b, pagerange_t *out)
{
    pagerange_t inter;
    int count = 0;
    
    if (!intersect_pr(a, b, &inter)) {
        *out = *a;
        return 1;
    }

    if (a->start < b->start) {
        out->start = a->start;
        out->end   = b->start - 1;
        out++;
        count++;
    }

    if (a->end > b->end) {
        out->start = b->end + 1;
        out->end   = a->end;
        out++;
        count++;
    }

    return count;
}
#endif

/**
 * Map host ram into partition
  */
static int
map_region_to_vm(uint64_t phys_addr, uint64_t len, void *va, uint32_t flags)
{
    mb_entry_t *e, *next;
    pagerange_t r;
    uint64_t page_start = phys_addr >> PAGE_SHIFT;

    assert((phys_addr & ~TARGET_PAGE_MASK) == 0);
    assert((len & ~TARGET_PAGE_MASK) == 0);

    r.start = phys_addr >> PAGE_SHIFT;
    r.end = (phys_addr + len -1) >> PAGE_SHIFT;

    TAILQ_FOREACH_SAFE(e, &mb_entries, entry, next) {
        pagerange_t inter;

        if (!(r.start <= r.end))
            return 0; /* all done */

        if (!intersect_pr(&r, &e->r, &inter))
            continue; /* region to insert does not intersect 'e', no need to trim it */
        else {
            assert(0);
#if 0
            pagerange_t diff[2];
            int n;

            /* intersection - split region to insert into the left-side part & insert it,
             * and continue processing on the right-side part */
            n = diff_pr(&r, &e->r, diff);

            if (n == 1) {
                r = diff[0];
            } else if (n == 2) {
                if (!create_mb_from_pr(&diff[0],
                    (uint8_t*)va + ((diff[0].start - page_start) << PAGE_SHIFT),
                    flags))
                    return -1;
                /* 'r' becomes right-side part */
                r = diff[1];
            }
#endif
        }
    }

    /* any leftover part */
    if (r.start <= r.end)
        if (!create_mb_from_pr(&r,
            (uint8_t*)va + ((r.start - page_start) << PAGE_SHIFT),
            flags))
            return -1;

    return 0;
}

/**
 * Unmap host ram from partition. Take special care for partial unmaps since
 * WHP api does not support them.
 * Simulate via unmapping whole range & remapping up to two smaller parts.
 */
static int
unmap_region_from_vm(uint64_t phys_addr, uint64_t len, uint32_t flags)
{
    mb_entry_t *e, *next;
    pagerange_t r;
    int ret = -1;

    assert((phys_addr & ~TARGET_PAGE_MASK) == 0);
    assert((len & ~TARGET_PAGE_MASK) == 0);

    r.start = phys_addr >> PAGE_SHIFT;
    r.end = (phys_addr + len - 1) >> PAGE_SHIFT;

    TAILQ_FOREACH_SAFE(e, &mb_entries, entry, next) {
        pagerange_t inter;
        pagerange_t new1, new2;
        void *new1va = 0, *new2va = 0;
        new1.start = new1.end = new2.start = new2.end = -1LL;

        if (intersect_pr(&e->r, &r, &inter)) {
            if (inter.start > e->r.start) {
                new1.start = e->r.start;
                new1.end   = inter.start - 1;
                new1va     = e->va;
            }
            if (inter.end < e->r.end) {
                new2.start = inter.end + 1;
                new2.end   = e->r.end;
                new2va     = (uint8_t*)e->va +
                  ((inter.end - e->r.start + 1) << PAGE_SHIFT);
            }

            // unmap existing block
            destroy_mb(e);
            // maybe map smaller blocks
            if (new1.start != -1LL) {
                if (!create_mb_from_pr(&new1, new1va, e->flags))
                    goto out;
            }
            if (new2.start != -1LL) {
                if (!create_mb_from_pr(&new2, new2va, e->flags))
                    goto out;
            }
        }
    }

    ret = 0;
out:
    return ret;
}

int
whpx_ram_populate(uint64_t phys_addr, uint64_t len, uint32_t flags)
{
    int ret;

    debug_printf("WHPX: +++ vm ram %016"PRIx64" - %016"PRIx64 " (%d pages)\n",
        phys_addr, phys_addr+len-1,
        (int)(len >> PAGE_SHIFT));

    assert((phys_addr & ~TARGET_PAGE_MASK) == 0);
    assert((len & ~TARGET_PAGE_MASK) == 0);

    if (!VirtualAlloc(vm_ram_base + phys_addr, len, MEM_COMMIT, PAGE_READWRITE))
        whpx_panic("FAILED to commit ram!\n");

    /* remove any stale mem blocks */
    ret = unmap_region_from_vm(phys_addr, len, flags);
    if (ret)
        whpx_panic("FAILED to unmap region (%d)!\n", ret);

    ret = map_region_to_vm(phys_addr, len, vm_ram_base + phys_addr, flags);
    if (ret)
        whpx_panic("FAILED to map region (%d)!\n", ret);

    return 0;
}

int
whpx_ram_populate_with(uint64_t phys_addr, uint64_t len, void *va, uint32_t flags)
{
    int ret;

    assert((phys_addr & ~TARGET_PAGE_MASK) == 0);
    assert((len & ~TARGET_PAGE_MASK) == 0);

    debug_printf("WHPX: +++ vm hostva mapping %016"PRIx64" - %016"PRIx64
                 " (%d pages) va=%p\n",
                 phys_addr, phys_addr+len-1, (int)(len >> PAGE_SHIFT), va);

    /* remove any stale mem blocks */
    ret = unmap_region_from_vm(phys_addr, len, flags);
    if (ret)
        whpx_panic("FAILED to unmap region (%d)!\n", ret);

    return map_region_to_vm(phys_addr, len, va, flags);
}


int
whpx_ram_depopulate(uint64_t phys_addr, uint64_t len, uint32_t flags)
{
    int ret;

    debug_printf("WHPX: --- vm ram %016"PRIx64" - %016"PRIx64 " (%d pages)\n",
        phys_addr, phys_addr+len-1,
        (int)(len >> PAGE_SHIFT));

    assert((phys_addr & ~TARGET_PAGE_MASK) == 0);
    assert((len & ~TARGET_PAGE_MASK) == 0);

    ret = unmap_region_from_vm(phys_addr, len, flags);
    if (ret)
        whpx_panic("FAILED to unmap region (%d)!\n", ret);

    if (!VirtualFree(vm_ram_base + phys_addr, len, MEM_DECOMMIT))
        whpx_panic("FAILED to decommit ram!");

    return 0;
}

void *
whpx_ram_map(uint64_t phys_addr, uint64_t *len)
{
    uint64_t l = *len;

    // sanity
    assert((phys_addr < VM_VA_RANGE_SIZE) && (phys_addr + l < VM_VA_RANGE_SIZE));

    mb_entry_t *e;
    uint64_t page = phys_addr >> PAGE_SHIFT;
    uint64_t page_off = phys_addr & ~TARGET_PAGE_MASK;
    uint64_t phys_addr_end = phys_addr + (*len) - 1;

    TAILQ_FOREACH(e, &mb_entries, entry) {
        if (page >= e->r.start && page <= e->r.end) {
            uint64_t mb_max_addr = ((e->r.end+1) << PAGE_SHIFT) - 1;

            if (phys_addr_end > mb_max_addr) {
                phys_addr_end = mb_max_addr;
                *len = phys_addr_end - phys_addr + 1;
            }
            uint64_t mb_page = page - e->r.start;

            return e->va + (mb_page << UXEN_PAGE_SHIFT) + page_off;
        }
    }
    return NULL;
}

void
whpx_ram_unmap(void *ptr)
{
    /* no-op */
}

void
whpx_register_iorange(uint64_t start, uint64_t length, int is_mmio)
{
    if (is_mmio) {
        /* for mmio, unmap the area in order to get notifications from HV */
        debug_printf("WHPX: +++ mmio range %016"PRIx64" - %016"PRIx64"\n",
            start, start+length-1);

        if (whpx_ram_depopulate(start, length, 0))
            whpx_panic("depopulate failed\n");
        debug_printf("WHPX: mmio range registered\n");
    } else {
        /* no-op for ioports (no api for that, HV should forward us everything */
    }
}

void
whpx_unregister_iorange(uint64_t start, uint64_t length, int is_mmio)
{
    if (is_mmio) {
        debug_printf("WHPX: --- mmio range %016"PRIx64" - %016"PRIx64"\n",
            start, start+length-1);

        /* only way to stop emulated mmio is to give that area some backing ram */
        if (whpx_ram_populate(start, length, 0))
            whpx_panic("populate failed\n");
    }
}

int whpx_ram_init(void)
{
    TAILQ_INIT(&mb_entries);

    /* reserve 4GB VA Range for vm use */
    vm_ram_base = VirtualAlloc(NULL, (SIZE_T)VM_VA_RANGE_SIZE, MEM_RESERVE,
        PAGE_READWRITE);
    if (!vm_ram_base)
        whpx_panic("ram reservation failed\n");
    debug_printf("vm_ram_base = 0x%p\n", vm_ram_base);

    return 0;
}
