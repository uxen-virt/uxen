/*
 * Copyright 2018, Bromium, Inc.
 * Author: Tomasz Wroblewski <tomasz.wroblewski@gmail.com>
 * SPDX-License-Identifier: ISC
 */

#include <dm/qemu_glue.h>
#include "whpx.h"
#include "core.h"
#include "paging.h"
#include "util.h"
#include <dm/vm-save.h>
#include <dm/vm-savefile.h>
#include <dm/filebuf.h>

#define VM_VA_RANGE_SIZE 0x100000000ULL

/* base for ram allocated by uxendm (won't be used if vm runs off
 * memory mapped file for example */
static uint8_t *vm_ram_base = NULL;

/* vm-mappable block */
typedef struct mb_entry {
    TAILQ_ENTRY(mb_entry) entry;

    pagerange_t r;
    void *va;
    int partition_mapped;
    uint32_t flags;
} mb_entry_t;

/* sorted list of blocks */
static TAILQ_HEAD(, mb_entry) mb_entries;

static uint64_t mb_pages(mb_entry_t *mb)
{
    return pr_bytes(&mb->r) >> PAGE_SHIFT;
}

static void
remap_mb(mb_entry_t *mb, int map)
{
    if (mb->partition_mapped == map)
        return;

    whpx_update_mapping(
        mb->r.start << PAGE_SHIFT,
        mb_pages(mb) << PAGE_SHIFT,
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
    entry->r.end = entry->r.start + (len >> PAGE_SHIFT);
    entry->va = va;
    entry->flags = flags;

    insert_mb(entry);

    return entry;
}

static void
destroy_mb(mb_entry_t *mb)
{
    if (mb) {
        uint64_t addr_start = mb->r.start << PAGE_SHIFT;
        uint64_t addr_end =  (mb->r.end << PAGE_SHIFT) - 1;

        debug_printf("WHPX: --- memory block %016"PRIx64" - %016"PRIx64
                     " (%d pages) va %p\n",
                     addr_start, addr_end,
                     (int)mb_pages(mb), mb->va);
        TAILQ_REMOVE(&mb_entries, mb, entry);

        free(mb);
    }
}

static mb_entry_t *
create_mb_from_pr(pagerange_t *pr, void *va, uint32_t flags)
{
    return create_mb(
      pr->start << PAGE_SHIFT,
      (pr->end - pr->start) << PAGE_SHIFT,
      va, flags);
}

/* calculate existing memory block intersections with given range and split them into
 * smaller ones at intersection points */
static int
vm_intersect_split(uint64_t phys_addr, uint64_t len)
{
    mb_entry_t *e, *next;
    pagerange_t r = mk_pr(phys_addr, len);
    int ret = -1;

    TAILQ_FOREACH_SAFE(e, &mb_entries, entry, next) {
        pagerange_t inter;
        pagerange_t new1, new2;
        void *new1va = 0, *new2va = 0;

        new1.start = new1.end = new2.start = new2.end = -1LL;
        if (intersect_pr(&e->r, &r, &inter)) {
            if (inter.start == e->r.start &&
                inter.end == e->r.end)
                continue;

            if (inter.start > e->r.start) {
                new1.start = e->r.start;
                new1.end   = inter.start;
                new1va     = e->va;
            }
            if (inter.end < e->r.end) {
                new2.start = inter.end;
                new2.end   = e->r.end;
                new2va     = (uint8_t*)e->va +
                  ((inter.end - e->r.start) << PAGE_SHIFT);
            }

            int mapped = e->partition_mapped;

            // unmap existing block
            remap_mb(e, 0);

            // trim existing intersecting element to intersection
            e->va = (uint8_t*)e->va + ((inter.start - e->r.start) << PAGE_SHIFT);
            e->r  = inter;

            // map trimmed block
            remap_mb(e, mapped);
            // add elements to left, right of existing one if necessary
            if (new1.start != -1LL) {
                mb_entry_t *new_mb = create_mb_from_pr(&new1, new1va, e->flags);
                if (!new_mb)
                    goto out;
                remap_mb(new_mb, mapped);
            }
            if (new2.start != -1LL) {
                mb_entry_t *new_mb = create_mb_from_pr(&new2, new2va, e->flags);
                if (!new_mb)
                    goto out;
                remap_mb(new_mb, mapped);
            }
        }
    }
    ret = 0;

out:
    return ret;
}

static void
vm_intersect_for_each(
    uint64_t phys_addr, uint64_t len,
    void (*f)(mb_entry_t *, void *),
    void *opaque)
{
    mb_entry_t *e, *next;
    pagerange_t r = mk_pr(phys_addr, len);

    TAILQ_FOREACH_SAFE(e, &mb_entries, entry, next) {
        pagerange_t inter;
        if (intersect_pr(&e->r, &r, &inter))
            f(e, opaque);
    }
}

static int
vm_commit_region(uint64_t phys_addr, uint64_t len)
{
    if (!VirtualAlloc(vm_ram_base + phys_addr, len, MEM_COMMIT, PAGE_READWRITE))
        return -1;
    return 0;
}

static int
vm_decommit_region(uint64_t phys_addr, uint64_t len)
{
    if (!VirtualFree(vm_ram_base + phys_addr, len, MEM_DECOMMIT))
        return -1;
    return 0;
}

static void
vm_map_region_remap(mb_entry_t *mb, void *opaque)
{
    remap_mb(mb, 1);
}

static int
vm_map_region(uint64_t phys_addr, uint64_t len)
{
    /* split intersecting blocks */
    if (vm_intersect_split(phys_addr, len))
        whpx_panic("vm_intersect_split failed!\n");
    /* map each intersecting block */
    vm_intersect_for_each(phys_addr, len, vm_map_region_remap, NULL);

    return 0;
}

static void
vm_unmap_region_remap(mb_entry_t *mb, void *opaque)
{
    remap_mb(mb, 0);
}

static int
vm_unmap_region(uint64_t phys_addr, uint64_t len)
{
    /* split intersecting blocks */
    if (vm_intersect_split(phys_addr, len))
        whpx_panic("vm_intersect_split failed!\n");
    /* unmap each intersecting block */
    vm_intersect_for_each(phys_addr, len, vm_unmap_region_remap, NULL);

    return 0;
}

static void
vm_create_region_remove(mb_entry_t *mb, void *opaque)
{
    destroy_mb(mb);
}

static int
vm_create_region(uint64_t phys_addr, uint64_t len, void *va, uint32_t flags)
{
    /* split intersecting blocks */
    if (vm_intersect_split(phys_addr, len))
        whpx_panic("vm_intersect_split failed!\n");
    /* remove each intersecting block */
    vm_intersect_for_each(phys_addr, len, vm_create_region_remove, NULL);
    /* insert new block */
    if (!create_mb(phys_addr, len, va, flags))
        return -1;

    return 0;
}

static void
vm_destroy_region_remove(mb_entry_t *mb, void *opaque)
{
    destroy_mb(mb);
}

static int
vm_destroy_region(uint64_t phys_addr, uint64_t len)
{
    /* split intersecting blocks */
    if (vm_intersect_split(phys_addr, len))
        whpx_panic("vm_intersect_split failed!\n");

    /* remove each intersecting block */
    vm_intersect_for_each(phys_addr, len, vm_destroy_region_remove, NULL);

    return 0;
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

    /* allocate ram */
    ret = vm_commit_region(phys_addr, len);
    if (ret)
        whpx_panic("FAILED to commit region (%d)!\n", ret);
    /* remove any previous mapping */
    ret = vm_unmap_region(phys_addr, len);
    if (ret)
        whpx_panic("FAILED to unmap region (%d)!\n", ret);
    /* create new region */
    ret = vm_create_region(phys_addr, len, (uint8_t*)vm_ram_base + phys_addr,
        flags);
    if (ret)
        whpx_panic("FAILED to create region (%d)!\n", ret);
    /* create new mapping */
    ret = vm_map_region(phys_addr, len);
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

    /* remove any previous mapping */
    ret = vm_unmap_region(phys_addr, len);
    if (ret)
        whpx_panic("FAILED to unmap region (%d)!\n", ret);
    /* free any existing memory at phys_addr */
    ret = vm_decommit_region(phys_addr, len);
    if (ret)
        whpx_panic("FAILED to decommit ram!");
    /* create new region */
    ret = vm_create_region(phys_addr, len, va, flags);
    if (ret)
        whpx_panic("FAILED to create region (%d)!\n", ret);
    /* add new mapping */
    ret = vm_map_region(phys_addr, len);
    if (ret)
        whpx_panic("FAILED to map region (%d)!\n", ret);

    return 0;
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

    /* remove mapping */
    ret = vm_unmap_region(phys_addr, len);
    if (ret)
        whpx_panic("FAILED to unmap region (%d)!\n", ret);
    /* remove region */
    ret = vm_destroy_region(phys_addr, len);
    if (ret)
        whpx_panic("FAILED to destroy region (%d)!\n", ret);
    /* free ram */
    ret = vm_decommit_region(phys_addr, len);
    if (ret)
        whpx_panic("FAILED to decommit ram (%d)!", ret);
    return 0;
}

void *
whpx_ram_map(uint64_t phys_addr, uint64_t *len)
{
    uint64_t l = *len;

    // sanity
    if (!((phys_addr < VM_VA_RANGE_SIZE) && (phys_addr + l < VM_VA_RANGE_SIZE)))
        whpx_panic("bad map attempt: addr=0x%"PRIx64" len=0x%"PRIx64"\n",
            phys_addr, l);

    mb_entry_t *e;
    uint64_t page = phys_addr >> PAGE_SHIFT;
    uint64_t page_off = phys_addr & ~TARGET_PAGE_MASK;
    uint64_t phys_addr_end = phys_addr + (*len) - 1;

    TAILQ_FOREACH(e, &mb_entries, entry) {
        if (page >= e->r.start && page < e->r.end) {
            uint64_t mb_max_addr = (e->r.end << PAGE_SHIFT) - 1;

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

#if 0
        if (vm_unmap_region(start, length))
            whpx_panic("unmap failed\n");
#endif
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

#if 0
        if (vm_map_region(start, length))
            whpx_panic("remap failed\n");
#endif
    }
}

typedef enum paging_mode {
    PM_OFF,
    PM_32,
    PM_PAE,
    PM_64
} paging_mode_t;

static paging_mode_t
paging_mode(uint64_t cr0, uint64_t cr4, uint64_t efer)
{
    if (! (cr0 & CR0_PG_MASK)) return PM_OFF;
    if (! (cr4 & CR4_PAE_MASK)) return PM_32;
    if (! (efer & MSR_EFER_LME)) return PM_PAE;
    return PM_64;
}

static int
gva_to_gpa_pae(CPUState *cpu, uint64_t gva, uint64_t *gpa, int w, int x)
{
    pte64_t *pd, pte;
    uint64_t pa;
    int level;

    pd = (pte64_t*)(vm_ram_base + (cpu->cr[3] & PAGE_MASK));
    for (level = 3; ; level--) {
        pte = pd[PAGE_OFFSET_A(gva, level)];
        if (!pte.p)
            return -1;
        if (level != 3) {
            if (w && !pte.rw)
                return -1;
            if (x && pte.xd)
                return -1;
            if ((level && pte.ps) || !level)
                break;
        }

        pd = (pte64_t *) (vm_ram_base + ((uint64_t) pte.mfn << PAGE_SHIFT));
    }

    gva &= LEAF_MASK (level);
    pa = pte.mfn << PAGE_SHIFT;
    pa &= ~LEAF_MASK (level);

    gva |= pa;

    if (gpa)
        *gpa = gva;

    return 0;
}

static int
gva_to_gpa_64(CPUState *cpu, uint64_t gva, uint64_t *gpa, int w, int x)
{
    pte64_t *pd, pte;
    uint64_t pa;
    int level;

    pd = (pte64_t*)(vm_ram_base + (cpu->cr[3] & PAGE_MASK));
    for (level = 3; ; level--) {
        pte = pd[PAGE_OFFSET_A(gva, level)];
        if (!pte.p)
            return -1;
        if (level != 3) {
            if (w && !pte.rw)
                return -1;
        if (x && pte.xd)
            return -1;
        if ((level && pte.ps) || !level)
            break;
        }
        pd = (pte64_t *) (vm_ram_base + ((uint64_t) pte.mfn << PAGE_SHIFT));
    }

    gva &= LEAF_MASK (level);
    pa = pte.mfn << PAGE_SHIFT;
    pa &= ~LEAF_MASK (level);

    gva |= pa;

    if (gpa)
        *gpa = gva;

    return 0;
}

static int
gva_to_gpa_hv_slow(CPUState *cpu,
    int write, uint64_t gva, uint64_t *gpa, int *is_unmapped)
{
    WHV_TRANSLATE_GVA_RESULT res;
    WHV_TRANSLATE_GVA_FLAGS flags =
        write ? WHvTranslateGvaFlagValidateWrite
              : WHvTranslateGvaFlagValidateRead;
    HRESULT hr;
    uint64_t t0 = 0;

    *is_unmapped = 0;

    if (whpx_perf_stats)
        t0 = _rdtsc();
    hr = WHvTranslateGva(whpx_get_partition(), cpu->cpu_index,
                         gva, flags, &res, gpa);
    if (whpx_perf_stats) {
        tmsum_xlate += _rdtsc() - t0;
        count_xlate++;
    }
    if (FAILED(hr)) {
        whpx_panic("WHPX: Failed to translate GVA, hr=%08lx", hr);
    } else {
        /* API call seems to not give us the page offset component */
        *gpa &= PAGE_MASK;
        *gpa |= gva & ~PAGE_MASK;

        if (res.ResultCode == WHvTranslateGvaResultSuccess)
            return 0;
        else if (res.ResultCode == WHvTranslateGvaResultGpaUnmapped) {
            *is_unmapped = 1;
            return 0;
        } else {
            debug_printf("WHPX: translation fail: code=%d gva=%"PRIx64"\n",
                res.ResultCode, gva);
            return -1;
        }
    }

    return 0;
}

int
whpx_translate_gva_to_gpa(CPUState *cpu, int write, uint64_t gva, uint64_t *gpa,
                              int *is_unmapped)
{
    paging_mode_t pm;

    *is_unmapped = 0;
    pm = paging_mode(cpu->cr[0], cpu->cr[4], cpu->efer);
    switch (pm) {
    case PM_64:
        return gva_to_gpa_64(cpu, gva, gpa, write, 0);
    case PM_PAE:
        return gva_to_gpa_pae(cpu, gva, gpa, write, 0);
    default:
        /* fallback: use whpx function to translate gva to gpa; extremely slow */
        return gva_to_gpa_hv_slow(cpu, write, gva, gpa, is_unmapped);
    }
}

void
whpx_copy_from_guest_va(CPUState *cpu, void *dst, uint64_t src_va, uint64_t len)
{
   void *src_p;
   int ret;
   int unmapped;

   assert(cpu);

   while (len) {
       uint64_t copy_len = len;
       uint64_t off = src_va & ~TARGET_PAGE_MASK;
       uint64_t gpa = 0;

       if (copy_len > TARGET_PAGE_SIZE - off)
           copy_len = TARGET_PAGE_SIZE - off;

       ret = whpx_translate_gva_to_gpa(cpu, 0, src_va, &gpa, &unmapped);
       if (ret)
           whpx_panic("failed to translate gva to gpa: gva=%"PRIx64", ret=%d\n",
               src_va, ret);

       src_p = whpx_ram_map(gpa, &copy_len);
       assert(src_p != NULL);
       memcpy(dst, src_p, copy_len);

       len    -= copy_len;
       dst    += copy_len;
       src_va += copy_len;
   }
}

void
whpx_copy_to_guest_va(CPUState *cpu, uint64_t dst_va, void *src, uint64_t len)
{
   void *dst_p;
   int ret;
   int unmapped;

   assert(cpu);

   while (len) {
       uint64_t copy_len = len;
       uint64_t off = dst_va & ~TARGET_PAGE_MASK;
       uint64_t gpa = 0;

       if (copy_len > TARGET_PAGE_SIZE - off)
           copy_len = TARGET_PAGE_SIZE - off;

       ret = whpx_translate_gva_to_gpa(cpu, 0, dst_va, &gpa, &unmapped);
       if (ret)
           whpx_panic("failed to translate gva to gpa: gva=%"PRIx64", ret=%d\n",
               dst_va, ret);

       dst_p = whpx_ram_map(gpa, &copy_len);
       assert(dst_p != NULL);
       memcpy(dst_p, src, copy_len);

       len    -= copy_len;
       src    += copy_len;
       dst_va += copy_len;
   }
}


static int
whpx_count_entries(void)
{
    mb_entry_t *e;
    int count = 0;

    TAILQ_FOREACH(e, &mb_entries, entry)
        count++;

    return count;
}

int
whpx_write_pages(struct filebuf *f, char **err_msg)
{
    mb_entry_t *e;
    uint32_t num_entries = 0;
    uint32_t marker;
    struct xc_save_generic s;

    vm_save_info.page_batch_offset = filebuf_tell(f);

    s.marker = XC_SAVE_ID_WHP_PAGES;
    s.size = 0; /* updated later */
    filebuf_write(f, &s, sizeof(s));

    /* num_entries updated later too */
    filebuf_write(f, &num_entries, sizeof(num_entries));

    TAILQ_FOREACH(e, &mb_entries, entry) {
        uint64_t i, len;
        uint8_t *ram;
        uint32_t flags;

        len = mb_pages(e) << PAGE_SHIFT;
        ram = whpx_ram_map(e->r.start << PAGE_SHIFT, &len);
        assert(ram);
        assert(len == (mb_pages(e) << PAGE_SHIFT));

        if (e->flags & WHPX_RAM_EXTERNAL)
            continue; /* don't save external ram for now */
        filebuf_write(f, &e->r, sizeof(e->r));
        flags = e->flags;
        filebuf_write(f, &flags, sizeof(flags));
        uint64_t pages = mb_pages(e);
        for (i = 0; i  < pages; i++) {
            uint8_t *page = ram + PAGE_SIZE * i;
            filebuf_write(f, page, PAGE_SIZE);
        }
        num_entries++;
    }

    /* update size */
    off_t size = filebuf_tell(f) - vm_save_info.page_batch_offset;
    s.size = size;
    filebuf_seek(f, vm_save_info.page_batch_offset, FILEBUF_SEEK_SET);
    filebuf_write(f, &s, sizeof(s));
    /* update number of entries */
    filebuf_write(f, &num_entries, sizeof(num_entries));
    filebuf_seek(f, vm_save_info.page_batch_offset + size, FILEBUF_SEEK_SET);

    /* 0: end marker */
    marker = 0;
    filebuf_write(f, &marker, sizeof(marker));

    return 0;
}

int
whpx_read_pages(struct filebuf *f, char **err_msg)
{
    uint32_t num_entries = 0, i;
    uint32_t sz;
    mb_entry_t *e, *next;

    /* depopulate any pre-existing ranges - needed because some device initialization functions
     * called before loading setup preliminary ranges */
    TAILQ_FOREACH_SAFE(e, &mb_entries, entry, next) {
        /* remove hyperv mapping + free ram */
        whpx_ram_depopulate(e->r.start << PAGE_SHIFT, mb_pages(e) << PAGE_SHIFT, 0);
    }

    /* should be nothing in memory map yet */
    assert(whpx_count_entries() == 0);

    filebuf_read(f, &sz, sizeof(sz));

    filebuf_read(f, &num_entries, sizeof(num_entries));
    for (i = 0; i < num_entries; i++) {
        pagerange_t r;
        uint64_t len, npages, j, addr;
        uint8_t *ram;
        uint32_t flags;

        filebuf_read(f, &r, sizeof(r));
        filebuf_read(f, &flags, sizeof(flags));
        npages = r.end - r.start;
        len = npages << PAGE_SHIFT;
        addr = r.start << PAGE_SHIFT;
        /* allocate ram range */
        whpx_ram_populate(addr, len, flags);
        ram = whpx_ram_map(addr, &len);
        assert(ram);
        assert(len == (npages << PAGE_SHIFT));
        /* read & populate ram range with data */
        for (j = 0; j < npages; j++) {
            uint8_t *page = ram + PAGE_SIZE * j;

            filebuf_read(f, page, PAGE_SIZE);
        }
    }

    return 0;
}

int
whpx_ram_init(void)
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

void
whpx_ram_uninit(void)
{
    /* for now, keep ram mapped/allocated during shutdown because there's some silly
     * code which accesses mapped memory after vm destroy (ps2 mouse shared
     * page at least) */
#if 0
    mb_entry_t *e, *next;

    TAILQ_FOREACH_SAFE(e, &mb_entries, entry, next) {
        /* remove hyperv mapping + free ram */
        whpx_ram_depopulate(e->r.start << PAGE_SHIFT, mb_pages(e) << PAGE_SHIFT, 0);
    }

    /* should have no entries left in rammap after depopulating everything */
    assert(whpx_count_entries() == 0);
#endif
}
