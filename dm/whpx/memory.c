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
#define ZERO_RANGE_MIN_PAGES 8
#define mb_saveable(mb) (!((mb)->flags & WHPX_RAM_EXTERNAL))
#define SAVE_BUFFER_SIZE (1024*1024*64)

/* vm-mappable block */
typedef struct mb_entry {
    TAILQ_ENTRY(mb_entry) entry;

    pagerange_t r;
    void *va;
    int partition_mapped;
    uint32_t flags;
} mb_entry_t;

typedef struct saved_mb_entry {
    pagerange_t r;
    uint32_t flags;
    off_t file_off;
} saved_mb_entry_t;

typedef struct file_mapping {
    TAILQ_ENTRY(file_mapping) entry;

    pagerange_t r; /* phys range */
    void *va;
    void *aligned_map_va;
    uint64_t file_off;
} file_mapping_t;

/* base for ram allocated by uxendm (won't be used if vm runs off
 * memory mapped file for example */
static uint8_t *vm_ram_base = NULL;
static bool vm_ram_owned = false;

/* sorted list of blocks */
static TAILQ_HEAD(, mb_entry) mb_entries;
/* list of memory file mappings */
static TAILQ_HEAD(, file_mapping) file_ram_mappings;

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
    if (!vm_ram_owned)
        return 0;

    if (!VirtualAlloc(vm_ram_base + phys_addr, len, MEM_COMMIT, PAGE_READWRITE))
        return -1;
    return 0;
}

static int
vm_decommit_region(uint64_t phys_addr, uint64_t len)
{
    if (!vm_ram_owned)
        return 0;

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
    if (!(flags & WHPX_RAM_NO_DECOMMIT)) {
        /* free any existing memory at phys_addr */
        ret = vm_decommit_region(phys_addr, len);
        if (ret)
            whpx_panic("FAILED to decommit ram!");
    }
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
    if (!(flags & WHPX_RAM_NO_DECOMMIT)) {
        /* free ram */
        ret = vm_decommit_region(phys_addr, len);
        if (ret)
            whpx_panic("FAILED to decommit ram (%d)!", ret);
    }

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

static void *
page_map(uint64_t gpa)
{
    uint64_t len = PAGE_SIZE;
    void *va = whpx_ram_map(gpa, &len);

    assert(len == PAGE_SIZE);

    return va;
}

static int
gva_to_gpa_64(CPUState *cpu, uint64_t gva, uint64_t *gpa, int w, int x)
{
    pte64_t *pd, pte;
    uint64_t pa;
    int level;

    pd = (pte64_t*) page_map(cpu->cr[3] & PAGE_MASK);
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
        pd = (pte64_t *) page_map((uint64_t) pte.mfn << PAGE_SHIFT);
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
    case PM_PAE:
        return gva_to_gpa_64(cpu, gva, gpa, write, 0);
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

static bool
page_is_zero(void *p)
{
    uint64_t *q = p;
    uint64_t *end = (uint64_t*)((uint8_t*)p + PAGE_SIZE);

    while (q != end) {
        if (*q)
            return false;
        q++;
    }

    return true;
}

static bool
find_nonzero_pagerange(uint8_t *p, uint64_t npages, pagerange_t *pr)
{
    bool in_nonzero = false;
    uint64_t s, e;
    uint64_t idx = 0;
    int zeroc;

    while (npages) {
        bool is_zero = page_is_zero(p);

        if (in_nonzero) {
            if (is_zero == false) {
                e = idx;
                zeroc = 0;
            } else
                zeroc++;
        } else {
            if (is_zero == false) {
                s = e = idx;
                zeroc = 0;
                in_nonzero = true;
            }
        }

        if (in_nonzero && ((zeroc > ZERO_RANGE_MIN_PAGES) || (npages == 1))) {
            pr->start = s;
            pr->end = e+1;

            return true;
        }

        p += PAGE_SIZE;
        npages--;
        idx++;
    }

    return false;
}

static pagerange_t *
find_nonzero_pageranges(uint8_t *p, uint64_t len, int *count)
{
    uint64_t scanoff = 0;
    int num_ranges = 0;
    pagerange_t *ranges = NULL;
    pagerange_t *r;

    *count = 0;

    while (scanoff < len) {
        pagerange_t nonz = { };

        if (!find_nonzero_pagerange(p + scanoff,
                (len - scanoff) >> PAGE_SHIFT, &nonz))
            break;

        num_ranges++;
        ranges = realloc(ranges, num_ranges * sizeof(pagerange_t));

        r = &ranges[num_ranges-1];
        r->start = nonz.start + (scanoff >> PAGE_SHIFT);
        r->end   = nonz.end   + (scanoff >> PAGE_SHIFT);

        scanoff  = r->end << PAGE_SHIFT;
    }

    *count = num_ranges;

    return ranges;
}


static int
save_cancelled(void)
{
    int cancelled = vm_save_info.save_requested &&
        (vm_save_info.save_abort || vm_quit_interrupt);
    if (cancelled)
        debug_printf("save cancelled\n");
    return cancelled;
}

static int
whpx_ram_reserve_virtual(void)
{
    vm_ram_base = VirtualAlloc(NULL, (SIZE_T)VM_VA_RANGE_SIZE, MEM_RESERVE,
        PAGE_READWRITE);
    if (!vm_ram_base)
        whpx_panic("ram reservation failed\n");
    debug_printf("vm_ram_base = 0x%p\n", vm_ram_base);
    vm_ram_owned = true;

    return 0;
}

static int
whpx_ram_release_cow(void)
{
    file_mapping_t *e, *next;

    /* unmap file mappings */
    TAILQ_FOREACH_SAFE(e, &file_ram_mappings, entry, next) {
        UnmapViewOfFile(e->va);
        TAILQ_REMOVE(&file_ram_mappings, e, entry);
        free(e);
    }

    return 0;
}

static void
whpx_ram_release_hv_mappings(void)
{
    mb_entry_t *e, *next;

    TAILQ_FOREACH_SAFE(e, &mb_entries, entry, next) {
        /* remove hyperv mapping */
        whpx_ram_depopulate(e->r.start << PAGE_SHIFT, mb_pages(e) << PAGE_SHIFT,
            WHPX_RAM_NO_DECOMMIT);
    }
    /* should have no entries left in rammap after depopulating everything */
    assert(whpx_count_entries() == 0);
}

static void
whpx_ram_free(void)
{
    mb_entry_t *e, *next;

    debug_printf("freeing vm ram\n");

    /* depopulate everything */
    TAILQ_FOREACH_SAFE(e, &mb_entries, entry, next) {
        /* remove hyperv mapping */
        whpx_ram_depopulate(e->r.start << PAGE_SHIFT, mb_pages(e) << PAGE_SHIFT, 0);
    }
    /* should have no entries left in rammap after depopulating everything */
    assert(whpx_count_entries() == 0);

    /* release file cow mappings */
    whpx_ram_release_cow();
}

static int
cancellable_write(struct filebuf *f, uint8_t *p, size_t len, uint64_t *acclen)
{
    const int CHUNK_SIZE = 1024*1024*256;
    size_t l;

    while (len) {
        if (save_cancelled())
            return -1;

        l = len > CHUNK_SIZE ? CHUNK_SIZE : len;
        filebuf_write(f, p, l);

        *acclen += l;
        if (*acclen >= CHUNK_SIZE) {
            *acclen -= CHUNK_SIZE;
            filebuf_flush(f);
            FlushFileBuffers(f->file);
        }

        len -= l;
        p += l;
    }

    return 0;
}

static int
save_mb(struct filebuf *f, saved_mb_entry_t *e, uint64_t *saved_bytes)
{
    int num_ranges = 0;
    pagerange_t *saved_ranges = NULL;
    uint64_t max_addr = e->r.end << PAGE_SHIFT;
    int ret = 0;
    int i;

    e->file_off = filebuf_tell(f);
    debug_printf("saving block %016"PRIx64" - %016"PRIx64" @ offset %016"PRIx64"\n",
        e->r.start << PAGE_SHIFT, e->r.end << PAGE_SHIFT, e->file_off);

    uint64_t len0 = (e->r.end - e->r.start) << PAGE_SHIFT;
    uint64_t len = len0;

    uint8_t *ram0 = whpx_ram_map(e->r.start << PAGE_SHIFT, &len);
    assert(len == len0);
    saved_ranges = find_nonzero_pageranges(ram0, len, &num_ranges);
    for (i = 0; i < num_ranges; i++) {
        saved_ranges[i].start += e->r.start;
        saved_ranges[i].end += e->r.start;
    }
    whpx_ram_unmap(ram0);

    debug_printf("  .. found %d non-zero ranges to save\n", num_ranges);

    /* set sparse ranges */
    uint64_t mb_beg   = e->r.start << PAGE_SHIFT;
    uint64_t zero_beg = mb_beg;
    uint64_t zero_end = mb_beg;
    int num_sparse = 0;

    for (i = 0; i < num_ranges+1; i++) {
        pagerange_t *r = 0;

        if (save_cancelled())
            goto out;

        if (i != num_ranges) {
            r = &saved_ranges[i];
            zero_end = r->start << PAGE_SHIFT;
        } else
            zero_end = max_addr;

        uint64_t zero_len = zero_end - zero_beg;
        if (zero_len > 0) {
            debug_printf("  .. set zero data %016"PRIx64" - %016"PRIx64"\n",
                (uint64_t)(zero_beg - mb_beg),
                (uint64_t)(zero_end - mb_beg));
            ret = filebuf_set_zero_data(f, e->file_off + zero_beg - mb_beg,
                zero_len);
            if (ret) {
                debug_printf("failed to set zero data");
                goto out;
            }
            num_sparse++;
        }
        if (i != num_ranges)
            zero_beg = r->end << PAGE_SHIFT;
    }

    /* write non zero data */
    uint64_t acclen = 0;
    for (i = 0; i < num_ranges; i++) {
        uint64_t len, start, end;
        uint8_t *ram;
        pagerange_t *r = &saved_ranges[i];

        if (save_cancelled())
            goto out;

        len = pr_bytes(r);
        ram = whpx_ram_map(r->start << PAGE_SHIFT, &len);
        assert(ram);
        assert(len == pr_bytes(r));

        start = r->start << PAGE_SHIFT;
        end = r->end << PAGE_SHIFT;
        filebuf_seek(f, e->file_off + start - mb_beg, FILEBUF_SEEK_SET);
        debug_printf("  .. write non-zero range %016"PRIx64" - %016"PRIx64" @ offset %016"PRIx64" len=%"PRIx64" \n",
            start, end, (uint64_t) filebuf_tell(f), len);
        ret = cancellable_write(f, ram, len, &acclen);
        *saved_bytes += len;
        whpx_ram_unmap(ram);
        if (ret)
            goto out;
    }

    debug_printf("  .. total %d zero areas, %d non-zero areas\n", num_sparse, num_ranges);

out:
    free(saved_ranges);

    return ret;
}

int
whpx_write_pages(struct filebuf *f)
{
    mb_entry_t *e;
    uint32_t num_saved = 0;
    uint32_t marker;
    struct xc_save_whp_pages s;
    saved_mb_entry_t *saved_entries = NULL;
    pagerange_t *saved_ranges = NULL;
    int i,ret=0;
    off_t pages_start_off;
    uint32_t no_pages = 0;
    off_t size;

    uint64_t start_off = filebuf_tell(f);

    /* For now: we'll replace cuckoo compression with a mode where vm is paused,
     * vm memory is kept allocated to uxendm, but we'll remove all hyperv mappings.
     * Therefore OS will be responsible for swapping it out to pagefile when system is
     * low on memory, rather than manually controlling it. */

    if (whpx_shallow_save && (
        vm_save_info.compress_mode == VM_SAVE_COMPRESS_CUCKOO ||
        vm_save_info.compress_mode == VM_SAVE_COMPRESS_CUCKOO_SIMPLE))
        no_pages = 1;

    ret = filebuf_set_sparse(f, true);
    if (ret) {
        debug_printf("failed to set sparse flag");
        goto out;
    }

    vm_save_info.page_batch_offset = start_off;
    vm_save_set_abortable();

    if (save_cancelled())
        goto out;

    s.marker = XC_SAVE_ID_WHP_PAGES;
    s.size = 0; /* updated later */
    s.no_pages = no_pages;
    filebuf_write(f, &s, sizeof(s));

    /* num_saved updated later too */
    filebuf_write(f, &num_saved, sizeof(num_saved));

    i = 0;
    TAILQ_FOREACH(e, &mb_entries, entry) {
        if (mb_saveable(e)) {
            saved_entries = realloc(saved_entries,
                (i+1) * sizeof(saved_mb_entry_t));

            memset(&saved_entries[i], 0, sizeof(saved_entries[i]));
            saved_entries[i].r = e->r;
            saved_entries[i].flags = e->flags & WHPX_RAM_FLAGS_SAVE_MASK;
            saved_entries[i].file_off = 0; /* updated later */

            i++;
        }
    }
    num_saved = i;
    size_t saved_entries_sz = num_saved * sizeof(saved_mb_entry_t);
    /* write saved areas metadata placeholder */
    uint64_t saved_entries_off = filebuf_tell(f);
    filebuf_write(f, saved_entries, saved_entries_sz);

    debug_printf("wrote %d memory block entries\n", num_saved);

    /* start of page data area, in file */
    pages_start_off = filebuf_tell(f);
    pages_start_off += PAGE_SIZE-1;
    pages_start_off &= PAGE_MASK;

    size = pages_start_off - start_off;
    if (no_pages)
        goto final_update;

    filebuf_buffer_max(f, SAVE_BUFFER_SIZE);

    uint64_t saved_bytes = 0;
    LARGE_INTEGER freq, t0, t1;
    QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&t0);
    filebuf_seek(f, pages_start_off, FILEBUF_SEEK_SET);
    for (i = 0; i < num_saved; i++) {
        ret = save_mb(f, &saved_entries[i], &saved_bytes);
        if (ret || save_cancelled())
            goto out;
        size += pr_bytes(&saved_entries[i].r);
    }
    filebuf_flush(f);
    FlushFileBuffers(f->file);
    QueryPerformanceCounter(&t1);
    debug_printf("wrote %d memory blocks, total %"PRId64"Mb in %.2fs\n",
        num_saved, saved_bytes / 1024 / 1024,
        (((t1.QuadPart - t0.QuadPart) * 1000) / freq.QuadPart) / 1000.0f);

final_update:
    /* update size */
    s.size = size;
    filebuf_seek(f, vm_save_info.page_batch_offset, FILEBUF_SEEK_SET);
    filebuf_write(f, &s, sizeof(s));
    /* update number of entries */
    filebuf_write(f, &num_saved, sizeof(num_saved));
    /* update saved entries metadata */
    filebuf_seek(f, saved_entries_off, FILEBUF_SEEK_SET);
    filebuf_write(f, saved_entries, saved_entries_sz);

    filebuf_seek(f, vm_save_info.page_batch_offset + size, FILEBUF_SEEK_SET);

    /* 0: end marker */
    marker = 0;
    filebuf_write(f, &marker, sizeof(marker));

    filebuf_flush(f);

    /* remove mappings / vram */
    if (!no_pages) // && vm_save_info.free_mem
        whpx_ram_free(); /* full free */
    else
        whpx_ram_release_hv_mappings(); /* only release hv happings */

out:
    free(saved_entries);
    free(saved_ranges);

    return ret;
}

saved_mb_entry_t *
read_mb_entries(struct filebuf *f, uint32_t *out_num_entries, uint64_t *out_max_addr)
{
    uint32_t num_entries;
    uint64_t max_addr = 0;
    saved_mb_entry_t *saved_entries;
    int i;

    filebuf_read(f, &num_entries, sizeof(num_entries));
    saved_entries = malloc(num_entries * sizeof(saved_mb_entry_t));
    if (!saved_entries)
        return NULL;
    for (i = 0; i < num_entries; i++) {
        saved_mb_entry_t *se = &saved_entries[i];

        filebuf_read(f, &saved_entries[i], sizeof(saved_mb_entry_t));
        if (se->r.end << PAGE_SHIFT > max_addr)
            max_addr = se->r.end << PAGE_SHIFT;
    }

    *out_num_entries = num_entries;
    *out_max_addr = max_addr;

    return saved_entries;

}

static file_mapping_t *
find_file_ram_mapping(struct filebuf *f, pagerange_t r)
{
    file_mapping_t *e;

    TAILQ_FOREACH(e, &file_ram_mappings, entry) {
        if (r.start == e->r.start && r.end == e->r.end)
            return e;
    }

    return NULL;
}

static void *
mmap_cow(struct filebuf *f, pagerange_t r, uint64_t fileoff)
{
    static uint64_t align_mask = 0;
    uint64_t aligned_off;
    SYSTEM_INFO si;
    HANDLE h;
    void *map;
    size_t len = pr_bytes(&r);

    if (!align_mask) {
        GetSystemInfo(&si);
        align_mask = ~(si.dwAllocationGranularity - 1);
    }

    file_mapping_t *prev = find_file_ram_mapping(f, r);
    if (prev) {
        debug_printf("reuse cow mapping %016"PRIx64" - %016"PRIx64" file offset %016"PRIx64"\n",
            r.start << PAGE_SHIFT, r.end << PAGE_SHIFT, fileoff);
        return prev->va;
    }

    debug_printf("create cow mapping %016"PRIx64" - %016"PRIx64" file offset %016"PRIx64"\n",
        r.start << PAGE_SHIFT, r.end << PAGE_SHIFT, fileoff);
    aligned_off = fileoff & align_mask;

    h = CreateFileMapping(f->file, NULL, PAGE_READONLY, 0, 0, NULL);
    if (!h)
        Werr(1, "%s: CreateFileMapping failed", __FUNCTION__);
    map = MapViewOfFileEx(h, FILE_MAP_COPY,
        (uint32_t)(aligned_off >> 32),
        (uint32_t)(aligned_off),
        len + fileoff - aligned_off, NULL);
    if (!map)
        Werr(1, "%s: MapViewOfFileEx failed", __FUNCTION__);
    CloseHandle(h);

    file_mapping_t *fm = calloc(1, sizeof(file_mapping_t));
    fm->r = r;
    fm->file_off = fileoff;
    fm->va = map + fileoff - aligned_off;
    fm->aligned_map_va = map;
    TAILQ_INSERT_TAIL(&file_ram_mappings, fm, entry);

    return fm->va;
}

int
whpx_clone_pages(struct filebuf *f, uint8_t *template_uuid, int no_pages)
{
    uint32_t num_entries = 0;
    off_t pages_start_off;
    uint64_t max_addr = 0;
    saved_mb_entry_t *saved_entries = NULL;
    int i;

    debug_printf("clone whp pages, no_pages=%d\n", no_pages);

    saved_entries = read_mb_entries(f, &num_entries, &max_addr);

    pages_start_off = filebuf_tell(f);
    pages_start_off += PAGE_SIZE-1;
    pages_start_off &= PAGE_MASK;

    /* read file data & populate vmem */
    for (i = 0; i < num_entries; i++) {
        saved_mb_entry_t *se = &saved_entries[i];
        /* will either do a new cow mapping or reuse previous */
        void *ram = mmap_cow(f, se->r, se->file_off);

        assert(ram);
        whpx_ram_populate_with(se->r.start << PAGE_SHIFT, pr_bytes(&se->r), ram, se->flags);
    }

    free(saved_entries);

    return 0;
}

int
whpx_read_pages(struct filebuf *f, int no_pages)
{
    uint32_t num_entries = 0, i;
    saved_mb_entry_t *saved_entries = NULL;
    uint64_t max_addr;

    debug_printf("read whp pages, no_pages=%d\n", no_pages);

    saved_entries = read_mb_entries(f, &num_entries, &max_addr);

    /* read file data & populate vmem */
    for (i = 0; i < num_entries; i++) {
        saved_mb_entry_t *se = &saved_entries[i];
        uint64_t len, npages, addr;
        uint8_t *ram;

        npages = se->r.end - se->r.start;
        len = npages << PAGE_SHIFT;
        addr = se->r.start << PAGE_SHIFT;

        if (!no_pages) {
            /* allocate new memory and read page data */
            filebuf_seek(f, se->file_off, FILEBUF_SEEK_SET);
            /* allocate ram range */
            whpx_ram_populate(addr, len, se->flags);
            ram = whpx_ram_map(addr, &len);
            assert(ram);
            assert(len == (npages << PAGE_SHIFT));
            /* read & populate ram range with data */
            filebuf_read(f, ram, len);
        } else {
            /* use preexisting memory */
            assert(vm_ram_base);
            whpx_ram_populate_with(addr, len, vm_ram_base + addr,
                se->flags | WHPX_RAM_NO_DECOMMIT);
        }
    }

    free(saved_entries);

    return 0;
}

int
whpx_ram_init(void)
{
    TAILQ_INIT(&mb_entries);
    TAILQ_INIT(&file_ram_mappings);

    /* reserve 4GB VA Range for vm use */
    whpx_ram_reserve_virtual();

    return 0;
}

void
whpx_ram_uninit(void)
{
    whpx_ram_free();
}
