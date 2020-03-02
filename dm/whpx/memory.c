/*
 * Copyright 2018-2020, Bromium, Inc.
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
#include <dm/control.h>
#include <uuid/uuid.h>

#define VM_VA_RANGE_SIZE 0x100000000ULL
#define ZERO_RANGE_MIN_PAGES 64
#define mb_saveable(mb) (!((mb)->flags & WHPX_RAM_EXTERNAL))
#define SAVE_BUFFER_SIZE (1024*1024*64)

#define PRIVATE_MEM_QUERY_INTERVAL_NS (4 * 1000000000ULL)

//#define DEBUG_CAPPOP_TIMES

/* vm-mappable block */
typedef struct mb_entry {
    TAILQ_ENTRY(mb_entry) entry;

    pagerange_t r;
    void *va;
    int partition_map_request;
    int partition_mapped;
    uint32_t flags;
} mb_entry_t;

typedef struct saved_mb_entry {
    pagerange_t r;
    uint32_t flags;
    off_t file_off;
} saved_mb_entry_t;

typedef enum file_mapping_type {
    FMT_RO,
    FMT_COW
} file_mapping_type_t;

typedef struct file_mapping {
    TAILQ_ENTRY(file_mapping) entry;

    file_mapping_type_t type;
    int is_template; /* ro mapping to template */
    pagerange_t r; /* phys range */
    void *va;
    void *aligned_map_va;
    uint64_t aligned_size;
    uint64_t file_off;
    size_t locked; /* amount of virtual locked bytes */
} file_mapping_t;

struct shared_template_info {
    LONG owner_pid;
};

/* partial SYSTEM_PROCESS_INFORMATION */
struct spi_hdr {
    ULONG NextEntryOffset;
    ULONG NumberOfThreads;
    LARGE_INTEGER WorkingSetPrivateSize;
    BYTE pad[0x40];
    HANDLE ProcessId; /* offset 0x50 */
};

/* base for ram allocated by uxendm (won't be used if vm runs off
 * memory mapped file for example */
static uint8_t *vm_ram_base = NULL;
static bool vm_ram_owned = false;

/* sorted list of blocks */
static TAILQ_HEAD(, mb_entry) mb_entries;
/* list of memory file mappings */
static TAILQ_HEAD(, file_mapping) file_ram_mappings;

static HANDLE sti_handle;
static struct shared_template_info *sti_ptr;

extern uint64_t whpx_private_mem_query_ts;
extern critical_section whpx_private_mem_cs;

static uint64_t private_mem_pages;
static void *   sys_info;
static uint64_t sys_info_sz;
static int partition_mappings_enable;

#define uxenvm_load_read(f, buf, size, ret, err_msg, _out) do {         \
        (ret) = filebuf_read((f), (buf), (size));                       \
        if ((ret) != (size)) {                                          \
            asprintf((err_msg), "uxenvm_load_read(%s) failed", #buf);   \
            if ((ret) >= 0)                                             \
                (ret) = -EIO;                                           \
            else                                                        \
                (ret) = -errno;                                         \
            goto _out;                                                  \
        }                                                               \
    } while(0)


static uint64_t mb_pages(mb_entry_t *mb)
{
    return pr_bytes(&mb->r) >> PAGE_SHIFT;
}

/* Request mapping of host memory into WHP partition; actual map can happen
 * immediately or be delayed if partition mappings are disabled */
static void
do_partition_remap(mb_entry_t *mb, int map)
{
    if (mb->partition_mapped != map) {
        whpx_update_mapping(
            mb->r.start << PAGE_SHIFT,
            mb_pages(mb) << PAGE_SHIFT,
            mb->va,
            map ? 1:0,
            0 /* rom */,
            NULL);
        mb->partition_mapped = map;
    }
}

static void
request_partition_remap(mb_entry_t *mb, int map)
{
    mb->partition_map_request = map;
    if (map && !partition_mappings_enable)
        return;

    do_partition_remap(mb, map);
}

void
whpx_partition_mappings_enable(int enable)
{
    mb_entry_t *e;

    partition_mappings_enable = enable;
    TAILQ_FOREACH(e, &mb_entries, entry) {
        do_partition_remap(e, enable ? e->partition_map_request : 0);
    }
}

static void
insert_mb(mb_entry_t *mb)
{
    mb_entry_t *e;
    mb_entry_t *before = NULL;

    TAILQ_FOREACH(e, &mb_entries, entry) {
        if (mb->r.start < e->r.start) {
            before = e;
            break;
        }
    }

    if (before)
        TAILQ_INSERT_BEFORE(before, mb, entry);
    else
        TAILQ_INSERT_TAIL(&mb_entries, mb, entry);
}

void
whpx_ram_dump_layout(void)
{
    mb_entry_t *e;

    debug_printf("ram layout:\n");
    TAILQ_FOREACH(e, &mb_entries, entry) {
        debug_printf("  memory block %016"PRIx64" - %016"PRIx64" va %p flags %x\n",
            e->r.start << PAGE_SHIFT,
            e->r.end << PAGE_SHIFT,
            e->va,
            e->flags);
    }
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

            int mapped = e->partition_map_request;

            // unmap existing block
            request_partition_remap(e, 0);

            // trim existing intersecting element to intersection
            e->va = (uint8_t*)e->va + ((inter.start - e->r.start) << PAGE_SHIFT);
            e->r  = inter;

            // map trimmed block
            request_partition_remap(e, mapped);
            // add elements to left, right of existing one if necessary
            if (new1.start != -1LL) {
                mb_entry_t *new_mb = create_mb_from_pr(&new1, new1va, e->flags);
                if (!new_mb)
                    goto out;
                request_partition_remap(new_mb, mapped);
            }
            if (new2.start != -1LL) {
                mb_entry_t *new_mb = create_mb_from_pr(&new2, new2va, e->flags);
                if (!new_mb)
                    goto out;
                request_partition_remap(new_mb, mapped);
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
    request_partition_remap(mb, 1);
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
    request_partition_remap(mb, 0);
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
            debug_printf("warning: failed to decommit ram at phys %016"PRIx64" - not commited?\n", phys_addr);
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
            debug_printf("warning: failed to decommit ram at phys %016"PRIx64" - not commited?\n", phys_addr);
    }

    return 0;
}

static mb_entry_t *
find_page_mb_entry(uint64_t pfn)
{
    mb_entry_t *e;

    TAILQ_FOREACH(e, &mb_entries, entry) {
        if (pfn >= e->r.start && pfn < e->r.end)
            return e;
    }
    return NULL;
}

void *
whpx_ram_map(uint64_t phys_addr, uint64_t *len)
{
    uint64_t l = *len;

    // sanity
    if (!((phys_addr < VM_VA_RANGE_SIZE) && (phys_addr + l < VM_VA_RANGE_SIZE)))
        debug_printf("bad map attempt: addr=0x%"PRIx64" len=0x%"PRIx64"\n",
            phys_addr, l);

    uint64_t page = phys_addr >> PAGE_SHIFT;
    uint64_t page_off = phys_addr & ~TARGET_PAGE_MASK;
    uint64_t phys_addr_end = phys_addr + (*len) - 1;
    mb_entry_t *e = find_page_mb_entry(page);
    if (e) {
        uint64_t mb_max_addr = (e->r.end << PAGE_SHIFT) - 1;

        if (phys_addr_end > mb_max_addr) {
            phys_addr_end = mb_max_addr;
            *len = phys_addr_end - phys_addr + 1;
        }
        uint64_t mb_page = page - e->r.start;

        return e->va + (mb_page << UXEN_PAGE_SHIFT) + page_off;
    }
    return NULL;
}

void *
whpx_ram_map_assert(uint64_t phys_addr, uint64_t len)
{
    uint64_t mapped_len = len;
    void *p;

    p = whpx_ram_map(phys_addr, &mapped_len);
    if (!p)
        whpx_panic(
            "no mapping @ addr=0x%"PRIx64" len=0x%"PRIx64"\n",
            phys_addr, len);

    if (mapped_len != len)
        whpx_panic(
            "bad map length @ addr=0x%"PRIx64
            " len=0x%"PRIx64" mapped_len=0x%"PRIx64"\n",
            phys_addr, len, mapped_len);

    return p;
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

/* enumerate vm private (diverged) page ranges (they're usually PAGE_READWRITE not MEM_PRIVATE for the
 * mapped file case) */
static int
enum_private_ranges(void *opaque, int (*cb)(uint64_t pfn, uint64_t count, void *opaque))
{
    mb_entry_t *e, *next;

    TAILQ_FOREACH_SAFE(e, &mb_entries, entry, next) {
        SIZE_T sz = pr_bytes(&e->r);
        uint64_t pages_left = sz / PAGE_SIZE;
        MEMORY_BASIC_INFORMATION mbi;
        uint8_t *p = e->va;
        uint64_t pfn = e->r.start;

        while (pages_left) {
            if (!VirtualQuery(p, &mbi, sizeof(mbi)))
                whpx_panic("VirtualQuery failed: %d\n", (int)GetLastError());
            if (mbi.BaseAddress != p)
                whpx_panic("unexpected base %p, expected %p\n", mbi.BaseAddress, p);
            uint64_t npages = mbi.RegionSize / PAGE_SIZE;
            if (npages > pages_left)
                npages = pages_left;
            if ((mbi.Protect & PAGE_READWRITE) ||
                (mbi.Type & MEM_PRIVATE)) {
                int err = cb(pfn, npages, opaque);
                if (err)
                    return err;
            }
            p += mbi.RegionSize;
            pages_left -= npages;
            pfn += npages;
        }
    }

    return 0;
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
    int zeroc = 0;

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

#if 0
static int
whpx_count_file_ram_mappings(void)
{
    file_mapping_t *e, *next;
    int num = 0;

    TAILQ_FOREACH_SAFE(e, &file_ram_mappings, entry, next)
        num++;

    return num;
}

static int
whpx_ram_release_file_mappings(void)
{
    file_mapping_t *e, *next;

    /* unmap file mappings */
    TAILQ_FOREACH_SAFE(e, &file_ram_mappings, entry, next) {
        TAILQ_REMOVE(&file_ram_mappings, e, entry);
        if (!UnmapViewOfFile(e->aligned_map_va))
            Werr(1, "%s: UnmapViewOfFile failed: %d\n", __FUNCTION__, (int)GetLastError());
        free(e);
    }

    return 0;
}
#endif

static int
whpx_ram_release_file_cow_mappings(void)
{
    file_mapping_t *e, *next;

    /* unmap CoW file mappings */
    TAILQ_FOREACH_SAFE(e, &file_ram_mappings, entry, next) {
        if (e->type == FMT_COW) {
            TAILQ_REMOVE(&file_ram_mappings, e, entry);
            if (!UnmapViewOfFile(e->aligned_map_va))
                Werr(1, "%s: UnmapViewOfFile failed: %d\n", __FUNCTION__, (int)GetLastError());
            free(e);
        }
    }

    return 0;
}

#if 0
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
#endif

void
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

    /* release any file cow mappings */
    whpx_ram_release_file_cow_mappings();
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

static int
compression_is_cuckoo(void)
{
    return
        vm_save_info.compress_mode == VM_SAVE_COMPRESS_CUCKOO ||
        vm_save_info.compress_mode == VM_SAVE_COMPRESS_CUCKOO_SIMPLE;
}

struct private_hashes {
    struct page_fingerprint *hashes;
    int hashes_nr;
};

static int
enum_hashes_cb(uint64_t pfn, uint64_t count, void *opaque)
{
    struct private_hashes *h = opaque;
    uint64_t end = pfn + count;

    while (pfn != end) {
        if (save_cancelled())
            return -EINTR;

        if (!((h->hashes_nr - 1) & h->hashes_nr)) {
            h->hashes = realloc(h->hashes, sizeof(h->hashes[0]) *
                (h->hashes_nr ? 2 * h->hashes_nr : 32));
            assert(h->hashes);
        }
        h->hashes[h->hashes_nr].pfn = pfn;
        h->hashes_nr++;
        pfn++;
    }

    return 0;
}

#define BATCH_SIZE 1024

static int
calculate_hashes(struct private_hashes *h)
{
    mb_entry_t *mb = NULL;
    win32_memory_range_entry *mre = malloc(sizeof(win32_memory_range_entry) * BATCH_SIZE);
    int i, ret = 0;
    int batch_start = 0, batch_len = 0;

    for (i = 0; i < h->hashes_nr; i++) {
        struct page_fingerprint *fp = &h->hashes[i];
        uint64_t pfn = fp->pfn;
        void *page;

        if (save_cancelled()) {
            ret = -EINTR;
            goto out;
        }

        if (!mb || !(pfn >= mb->r.start && pfn < mb->r.end))
            mb = find_page_mb_entry(pfn);
        assert(mb);
        page = mb->va + ((pfn - mb->r.start) << PAGE_SHIFT);
        mre[batch_len].VirtualAddress = page;
        mre[batch_len].NumberOfBytes = PAGE_SIZE;
        batch_len++;

        if (batch_len == BATCH_SIZE || i == h->hashes_nr - 1) {
            int j;

           if (!PrefetchVirtualMemoryP(GetCurrentProcess(), batch_len, mre, 0))
                debug_printf("PrefetchVirtualMemory failed: %d\n", (int)GetLastError());
            for (j = 0; j < batch_len; j++) {
                if (save_cancelled()) {
                    ret = -EINTR;
                    goto out;
                }

                h->hashes[batch_start + j].hash = page_fingerprint(
                    mre[j].VirtualAddress,
                    &h->hashes[batch_start + j].rotate);
            }

            batch_start = i + 1;
            batch_len = 0;
        }
    }

out:
    free(mre);

    return ret;
}

int
whpx_write_memory(struct filebuf *f)
{
    mb_entry_t *e;
    uint32_t num_saved = 0;
    uint32_t marker;
    struct xc_save_whpx_memory_data s;
    saved_mb_entry_t *saved_entries = NULL;
    pagerange_t *saved_ranges = NULL;
    int i,ret=0;
    off_t raw_pagedata_off;
    int write_page_contents;
    off_t size;
    char *err_msg = NULL;

    struct xc_save_vm_fingerprints s_vm_fingerprints;
    struct private_hashes pr_hashes;
    struct xc_save_index fingerprints_index = { 0, XC_SAVE_ID_FINGERPRINTS };
    struct xc_save_index whpx_memory_data_index = { 0, XC_SAVE_ID_WHPX_MEMORY_DATA };

    write_page_contents = !compression_is_cuckoo();

    uint64_t whpx_memory_data_off = filebuf_tell(f);

    ret = filebuf_set_sparse(f, true);
    if (ret) {
        debug_printf("failed to set sparse flag");
        goto out;
    }

    vm_save_info.page_batch_offset = whpx_memory_data_off;

    whpx_memory_data_index.offset = whpx_memory_data_off;
    s.marker = XC_SAVE_ID_WHPX_MEMORY_DATA;
    s.size = 0; /* updated later */
    s.has_page_contents = write_page_contents;
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
    raw_pagedata_off = filebuf_tell(f);
    raw_pagedata_off += PAGE_SIZE-1;
    raw_pagedata_off &= PAGE_MASK;

    size = raw_pagedata_off - whpx_memory_data_off;
    vm_save_set_abortable();

    /* calculate page hashes - can be slow operation */
    debug_printf("calculating page hashes...\n");
    memset(&pr_hashes, 0, sizeof(pr_hashes));
    enum_private_ranges(&pr_hashes, enum_hashes_cb);
    debug_printf("detected private ranges : %d pages\n", pr_hashes.hashes_nr);
    calculate_hashes(&pr_hashes);
    debug_printf("calculating page hashes done, %d hashes\n", pr_hashes.hashes_nr);

    if (write_page_contents) {
        /* save page contents */
        filebuf_buffer_max(f, SAVE_BUFFER_SIZE);

        uint64_t saved_bytes = 0;
        LARGE_INTEGER freq, t0, t1;
        QueryPerformanceFrequency(&freq);
        QueryPerformanceCounter(&t0);
        filebuf_seek(f, raw_pagedata_off, FILEBUF_SEEK_SET);
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
    }

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

    /* save cuckoo data */
    if (compression_is_cuckoo()) {
        struct xc_save_cuckoo_data xc_cuckoo;
        xc_cuckoo.marker = XC_SAVE_ID_CUCKOO_DATA;
        xc_cuckoo.simple_mode = (vm_save_info.compress_mode ==
            VM_SAVE_COMPRESS_CUCKOO_SIMPLE);
        filebuf_write(f, &xc_cuckoo, sizeof(xc_cuckoo));
        debug_printf("saving cuckoo pages..\n");
        ret = save_cuckoo_pages(f, pr_hashes.hashes, pr_hashes.hashes_nr,
            xc_cuckoo.simple_mode, &err_msg);
        if (ret) {
            debug_printf("save_cuckoo_pages failed: %d: %s\n", ret, err_msg ? err_msg : "");
            goto out;
        }
        debug_printf("saving cuckoo pages done\n");
    }

    /* save fingerprints */
    if (vm_save_info.fingerprint && !compression_is_cuckoo()) {
        s_vm_fingerprints.marker = XC_SAVE_ID_FINGERPRINTS;
        s_vm_fingerprints.hashes_nr = pr_hashes.hashes_nr;
        fingerprints_index.offset = filebuf_tell(f);
        BUILD_BUG_ON(sizeof(pr_hashes.hashes[0]) !=
            sizeof(s_vm_fingerprints.hashes[0]));
        s_vm_fingerprints.size = s_vm_fingerprints.hashes_nr *
            sizeof(s_vm_fingerprints.hashes[0]);
        s_vm_fingerprints.size += sizeof(s_vm_fingerprints);
        debug_printf("fingerprints: pos %"PRId64" size %d nr hashes %d\n",
            fingerprints_index.offset, s_vm_fingerprints.size,
            s_vm_fingerprints.hashes_nr);
        filebuf_write(f, &s_vm_fingerprints, sizeof(s_vm_fingerprints));
        filebuf_write(f, pr_hashes.hashes,
            s_vm_fingerprints.size - sizeof(s_vm_fingerprints));
    }

    /* 0: end marker */
    marker = 0;
    filebuf_write(f, &marker, sizeof(marker));

    /* indexes */
    filebuf_write(f, &whpx_memory_data_index, sizeof(whpx_memory_data_index));
    if (vm_save_info.fingerprint && !compression_is_cuckoo())
        filebuf_write(f, &fingerprints_index, sizeof(fingerprints_index));

    filebuf_flush(f);

out:
    free(saved_entries);
    free(saved_ranges);
    free(pr_hashes.hashes);
    free(err_msg);

    return ret;
}

void
whpx_memory_post_save_hook(void)
{
    if (vm_save_info.free_mem && !save_cancelled()) {
        debug_printf("whpx: post save ram free\n");
        whpx_ram_free();
    }
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
find_file_ram_mapping(pagerange_t r, file_mapping_type_t type)
{
    file_mapping_t *e;

    TAILQ_FOREACH(e, &file_ram_mappings, entry) {
        if (e->type == type && r.start == e->r.start && r.end == e->r.end)
            return e;
    }

    return NULL;
}

static struct shared_template_info *
sti_open(int *existed)
{
    int existed_ = 0;

    *existed = 0;

    if (!sti_ptr) {
        char uuid_str[37];
        char *mapname = NULL;
        void *p;

        uuid_unparse_lower(vm_template_uuid, uuid_str);
        asprintf(&mapname, "uxendm-whpx-template-%s", uuid_str);
        if (!mapname)
            return NULL;
        HANDLE h = CreateFileMapping(INVALID_HANDLE_VALUE, NULL,
            PAGE_READWRITE, 0, sizeof(struct shared_template_info), mapname);
        if (!h) {
            debug_printf("%s: create mapping failed: %d\n", __FUNCTION__,
                (int)GetLastError());
            return NULL;
        }
        if (GetLastError() == ERROR_ALREADY_EXISTS)
            existed_ = 1;
        else
            /* place mapping in the control pipe owning process so it is reused */
            control_dup_handle(h);

        p = MapViewOfFile(h, FILE_MAP_READ | FILE_MAP_WRITE, 0, 0,
            sizeof(struct shared_template_info));
        if (!p) {
            CloseHandle(h);
            debug_printf("%s: map view failed: %d\n", __FUNCTION__,
                (int)GetLastError());
            return NULL;
        }

        sti_handle = h;
        sti_ptr = p;
    }

    *existed = existed_;

    return sti_ptr;
}

static void
sti_close(void)
{
    if (sti_ptr) {
        UnmapViewOfFile(sti_ptr);
        sti_ptr = NULL;
    }

    if (sti_handle) {
        CloseHandle(sti_handle);
        sti_handle = NULL;
    }
}

static int
dm_process_exists(DWORD pid)
{
    int exists = 0;
    char current_name[512] = { 0 };
    char name[512] = { 0 };
    DWORD sz;

    HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!h)
        return 0;

    sz = sizeof(current_name);
    QueryFullProcessImageNameA(GetCurrentProcess(), 0, current_name, &sz);
    sz = sizeof(name);
    QueryFullProcessImageNameA(h, 0, name, &sz);
    exists = !strncmp(name, current_name, sizeof(name));
    CloseHandle(h);

    return exists;
}

static int
sti_take_ownership(void)
{
    struct shared_template_info *sti;
    char uuid_str[37];
    int existed = 0;
    int attempts = 100;

    uuid_unparse_lower(vm_template_uuid, uuid_str);

    sti = sti_open(&existed);
    if (!sti) {
        debug_printf("failed to open shared template info");
        return 0;
    }

    LONG pid = GetCurrentProcessId();
    LONG prev_pid = 0;

    while (attempts--) {
        LONG cmpold = InterlockedCompareExchange(&sti->owner_pid, pid, prev_pid);
        if (prev_pid == cmpold) {
            debug_printf("template %s took ownership pid %d from pid %d\n",
                uuid_str, (int) pid, (int) prev_pid);
            return 1;
        }
        prev_pid = cmpold;
        if (prev_pid != 0 && dm_process_exists(prev_pid))
            break;
    }
    debug_printf("template %s already owned by pid %d\n",
        uuid_str, (int) prev_pid);

    return 0;
}

static void *
new_file_mapping(
    struct filebuf *f, file_mapping_type_t type,
    pagerange_t r, uint64_t fileoff, int is_template)
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

    file_mapping_t *prev = find_file_ram_mapping(r, type);
    if (prev) {
        debug_printf("reuse %s mapping %016"PRIx64" - %016"PRIx64" file offset %016"PRIx64"\n",
            type == FILE_MAP_COPY ? "cow" : "rdo",
            r.start << PAGE_SHIFT, r.end << PAGE_SHIFT, fileoff);
        return prev->va;
    }

    debug_printf("create %s mapping %016"PRIx64" - %016"PRIx64" file offset %016"PRIx64"\n",
        type == FILE_MAP_COPY ? "cow" : "rdo",
        r.start << PAGE_SHIFT, r.end << PAGE_SHIFT, fileoff);
    aligned_off = fileoff & align_mask;

    h = CreateFileMapping(f->file, NULL, PAGE_READONLY, 0, 0, NULL);
    if (!h)
        Werr(1, "%s: CreateFileMapping failed", __FUNCTION__);

    void *va = VirtualAlloc2P(NULL, NULL, len + fileoff - aligned_off,
        MEM_RESERVE|MEM_RESERVE_PLACEHOLDER, PAGE_NOACCESS, NULL, 0);
    if (!va)
        Werr(1, "%s: VirtualAlloc2 failed\n", __FUNCTION__);
    map = MapViewOfFile3P(h, NULL, va,
        aligned_off,
        len + fileoff - aligned_off,
        MEM_REPLACE_PLACEHOLDER,
        type == FMT_COW ? PAGE_WRITECOPY : PAGE_READONLY,
        NULL, 0);
    if (!map)
        Werr(1, "%s: MapViewOfFile3 failed\n", __FUNCTION__);
    CloseHandle(h);

    file_mapping_t *fm = calloc(1, sizeof(file_mapping_t));
    fm->type = type;
    fm->r = r;
    fm->file_off = fileoff;
    fm->va = map + fileoff - aligned_off;
    fm->aligned_map_va = map;
    fm->aligned_size = len + fileoff - aligned_off;
    fm->is_template = is_template;
    TAILQ_INSERT_TAIL(&file_ram_mappings, fm, entry);

    return fm->va;
}

static int
lock_mapping(file_mapping_t *fm)
{
    SIZE_T ws_min = 0, ws_max = 0;
    SIZE_T lock_size = fm->aligned_size;
    int ws_modified = 0;

    if (fm->locked)
        return 0;

    if (!GetProcessWorkingSetSize(GetCurrentProcess(), &ws_min, &ws_max)) {
        debug_printf("%s: GetProcessWorkingSetSize fails\n", __FUNCTION__);
        goto err;
    }
    if (!SetProcessWorkingSetSize(GetCurrentProcess(), ws_min + lock_size,
                                  ws_max + lock_size)) {
        debug_printf("%s: SetProcessWorkingSetSize fails\n", __FUNCTION__);
        goto err;
    }

    ws_modified = 1;

    if (lock_size && !VirtualLock(fm->aligned_map_va, lock_size)) {
        debug_printf("%s: VirtualLock fails err=%d\n", __FUNCTION__, (int)GetLastError());
        goto err;
    }
    fm->locked = 1;

    debug_printf("locked %s mapping %016"PRIx64" - %016"PRIx64" file offset %016"PRIx64"\n",
        fm->type == FILE_MAP_COPY ? "cow" : "rdo",
        fm->r.start << PAGE_SHIFT, fm->r.end << PAGE_SHIFT, fm->file_off);

    return 0;

err:
    if (ws_modified) {
        if (!SetProcessWorkingSetSize(GetCurrentProcess(), ws_min, ws_max))
            whpx_panic("%s: SetProcessWorkingSetSize fails\n", __FUNCTION__);
    }
    debug_printf(
        "FAILED locking %s mapping %016"PRIx64" - %016"PRIx64" file offset %016"PRIx64" mapva %p\n",
        fm->type == FILE_MAP_COPY ? "cow" : "rdo",
        fm->r.start << PAGE_SHIFT, fm->r.end << PAGE_SHIFT,
        fm->file_off,
        fm->aligned_map_va);

    return -1;
}

/* one of the running dms locks template in memory */
static int
lock_template_mappings(void)
{
    file_mapping_t *e, *next;

    if (!sti_take_ownership())
        /* locked / owned by another uxendm */
        return 0;

    TAILQ_FOREACH_SAFE(e, &file_ram_mappings, entry, next) {
        if (e->is_template)
            lock_mapping(e);
    }

    return 1;
}

static int
whpx_clone_memory_pages(struct filebuf *f)
{
    uint32_t num_entries = 0;
    off_t raw_pagedata_off;
    uint64_t max_addr = 0;
    saved_mb_entry_t *saved_entries = NULL;
    int i, locked;
    uint64_t t0, dt;

    saved_entries = read_mb_entries(f, &num_entries, &max_addr);

    raw_pagedata_off = filebuf_tell(f);
    raw_pagedata_off += PAGE_SIZE-1;
    raw_pagedata_off &= PAGE_MASK;

    t0 = get_clock_ns(rt_clock);

    /* read file data & populate vmem */
    for (i = 0; i < num_entries; i++) {
        saved_mb_entry_t *se = &saved_entries[i];
        /* separate readonly mapping for templating/cuckoo */
        new_file_mapping(f, FMT_RO, se->r, se->file_off, 1);
        /* will either do a new cow mapping or reuse previous */
        void *ram = new_file_mapping(f, FMT_COW, se->r, se->file_off, 0);
        assert(ram);
        whpx_ram_populate_with(se->r.start << PAGE_SHIFT, pr_bytes(&se->r), ram, se->flags);

    }

    free(saved_entries);

    locked = lock_template_mappings();

    dt = get_clock_ns(rt_clock) - t0;
    debug_printf("memory clone took %dms, template lock=%d\n", (int)(dt / 1000000), locked);

    return 0;
}

int
whpx_clone_memory(char *template_file)
{
    int ret = 0;
    struct filebuf *t = NULL;
    char *err_msg = NULL;
    uint64_t data_off = 0;
    off_t pos;

    if (!template_file) {
        debug_printf("no template file!\n");
        ret = -1;
        goto out;
    }
    t = filebuf_open(template_file, "rb");
    if (!t) {
        debug_printf("filebuf_open(vm_template_file = %s) failed\n",
            vm_template_file);
        ret = -errno;
        goto out;
    }

    /* find page data in template file */
    filebuf_seek(t, 0, FILEBUF_SEEK_END);
    for (;;) {
        struct xc_save_index index;

        pos = filebuf_seek(t, -(off_t)sizeof(index), FILEBUF_SEEK_CUR);
        uxenvm_load_read(t, &index, sizeof(index), ret, &err_msg, out);
        if (!index.marker) {
            break;
        } else if (index.marker == XC_SAVE_ID_WHPX_MEMORY_DATA) {
            data_off = index.offset;
            break;
        }
        filebuf_seek(t, pos, FILEBUF_SEEK_SET);
    }

    if (!data_off) {
        debug_printf("page data index not found in template\n");
        ret = -1;
        goto out;
    }
    filebuf_seek(t, data_off, FILEBUF_SEEK_SET);
    struct xc_save_whpx_memory_data whpx_memory_data;
    uxenvm_load_read(t, &whpx_memory_data, sizeof(whpx_memory_data), ret, &err_msg, out);

    /* actual clone */
    ret = whpx_clone_memory_pages(t);

out:
    if (t)
        filebuf_close(t);
    if (err_msg) {
        debug_printf("error: %s\n", err_msg);
        free(err_msg);
    }

    return ret;
}

int
whpx_read_memory(struct filebuf *f, int layout_only)
{
    uint32_t num_entries = 0, i;
    saved_mb_entry_t *saved_entries = NULL;
    uint64_t max_addr;

    debug_printf("read whp pages, layout_only=%d\n", layout_only);

    saved_entries = read_mb_entries(f, &num_entries, &max_addr);

    /* read file data & populate vmem */
    for (i = 0; i < num_entries; i++) {
        saved_mb_entry_t *se = &saved_entries[i];
        uint64_t len, npages, addr;
        uint8_t *ram;

        npages = se->r.end - se->r.start;
        len = npages << PAGE_SHIFT;
        addr = se->r.start << PAGE_SHIFT;

        if (!layout_only) {
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

#ifdef DEBUG_CAPPOP_TIMES
static uint64_t cap_time, cap_cpy_time, pop_time, pop_cpy_time, cap_pages, pop_pages, cap_vp_count;
static uint64_t cap_vp_time;
#endif

/* atm this will only work on clones since it relies on reverting to template pages via
 * PAGE_REVERT_TO_FILE_MAP */
int
whpx_memory_balloon_grow(unsigned long nr_pfns, uint64_t *pfns)
{
    unsigned long i;
    mb_entry_t *mb = NULL;

    for (i = 0; i < nr_pfns; i++) {
        uint64_t pfn = pfns[i];
        if (!mb || !(pfn >= mb->r.start && pfn < mb->r.end))
            mb = find_page_mb_entry(pfn);
        assert(mb);
        void *page = mb->va + ((pfn - mb->r.start) << PAGE_SHIFT);
        DWORD oldp;
        if (!VirtualProtect(page, PAGE_SIZE, PAGE_REVERT_TO_FILE_MAP|PAGE_WRITECOPY, &oldp)) {
            debug_printf("balloon page add %"PRIx64" via VirtualProtect failed: %d\n",
                pfn, (int)GetLastError());
            return -1;
        }
    }

    return 0;
}

int
whpx_memory_capture(unsigned long nr_pfns, whpx_memory_capture_gpfn_info_t *pfns,
    unsigned long *nr_done, void *buffer, uint32_t buffer_size)
{
    uint64_t offset = 0;
    unsigned long i;
    mb_entry_t *mb = NULL;
    file_mapping_t *template_mapping = NULL;
    win32_memory_range_entry *mre = NULL;

    *nr_done = 0;

#ifdef DEBUG_CAPPOP_TIMES
    LARGE_INTEGER t0, freq, t1, cpy_t0, cpy_t1, vp_t0, vp_t1;
    QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&t0);
#endif

    mre = malloc(sizeof(win32_memory_range_entry) * nr_pfns);
    assert(mre);

    /* prefetch vmem */
    for (i = 0; i < nr_pfns; i++) {
        whpx_memory_capture_gpfn_info_t *info;
        uint64_t pfn;
        void *page = NULL;

        info = &pfns[i];
        pfn  = info->gpfn;

        if (!mb || !(pfn >= mb->r.start && pfn < mb->r.end)) {
            mb = find_page_mb_entry(pfn);
            if (mb)
                template_mapping = find_file_ram_mapping(mb->r, FMT_RO);
            else
                template_mapping = NULL;
        }
        if (info->flags & WHPX_MCGI_FLAGS_TEMPLATE) {
            if (template_mapping)
                page = template_mapping->va + ((pfn - mb->r.start) << PAGE_SHIFT);
        } else {
            if (mb)
                page = mb->va + ((pfn - mb->r.start) << PAGE_SHIFT);
        }
        if (!page) {
            info->type = WHPX_MCGI_TYPE_NOT_PRESENT;
            info->offset = offset;
            mre[i].VirtualAddress = NULL;
            mre[i].NumberOfBytes = 0;
        } else {
            mre[i].VirtualAddress = page;
            mre[i].NumberOfBytes = PAGE_SIZE;
        }
        offset += PAGE_SIZE;
    }

    if (!PrefetchVirtualMemoryP(GetCurrentProcess(), nr_pfns, mre, 0))
        debug_printf("capture: PrefetchVirtualMemory failed: %d\n", (int)GetLastError());

    offset = 0;

    /* read vmem */
    for (i = 0; i < nr_pfns; i++) {
        whpx_memory_capture_gpfn_info_t *info;
        uint64_t pfn;
        void *page = NULL;

        if (offset + PAGE_SIZE > buffer_size) {
            *nr_done = i;
            goto out;
        }

        info = &pfns[i];
        pfn  = info->gpfn;
        page = mre[i].VirtualAddress;

        if (page) {
#ifdef DEBUG_CAPPOP_TIMES
            QueryPerformanceCounter(&cpy_t0);
#endif
            memcpy(buffer, page, PAGE_SIZE);
#ifdef DEBUG_CAPPOP_TIMES
            QueryPerformanceCounter(&cpy_t1);
            cap_cpy_time += (cpy_t1.QuadPart - cpy_t0.QuadPart);
            cap_pages++;
#endif
            if (info->flags & WHPX_MCGI_FLAGS_REMOVE_PFN) {
                DWORD oldp;
#ifdef DEBUG_CAPPOP_TIMES
                QueryPerformanceCounter(&vp_t0);
#endif
                /* note: seems fairly slow operation */
                if (!VirtualProtect(page, PAGE_SIZE, PAGE_REVERT_TO_FILE_MAP|PAGE_WRITECOPY, &oldp)) {
                    debug_printf("remove_pfn %"PRIx64" (flags=%x) via VirtualProtect failed: %d\n",
                        pfn, info->flags, (int)GetLastError());
                }
#ifdef DEBUG_CAPPOP_TIMES
                QueryPerformanceCounter(&vp_t1);
                cap_vp_time += vp_t1.QuadPart - vp_t0.QuadPart;
                cap_vp_count++;
#endif
            }
            info->type = WHPX_MCGI_TYPE_NORMAL;
            info->offset = offset;
        }

        buffer += PAGE_SIZE;
        offset += PAGE_SIZE;
    }

    *nr_done = i;

#ifdef DEBUG_CAPPOP_TIMES
    QueryPerformanceCounter(&t1);
    cap_time += (t1.QuadPart - t0.QuadPart);

    debug_printf("capture: total %"PRId64"ms cpy %"PRId64"ms vp %"PRId64"ms vppages %"PRId64", pages %"PRId64"\n",
        cap_time * 1000 / freq.QuadPart,
        cap_cpy_time * 1000 / freq.QuadPart,
        cap_vp_time * 1000 / freq.QuadPart,
        cap_vp_count,
        cap_pages);
#endif

out:
    free(mre);

    return 0;
}

int
whpx_memory_populate_from_buffer(unsigned long nr_pfns, uint64_t *pfns, void *buffer)
{
    unsigned long i;
    mb_entry_t *mb = NULL;
#ifdef DEBUG_CAPPOP_TIMES
    LARGE_INTEGER t0, freq, t1, cpy_t0, cpy_t1;
    QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&t0);
#endif
    for (i = 0; i < nr_pfns; i++) {
        void *page = NULL;
        uint64_t pfn = pfns[i];

        if (!mb || !(pfn >= mb->r.start && pfn < mb->r.end))
            mb = find_page_mb_entry(pfn);

        assert(mb);
        page = mb->va + ((pfn - mb->r.start) << PAGE_SHIFT);
#ifdef DEBUG_CAPPOP_TIMES
        QueryPerformanceCounter(&cpy_t0);
#endif
        memcpy(page, buffer, PAGE_SIZE);
#ifdef DEBUG_CAPPOP_TIMES
        pop_pages++;
        QueryPerformanceCounter(&cpy_t1);
        pop_cpy_time += (cpy_t1.QuadPart - cpy_t0.QuadPart);
#endif
        buffer += PAGE_SIZE;
    }

#ifdef DEBUG_CAPPOP_TIMES
    QueryPerformanceCounter(&t1);
    pop_time += (t1.QuadPart - t0.QuadPart);

    debug_printf("populate: total %"PRId64"ms cpy %"PRId64"ms, pages %"PRId64"\n",
        pop_time * 1000 / freq.QuadPart,
        pop_cpy_time * 1000 / freq.QuadPart, pop_pages);
#endif
    return 0;
}

uint64_t
whpx_get_private_memory_usage(void)
{
    uint64_t now = get_clock_ns(rt_clock);

    if (TAILQ_EMPTY(&mb_entries))
        return 0;

    critical_section_enter(&whpx_private_mem_cs);

    /* private memory calculation is expensive, throttle to max once per 4s */
    if (!whpx_private_mem_query_ts ||
        (now - whpx_private_mem_query_ts) >= PRIVATE_MEM_QUERY_INTERVAL_NS) {
        for (;;) {
            ULONG len = 0;
            NTSTATUS status = NtQuerySystemInformationP(SystemProcessInformation,
                sys_info, sys_info_sz, &len);
            if (!status)
                break;
            if (status != STATUS_INFO_LENGTH_MISMATCH) {
                debug_printf("NtQuerySystemInformation failed with %x\n",
                    (int) status);
                goto out;
            }
            if (len > sys_info_sz) {
                sys_info_sz = len + 0x10000;
                sys_info = realloc(sys_info, sys_info_sz);
                assert(sys_info);
            }
        }

        HANDLE pid = (HANDLE) (uintptr_t) GetCurrentProcessId();
        uint8_t *buf = sys_info;

        for (;;) {
            struct spi_hdr *spi = (struct spi_hdr*) buf;

            if (pid == spi->ProcessId) {
                whpx_private_mem_query_ts = now;
                private_mem_pages =
                    spi->WorkingSetPrivateSize.QuadPart >> PAGE_SHIFT;
                break;
            } else if (!spi->NextEntryOffset)
                break;
            else
                buf += spi->NextEntryOffset;
        }
    }
out:
    critical_section_leave(&whpx_private_mem_cs);

    return private_mem_pages << PAGE_SHIFT;
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
    sti_close();
}
