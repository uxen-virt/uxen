/*
 *  uxen_mem.c
 *  uxen
 *
 * Copyright 2011-2016, Bromium, Inc.
 * Author: Christian Limpach <Christian.Limpach@gmail.com>
 * SPDX-License-Identifier: ISC
 * 
 */

#include "uxen.h"

#include <stddef.h>

#include <ntddk.h>
#include <xen/errno.h>

#include <uxen_ioctl.h>

#define UXEN_DEFINE_SYMBOLS_PROTO
#include <uxen/uxen_link.h>

#include "pagemap.h"

static KSPIN_LOCK map_page_range_lock;
static MDL *map_page_range_mdl = NULL;
int map_page_range_max_nr = 64;

KSPIN_LOCK idle_free_lock;
uint32_t idle_free_list = 0;
static uint32_t idle_free_count = 0;

#define INCREASE_RESERVE_BATCH 512

static PMDL idle_free_mfns_mdl = NULL;

static uint32_t pages_reserve[MAXIMUM_PROCESSORS];

KGUARDED_MUTEX populate_frametable_mutex;
static PMDL frametable_page_mdl = NULL;
#define FRAMETABLE_MFNS_BATCH 256
static unsigned int nr_frametable_mfns = 0;

KGUARDED_MUTEX populate_vframes_mutex;
uxen_pfn_t vframes_start, vframes_end;

#ifdef _WIN64
/* assuming phys addr size to be 36 bit */
#define PML4_PHYS_ADDR_MASK 0x0000fffffffff000
static uintptr_t linear_pt_va;
#define LINEAR_PT_VA linear_pt_va
#define VA_TO_LINEAR_PTE(v)						\
    (uint64_t *)(LINEAR_PT_VA +						\
		 (((v) & ~0xffff000000000fff) >> (PAGE_SHIFT - 3)))
#else
#define LINEAR_PT_VA 0xc0000000
#define VA_TO_LINEAR_PTE(v)						\
    (uint32_t *)(LINEAR_PT_VA +						\
		 (((v) & ~0x00000fff) >> (PAGE_SHIFT - 3)))

uxen_pfn_t os_max_pfn = -1;
#endif

#undef GB
#define KB(x) (1024ULL * x)
#define MB(x) (1024ULL * KB(x))
#define GB(x) (1024ULL * MB(x))
#define TB(x) (1024ULL * GB(x))

#ifdef _DEFENSIVE_LIMITS
#define DEFENSIVE_CHECK(type, var, limit, ret_val) \
    do { \
        if (((type)(var)) >= ((type)(limit))) { \
            dprintk("%s:%d: unexpected value %lld for "#var". bail.\n", \
                    __FUNCTION__, __LINE__, (uint64_t)(var)); \
            return (ret_val); \
        } \
    } while (0)
#else
#define DEFENSIVE_CHECK(type, var, limit, ret_val)
#endif

#ifdef _WIN64
static int
set_linear_pt_va(void)
{
    uintptr_t cr3;
    PMDL mdl = NULL;
    uint64_t *addr = NULL;
    unsigned int offset;
    int ret = 0;

    mdl = IoAllocateMdl(NULL, 1 << PAGE_SHIFT, FALSE, FALSE, NULL);
    if (!mdl) {
        fail_msg("%s: IoAllocateMdl failed", __FUNCTION__);
        ret = ENOMEM;
        goto out;
    }

    cr3 = read_cr3();

    mdl->MdlFlags = MDL_PAGES_LOCKED;
    MmGetMdlPfnArray(mdl)[0] = cr3 >> PAGE_SHIFT;
    try {
        addr = MmMapLockedPagesSpecifyCache(
            mdl, KernelMode,
            MmCached, NULL, FALSE, LowPagePriority);
    } except (HOSTDRV_EXCEPTION_EXECUTE_HANDLER(
                  "MmMapLockedPagesSpecifyCache")) {
	addr = NULL;
    }

    for (offset = 0; offset < PAGE_SIZE; offset++)
        if ((addr[offset / sizeof(addr[0])] & PML4_PHYS_ADDR_MASK) == cr3)
            break;

    if (offset == PAGE_SIZE) {
        fail_msg("%s: linear_pt_va not found", __FUNCTION__);
        ret = EINVAL;
        goto out;
    }

    linear_pt_va = (uintptr_t)offset << 36;
    if (offset >= PAGE_SIZE / 2)
        linear_pt_va |= 0xffff000000000000;

  out:
    if (mdl) {
        if (addr)
            MmUnmapLockedPages((uint8_t *)addr, mdl);
        IoFreeMdl(mdl);
    }
    return ret;
}
#else  /* _WIN64 */
static int
set_linear_pt_va(void)
{

    return 0;
}
#endif  /* _WIN64 */

static uint64_t
set_pte(uintptr_t va, uint64_t new)
{
#ifdef _WIN64
    volatile uint64_t *pteaddr = VA_TO_LINEAR_PTE(va);
    uint64_t old;

    old = *pteaddr;
    if (new != ~0ULL)
        *pteaddr = new;
#else
    volatile uint32_t *pteaddr = VA_TO_LINEAR_PTE(va);
    uint64_t old;

    old = *(uint64_t *)pteaddr;
    if (new != ~0ULL) {
        if (old & 1) {
            pteaddr[0] = 0;
            _WriteBarrier();
        }
        pteaddr[1] = (new >> 32);
        _WriteBarrier();
        pteaddr[0] = new & 0xffffffff;
    }
#endif

    return old;
}

static uint64_t map_mfn_pte_flags = 0;

uint64_t __cdecl
map_mfn(uintptr_t va, xen_pfn_t mfn)
{

    return set_pte(va, (mfn == ~0ULL || mfn == 0ULL) ? mfn :
                   (((uint64_t)mfn << PAGE_SHIFT) | map_mfn_pte_flags));
}

static void
set_map_mfn_pte_flags(void)
{
    uint64_t dummy = 0;

    /* ---DA--UW-V and avail2 */
    map_mfn_pte_flags = 0x0000000000000867;
    
    /* set NX bit if it's used for stack PTE */
    map_mfn_pte_flags |= (*((uint64_t *)VA_TO_LINEAR_PTE((size_t)&dummy)) &
                          0x8000000000000000);

    if (!(map_mfn_pte_flags & 0x8000000000000000))
        printk("NX is disabled\n");
}

static int user_free_user_mapping(struct user_mapping *);

typedef struct {
    const void *addr;
    uintptr_t size;
} user_mapping_va;

#define USER_MAPPING_VA_START(va) ((va).addr)
#define USER_MAPPING_VA_END(va) ((void *)((uintptr_t)((va).addr) + (va).size))

struct user_mapping {
    user_mapping_va va;
    union {
        struct {
            MDL *mdl;
            union {
                struct {
                    xen_pfn_t *mfns;
                    uint32_t num;
                };
                xen_pfn_t *gpfns;
            };
            struct fd_assoc *fda;
        };
    };
    enum user_mapping_type type;
    /* int mapping_mode; */
    struct rb_node rbnode;
};

static intptr_t
user_mapping_compare_key(void *ctx, const void *b, const void *key)
{
    const struct user_mapping * const pnp =
        (const struct user_mapping * const)b;
    const user_mapping_va * const fhp = (const user_mapping_va * const)key;

    if (USER_MAPPING_VA_START(pnp->va) >= USER_MAPPING_VA_END(*fhp))
        return 1;
    else if (USER_MAPPING_VA_END(pnp->va) <= USER_MAPPING_VA_START(*fhp))
        return -1;
    return 0;
}

static intptr_t
user_mapping_compare_nodes(void *ctx, const void *parent, const void *node)
{
    const struct user_mapping * const np =
        (const struct user_mapping * const)node;

    return user_mapping_compare_key(ctx, parent, &np->va);
}

const rb_tree_ops_t user_mapping_rbtree_ops = {
    /* .rbto_compare_nodes = */ user_mapping_compare_nodes,
    /* .rbto_compare_key = */ user_mapping_compare_key,
    /* .rbto_node_offset = */ offsetof(struct user_mapping, rbnode),
    /* .rbto_context = */ NULL
};

int
mem_init(void)
{
    int ret = 0;

    KeInitializeSpinLock(&map_page_range_lock);

    map_page_range_mdl = ExAllocatePoolWithTag(
        NonPagedPool, sizeof(MDL) +
        sizeof(PFN_NUMBER) * map_page_range_max_nr, UXEN_POOL_TAG);
    if (!map_page_range_mdl) {
        ret = ENOMEM;
        goto out;
    }

    memset(map_page_range_mdl, 0, sizeof(*map_page_range_mdl));
    map_page_range_mdl->Size = sizeof(MDL) +
        sizeof(PFN_NUMBER) * map_page_range_max_nr;

    BUILD_BUG_ON(sizeof(PFN_NUMBER) != sizeof(uintptr_t));

    idle_free_mfns_mdl = ExAllocatePoolWithTag(
        NonPagedPool, sizeof(MDL) +
        sizeof(PFN_NUMBER) * INCREASE_RESERVE_BATCH, UXEN_POOL_TAG);
    if (!idle_free_mfns_mdl) {
        ret = ENOMEM;
        goto out;
    }

    ret = set_linear_pt_va();
    if (ret)
        goto out;

    set_map_mfn_pte_flags();

  out:
    return ret;
}

void
mem_exit(void)
{

    if (map_page_range_mdl != NULL) {
        ExFreePoolWithTag(map_page_range_mdl, UXEN_POOL_TAG);
        map_page_range_mdl = NULL;
    }

    if (idle_free_mfns_mdl != NULL) {
        ExFreePoolWithTag(idle_free_mfns_mdl, UXEN_POOL_TAG);
        idle_free_mfns_mdl = NULL;
    }
}

void *
_kernel_malloc_unchecked(size_t size, int line)
{
    void *p;
    ULONG tag;
    char hex[] = "0123456789abcdef";

    tag = hex[(line >> 0) & 0xf] << 24 |
          hex[(line >> 4) & 0xf] << 16 |
          hex[(line >> 8) & 0xf] << 8 |
          'u';

    size = (size + sizeof(uintptr_t) - 1) & ~(sizeof(uintptr_t) - 1);
    p = ExAllocatePoolWithTag(NonPagedPool, size, tag);
    if (p)
        memset(p, 0, size);

    return p;
}

void *
_kernel_malloc(size_t size, int line)
{

    size = (size + sizeof(uintptr_t) - 1) & ~(sizeof(uintptr_t) - 1);
    if (size > (1 << 30)) {
        fail_msg("size assert: %Ix", size);
        return NULL;
    }

    return _kernel_malloc_unchecked(size, line);
}

void
kernel_free(void *addr, size_t size)
{

    /* size = (size + sizeof(uintptr_t) - 1) & ~(sizeof(uintptr_t) - 1); */
    ExFreePool(addr);
}

int
kernel_query_mfns(void *va, uint32_t nr_pages,
                  uxen_pfn_t *mfn_list, uint32_t max_mfn)
{
    int ret;
    PFN_NUMBER *mfn_array;
    PMDL mdl;
    uint32_t i;

    mdl = IoAllocateMdl(va, nr_pages << PAGE_SHIFT, FALSE, FALSE, NULL);
    if (!mdl) {
        fail_msg("IoAllocateMdl failed: va=%p, size=0x%x",
                 va, nr_pages << PAGE_SHIFT);
        return ENOMEM;
    }

    if (max_mfn == 0)
        max_mfn = uxen_info ? uxen_info->ui_max_page : -1;

    ret = 0;

    MmBuildMdlForNonPagedPool(mdl);

    mfn_array = MmGetMdlPfnArray(mdl);
    for (i = 0; i < nr_pages; i++) {
        mfn_list[i] = (uxen_pfn_t)mfn_array[i];
        if (mfn_list[i] > max_mfn) {
            fail_msg("invalid mfn %lx at entry %d", mfn_list[i], i);
            ret = EINVAL;
            break;
        }
    }

    IoFreeMdl(mdl);
    
    return ret;
}

/* same as struct page_info/page_list_entry */
struct page_list_entry {
    uint32_t next, prev;
    uint32_t count_info;
    uint16_t domain;
#ifdef DEBUG_STRAY_PAGES
    uint16_t pad1;
    void *alloc0;
    void *alloc1;
#endif  /* DEBUG_STRAY_PAGES */
};

int
kernel_alloc_mfn(uxen_pfn_t *mfn)
{
    PHYSICAL_ADDRESS low_address;
    PHYSICAL_ADDRESS high_address;
    PHYSICAL_ADDRESS skip_bytes;
    PMDL mdl = NULL;
    KIRQL old_irql;
    int ret = 1;

    low_address.QuadPart = 0;
    high_address.QuadPart = -1;
    skip_bytes.QuadPart = 0;

    mdl = MmAllocatePagesForMdlEx(low_address, high_address, skip_bytes,
                                  1 << PAGE_SHIFT, MmCached,
                                  MM_ALLOCATE_FULLY_REQUIRED);
    if (mdl == NULL) {
        fail_msg("MmAllocatePagesForMdlEx failed");
        goto out;
    }

    *mfn = (uxen_pfn_t)MmGetMdlPfnArray(mdl)[0];
    ret = 0;

#ifdef DEBUG_PAGE_ALLOC
    DASSERT(!pinfotable[*mfn].allocated);
    pinfotable[*mfn].allocated = 1;
#endif  /* DEBUG_PAGE_ALLOC */

  out:
    if (mdl)
        ExFreePool(mdl);
    return ret;
}

int
_populate_frametable(uxen_pfn_t mfn, uxen_pfn_t pmfn)
{
    unsigned int offset;
    uintptr_t frametable_va;
    PFN_NUMBER frametable_mfn;
    int s = uxen_info->ui_sizeof_struct_page_info;

    offset = (s * mfn) >> PAGE_SHIFT;

    KeAcquireGuardedMutex(&populate_frametable_mutex);
    while (!(frametable_populated[offset / 8] & (1 << (offset % 8)))) {
        if (!pmfn && !nr_frametable_mfns) {
            PHYSICAL_ADDRESS low_address;
            PHYSICAL_ADDRESS high_address;
            PHYSICAL_ADDRESS skip_bytes;
            PMDL mdl;

            KeReleaseGuardedMutex(&populate_frametable_mutex);
            low_address.QuadPart = 0;
            high_address.QuadPart = -1;
            skip_bytes.QuadPart = 0;
            mdl = MmAllocatePagesForMdlEx(low_address, high_address, skip_bytes,
                                          FRAMETABLE_MFNS_BATCH << PAGE_SHIFT,
                                          MmCached, 0);
            KeAcquireGuardedMutex(&populate_frametable_mutex);

            if (!nr_frametable_mfns) {
                /* if our allocation failed, take advantage of the
                 * slim chance that another thread filled the mdl */
                if (!mdl || MmGetMdlByteCount(mdl) < PAGE_SIZE) {
                    KeReleaseGuardedMutex(&populate_frametable_mutex);
                    fail_msg("MmAllocatePagesForMdlEx failed");
                    if (mdl)
                        ExFreePool(mdl);
                    return 1;
                }
                if (frametable_page_mdl)
                    ExFreePool(frametable_page_mdl);
                frametable_page_mdl = mdl;
                nr_frametable_mfns =
                    MmGetMdlByteCount(frametable_page_mdl) >> PAGE_SHIFT;
            } else if (mdl)
                ExFreePool(mdl);
            continue;
        }
        frametable_va = (uintptr_t)frametable + (offset << PAGE_SHIFT);
        if (pmfn) {
            frametable_mfn = pmfn;
            pmfn = 0;
        } else
            frametable_mfn =
                MmGetMdlPfnArray(frametable_page_mdl)[--nr_frametable_mfns];
#ifdef DEBUG_PAGE_ALLOC
        DASSERT(!pinfotable[frametable_mfn].allocated);
        pinfotable[frametable_mfn].allocated = 1;
#endif  /* DEBUG_PAGE_ALLOC */
        map_mfn(frametable_va, frametable_mfn);
        memset((void *)frametable_va, 0, PAGE_SIZE);
        frametable_populated[offset / 8] |= (1 << (offset % 8));
        break;
    }
    KeReleaseGuardedMutex(&populate_frametable_mutex);

    /* Check if last byte of mfn's page_info is in same frametable
     * page, otherwise populate next mfn as well */
    if (((s * (mfn + 1) - 1) >> PAGE_SHIFT) != offset)
        return _populate_frametable(mfn + 1, pmfn);
    return 0;
}

int frametable_check_populate = 0;

static uxen_pfn_t
populate_frametable_range(uxen_pfn_t start, uxen_pfn_t end, int self)
{
    int s = uxen_info->ui_sizeof_struct_page_info;
    uxen_pfn_t mfn;

    for (mfn = start; mfn < end;) {
        if (_populate_frametable(mfn, self ? --end : 0)) {
            fail_msg("failed to populate frametable for mfn %lx", mfn);
            return 0;
        }
        mfn = (((((s * mfn) >> PAGE_SHIFT) + 1) << PAGE_SHIFT) + s - 1) / s;
    }

    return end;
}

int
populate_frametable_physical_memory(void)
{
    PPHYSICAL_MEMORY_RANGE pMemMap;
    uxen_pfn_t start, end;

    if (frametable_check_populate)
        goto out;

    for (pMemMap = MmGetPhysicalMemoryRanges();
         pMemMap[0].BaseAddress.QuadPart || pMemMap[0].NumberOfBytes.QuadPart;
         pMemMap++) {
        start = (uxen_pfn_t)(pMemMap[0].BaseAddress.QuadPart >> PAGE_SHIFT);
        end = (uxen_pfn_t)((pMemMap[0].BaseAddress.QuadPart +
                            pMemMap[0].NumberOfBytes.QuadPart +
                            PAGE_SIZE - 1) >> PAGE_SHIFT);
#ifdef __i386__
        if (start >= os_max_pfn)
            continue;
        if (end > os_max_pfn)
            end = os_max_pfn;
#endif  /* __i386__ */
        if (!populate_frametable_range(start, end, 0))
            frametable_check_populate = 1;
    }
  out:
    if (frametable_check_populate)
        printk("%s: populate frametable incomplete\n", __FUNCTION__);
    return 0;
}

void
depopulate_frametable(unsigned int pages)
{
    unsigned int offset;
    uxen_pfn_t mfn;
    uintptr_t frametable_va;
    uint32_t freed_pages = 0;

    for (offset = 0; offset < pages; offset++) {
        if (!(frametable_populated[offset / 8] & (1 << (offset % 8))))
            continue;
        if (nr_frametable_mfns == FRAMETABLE_MFNS_BATCH) {
            frametable_page_mdl->Size = sizeof(MDL) +
                sizeof(PFN_NUMBER) * nr_frametable_mfns;
            MmFreePagesFromMdl(frametable_page_mdl);
            nr_frametable_mfns = 0;
        }
        frametable_va = (uintptr_t)frametable + (offset << PAGE_SHIFT);
        mfn = map_mfn(frametable_va, ~0ULL) >> PAGE_SHIFT;
        if (mfn) {
#ifdef __i386__
          if (mfn < os_max_pfn)
#endif  /* __i386__ */
            MmGetMdlPfnArray(frametable_page_mdl)[nr_frametable_mfns++] = mfn;
            freed_pages++;
        }
    }

    if (nr_frametable_mfns) {
        frametable_page_mdl->Size = sizeof(MDL) +
            sizeof(PFN_NUMBER) * nr_frametable_mfns;
        MmFreePagesFromMdl(frametable_page_mdl);
        ExFreePool(frametable_page_mdl);
        nr_frametable_mfns = 0;
    }
    dprintk("%s: freed %d frametable pages\n", __FUNCTION__, freed_pages);
}

#ifdef DEBUG_STRAY_PAGES
void
find_stray_pages_in_frametable(unsigned int pages)
{
    unsigned int offset;
    uintptr_t frametable_va;
    int i;
    int s = uxen_info->ui_sizeof_struct_page_info;
    int strays = 0;

    uxen_lock();
    for (offset = 0; offset < pages; offset++) {
        if (!(frametable_populated[offset / 8] & (1 << (offset % 8))))
            continue;
        frametable_va = (uintptr_t)frametable + (offset << PAGE_SHIFT);
        for (i = ((offset << PAGE_SHIFT) % s) ?
                 (s - ((offset << PAGE_SHIFT) % s)) : 0;
             i < PAGE_SIZE; i += s) {
            struct page_list_entry *p =
                (struct page_list_entry *)(frametable_va + i);
            if (i + s > PAGE_SIZE &&
                !(frametable_populated[(offset + 1) / 8] &
                  (1 << ((offset + 1) % 8))))
                break;
            if ((p->count_info && (p->count_info != (2 << (32 - 9))) &&
                 (p->count_info != (3 << (32 - 9)))) || p->domain) {
                if (strays < 100) {
                    char symbol_buffer0[200];
                    char symbol_buffer1[200];
                    uxen_do_lookup_symbol((uint64_t)p->alloc0, symbol_buffer0,
                                          sizeof(symbol_buffer0));
                    uxen_do_lookup_symbol((uint64_t)p->alloc1, symbol_buffer1,
                                          sizeof(symbol_buffer0));
                    dprintk("%s: stray mfn %x caf %x dom %x"
                            " alloc0 %p/%s alloc1 %p/%s\n", __FUNCTION__,
                            (uint32_t)((uint8_t *)p - frametable) / s,
                            p->count_info, p->domain,
                            p->alloc0, symbol_buffer0,
                            p->alloc1, symbol_buffer1);
                }
                strays++;
            }
        }
    }
    uxen_unlock();

    if (strays)
        printk("%s: %d stray entries in frametable\n", __FUNCTION__, strays);
}
#endif  /* DEBUG_STRAY_PAGES */

int
kernel_malloc_mfns(uint32_t nr_pages, uxen_pfn_t *mfn_list, uint32_t max_mfn)
{
    PHYSICAL_ADDRESS low_address;
    PHYSICAL_ADDRESS high_address;
    PHYSICAL_ADDRESS skip_bytes;
    PFN_NUMBER *mfnarray;
    PMDL mdl = NULL;
    KIRQL old_irql;
    uint32_t i = 0, j, k;

    if (max_mfn == 0)
        max_mfn = uxen_info ? uxen_info->ui_max_page : -1;

    while (idle_free_count > 0 && i < nr_pages) {
        int s = uxen_info->ui_sizeof_struct_page_info;
        struct page_list_entry *p;
        uint32_t *plist;

        KeAcquireSpinLock(&idle_free_lock, &old_irql);
        plist = &idle_free_list;
        while (*plist) {
            if (*plist >= max_mfn)
                break;
            p = (struct page_list_entry *)(frametable + (*plist) * s);
            if (p->prev) {
                plist = &p->prev;
                continue;
            }
            mfn_list[i] = *plist;
            i++;
            idle_free_count--;
            *plist = p->next;
            p->next = 0;
#ifdef DBG
            ASSERT(!p->count_info);
#endif  /* DBG */
            if (i >= nr_pages)
                break;
        }
        KeReleaseSpinLock(&idle_free_lock, old_irql);
    }

    while (i < nr_pages) {
        low_address.QuadPart = 0;
        high_address.QuadPart = -1;
        skip_bytes.QuadPart = 0;
        k = nr_pages - i;
        if (mdl)
            ExFreePool(mdl);
        mdl = MmAllocatePagesForMdlEx(low_address, high_address, skip_bytes,
                                      k << PAGE_SHIFT, MmCached,
                                      MM_ALLOCATE_NO_WAIT);
        if (mdl == NULL || MmGetMdlByteCount(mdl) < PAGE_SIZE) {
            fail_msg("MmAllocatePagesForMdlEx failed: %d pages", k);
            goto out;
        }

        KeAcquireSpinLock(&idle_free_lock, &old_irql);
        k = MmGetMdlByteCount(mdl) >> PAGE_SHIFT;
        mfnarray = MmGetMdlPfnArray(mdl);
        for (j = 0; j < k && i < nr_pages; j++) {
            mfn_list[i] = (uxen_pfn_t)mfnarray[j];
            if (mfn_list[i] > max_mfn || mfn_list[i] == 0) {
                fail_msg("invalid mfn %lx at entry %d", mfn_list[i], j);
                continue;
            }
            if (populate_frametable(mfn_list[i], 0)) {
                fail_msg("failed to populate frametable for mfn %lx"
                         " at entry %d", mfn_list[i], j);
                continue;
            }
#ifdef DEBUG_PAGE_ALLOC
            DASSERT(!pinfotable[mfn_list[i]].allocated);
            pinfotable[mfn_list[i]].allocated = 1;
#endif  /* DEBUG_PAGE_ALLOC */
            i++;
        }
        KeReleaseSpinLock(&idle_free_lock, old_irql);
    }

  out:
    if (mdl)
	ExFreePool(mdl);
    return i;
}

void
kernel_free_mfn(uxen_pfn_t mfn)
{
    uint8_t _mdl[sizeof(MDL) + sizeof(PFN_NUMBER)];
    PMDL mdl = (PMDL)&_mdl;
    PFN_NUMBER *pfn;

#ifdef DEBUG_PAGE_ALLOC
    DASSERT(pinfotable[mfn].allocated);
    pinfotable[mfn].allocated = 0;
#endif  /* DEBUG_PAGE_ALLOC */
    memset(mdl, 0, sizeof(MDL));
    mdl->MdlFlags = MDL_PAGES_LOCKED;
    mdl->Size = sizeof(MDL) + sizeof(PFN_NUMBER);
    mdl->ByteCount = PAGE_SIZE;

    pfn = MmGetMdlPfnArray(mdl);
    pfn[0] = (PFN_NUMBER)mfn;

    MmFreePagesFromMdl(mdl);
}

void *
kernel_alloc_contiguous(uint32_t size)
{
    PHYSICAL_ADDRESS highest_contiguous;
    void *va;
    uxen_pfn_t mfn;
    int i, ret;

#ifdef __x86_64__
    highest_contiguous.QuadPart =
        ((uint64_t)uxen_info->ui_max_page << PAGE_SHIFT) - 1;
#else
    highest_contiguous.QuadPart = 0xffffffff; /* 4GB max */
#endif

    va = MmAllocateContiguousMemory(size, highest_contiguous);

    ret = kernel_query_mfns(va, 1, &mfn, 0);
    if (ret)
        fail_msg("kernel_query_mfns failed: %d", ret);
    else {
        for (i = 0; i < (size >> PAGE_SHIFT); i++) {
            if (populate_frametable(mfn + i, 0)) {
                MmFreeContiguousMemory(va);
                return NULL;
            }
#ifdef DEBUG_PAGE_ALLOC
            DASSERT(!pinfotable[mfn + i].allocated);
            pinfotable[mfn + i].allocated = 1;
#endif  /* DEBUG_PAGE_ALLOC */
        }
    }

    return va;
}

void
kernel_free_contiguous(void *va, uint32_t size)
{
#ifdef DEBUG_PAGE_ALLOC
    uxen_pfn_t mfn;
    int i, ret;

    ret = kernel_query_mfns(va, 1, &mfn, 0);
    if (ret)
        fail_msg("kernel_query_mfns failed: %d", ret);
    else {
        for (i = 0; i < (size >> PAGE_SHIFT); i++) {
            DASSERT(pinfotable[mfn + i].allocated);
            pinfotable[mfn + i].allocated = 0;
        }
    }
#endif  /* DEBUG_PAGE_ALLOC */

    MmFreeContiguousMemory(va);
}

void *
kernel_alloc_va(uint32_t num)
{
    PMDL mdl;
    PFN_NUMBER *pfn;
    void *va;
    unsigned int i;
    int failed = 1;

    va = MmAllocateMappingAddress(num << PAGE_SHIFT, UXEN_MAPPING_TAG);
    if (va == NULL) {
        fail_msg("MmAllocateMappingAddress failed: %d pages", num);
        return NULL;
    }

    mdl = ExAllocatePoolWithTag(
        NonPagedPool, sizeof(MDL) + sizeof(PFN_NUMBER) * num,
        UXEN_POOL_TAG);
    if (mdl == NULL) {
        fail_msg("ExAllocatePoolWithTag failed: %d pfns", num);
        goto out;
    }
    memset(mdl, 0, sizeof(*mdl));

    mdl->Size = sizeof(MDL) + sizeof(PFN_NUMBER) * num;
    mdl->ByteCount = num << PAGE_SHIFT;
    mdl->MdlFlags = MDL_PAGES_LOCKED;

    pfn = MmGetMdlPfnArray(mdl);
    for (i = 0; i < num; i++)
        pfn[i] = uxen_zero_mfn;

    if (MmMapLockedPagesWithReservedMapping(va, UXEN_MAPPING_TAG, mdl,
                                            MmCached))
        failed = 0;
    else
        fail_msg("MmMapLockedPagesWithReservedMapping failed: "
                 "%x pages at va %p", num, va);

    /* Clear va space even in failed case, since otherwise
     * MmFreeMappingAddress below can blue screen because the va space
     * is "dirty"  */
    for (i = 0; i < num; i++) {
#ifdef __x86_64__
        uint64_t *pteaddr = VA_TO_LINEAR_PTE((uintptr_t)va + (i << PAGE_SHIFT));
        *pteaddr = 0;
#else
        volatile uint32_t *pteaddr =
            VA_TO_LINEAR_PTE((uintptr_t)va + (i << PAGE_SHIFT));
        pteaddr[0] = 0;
        _WriteBarrier();
        pteaddr[1] = 0;
#endif
    }

    uxen_mem_tlb_flush();

  out:
    if (mdl)
        ExFreePoolWithTag(mdl, UXEN_POOL_TAG);
    if (failed && va) {
        MmFreeMappingAddress(va, UXEN_MAPPING_TAG);
        va = NULL;
    }
    return va;
}

int
kernel_free_va(void *va, uint32_t num)
{
    uint32_t i;

    /* Clear va space, since otherwise MmFreeMappingAddress below can
     * blue screen because the va space is "dirty" */
    for (i = 0; i < num; i++) {
#ifdef __x86_64__
        uint64_t *pteaddr = VA_TO_LINEAR_PTE((uintptr_t)va + (i << PAGE_SHIFT));
        *pteaddr = 0;
#else
        volatile uint32_t *pteaddr =
            VA_TO_LINEAR_PTE((uintptr_t)va + (i << PAGE_SHIFT));
        pteaddr[0] = 0;
        _WriteBarrier();
        pteaddr[1] = 0;
#endif
    }

    MmFreeMappingAddress(va, UXEN_MAPPING_TAG);
    return 0;
}

int
_uxen_pages_increase_reserve(preemption_t *i, uint32_t pages,
                             uint32_t extra_pages, uint32_t *increase,
                             const char *fn)
{
    int cpu = cpu_number();
    uxen_pfn_t mfn_list[INCREASE_RESERVE_BATCH];
    int s = uxen_info->ui_sizeof_struct_page_info;
    struct page_list_entry *p;
    int n, needed, ret;

    *increase = 0;
    if (pages < MIN_RESERVE)
        pages = MIN_RESERVE;
    if (pages >= MAX_RESERVE)
        return -1;

    if (fill_vframes())
        return -1;

    disable_preemption(i);

    if (pages <= uxen_info->ui_free_pages[cpu].count)
        return 0;

    pages += extra_pages ? extra_pages : EXTRA_RESERVE;
    pages_reserve[cpu] += pages;
    if (pages_reserve[cpu] >= MAX_PAGES_RESERVE_CPU) {
        pages_reserve[cpu] -= pages;
        enable_preemption(*i);
        return -1;
    }

    if (pages > uxen_info->ui_free_pages[cpu].count)
        mm_dprintk("%s: cpu%d %d -> %d from %s\n", __FUNCTION__, cpu,
                   uxen_info->ui_free_pages[cpu].count, pages, fn);

    while (1) {
        needed = pages - uxen_info->ui_free_pages[cpu].count;
        if (needed <= 0)
            break;
        enable_preemption(*i);
        if (needed > INCREASE_RESERVE_BATCH)
            needed = INCREASE_RESERVE_BATCH;
        ret = kernel_malloc_mfns(needed, &mfn_list[0], 0);
        disable_preemption(i);
        for (n = 0; n < ret; n++) {
            p = (struct page_list_entry *)(frametable + mfn_list[n] * s);
            p->next = uxen_info->ui_free_pages[cpu].list;
            p->prev = 0;
#ifdef DBG
            ASSERT(!p->count_info);
#endif  /* DBG */
            uxen_info->ui_free_pages[cpu].list = mfn_list[n];
        }
        uxen_info->ui_free_pages[cpu].count += ret;
        if (ret != needed &&
            (pages - uxen_info->ui_free_pages[cpu].count) > 0) {
            LARGE_INTEGER delay;
            NTSTATUS status;
            LONG pri;
            enable_preemption(*i);
            if (KeGetCurrentIrql() >= DISPATCH_LEVEL) {
                pages_reserve[cpu] -= pages;
                return -1;
            }
            mm_dprintk("kernel_malloc_mfns need to alloc %d pages\n",
                       pages - uxen_info->ui_free_pages[cpu].count);
            delay.QuadPart = -TIME_MS(50);
            pri = KeSetBasePriorityThread(KeGetCurrentThread(),
                                          LOW_VCPUTHREAD_PRI);
            status = KeDelayExecutionThread(KernelMode, FALSE, &delay);
            KeSetBasePriorityThread(KeGetCurrentThread(), pri);
            if (status != STATUS_SUCCESS) {
                pages_reserve[cpu] -= pages;
                return -1;
            }
            disable_preemption(i);
        }
    }
    *increase = pages;
    return 0;
}

static uint32_t
uxen_pages_retire_one_cpu(int cpu, uint32_t left)
{
    int s = uxen_info->ui_sizeof_struct_page_info;
    struct page_list_entry *p;
    uint32_t *plist, free_list, n;

    ASSERT(left < uxen_info->ui_free_pages[cpu].count);

#ifdef DBG
    plist = &uxen_info->ui_free_pages[cpu].list;
    for (n = 0; n < uxen_info->ui_free_pages[cpu].count; n++) {
        p = (struct page_list_entry *)(frametable + (*plist) * s);
        plist = &p->next;
        ASSERT(!p->prev);
        ASSERT(!p->count_info);
    }
    ASSERT(!p->next);
#endif  /* DBG */

    plist = &uxen_info->ui_free_pages[cpu].list;
    for (n = 0; n < left; n++) {
        p = (struct page_list_entry *)(frametable + (*plist) * s);
        plist = &p->next;
#ifdef DBG
        ASSERT(!p->count_info);
#endif  /* DBG */
    }

    free_list = *plist;
    *plist = 0;
    uxen_info->ui_free_pages[cpu].count = left;

    return free_list;
}

static int
uxen_pages_retire(preemption_t i, int cpu, uint32_t left)
{
    int s = uxen_info->ui_sizeof_struct_page_info;
    struct page_list_entry *p;
    uint32_t free_list, n;
    KIRQL old_irql;

    if (uxen_info->ui_free_pages[cpu].count <= left) {
        enable_preemption(i);
        return 0;
    }

    n = uxen_info->ui_free_pages[cpu].count - left;

    free_list = uxen_pages_retire_one_cpu(cpu, left);

    enable_preemption(i);

    KeAcquireSpinLock(&idle_free_lock, &old_irql);
    p = (struct page_list_entry *)(frametable + free_list * s);
    p->prev = idle_free_list;
    idle_free_list = free_list;
    mm_dprintk("adding %d pages to %d pages in idle free list\n", n,
               idle_free_count);
    idle_free_count += n;
    KeReleaseSpinLock(&idle_free_lock, old_irql);
    uxen_signal_idle_thread(0);
    return n;
}

int
idle_free_free_list(void)
{
    PFN_NUMBER *pfn_list;
    int s = uxen_info->ui_sizeof_struct_page_info;
    struct page_list_entry *p;
    uint32_t *plist;
    int more = 0;
    int n = 0;
    int ret;
    KIRQL old_irql;

    KeAcquireSpinLock(&idle_free_lock, &old_irql);
    if (!idle_free_count) {
        KeReleaseSpinLock(&idle_free_lock, old_irql);
        return 0;
    }

    memset(idle_free_mfns_mdl, 0, sizeof(MDL));
    idle_free_mfns_mdl->MdlFlags = MDL_PAGES_LOCKED;

    pfn_list = MmGetMdlPfnArray(idle_free_mfns_mdl);

    plist = &idle_free_list;
    while (*plist) {
        p = (struct page_list_entry *)(frametable + (*plist) * s);
        if (p->prev) {
            plist = &p->prev;
            more = 1;
            continue;
        }
        pfn_list[n] = (PFN_NUMBER)*plist;
#ifdef DEBUG_PAGE_ALLOC
        DASSERT(pinfotable[pfn_list[n]].allocated);
        pinfotable[pfn_list[n]].allocated = 0;
#endif  /* DEBUG_PAGE_ALLOC */
        n++;
        *plist = p->next;
        p->next = 0;
#ifdef DBG
        ASSERT(!p->count_info);
#endif  /* DBG */
        if (n >= INCREASE_RESERVE_BATCH) {
            more = 1;
            break;
        }
    }
    idle_free_count -= n;
    KeReleaseSpinLock(&idle_free_lock, old_irql);

    idle_free_mfns_mdl->Size = sizeof(MDL) + sizeof(PFN_NUMBER) * n;
    idle_free_mfns_mdl->ByteCount = n << PAGE_SHIFT;
    MmFreePagesFromMdl(idle_free_mfns_mdl);

    mm_dprintk("%s: freed %d pages, %d pages left\n", __FUNCTION__, n,
               idle_free_count);
    return more;
}

void
uxen_pages_decrease_reserve(preemption_t i, uint32_t decrease)
{

    pages_reserve[cpu_number()] -= decrease;
    uxen_pages_retire(i, cpu_number(), 768 + pages_reserve[cpu_number()]);
}

void
uxen_pages_clear(void)
{
    int cpu;
    preemption_t i;
    uint32_t freed = 0;

    for (cpu = 0; cpu < max_host_cpu; cpu++) {
        disable_preemption(&i);
        freed += uxen_pages_retire(i, cpu, 0);
    }

    dprintk("%s: freed %d pages\n", __FUNCTION__, freed);

    while (idle_free_list)
        idle_free_free_list();
}

static void
remove_host_mfns_mapping(uint64_t *gpfns, size_t len, PFN_NUMBER *pfn_array,
                         struct fd_assoc *fda)
{
    struct vm_info *vmi = fda->vmi;
    unsigned int i;

    if (gpfns == NULL)
        return;

    for (i = 0; i < (len >> PAGE_SHIFT); i++) {
        xen_add_to_physmap_t memop_arg;

        memop_arg.domid = vmi->vmi_shared.vmi_domid;
        memop_arg.size = 1;
        memop_arg.space = XENMAPSPACE_host_mfn;
        memop_arg.idx = ~0ULL;
        memop_arg.gpfn = gpfns[i];

        uxen_dom0_hypercall(&vmi->vmi_shared, &fda->user_mappings,
                            UXEN_UNRESTRICTED_ACCESS_HYPERCALL |
                            (fda->admin_access ? UXEN_ADMIN_HYPERCALL : 0) |
                            UXEN_VMI_OWNER, __HYPERVISOR_memory_op,
                            XENMEM_add_to_physmap, &memop_arg);

#ifdef DEBUG_PAGE_ALLOC
        DASSERT(pinfotable[pfn_array[i]].allocated);
        pinfotable[pfn_array[i]].allocated = 0;
#endif  /* DEBUG_PAGE_ALLOC */
    }
}

/*
 * Maximum length that an MDL can describe.
 *
 * win7: 4GB - PAGE_SIZE
 */
#define MAX_MDL_LEN ((4ULL << 30) - PAGE_SIZE)

int
map_host_pages(void *va, size_t len, uint64_t *gpfns,
               struct fd_assoc *fda)
{
    struct user_mapping_info *umi = &fda->user_mappings;
    struct vm_info *vmi = fda->vmi;
    struct user_mapping *um = NULL;
    user_mapping_va key;
    int ret = 0;
    KIRQL old_irql;
    PFN_NUMBER *pfn_array;
    size_t gpfn_num = len >> PAGE_SHIFT;
    unsigned int i;

    if (len > MAX_MDL_LEN) {
        fail_msg("len %lx too large", len);
        return EINVAL;
    }

    /* Only allow aligned va/len */
    if (((uintptr_t)va & ~PAGE_MASK) || (len & ~PAGE_MASK)) {
        fail_msg("va %p len %lx not aligned", va, len);
        return EINVAL;
    }

    /* Make sure the range hasn't been locked before */
    key.addr = va;
    key.size = len;

    KeAcquireSpinLock(&umi->lck, &old_irql);
    um = (struct user_mapping *)rb_tree_find_node(&umi->rbtree, &key);
    KeReleaseSpinLock(&umi->lck, old_irql);
    if (um) {
        fail_msg("va range already locked");
        return EINVAL;
    }

    um = (struct user_mapping *)kernel_malloc(sizeof(struct user_mapping));
    if (!um) {
        fail_msg("kernel_malloc(user_mapping) failed");
        return ENOMEM;
    }

    um->gpfns = (uint64_t *)kernel_malloc(gpfn_num * sizeof(gpfns[0]));
    if (!um->gpfns) {
        fail_msg("kernel_malloc(um->gpfns) failed");
        ret = ENOMEM;
        goto out;
    }

    ret = copyin(gpfns, um->gpfns, gpfn_num * sizeof(gpfns[0]));
    if (ret) {
        fail_msg("copyin failed: %d/0x%p/0x%p", gpfn_num, gpfns, um->gpfns);
        goto out;
    }

    um->mdl = IoAllocateMdl(va, len, FALSE, FALSE, NULL);
    if (!um->mdl) {
        fail_msg("IoAllocateMdl failed");
        ret = ENOMEM;
        goto out;
    }

    ASSERT(um->mdl->ByteCount == len);

    try {
        MmProbeAndLockPages(um->mdl, UserMode, IoWriteAccess);
    } except (HOSTDRV_EXCEPTION_EXECUTE_HANDLER(
                "MmProbeAndLockPages failed, va=%p/%x",
                MmGetMdlVirtualAddress(um->mdl), MmGetMdlByteCount(um->mdl))) {
        ret = EINVAL;
        goto out;
    }

    um->va.addr = va;
    um->va.size = len;
    um->fda = fda;
    um->type = USER_MAPPING_HOST_MFNS;

    pfn_array = MmGetMdlPfnArray(um->mdl);
    for (i = 0; i < gpfn_num; i++) {
        xen_add_to_physmap_t memop_arg;

        /* use _populate_frametable, in case host pages being added
         * aren't part of the memory regions returned by
         * MmGetPhysicalMemoryRanges */
        if (pfn_array[i] >= uxen_info->ui_max_page ||
            _populate_frametable(pfn_array[i], 0)) {
            fail_msg("invalid mfn %p or failed to populate physmap:"
                     " gpfn=%p, domid=%d",
                     pfn_array[i], um->gpfns[i], vmi->vmi_shared.vmi_domid);
            ret = ENOMEM;
            goto out;
        }
        memop_arg.domid = vmi->vmi_shared.vmi_domid;
        memop_arg.size = 1;
        memop_arg.space = XENMAPSPACE_host_mfn;
        memop_arg.idx = (xen_ulong_t)pfn_array[i];
        memop_arg.gpfn = um->gpfns[i];

        ret = (int)uxen_dom0_hypercall(&vmi->vmi_shared, &fda->user_mappings,
                                       UXEN_UNRESTRICTED_ACCESS_HYPERCALL |
                                       (fda->admin_access ?
                                        UXEN_ADMIN_HYPERCALL : 0) |
                                       UXEN_VMI_OWNER, __HYPERVISOR_memory_op,
                                       XENMEM_add_to_physmap, &memop_arg);
        if (ret) {
            fail_msg("failed to add mapping: mfn=%p, gpfn=%p, domid=vm%u",
                     pfn_array[i], um->gpfns[i], vmi->vmi_shared.vmi_domid);
            goto out;
        }

#ifdef DEBUG_PAGE_ALLOC
        DASSERT(!pinfotable[pfn_array[i]].allocated);
        pinfotable[pfn_array[i]].allocated = 1;
#endif  /* DEBUG_PAGE_ALLOC */
    }

    KeAcquireSpinLock(&umi->lck, &old_irql);
    rb_tree_insert_node(&umi->rbtree, um);
    KeReleaseSpinLock(&umi->lck, old_irql);

    ret = 0;
  out:
    if (ret && um) {
        if (um->gpfns) {
            remove_host_mfns_mapping(um->gpfns, i << PAGE_SHIFT, pfn_array,
                                     fda);
            kernel_free(um->gpfns, gpfn_num * sizeof(um->gpfns[0]));
        }
        if (um->mdl) {
            if (um->mdl->MdlFlags & MDL_PAGES_LOCKED)
                MmUnlockPages(um->mdl);
            IoFreeMdl(um->mdl);
        }
        kernel_free(um, sizeof (struct user_mapping));
    }

    return ret;
}

int
unmap_host_pages(void *va, size_t len, struct fd_assoc *fda)
{
    struct user_mapping_info *umi = &fda->user_mappings;
    user_mapping_va key;
    KIRQL old_irql;
    struct user_mapping *um;

    /* Only allow aligned va/len */
    if (((uintptr_t)va & ~PAGE_MASK) || (len & ~PAGE_MASK)) {
        fail_msg("va %p len %lx not aligned", va, len);
        return EINVAL;
    }

    key.addr = va;
    key.size = len;

    KeAcquireSpinLock(&umi->lck, &old_irql);
    um = (struct user_mapping *)rb_tree_find_node(&umi->rbtree, &key);
    if (um)
        rb_tree_remove_node(&umi->rbtree, um);
    KeReleaseSpinLock(&umi->lck, old_irql);
    if (!um) {
        fail_msg("va %p not locked", va);
        return EINVAL;
    }

    return user_free_user_mapping(um);
}

static void *
map_page_range(int n, uxen_pfn_t *mfn, int mode, struct fd_assoc *fda)
{
    struct user_mapping_info *umi = fda ? &fda->user_mappings : NULL;
    PFN_NUMBER *pfn;
    MDL *mdl;
    void *addr = NULL;
    struct user_mapping *um = NULL;
    uint32_t max_mfn;
    int i;

    max_mfn = uxen_info ? uxen_info->ui_max_page : -1;

    if (umi) {
        ASSERT(mode & MAP_PAGE_RANGE_USER_MODE);
        um = (struct user_mapping *)kernel_malloc(sizeof(struct user_mapping));
        if (!um) {
            fail_msg("kernel_malloc(user_mapping) failed");
            return NULL;
        }

        um->mdl = IoAllocateMdl(NULL, n << PAGE_SHIFT, FALSE, FALSE, NULL);
        if (!um->mdl) {
            fail_msg("IoAllocateMdl failed");
            goto out;
        }

        mdl = um->mdl;
        ASSERT(mdl->ByteCount == n << PAGE_SHIFT);
    } else {
        ASSERT(!(mode & MAP_PAGE_RANGE_USER_MODE));
        if (n > map_page_range_max_nr) {
            fail_msg("too many pages: %d > %d", n, map_page_range_max_nr);
            return NULL;
        }

        mdl = map_page_range_mdl;
        mdl->ByteCount = n << PAGE_SHIFT;
    }

    mdl->MdlFlags = MDL_PAGES_LOCKED;

    pfn = MmGetMdlPfnArray(mdl);
    for (i = 0; i < n; i++) {
	pfn[i] = mfn[i];
        if (pfn[i] >= max_mfn) {
            fail_msg("invalid mfn %lx at entry %d", pfn[i], i);
	    goto out;
	}
#ifdef __i386__
        if (pfn[i] >= os_max_pfn)
            mdl->MdlFlags |= MDL_IO_SPACE;
#endif /* __i386__ */
    }

    try {
        addr = MmMapLockedPagesSpecifyCache(
            mdl,
            (mode & MAP_PAGE_RANGE_USER_MODE) ? UserMode : KernelMode,
            MmCached, NULL, FALSE, LowPagePriority);
    } except (HOSTDRV_EXCEPTION_EXECUTE_HANDLER(
                "MmMapLockedPagesSpecifyCache")) {
	addr = NULL;
    }

    if (addr && umi) {
        KIRQL old_irql;

        um->va.addr = addr;
        um->va.size = n << PAGE_SHIFT;
        um->fda = fda;
        um->num = n;
        um->type = USER_MAPPING_MEMORY_MAP;

        KeAcquireSpinLock(&umi->lck, &old_irql);
        rb_tree_insert_node(&umi->rbtree, um);
        KeReleaseSpinLock(&umi->lck, old_irql);
    }

  out:
    if (!addr && um) {
        if (um->mdl)
            IoFreeMdl(um->mdl);
        kernel_free(um, sizeof(struct user_mapping));
    }
    return addr;
}

void *
kernel_mmap_pages(int n, uxen_pfn_t *mfn)
{
    void *addr;
    KIRQL old_irql;

    KeAcquireSpinLock(&map_page_range_lock, &old_irql);
    addr = map_page_range(n, mfn, MAP_PAGE_RANGE_KERNEL_MODE, NULL);
    KeReleaseSpinLock(&map_page_range_lock, old_irql);

    return addr;
}

void *
user_mmap_pages(int n, uxen_pfn_t *mfn, int mode, struct fd_assoc *fda)
{

    return map_page_range(n, mfn, MAP_PAGE_RANGE_USER_MODE | mode, fda);
}

static int
unmap_page_range(const void *addr, int n, uxen_pfn_t *mfn,
                 struct fd_assoc *fda)
{
    struct user_mapping_info *umi = fda ? &fda->user_mappings : NULL;
    PFN_NUMBER *pfn;
    PHYSICAL_ADDRESS pa;
    MDL *mdl;
    struct user_mapping *um = NULL;
    int i;
    int ret = 0;

    if (umi) {
        user_mapping_va va;
        KIRQL old_irql;

        va.addr = addr;
        va.size = 1;

        KeAcquireSpinLock(&umi->lck, &old_irql);
        um = (struct user_mapping *)rb_tree_find_node(&umi->rbtree, &va);
        if (um)
            rb_tree_remove_node(&umi->rbtree, um);
        KeReleaseSpinLock(&umi->lck, old_irql);

        if (!um) {
            fail_msg("va %p not mapped", addr);
            return EINVAL;
        }

        return user_free_user_mapping(um);
    }

    if (n > map_page_range_max_nr) {
        fail_msg("too many pages: %d > %d", n, map_page_range_max_nr);
        return EINVAL;
    }

    mdl = map_page_range_mdl;
    mdl->ByteCount = n << PAGE_SHIFT;
    mdl->MdlFlags = MDL_PAGES_LOCKED | MDL_MAPPED_TO_SYSTEM_VA;

    pfn = MmGetMdlPfnArray(mdl);
    for (i = 0; i < n; i++) {
#ifndef DBG
        /* Skip va->mfn lookup if this mdl was last used to map the pages */
        if (mdl->MappedSystemVa != addr) {
            pa = MmGetPhysicalAddress((uint8_t *)addr + (i << PAGE_SHIFT));
	    pfn[i] = (PFN_NUMBER)(pa.QuadPart >> PAGE_SHIFT);
        }
#else  /* DBG */
        /* In the DBG version, assert that nothing messed with the mdl */
	pa = MmGetPhysicalAddress((uint8_t *)addr + (i << PAGE_SHIFT));
        if (mdl->MappedSystemVa == addr)
	    ASSERT(pfn[i] == (PFN_NUMBER)(pa.QuadPart >> PAGE_SHIFT));
	else
	    pfn[i] = (PFN_NUMBER)(pa.QuadPart >> PAGE_SHIFT);
#endif  /* DBG */
	if (mfn)
	    mfn[i] = (uxen_pfn_t)pfn[i];
    }

    MmUnmapLockedPages((uint8_t *)addr, mdl);

    mdl->MappedSystemVa = 0;

    return ret;
}

int
kernel_munmap_pages(const void *addr, int n, uxen_pfn_t *mfn)
{
    int ret;
    KIRQL old_irql;

    KeAcquireSpinLock(&map_page_range_lock, &old_irql);
    ret = unmap_page_range(addr, n, mfn, NULL);
    KeReleaseSpinLock(&map_page_range_lock, old_irql);

    return ret;
}

static int
release_user_mapping_range(xen_pfn_t *mfns, uint32_t num,
                           struct fd_assoc *fda)
{
    struct vm_info *vmi = fda->vmi;
    union uxen_memop_arg umemopa;
    unsigned int i, n, done;
    int ret = 0, _ret;

    for (i = 0; i < num; i++)
        if (mfns[i] == vmi->vmi_undefined_mfn)
            mfns[i] = ~0ULL;

    done = 0;
    while (done < num) {
        n = num - done;
        if (n > XENMEM_TRANSLATE_MAX_BATCH)
            n = XENMEM_TRANSLATE_MAX_BATCH;

        umemopa.translate_gpfn_list_for_map.domid = vmi->vmi_shared.vmi_domid;
        umemopa.translate_gpfn_list_for_map.prot = 0;
        umemopa.translate_gpfn_list_for_map.gpfns_start = 0;
        umemopa.translate_gpfn_list_for_map.gpfns_end = n;
        umemopa.translate_gpfn_list_for_map.map_mode =
            XENMEM_TRANSLATE_MAP_RELEASE;
        set_xen_guest_handle(umemopa.translate_gpfn_list_for_map.mfn_list,
                             &mfns[done]);
        _ret = (int)uxen_dom0_hypercall(
            NULL, &fda->user_mappings,
            UXEN_UNRESTRICTED_ACCESS_HYPERCALL | UXEN_ADMIN_HYPERCALL,
            __HYPERVISOR_memory_op,
            (uintptr_t)XENMEM_translate_gpfn_list_for_map, (uintptr_t)&umemopa);
        if (_ret) {
            if (!ret)
                ret = _ret;
            fail_msg("XENMEM_translate_gpfn_list failed: %d", _ret);
            /* keep releasing as much as possible */
        }
        done += n;
    }

    return ret;
}

int
user_munmap_pages(const void *addr, int n, uxen_pfn_t *mfn,
                  struct fd_assoc *fda)
{
    return unmap_page_range(addr, n, mfn, fda);
}

void *
uxen_mem_user_va_with_page(uint32_t num, uint32_t mfn,
                           struct fd_assoc *fda)
{
    uxen_pfn_t *r;
    unsigned int i;
    void *va;

    r = (uxen_pfn_t *)kernel_malloc(num * sizeof (uxen_pfn_t));
    if (!r)
        return NULL;

    for (i = 0; i < num; i++)
        r[i] = mfn;

    va = map_page_range(num, r, MAP_PAGE_RANGE_USER_MODE, fda);

    kernel_free(r, num * sizeof (uxen_pfn_t));

    return va;
}

void
uxen_mem_user_va_remove(uint32_t num, void *va, struct fd_assoc *fda)
{

    user_munmap_pages(va, num, NULL, fda);
}

void *
user_malloc(size_t size, enum user_mapping_type type,
            struct fd_assoc *fda)
{
    struct user_mapping_info *umi = &fda->user_mappings;
    PHYSICAL_ADDRESS low_address;
    PHYSICAL_ADDRESS high_address;
    PHYSICAL_ADDRESS skip_bytes;
    void *addr = NULL;
    struct user_mapping *um;
    size_t nr_pages;
    uint32_t max_mfn;

    DEFENSIVE_CHECK(size_t, size, GB(2), NULL);

    nr_pages = (size + PAGE_SIZE - 1) >> PAGE_SHIFT;
    if (!nr_pages) {
        fail_msg("invalid size requested");
        return NULL;
    }

    max_mfn = uxen_info ? uxen_info->ui_max_page : -1;

    um = (struct user_mapping *)kernel_malloc(sizeof(struct user_mapping));
    if (!um) {
        fail_msg("kernel_malloc(user_mapping) failed");
        return NULL;
    }

    low_address.QuadPart = 0;
    high_address.QuadPart = -1;
    skip_bytes.QuadPart = 0;
    um->mdl = MmAllocatePagesForMdlEx(low_address, high_address, skip_bytes,
                                      nr_pages << PAGE_SHIFT, MmCached,
                                      MM_ALLOCATE_FULLY_REQUIRED);
    if (um->mdl == NULL || MmGetMdlByteCount(um->mdl) < size) {
        fail_msg("MmAllocatePagesForMdlEx failed: %d pages", nr_pages);
        goto out;
    }

    try {
        addr = MmMapLockedPagesSpecifyCache(um->mdl, UserMode, MmCached, NULL,
					    FALSE, LowPagePriority);
    } except (HOSTDRV_EXCEPTION_EXECUTE_HANDLER(
                "MmMapLockedPagesSpecifyCache")) {
	addr = NULL;
    }

    if (addr) {
        KIRQL old_irql;

        um->va.addr = addr;
        um->va.size = nr_pages << PAGE_SHIFT;
        um->fda = fda;
        um->num = nr_pages;
        um->type = type;

        KeAcquireSpinLock(&umi->lck, &old_irql);
        rb_tree_insert_node(&umi->rbtree, um);
        KeReleaseSpinLock(&umi->lck, old_irql);
    }

  out:
    if (!addr) {
        if (um->mdl)  {
            MmFreePagesFromMdl(um->mdl);
            ExFreePool(um->mdl);
        }
        kernel_free(um, sizeof(struct user_mapping));
    }

    return addr;
}

static int
user_free_user_mapping(struct user_mapping *um)
{
    PFN_NUMBER *pfn_array;
    int ret = 0;

    switch (um->type) {
    case USER_MAPPING_MEMORY_MAP:
        MmUnmapLockedPages((uint8_t *)um->va.addr, um->mdl);
        if (um->mfns != NULL) {
            release_user_mapping_range(um->mfns, um->num, um->fda);
            kernel_free(um->mfns, um->num * sizeof(xen_pfn_t));
        }
        IoFreeMdl(um->mdl);
        break;
    case USER_MAPPING_BUFFER:
    case USER_MAPPING_USER_MALLOC:
        MmUnmapLockedPages((uint8_t *)um->va.addr, um->mdl);
        MmFreePagesFromMdl(um->mdl);
        ExFreePool(um->mdl);
        break;
    case USER_MAPPING_HOST_MFNS:
        pfn_array = MmGetMdlPfnArray(um->mdl);
        remove_host_mfns_mapping(um->gpfns, um->va.size, pfn_array, um->fda);
        kernel_free(
            um->gpfns, (um->va.size >> PAGE_SHIFT) * sizeof(um->gpfns[0]));
        MmUnlockPages(um->mdl);
        IoFreeMdl(um->mdl);
        break;
    }

    kernel_free(um, sizeof(struct user_mapping));
    return ret;
}

void
user_free(void *addr, struct fd_assoc *fda)
{
    struct user_mapping_info *umi = &fda->user_mappings;
    struct user_mapping *um;
    user_mapping_va va;
    KIRQL old_irql;

    va.addr = addr;
    va.size = 1;

    KeAcquireSpinLock(&umi->lck, &old_irql);
    um = (struct user_mapping *)rb_tree_find_node(&umi->rbtree, &va);
    if (um)
        rb_tree_remove_node(&umi->rbtree, um);
    KeReleaseSpinLock(&umi->lck, old_irql);

    if (!um)
        return;

    user_free_user_mapping(um);
}

void
user_free_all_user_mappings(struct fd_assoc *fda)
{
    struct user_mapping_info *umi = &fda->user_mappings;
    struct user_mapping *um;
    KIRQL old_irql;

    KeAcquireSpinLock(&umi->lck, &old_irql);
    while ((um = (struct user_mapping *)RB_TREE_MIN(&umi->rbtree))) {
        rb_tree_remove_node(&umi->rbtree, um);
        KeReleaseSpinLock(&umi->lck, old_irql);
        mm_dprintk("%s: freeing user mapping %p type %s\n", __FUNCTION__,
                   um->va.addr,
                   um->type == USER_MAPPING_MEMORY_MAP ? "mmap" :
                   um->type == USER_MAPPING_HOST_MFNS ? "host" : "malloc");
        user_free_user_mapping(um);
        KeAcquireSpinLock(&umi->lck, &old_irql);
    }
    KeReleaseSpinLock(&umi->lck, old_irql);
}

static void *
user_mmap_xen_mfns(unsigned int num, xen_pfn_t *mfns,
                   struct fd_assoc *fda)
{
    struct user_mapping_info *umi = &fda->user_mappings;
    PFN_NUMBER *pfn;
    void *addr = NULL;
    struct user_mapping *um;
    uint32_t max_mfn;
    unsigned int i;

    max_mfn = uxen_info ? uxen_info->ui_max_page : -1;

    um = (struct user_mapping *)kernel_malloc(sizeof(struct user_mapping));
    if (!um) {
        fail_msg("kernel_malloc(user_mapping) failed");
        return NULL;
    }

    um->mdl = IoAllocateMdl(NULL, num << PAGE_SHIFT, FALSE, FALSE, NULL);
    if (!um->mdl) {
        fail_msg("IoAllocateMdl failed");
        goto out;
    }

    ASSERT(um->mdl->ByteCount == num << PAGE_SHIFT);
    um->mdl->MdlFlags = MDL_PAGES_LOCKED;

    pfn = MmGetMdlPfnArray(um->mdl);
    for (i = 0; i < num; i++) {
        if (mfns[i] >= max_mfn) {
            fail_msg("invalid mfn %lx at entry %d", mfns[i], i);
	    goto out;
	}
	pfn[i] = (PFN_NUMBER)mfns[i];

#ifdef __i386__
        if (mfns[i] >= os_max_pfn)
            um->mdl->MdlFlags |= MDL_IO_SPACE;
#endif /* __i386__ */
    }

    try {
        addr = MmMapLockedPagesSpecifyCache(um->mdl, UserMode, MmCached, NULL,
					    FALSE, LowPagePriority);
    } except (HOSTDRV_EXCEPTION_EXECUTE_HANDLER(
                "MmMapLockedPagesSpecifyCache")) {
	addr = NULL;
    }

    if (addr) {
        KIRQL old_irql;

        um->va.addr = addr;
        um->va.size = num << PAGE_SHIFT;
        um->fda = fda;
        um->num = num;
        um->mfns = mfns;
        um->type = USER_MAPPING_MEMORY_MAP;

        KeAcquireSpinLock(&umi->lck, &old_irql);
        rb_tree_insert_node(&umi->rbtree, um);
        KeReleaseSpinLock(&umi->lck, old_irql);
    }

  out:
    if (!addr) {
        if (um->mdl)
            IoFreeMdl(um->mdl);
        kernel_free(um, sizeof(struct user_mapping));
    }

    return addr;
}

int
uxen_mem_malloc(struct uxen_malloc_desc *umd, struct fd_assoc *fda)
{
    int ret = 0;
    size_t len;

    len = (size_t)umd->umd_npages << PAGE_SHIFT;
    if (umd->umd_npages != (len >> PAGE_SHIFT) || !len)
        return EINVAL;

    umd->umd_addr = (uint64_t)user_malloc(len, USER_MAPPING_USER_MALLOC, fda);
    if (!umd->umd_addr)
        ret = ENOMEM;

    return ret;
}

int
uxen_mem_free(struct uxen_free_desc *ufd, struct fd_assoc *fda)
{

    KeAcquireGuardedMutex(&fda->user_malloc_mutex);
    user_free((void *)(uintptr_t)ufd->ufd_addr, fda);
    KeReleaseGuardedMutex(&fda->user_malloc_mutex);

    return 0;
}

uint64_t __cdecl
uxen_mem_user_access_ok(void *_umi, void *addr, uint64_t size)
{
    struct user_mapping_info *umi = (struct user_mapping_info *)_umi;
    struct user_mapping *um;
    user_mapping_va va;

    if (!_umi || !umi->initialized) {
        fail_msg("invalid user_access_opaque");
        return 0;
    }

    va.addr = addr;
    va.size = 1;

    KeAcquireSpinLockAtDpcLevel(&umi->lck);
    um = (struct user_mapping *)rb_tree_find_node(&umi->rbtree, &va);
    KeReleaseSpinLockFromDpcLevel(&umi->lck);

    if (!um) {
        fail_msg("no um for addr %p", addr);
        return 0;
    }

    if (um->type != USER_MAPPING_USER_MALLOC) {
        fail_msg("non-user-malloc um for addr %p", addr);
        return 0;
    }

    va.size = (uintptr_t)size;
    if (USER_MAPPING_VA_START(va) < USER_MAPPING_VA_START(um->va) ||
        USER_MAPPING_VA_END(va) > USER_MAPPING_VA_END(um->va)) {
        fail_msg("addr %p/%x out of bounds of um %p-%p", addr, size,
                 USER_MAPPING_VA_START(um->va), USER_MAPPING_VA_END(um->va));
        return 0;
    }

    return 1;
}

int
uxen_mem_mmapbatch(struct uxen_mmapbatch_desc *ummapbd, struct fd_assoc *fda)
{
    struct vm_info *vmi = fda->vmi;
    void *addr;
    unsigned int i;
    union uxen_memop_arg umemopa;
    xen_pfn_t *mfns = NULL, *gpfns = NULL;
    unsigned int n, done;
    int ret = ENOENT;

    DEFENSIVE_CHECK(uint32_t, ummapbd->umd_num, GB(1) >> PAGE_SHIFT, EINVAL);

    InterlockedIncrement(&vmi->vmi_running_vcpus);
    if (vmi->vmi_shared.vmi_runnable == 0)
        goto out;

    if (ummapbd->umd_num > (MAX_MDL_LEN >> PAGE_SHIFT)) {
        fail_msg("umd_num too large: %d > MAX_MDL_MAP_PAGES",
                 ummapbd->umd_num);
        ret = EINVAL;
        goto out;
    }

    if ((void *)&ummapbd->umd_arr[0] >= MmHighestUserAddress ||
        (void *)&ummapbd->umd_arr[ummapbd->umd_num] > MmHighestUserAddress) {
        fail_msg("umd_arr invalid");
        ret = EFAULT;
        goto out;
    }

    if ((void *)&ummapbd->umd_err[0] >= MmHighestUserAddress ||
        (void *)&ummapbd->umd_err[ummapbd->umd_num] > MmHighestUserAddress) {
        fail_msg("umd_err invalid");
        ret = EFAULT;
	goto out;
    }

    done = 0;
    mfns = kernel_malloc(ummapbd->umd_num * sizeof(mfns[0]));
    if (mfns == NULL) {
        fail_msg("kernel_malloc(mfns) failed");
        ret = ENOMEM;
        goto out;
    }

    gpfns = kernel_malloc(XENMEM_TRANSLATE_MAX_BATCH * sizeof(gpfns[0]));
    if (gpfns == NULL) {
        fail_msg("kernel_malloc(gpfns) failed");
	ret = ENOMEM;
	goto out;
    }

    while (done < ummapbd->umd_num) {
	n = ummapbd->umd_num - done;
	if (n > XENMEM_TRANSLATE_MAX_BATCH)
	    n = XENMEM_TRANSLATE_MAX_BATCH;
        umemopa.translate_gpfn_list_for_map.domid = vmi->vmi_shared.vmi_domid;
	switch (ummapbd->umd_prot) {
	default:
	case UXEN_MMAPBATCH_PROT_READ:
	    umemopa.translate_gpfn_list_for_map.prot =
		XENMEM_TRANSLATE_PROT_READ;
	    break;
	case UXEN_MMAPBATCH_PROT_WRITE:
	    umemopa.translate_gpfn_list_for_map.prot =
		XENMEM_TRANSLATE_PROT_WRITE;
	    break;
	}
	umemopa.translate_gpfn_list_for_map.gpfns_start = 0;
	umemopa.translate_gpfn_list_for_map.gpfns_end = n;
	umemopa.translate_gpfn_list_for_map.map_mode =
	    XENMEM_TRANSLATE_MAP_NOT;
        ret = copyin(&ummapbd->umd_arr[done], gpfns, n * sizeof(gpfns[0]));
        if (ret) {
            fail_msg("copyin failed: %d/%d/%d", done, n, ummapbd->umd_num);
            goto out;
        }
        set_xen_guest_handle(umemopa.translate_gpfn_list_for_map.gpfn_list,
                             gpfns);
	set_xen_guest_handle(umemopa.translate_gpfn_list_for_map.mfn_list,
			     &mfns[done]);
        ret = (int)uxen_dom0_hypercall(
            &vmi->vmi_shared, &fda->user_mappings,
            UXEN_UNRESTRICTED_ACCESS_HYPERCALL |
            (fda->admin_access ? UXEN_ADMIN_HYPERCALL : 0) |
            (fda->vmi_owner ? UXEN_VMI_OWNER : 0), __HYPERVISOR_memory_op,
            (uintptr_t)XENMEM_translate_gpfn_list_for_map, (uintptr_t)&umemopa);
	if (ret) {
            fail_msg("XENMEM_translate_gpfn_list failed at %d/%d/%d: %d",
                     done, n, ummapbd->umd_num, ret);
	    goto out;
	}
	done += n;
    }

    try {
	for (i = 0; i < ummapbd->umd_num; i++) {
	    if (mfns[i] >= uxen_info->ui_max_page) {
		ummapbd->umd_err[i] = -ENOENT;
		mfns[i] = vmi->vmi_undefined_mfn;
	    } else
		ummapbd->umd_err[i] = 0;
	}
    } except (HOSTDRV_EXCEPTION_EXECUTE_HANDLER(
                "update umd_err entry %d failed", i)) {
	ret = EINVAL;
	goto out;
    }	

    addr = user_mmap_xen_mfns(ummapbd->umd_num, mfns, fda);
    if (!addr) {
        ret = EINVAL;
        goto out;
    }

    ummapbd->umd_addr = (uint64_t)(uintptr_t)addr;

    ret = 0;
  out:
    if (gpfns)
        kernel_free(gpfns, XENMEM_TRANSLATE_MAX_BATCH * sizeof(gpfns[0]));
    if (ret && mfns) {
        release_user_mapping_range(mfns, done, fda);
        kernel_free(mfns, ummapbd->umd_num * sizeof(mfns[0]));
    }
    if (InterlockedDecrement(&vmi->vmi_running_vcpus) == 0)
        KeSetEvent(&vmi->vmi_notexecuting, 0, FALSE);
    return ret;
}

int
uxen_mem_munmap(struct uxen_munmap_desc *umd, struct fd_assoc *fda)
{
    struct vm_info *vmi = fda->vmi;
    int ret = ENOENT;

    InterlockedIncrement(&vmi->vmi_running_vcpus);
    if (vmi->vmi_shared.vmi_runnable == 0)
        goto out;

    user_free((void *)(uintptr_t)umd->umd_addr, fda);

    ret = 0;
  out:
    if (InterlockedDecrement(&vmi->vmi_running_vcpus) == 0)
        KeSetEvent(&vmi->vmi_notexecuting, 0, FALSE);
    return ret;
}

void * __cdecl
uxen_mem_map_page(xen_pfn_t mfn)
{
    void *va;

    if (mfn > uxen_info->ui_max_page)
	return NULL;

#ifdef DEBUG_PAGE_ALLOC
    DASSERT(mfn >= 0x100000 || pinfotable[mfn].allocated);
#endif  /* DEBUG_PAGE_ALLOC */

    va = pagemap_map_page(mfn);
#ifdef DBG
    if (!va)
        dprintk("%s: pagemap_map_page failed for mfn %x\n",
                __FUNCTION__, mfn);
#endif  /* DBG */
    return va;
}

uint64_t __cdecl
uxen_mem_unmap_page_va(const void *va)
{

    return pagemap_unmap_page_va(va);
}

void * __cdecl
uxen_mem_map_page_range(struct vm_vcpu_info_shared *vcis, uint64_t n,
                        uxen_pfn_t *mfn)
{
    struct vm_vcpu_info *vci = (struct vm_vcpu_info *)vcis;
    struct vm_info *vmi = (struct vm_info *)((uintptr_t)vcis & PAGE_MASK);

#ifdef DEBUG_PAGE_ALLOC
    int i;

    for (i = 0; i < n; i++)
        DASSERT(pinfotable[mfn[i]].allocated);
#endif  /* DEBUG_PAGE_ALLOC */

#ifdef DEBUG_POC_MAP_PAGE_RANGE_RETRY
    if (n >= 2 && vci) {
        if (vci->vci_map_page_range_provided != n) {
            dprintk("%s: vm%u.%u failing request %Id pages\n", __FUNCTION__,
                    vmi->vmi_shared.vmi_domid, vcis->vci_vcpuid, n);
            vcis->vci_map_page_range_requested = n;
            return NULL;
        }
        dprintk("%s: vm%u.%u doing request %d pages\n", __FUNCTION__,
                vmi->vmi_shared.vmi_domid, vcis->vci_vcpuid, n);
        vci->vci_map_page_range_provided = 0;
    }
#endif  /* DEBUG_POC_MAP_PAGE_RANGE_RETRY */

    return kernel_mmap_pages((int)n, mfn);
}

uint64_t __cdecl
uxen_mem_unmap_page_range(struct vm_vcpu_info_shared *vcis, const void *va,
                          uint64_t n, uxen_pfn_t *mfn)
{
    uint64_t ret;

    ret = kernel_munmap_pages(va, (int)n, mfn);
#ifdef DEBUG_PAGE_ALLOC
    {
        int i;
        for (i = 0; !ret && i < n; i++)
            DASSERT(pinfotable[mfn[i]].allocated);
    }
#endif  /* DEBUG_PAGE_ALLOC */
    return ret;
}

uxen_pfn_t __cdecl
uxen_mem_mapped_va_pfn(const void *va)
{
    PHYSICAL_ADDRESS pa;
    uxen_pfn_t ret;

    pa = MmGetPhysicalAddress((uint8_t *)va);
    ret = (uxen_pfn_t)(pa.QuadPart >> PAGE_SHIFT);
#ifdef DEBUG_PAGE_ALLOC
    DASSERT(ret == -1 || ret >= 0x100000 || pinfotable[ret].allocated);
#endif  /* DEBUG_PAGE_ALLOC */
    return ret;
}

void
uxen_mem_tlb_flush(void)
{

    KeIpiGenericCall(uxen_mem_tlb_flush_fn_global, 0);
}

#ifdef __i386__
struct hidden_mem {
    uint64_t start;
    uint64_t end;
};

#define MAX_HIDDEN_MEM 0x200000000ULL /* 8GB */
#define HIDDEN_MEM_STRUCT_MAX 4096
static struct hidden_mem *hidden_memory = NULL;
/* with >= 6GB, populate sub-4GB frametable lazily */
// #define LAZY_FT_HIDDEN_MEM 0x180000000ULL /* 6GB */

#pragma pack(push)
#pragma pack(4)

struct ec {
    LONG len;
    ULONG type;
};

struct resource_entry {
    uint32_t flags;
    uint64_t base;
    uint32_t size;
};

struct resource_list {
    uint64_t pad0;
    uint64_t pad1;
    uint32_t pad2;
};

#pragma pack(pop)

static int
probe_page(uint64_t addr)
{
    PHYSICAL_ADDRESS pa;
    volatile uint32_t *p;
    int ret = 0;

    pa.QuadPart = addr;
    p = MmMapIoSpace(pa, 0x1000, MmNonCached);

    if (p) {
        p[0] = 0x5a5a5a5a;
        KeMemoryBarrier();
        if (p[0] == 0x5a5a5a5a)
            ret = 1;
        MmUnmapIoSpace((void *) p, 0x1000);
    }

    /* dprintk("map %016I64x: %s\n", addr, ret ? "ok" : "fail"); */
    return ret;
}

static void
probe_mem(struct hidden_mem *hm, uint64_t start, uint64_t end)
{

    if (probe_page(start)) {
        hm->start = start;
        hm->end = end;
    }
}

static uint32_t
pci_conf1_read_32(uint32_t bus,uint32_t slot, uint32_t fn, uint32_t off)
{
    WRITE_PORT_ULONG((PULONG)0xcf8, 0x80000000 | (bus << 16) | (slot << 11) |
                     (fn << 8) | (off & ~3));
    return READ_PORT_ULONG((PULONG)0xcfc);
}

static uint64_t
pci_conf1_read_64(uint32_t bus,uint32_t slot, uint32_t fn, uint32_t off)
{
    uint64_t ret;
	
    ret = pci_conf1_read_32(bus, slot, fn, off + 4);
    ret <<= 32;
    ret |= pci_conf1_read_32(bus, slot, fn, off);

    return ret;
}

static uint64_t 
get_tom2(void)
{
    uint64_t tom2;

    tom2 = __readmsr(0xc001001d);
    dprintk("get_tom2: __readmsr(0xc001001d) = %016I64x\n", tom2);
    return tom2;
}

static uint64_t
get_touud(void)
{
    uint64_t touud;

    /* Naughty */
    touud = pci_conf1_read_64(0, 0, 0, 0xa8) & 0x7ffff00000ULL;

    dprintk("%s: pci config 0:0.0 0x00 VID:PID %8x\n", __FUNCTION__,
            pci_conf1_read_32(0, 0, 0, 0x00));
    dprintk("%s: pci config 0:0.0 0xa8         %8x\n", __FUNCTION__,
            pci_conf1_read_32(0, 0, 0, 0xa8));
    dprintk("%s: pci config 0:0.0 0xac         %8x\n", __FUNCTION__,
            pci_conf1_read_32(0, 0, 0, 0xac));
    dprintk("%s: %016I64x\n", __FUNCTION__, touud);

    return touud;
}

static uint64_t
get_top_of_ram(void)
{
    uint64_t ret;

    if (pv_vmware()) {
        /* We can't do better here, as vmware emulates a 440BX AGPset */
        /* so it doesn't have a concept of ram > 4Gb. */
        dprintk("uxen mem: PV vmware\n");
        ret = MAX_HIDDEN_MEM;
    } else {
        switch (uxen_cpu_vendor()) {
        case UXEN_CPU_VENDOR_INTEL:
            ret = get_touud();
            break;
        case UXEN_CPU_VENDOR_AMD:
            ret = get_tom2();
            break;
        default:
            dprintk("uxen mem: CPU vendor unknown\n");
            ret = 0;
        }
    }

    /* Leave this as printk rather than dprintk until we're sure */
    /* that no more bugs are caused by this. */

    printk("uxen mem:     haruspicated top of ram as %016I64x\n", ret);
    return ret;
}

static uxen_pfn_t
get_hidden_mem(uxen_pfn_t max_pfn)
{
    NTSTATUS status;
    RTL_QUERY_REGISTRY_TABLE param_table[2];
    struct hidden_mem *hm;
    int nr;
    struct ec *ec = NULL;
    struct resource_list *rl;
    struct resource_entry *re, *re_end;
    uint64_t mem_start, mem_ok, mem_bad, mem_end;

    memset(param_table, 0, sizeof(param_table));

    hm = kernel_malloc(HIDDEN_MEM_STRUCT_MAX);
    if (!hm) {
        fail_msg("malloc");
        goto out;
    }

    ec = (struct ec *)hm;
    ec->len = HIDDEN_MEM_STRUCT_MAX - sizeof(struct ec);

    param_table[0].QueryRoutine = NULL;
    param_table[0].Flags = RTL_QUERY_REGISTRY_DIRECT |
        /* RTL_QUERY_REGISTRY_TYPECHECK | */ RTL_QUERY_REGISTRY_NOEXPAND |
        RTL_QUERY_REGISTRY_REQUIRED;
    param_table[0].Name = L".Raw";
    param_table[0].EntryContext = ec;
    param_table[0].DefaultType = REG_RESOURCE_LIST;
    /* (REG_RESOURCE_LIST << RTL_QUERY_REGISTRY_TYPECHECK_SHIFT) | REG_NONE; */
    param_table[0].DefaultData = NULL;
    param_table[0].DefaultLength = 0;

    status = RtlQueryRegistryValues(
        RTL_REGISTRY_ABSOLUTE,
        L"\\REGISTRY\\MACHINE\\HARDWARE\\RESOURCEMAP\\System Resources\\Loader Reserved",
        &param_table[0], NULL, NULL);
    if (status != STATUS_SUCCESS) {
        fail_msg("RtlQueryRegistryValues failed");
        goto out;
    }

    rl = (struct resource_list *)&ec[1];
    re = (struct resource_entry *)&rl[1];
    re_end = (struct resource_entry *)((uint8_t *)rl + ec->len);

    mem_start = 0;

    nr = 0;
    hm[nr].start = 0;

    while (&re[1] <= re_end && mem_start < MAX_HIDDEN_MEM) {
        /* dprintk("  base %016I64x size %08x\n", re->base, re->size); */
        if (mem_start >= 0x100000000ULL) {
            if (re->base > MAX_HIDDEN_MEM)
                re->base = MAX_HIDDEN_MEM;
            probe_mem(&hm[nr], mem_start, re->base);
            if (hm[nr].start) {
                printk("memory physical region %016I64x - %016I64x (hidden)\n",
                       hm[nr].start, hm[nr].end);
                if ((hm[nr].end >> PAGE_SHIFT) > max_pfn)
                    max_pfn = (uxen_pfn_t)(hm[nr].end >> PAGE_SHIFT);
                nr++;
                hm[nr].start = 0;
            }
        }
        mem_start = re->base + re->size;
        re++;
    }

    /* probe mem above 4GB or after last region */
    if (mem_start < 0x100000000ULL)
        mem_start = 0x100000000ULL;
    mem_end = min(get_top_of_ram(), MAX_HIDDEN_MEM);
    mem_ok = mem_start;
    mem_bad = mem_end;
    while (mem_ok + PAGE_SIZE < mem_end) {
        if (probe_page(mem_end - PAGE_SIZE))
            mem_ok = mem_end;
        else
            mem_bad = mem_end;
        mem_end = (mem_ok + (mem_bad - mem_ok) / 2) & ~(PAGE_SIZE - 1);
    }
    if (mem_start != mem_ok) {
        probe_mem(&hm[nr], mem_start, mem_ok);
        if (hm[nr].start) {
            printk("memory physical region %016I64x - %016I64x (hidden)\n",
                   hm[nr].start, hm[nr].end);
            if ((hm[nr].end >> PAGE_SHIFT) > max_pfn)
                max_pfn = (uxen_pfn_t)(hm[nr].end >> PAGE_SHIFT);
            nr++;
            hm[nr].start = 0;
        }
    }

#ifdef LAZY_FT_HIDDEN_MEM
    if (mem_end >= LAZY_FT_HIDDEN_MEM)
        frametable_check_populate = 1;
#endif  /* LAZY_FT_HIDDEN_MEM */

  out:
    if (hm && !hm->start) {
        kernel_free(hm, HIDDEN_MEM_STRUCT_MAX);
        hm = NULL;
    }
    hidden_memory = hm;
    return max_pfn;
}

#endif

uxen_pfn_t
get_max_pfn(int use_hidden)
{
    PPHYSICAL_MEMORY_RANGE pMemMap;
    uxen_pfn_t max_pfn = 0, pfn;

    pMemMap = MmGetPhysicalMemoryRanges();

    while (pMemMap[0].BaseAddress.QuadPart ||
	   pMemMap[0].NumberOfBytes.QuadPart) {
	printk("memory physical region %016I64x - %016I64x\n",
               pMemMap[0].BaseAddress.QuadPart,
               pMemMap[0].BaseAddress.QuadPart +
               pMemMap[0].NumberOfBytes.QuadPart);
	pfn = (uxen_pfn_t)((pMemMap[0].BaseAddress.QuadPart +
                            pMemMap[0].NumberOfBytes.QuadPart +
                            PAGE_SIZE - 1) >> PAGE_SHIFT);
	if (pfn > max_pfn)
	    max_pfn = pfn;
	pMemMap++;
    }

#ifdef __i386__
    if (use_hidden) {
        os_max_pfn = max_pfn;
        max_pfn = get_hidden_mem(max_pfn);
    }
#endif

    if (max_pfn < 0x100000)
        max_pfn = 0x100000;
    return max_pfn;
}

#ifdef __i386__
void
add_hidden_memory(void)
{
    uint64_t end;
    int i;

    if (!hidden_memory)
        return;

    for (i = 0; hidden_memory[i].start; i++) {
        /* set 3rd argument to 1 to use hidden memory pages for frametable */
        end = populate_frametable_range(hidden_memory[i].start >> PAGE_SHIFT,
                                        hidden_memory[i].end >> PAGE_SHIFT, 0);
        if (!end) {
            fail_msg("failed to populate frametable for heap memory"
                     " %016I64x - %016I64x",
                     hidden_memory[i].start, hidden_memory[i].end);
            continue;
        }
        dprintk("adding heap memory %016I64x - %016I64x\n",
                hidden_memory[i].start, end << PAGE_SHIFT);
        uxen_exec_dom0_start();
        uxen_call(, , NO_RESERVE, uxen_do_add_heap_memory,
                  hidden_memory[i].start, end << PAGE_SHIFT);
        uxen_exec_dom0_end();
    }

    kernel_free(hidden_memory, HIDDEN_MEM_STRUCT_MAX);
    hidden_memory = NULL;
}
#endif

uint64_t
get_highest_user_address(void)
{

    return (uint64_t)MmHighestUserAddress;
}

int
fill_vframes(void)
{
    int s = uxen_info->ui_sizeof_struct_page_info;
    uxen_pfn_t start = 0;
    struct page_list_entry *p;
    uint32_t batch = 0, *tail = NULL;
    uint32_t count, added = 0;

    if (!preemption_enabled())
        return uxen_info->ui_vframes.count < uxen_info->ui_vframes_fill +
               VFRAMES_PCPU_FILL ? -1 : 0;

    KeAcquireGuardedMutex(&populate_vframes_mutex);
    count = uxen_info->ui_vframes.count;
    while (count < uxen_info->ui_vframes_fill + VFRAMES_PCPU_FILL) {
        start = vframes_start;
        _populate_frametable(start, 0);
        /* start vframe frametable entry (vfe) is completely
         * populated, keep using vframes until the end of the next vfe
         * is not in the same page as the end of the start vfe -- this
         * handles specifically the cases where the start vfe crosses
         * pages, and the case where the next vfe crosses pages */
        while ((((s * start) + s - 1) >> PAGE_SHIFT) ==
               (((s * vframes_start) + s - 1) >> PAGE_SHIFT)) {
            if (vframes_start >= vframes_end) {
                uxen_info->ui_out_of_vframes = 1;
                KeReleaseGuardedMutex(&populate_vframes_mutex);
                return 0;
            }
            p = (struct page_list_entry *)(frametable + vframes_start * s);
            p->next = batch;
            if (!tail)
                tail = &p->next;
            p->prev = 0;
            batch = vframes_start;
            vframes_start++;
            count++;
            added++;
        }
    }
    if (!start) {
        KeReleaseGuardedMutex(&populate_vframes_mutex);
        return 0;
    }

    do {
        *tail = uxen_info->ui_vframes.list;
    } while (cmpxchg(&uxen_info->ui_vframes.list, *tail, batch) != *tail);

#ifndef __i386__
    atomic_add(added, &uxen_info->ui_vframes.count);
#else
    /* XXX no InterlockedAdd on 32b? */
    do {
        count = uxen_info->ui_vframes.count;
    } while (cmpxchg(&uxen_info->ui_vframes.count, count, count + added) !=
             count);
#endif

    KeReleaseGuardedMutex(&populate_vframes_mutex);
    return 0;
}

void 
dump_mem_init_info()
{
#ifdef _WIN64
    printk("linear pt va %p\n", (void *)linear_pt_va);
#endif
}
