/*
 *  uxen_mem.c
 *  uxen
 *
 * Copyright 2012-2016, Bromium, Inc.
 * Author: Gianluca Guida <glguida@gmail.com>
 * SPDX-License-Identifier: ISC
 * 
 */

#include "uxen.h"

#include <mach/vm_map.h>
#include <mach/mach_vm.h>
#include <kern/sched_prim.h>
#include <libkern/libkern.h>

#include <rbtree/rbtree.h>

#define UXEN_DEFINE_SYMBOLS_PROTO
#include <uxen/uxen_link.h>

lck_spin_t *idle_free_lock;
uint32_t idle_free_list = 0;
static uint32_t idle_free_count = 0;

#define INCREASE_RESERVE_BATCH 512

static uint32_t pages_reserve[MAX_CPUS];

lck_mtx_t *populate_frametable_lock;

#define L1_PAGETABLE_SHIFT      12
#define L2_PAGETABLE_SHIFT      21
#define L3_PAGETABLE_SHIFT      30
#define L4_PAGETABLE_SHIFT      39

#define PAGETABLE_ORDER         9
#define L1_PAGETABLE_ENTRIES    (1 << PAGETABLE_ORDER)
#define L2_PAGETABLE_ENTRIES    (1 << PAGETABLE_ORDER)
#define L3_PAGETABLE_ENTRIES    (1 << PAGETABLE_ORDER)
#define L4_PAGETABLE_ENTRIES    (1 << PAGETABLE_ORDER)

/* Given a virtual address, get an entry offset into a page table. */
#define l1_table_offset(a)         \
    (((a) >> L1_PAGETABLE_SHIFT) & (L1_PAGETABLE_ENTRIES - 1))
#define l2_table_offset(a)         \
    (((a) >> L2_PAGETABLE_SHIFT) & (L2_PAGETABLE_ENTRIES - 1))
#define l3_table_offset(a)         \
    (((a) >> L3_PAGETABLE_SHIFT) & (L3_PAGETABLE_ENTRIES - 1))
#define l4_table_offset(a)         \
    (((a) >> L4_PAGETABLE_SHIFT) & (L4_PAGETABLE_ENTRIES - 1))

static uint64_t
set_pte(uintptr_t va, uint64_t _new)
{
    volatile uint64_t w, *p, old;

    asm ("movq %%cr3, %0\n"
         : "=a" (w));
    w &= PAGE_MASK;

    p = (volatile uint64_t *)physmap_pfn_to_va(w >> PAGE_SHIFT);
    w = p[l4_table_offset(va)];
    assert(w & 1);               /* page present */
    p = (volatile uint64_t *)physmap_pfn_to_va(w >> PAGE_SHIFT);
    w = p[l3_table_offset(va)];
    assert(w & 1);               /* page present */
    p = (volatile uint64_t *)physmap_pfn_to_va(w >> PAGE_SHIFT);
    w = p[l2_table_offset(va)];
    assert(w & 1);               /* page present */
    p = (volatile uint64_t *)physmap_pfn_to_va(w >> PAGE_SHIFT);

    old = p[l1_table_offset(va)];
    if (_new != ~0ULL)
        p[l1_table_offset(va)] = _new;

    return old;
}

/* NX AVAIL0 ACCESSED USER RW PRESENT */
#define map_mfn_pte_flags 0x8000000000000227

uint64_t __cdecl
map_mfn(uintptr_t va, xen_pfn_t mfn)
{

    return set_pte(va, mfn == ~0ULL ? mfn :
                   (((uint64_t)mfn << PAGE_SHIFT) | map_mfn_pte_flags));
}

#ifdef DEBUG
static int
verify_mapping(void *_va, uint32_t *pfns, int len, const char *fn, int line)
{
    int idx;
    uint64_t va = (uint64_t)_va;
    extern uint64_t physmap_base;

    if (!physmap_base)
        return 0;

    // dprintk("%s: ranges %d\n", __FUNCTION__, len);
    for (idx = 0; idx < len; idx++) {
        uint64_t pte, addr;

        pte = set_pte(va, ~0ULL);
        addr = (pte & ~0x8000000000000fff);
        if (addr != (uint64_t)pfns[idx] << PAGE_SHIFT) {
            uint64_t cr3;
            dprintk("%s: fail at range %d/%d for mfn %x != %"PRIx64
                    "from %s:%d\n", __FUNCTION__, idx, len,
                    pfns[idx] << PAGE_SHIFT, addr, fn, line);
            if (addr) {
                asm ("movq %%cr3, %0\n"
                     : "=a" (cr3));
                dprintk("%s: cr3 %"PRIx64"\n", __FUNCTION__, cr3);
                debug_break();
                return 1;
            }
        }

        va += PAGE_SIZE;
    }

    return 0;
}

static int
verify_mapping_xen(void *_va, xen_pfn_t *pfns, int len, const char *fn, int line)
{
    int idx;
    uint64_t va = (uint64_t)_va;
    extern uint64_t physmap_base;

    if (!physmap_base)
        return 0;

    // dprintk("%s: ranges %d\n", __FUNCTION__, len);
    for (idx = 0; idx < len; idx++) {
        uint64_t pte, addr;

        pte = set_pte(va, ~0ULL);
        addr = (pte & ~0x8000000000000fff);
        if (addr != pfns[idx] << PAGE_SHIFT) {
            uint64_t cr3;
            dprintk("%s: fail at range %d/%d for mfn %"PRIx64" != %"PRIx64
                    " from %s:%d\n", __FUNCTION__, idx, len,
                    pfns[idx] << PAGE_SHIFT, addr, fn, line);
            if (addr) {
                asm ("movq %%cr3, %0\n"
                     : "=a" (cr3));
                dprintk("%s: cr3 %"PRIx64"\n", __FUNCTION__, cr3);
                debug_break();
                return 1;
            }
        }

        va += PAGE_SIZE;
    }

    return 0;
}
#endif  // DEBUG

static LIST_HEAD(, map_pfn_array_pool_entry) map_pfn_array_pool =
    LIST_HEAD_INITIALIZER(&map_pfn_array_pool);
static LIST_HEAD(, map_pfn_array_pool_entry) map_pfn_array_pool_used =
    LIST_HEAD_INITIALIZER(&map_pfn_array_pool_used);
static lck_spin_t *map_pfn_array_pool_lock = NULL;
static int map_pfn_array_pool_min = 2;
#define MAP_PFN_ARRAY_POOL_ENTRY_SIZE UXEN_MAP_PAGE_RANGE_MAX
static uint32_t map_pfn_array_pool_entries = 0;

static int
alloc_map_pfn_array_pool_entry(struct map_pfn_array_pool_entry *e,
                               uint32_t *pfn_array, int num)
{
    kern_return_t rc = 0;
    vm_address_t addr = 0;
    int i;

    rc = vm_allocate(xnu_kernel_map(), &addr,
                     num * PAGE_SIZE_64, VM_FLAGS_ANYWHERE);
    if (rc != KERN_SUCCESS)
        return ENOMEM;

    e->va = (void *)addr;
    e->num = num;

    for (i = 0; i < num; i++) {
      xnu_pmap_enter(kernel_pmap, addr, pfn_array[i],
                     VM_PROT_READ|VM_PROT_WRITE, VM_PROT_NONE,
                     0, 1 /*wired*/);
      addr += PAGE_SIZE;
    }

#ifdef DEBUG
    if (verify_mapping(e->va, pfn_array, num, __FUNCTION__, __LINE__)) {
        fail_msg("verify_mapping failed");
        rc = vm_deallocate(xnu_kernel_map(),
                           (mach_vm_address_t)e->va, num * PAGE_SIZE);
        if (rc != KERN_SUCCESS)
            fail_msg("vm_deallocate also failed");
        return ENOMEM;
    }
#endif
    return 0;
}

static void
free_map_pfn_array_pool_entry(struct map_pfn_array_pool_entry *e)
{
    int num;
    kern_return_t rc;

    num = e->num;

    rc = vm_deallocate(xnu_kernel_map(),
                       (vm_offset_t)e->va, e->num * PAGE_SIZE);
    if (rc != KERN_SUCCESS)
        fail_msg("vm_deallocate failed");
}

static uint32_t *map_pfn_array_pool_zero_range = NULL;
int
map_pfn_array_pool_fill(void)
{
    struct map_pfn_array_pool_entry *e = NULL;
    unsigned int i;
    int ret = 0;

    if (!map_pfn_array_pool_lock) {
        map_pfn_array_pool_lock = lck_spin_alloc_init(uxen_lck_grp,
                                                      LCK_ATTR_NULL);
        if (!map_pfn_array_pool_lock) {
            fail_msg("lck_spin_alloc_init failed");
            return ENOMEM;
        }

        map_pfn_array_pool_min = 2 * uxen_nr_cpus;

        map_pfn_array_pool_zero_range =
            (uint32_t *)kernel_malloc(MAP_PFN_ARRAY_POOL_ENTRY_SIZE *
                                      sizeof (uint32_t));
        if (!map_pfn_array_pool_zero_range) {
            fail_msg("kernel_malloc failed");
            lck_spin_free(map_pfn_array_pool_lock, uxen_lck_grp);
            map_pfn_array_pool_lock = NULL;
            return ENOMEM;
        }
    }

    if (map_pfn_array_pool_entries >= map_pfn_array_pool_min)
        return 0;

    assert(uxen_zero_mfn != ~0);
    for (i = 0; i < MAP_PFN_ARRAY_POOL_ENTRY_SIZE; i++)
        map_pfn_array_pool_zero_range[i] = uxen_zero_mfn;

    while (map_pfn_array_pool_entries < map_pfn_array_pool_min) {
        e = (struct map_pfn_array_pool_entry *)
            kernel_malloc(sizeof(struct map_pfn_array_pool_entry));
        if (!e) {
            fail_msg("kernel_malloc failed");
            ret = ENOMEM;
            goto out;
        }

        ret = alloc_map_pfn_array_pool_entry(e, map_pfn_array_pool_zero_range,
                                             MAP_PFN_ARRAY_POOL_ENTRY_SIZE);
        if (ret) {
            fail_msg("alloc_map_pfn_array_pool_entry failed: %d", ret);
            goto out;
        }

        lck_spin_lock(map_pfn_array_pool_lock);
        LIST_INSERT_HEAD(&map_pfn_array_pool, e, list_entry);
        map_pfn_array_pool_entries++;
        lck_spin_unlock(map_pfn_array_pool_lock);
    }

  out:
    dprintk("%s: have %d/%d pool entries\n", __FUNCTION__,
            map_pfn_array_pool_entries, map_pfn_array_pool_min);
    return ret;
}

void
map_pfn_array_pool_clear(void)
{
    struct map_pfn_array_pool_entry *e = NULL;

    if (!map_pfn_array_pool_lock)
        return;

    dprintk("%s: freeing %d pool entries\n", __FUNCTION__,
            map_pfn_array_pool_entries);

    lck_spin_lock(map_pfn_array_pool_lock);
    assert(!LIST_EMPTY(&map_pfn_array_pool));
    while (!LIST_EMPTY(&map_pfn_array_pool)) {
        e = LIST_FIRST(&map_pfn_array_pool);
        assert(e);
        LIST_REMOVE(e, list_entry);
        lck_spin_unlock(map_pfn_array_pool_lock);

        free_map_pfn_array_pool_entry(e);
        kernel_free(e, sizeof(struct map_pfn_array_pool_entry));

        assert(map_pfn_array_pool_entries > 0);
        map_pfn_array_pool_entries--;

        lck_spin_lock(map_pfn_array_pool_lock);
    }
    lck_spin_unlock(map_pfn_array_pool_lock);

    lck_spin_free(map_pfn_array_pool_lock, uxen_lck_grp);
    map_pfn_array_pool_lock = NULL;

    kernel_free(map_pfn_array_pool_zero_range,
                MAP_PFN_ARRAY_POOL_ENTRY_SIZE * sizeof (uint32_t));
    map_pfn_array_pool_zero_range = NULL;

}

void *
map_pfn_array_from_pool(uint32_t *pfn_array, uint32_t n)
{
    struct map_pfn_array_pool_entry *e;
    unsigned int i;

    assert(map_pfn_array_pool_lock);

    lck_spin_lock(map_pfn_array_pool_lock);
    assert(map_pfn_array_pool_entries > 0);
    assert(!LIST_EMPTY(&map_pfn_array_pool));
    e = LIST_FIRST(&map_pfn_array_pool);
    assert(e);
    LIST_REMOVE(e, list_entry);
    map_pfn_array_pool_entries--;
    LIST_INSERT_HEAD(&map_pfn_array_pool_used, e, list_entry);
    lck_spin_unlock(map_pfn_array_pool_lock);

    for (i = 0; i < n; i++) {
        set_pte((uintptr_t)e->va + (i << PAGE_SHIFT),
                ((uint64_t)pfn_array[i] << PAGE_SHIFT) |
                0x8000000000000223); /* NX AVAIL0 ACCESSED RW PRESENT */
    }
    uxen_mem_tlb_flush();
    e->n_mapped = n;

    return e->va;
}

void
unmap_pfn_array_from_pool(const void *va, uxen_pfn_t *mfns)
{
    struct map_pfn_array_pool_entry *e = NULL;
    unsigned int i;

    assert(map_pfn_array_pool_lock);

    lck_spin_lock(map_pfn_array_pool_lock);
    LIST_FOREACH(e, &map_pfn_array_pool_used, list_entry)
        if (e ->va == va) {
            /* Exiting right after. No need for FOREACH_SAFE */
            LIST_REMOVE(e, list_entry);
            break;
        }
    assert(e);
    lck_spin_unlock(map_pfn_array_pool_lock);

    for (i = 0; i < e->n_mapped; i++) {
        uint64_t opte;
        opte = set_pte((uintptr_t)e->va + (i << PAGE_SHIFT),
                       ((uint64_t)uxen_zero_mfn << PAGE_SHIFT) |
                       0x8000000000000203); /* NX AVAIL0 RW PRESENT */
        mfns[i] = (opte & ~0x8000000000000fff) >> PAGE_SHIFT;
    }
    uxen_mem_tlb_flush();

    lck_spin_lock(map_pfn_array_pool_lock);
    LIST_INSERT_HEAD(&map_pfn_array_pool, e, list_entry);
    map_pfn_array_pool_entries++;
    lck_spin_unlock(map_pfn_array_pool_lock);
}

static void *
map_phys_range(uint32_t *pfn_array, int len,
               struct map_pfn_array_pool_entry *e)
{
    int ret;

    ret = alloc_map_pfn_array_pool_entry(e, pfn_array, len);
    if (ret) {
        fail_msg("alloc_map_pfn_array_pool_entry failed: %d", ret);
        return NULL;
    }

    return e->va;
}

void *
map_pfn_array(uint32_t *pfn_array, uint32_t num_pages,
              struct map_pfn_array_pool_entry *e)
{
    void *ret;

    ret = map_phys_range(pfn_array, num_pages, e);

    return ret;
}

void *
map_pfn(uint32_t pfn, struct map_pfn_array_pool_entry *e)
{
    return map_phys_range(&pfn, 1, e);
}

void
unmap(struct map_pfn_array_pool_entry *e)
{

    free_map_pfn_array_pool_entry(e);
}

typedef struct {
    const void *addr;
    uintptr_t size;
} user_mapping_va;

#define USER_MAPPING_VA_START(va) ((va).addr)
#define USER_MAPPING_VA_END(va) ((void *)((uintptr_t)((va).addr) + (va).size))

struct user_mapping {
    user_mapping_va va;
    struct {
        vm_map_t vm_map;
        xen_pfn_t *mfns;
        xen_pfn_t gmfn;
    };
    struct fd_assoc *fda;
    enum user_mapping_type type;
    int mapping_mode;
    struct rb_node rbnode;
};

static int user_free_user_mapping(struct user_mapping *um);

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
    .rbto_compare_nodes = user_mapping_compare_nodes,
    .rbto_compare_key = user_mapping_compare_key,
    .rbto_node_offset = offsetof(struct user_mapping, rbnode),
    .rbto_context = NULL
};

#define USER_MMAP_RANGE_MODE_DEFAULT   0x00
#define USER_MMAP_RANGE_MODE_WIRED     0x01
#define USER_MMAP_RANGE_MODE_XEN_PAGES 0x02
#define USER_MMAP_RANGE_ASREF          0x04

static void *
user_mmap_range(uxen_pfn_t *mfns, uint32_t num, int mapping_mode,
                struct fd_assoc *fda)
{
    struct user_mapping_info *umi = &fda->user_mappings;
    struct user_mapping *um = NULL;
    kern_return_t rc = 0;
    vm_map_t task_map;
    pmap_t task_pmap;
    vm_address_t addr = 0, tmp;
    void *va = NULL;
    int i;

    task_map = xnu_get_task_map_reference(fda->task);
    if (task_map == NULL) {
        fail_msg("get_task_map_reference(%p) failed", fda->task);
        goto out;
    }
    task_pmap = xnu_get_map_pmap(task_map);
    if (task_pmap == NULL) {
        fail_msg("get_map_pmap(%p) failed", task_pmap);
        goto out;
    }

    rc = vm_allocate(task_map, &addr,
                     num * PAGE_SIZE_64, VM_FLAGS_ANYWHERE);
    if (rc != KERN_SUCCESS)
        goto out;
    assert(addr != 0);

    tmp = addr;
    for (i = 0; i < num; i++) {
        xnu_pmap_enter(task_pmap, tmp, mfns[i],
                       VM_PROT_READ|VM_PROT_WRITE, VM_PROT_NONE,
                       0, 1 /*wired*/);
        tmp += PAGE_SIZE;
    }

#ifdef DEBUG
    if (verify_mapping((void *)addr, mfns, num, __FUNCTION__, __LINE__)) {
        fail_msg("verify_mapping failed");
        goto out;
    }
#endif

    um = (struct user_mapping *)kernel_malloc(sizeof(struct user_mapping));
    if (!um) {
        fail_msg("kernel_malloc(user_mapping) failed");
        goto out;
    }

    um->va.addr = (void *)addr;
    um->va.size = num * PAGE_SIZE;
    um->fda = fda;
    um->mfns = NULL; /* Discriminator for xen pages */
    um->vm_map = task_map;
    um->type = USER_MAPPING_MEMORY_MAP;
    um->mapping_mode = mapping_mode;
    lck_spin_lock(umi->lck);
    rb_tree_insert_node(&umi->rbtree, um);
    lck_spin_unlock(umi->lck);

    va = (void *)addr;

  out:
    if (va == NULL) {
        if (um) {
            kernel_free(um, sizeof(struct user_mapping));
            um = NULL;
        }
        if (addr) {
            xnu_pmap_remove(task_pmap, addr, addr + num * PAGE_SIZE_64);
            rc = vm_deallocate(task_map, addr, num * PAGE_SIZE_64);
            if (rc != KERN_SUCCESS)
                fail_msg("vm_deallocate failed");
        }
        if (task_map) {
            xnu_vm_map_deallocate(task_map); /* ref */
            task_map = NULL;
        }
    }
    return va;
}

static void *
user_mmap_xen_mfns(uint32_t num, xen_pfn_t *mfns, struct fd_assoc *fda)
{
    struct user_mapping_info *umi = &fda->user_mappings;
    struct user_mapping *um = NULL;
    kern_return_t rc = 0;
    vm_map_t task_map;
    pmap_t task_pmap;
    vm_address_t addr = 0, tmp;
    void *va = NULL;
    int i;

    task_map = xnu_get_task_map_reference(fda->task);
    if (task_map == NULL) {
        fail_msg("get_task_map_reference(%p) failed", fda->task);
        goto out;
    }
    task_pmap = xnu_get_map_pmap(task_map);
    if (task_pmap == NULL) {
        fail_msg("get_map_pmap(%p) failed", task_pmap);
        goto out;
    }

    rc = vm_allocate(task_map, &addr,
                     num * PAGE_SIZE_64, VM_FLAGS_ANYWHERE);
    if (rc != KERN_SUCCESS)
        goto out;
    assert(addr != 0);

    tmp = addr;
    for (i = 0; i < num; i++) {
        xnu_pmap_enter(task_pmap, tmp, mfns[i],
                       VM_PROT_READ|VM_PROT_WRITE, VM_PROT_NONE,
                       0, 1 /*wired*/);
        tmp += PAGE_SIZE;
    }

#ifdef DEBUG
    if (verify_mapping_xen((void *)addr, mfns, num, __FUNCTION__, __LINE__)) {
        fail_msg("verify_mapping failed");
        goto out;
    }
#endif

    um = (struct user_mapping *)kernel_malloc(sizeof(struct user_mapping));
    if (!um) {
        fail_msg("kernel_malloc(user_mapping) failed");
        goto out;
    }

    um->va.addr = (void *)addr;
    um->va.size = num * PAGE_SIZE;
    um->fda = fda;
    um->mfns = mfns;
    um->vm_map = task_map;
    um->type = USER_MAPPING_MEMORY_MAP;
    lck_spin_lock(umi->lck);
    rb_tree_insert_node(&umi->rbtree, um);
    lck_spin_unlock(umi->lck);

    va = (void *)um->va.addr;

  out:
    if (va == NULL) {
        if (um) {
            kernel_free(um, sizeof(struct user_mapping));
            um = NULL;
        }
        if (addr) {
            xnu_pmap_remove(task_pmap, addr, addr + num * PAGE_SIZE_64);
            rc = vm_deallocate(task_map, addr, num * PAGE_SIZE_64);
            if (rc != KERN_SUCCESS)
                fail_msg("vm_deallocate failed");
        }
        if (task_map) {
            xnu_vm_map_deallocate(task_map); /* ref */
            task_map = NULL;
        }
    }
    return va;
}

static int
release_user_mapping_range(xen_pfn_t *mfns, uint32_t num, struct fd_assoc *fda)
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

void *
user_mmap_pages(uint32_t num, uxen_pfn_t *pfn_array, struct fd_assoc *fda)
{

    return user_mmap_range(pfn_array, num, 0, fda);
}

int
user_munmap_pages(unsigned int num, const void *addr, struct fd_assoc *fda)
{
    struct user_mapping_info *umi = &fda->user_mappings;
    struct user_mapping *um;
    user_mapping_va va;

    va.addr = addr;
    va.size = 1;

    lck_spin_lock(umi->lck);
    um = (struct user_mapping *)rb_tree_find_node(&umi->rbtree, &va);
    if (um)
        rb_tree_remove_node(&umi->rbtree, um);
    lck_spin_unlock(umi->lck);

    if (!um)
        return EINVAL;

    return user_free_user_mapping(um);
}

#ifndef DEBUG_MALLOC
void *
kernel_malloc(uint32_t size)
{
    void *p;

    size = (size + sizeof(uintptr_t) - 1) & ~(sizeof(uintptr_t) - 1);
    if (size > (1 << 30)) {
        fail_msg("size assert: %x", size);
        return NULL;
    }

    if (preemption_enabled())
        p = OSMalloc(size, uxen_malloc_tag);
    else
        p = OSMalloc_noblock(size, uxen_malloc_tag);
    if (p)
        memset(p, 0, size);
    return p;
}

void
kernel_free(void *addr, uint32_t size)
{

    size = (size + sizeof(uintptr_t) - 1) & ~(sizeof(uintptr_t) - 1);
    OSFree(addr, size, uxen_malloc_tag);
}
#else
// #define MALLOC_VERBOSE 1
static lck_spin_t *malloc_info_lck = NULL;

typedef void *malloc_info_key;
struct malloc_info {
    char tag[4];
    void *v;
    uint32_t size;
    void *alloc_addr;
    struct rb_node rbnode;
};

static intptr_t
malloc_info_compare_key(void *ctx, const void *b, const void *key)
{
    const struct malloc_info * const pnp = (const struct malloc_info * const)b;
    const malloc_info_key * const fhp = (const malloc_info_key * const)key;

    if (pnp->v > *fhp)
        return 1;
    else if (pnp->v < *fhp)
        return -1;
    return 0;
}

static intptr_t
malloc_info_compare_nodes(void *ctx, const void *parent, const void *node)
{
    const struct malloc_info * const np =
        (const struct malloc_info * const)node;

    return malloc_info_compare_key(ctx, parent, &np->v);
}

static const rb_tree_ops_t malloc_info_rbtree_ops = {
    .rbto_compare_nodes = malloc_info_compare_nodes,
    .rbto_compare_key = malloc_info_compare_key,
    .rbto_node_offset = offsetof(struct malloc_info, rbnode),
    .rbto_context = NULL
};

static rb_tree_t malloc_info_rbtree;

void *
kernel_malloc(uint32_t size)
{
    void *v;
    struct malloc_info *m;

    size = (size + sizeof(uintptr_t) - 1) & ~(sizeof(uintptr_t) - 1);
    if (size > (1 << 30)) {
        fail_msg("size assert: %x", size);
        return NULL;
    }

    if (preemption_enabled())
        v = OSMalloc(size + sizeof(struct malloc_info), uxen_malloc_tag);
    else
        v = OSMalloc_noblock(size + sizeof(struct malloc_info),
                             uxen_malloc_tag);

    if (!v) {
        fail_msg("OSMalloc%s failed", preemption_enabled() ? "" : "_noblock");
        return NULL;
    }

#ifdef MALLOC_VERBOSE
    dprintk("%s: size %d => %p from %p\n", __FUNCTION__, size, v,
            __builtin_return_address(0));
#endif
    if (malloc_info_lck == NULL) {
        malloc_info_lck = lck_spin_alloc_init(uxen_lck_grp, LCK_ATTR_NULL);
        assert(malloc_info_lck);
        rb_tree_init(&malloc_info_rbtree, &malloc_info_rbtree_ops);
    }
    m = (struct malloc_info *)((uintptr_t)v + size);
    memcpy(m->tag, "5173", 4);
    m->v = v;
    m->size = size;
    m->alloc_addr = __builtin_return_address(0);
    lck_spin_lock(malloc_info_lck);
    rb_tree_insert_node(&malloc_info_rbtree, m);
    lck_spin_unlock(malloc_info_lck);

    memset(v, 0, size);

    return v;
}

void
kernel_free(void *addr, uint32_t size)
{
    struct malloc_info *m;

    size = (size + sizeof(uintptr_t) - 1) & ~(sizeof(uintptr_t) - 1);
#ifdef MALLOC_VERBOSE
    dprintk("%s: addr %p size %d\n", __FUNCTION__, addr, size);
#endif
    m = (struct malloc_info *)((uintptr_t)addr + size);
    if (strncmp(m->tag, "5173", 4))
        debug_break();
    if (m->v != addr || m->size != size)
        debug_break();
    lck_spin_lock(malloc_info_lck);
    if (m != rb_tree_find_node(&malloc_info_rbtree, &addr))
        debug_break();
    rb_tree_remove_node(&malloc_info_rbtree, m);
    lck_spin_unlock(malloc_info_lck);

    OSFree(addr, size + sizeof(struct malloc_info), uxen_malloc_tag);
}

void
debug_check_malloc(void)
{
    struct malloc_info *m;

    if (!malloc_info_lck)
        return;

    while ((m = (struct malloc_info *)RB_TREE_MIN(&malloc_info_rbtree))) {
        dprintk("%s: not freed %p size %d from %p\n", __FUNCTION__, m->v,
                m->size, m->alloc_addr);
        rb_tree_remove_node(&malloc_info_rbtree, m);
        OSFree(m->v, m->size + sizeof(struct malloc_info), uxen_malloc_tag);
    }

    lck_spin_free(malloc_info_lck, uxen_lck_grp);
    malloc_info_lck = NULL;
}
#endif

uxen_pfn_t
get_max_pfn(void)
{
    static uxen_pfn_t max_pfn = -1;
    uxen_pfn_t last, highest = 0;
    unsigned i, count = xnu_pmap_memory_region_count();

    if (!xnu_pmap_memory_regions() || !count) {
        return (uxen_pfn_t)-1;
    }

    if (max_pfn != -1)
        goto out;

    dprintk("Memory map:\n");
    dprintk("pmap_memory_region_count = %d\n", count);

    for (i = 0; i < count; i++) {

        dprintk("%16llx - %16llx Type:%02x Attr:%16llx\n",
               (uint64_t)pmap_memory_regions_get(i, base) << PAGE_SHIFT,
               (uint64_t)pmap_memory_regions_get(i, end) << PAGE_SHIFT,
               pmap_memory_regions_get(i, type),
               pmap_memory_regions_get(i, attribute));

        last = pmap_memory_regions_get(i, end) + 1;
        if (last > highest)
            highest = last;
    }

    max_pfn = highest;
  out:
    return max_pfn;
}

static lck_spin_t *vm_page_lck = NULL;
static size_t page_lookup_size = 0;
static struct vm_page **page_lookup = NULL;

static void
release_page(uint32_t pfn)
{
    struct vm_page *page;

    if (pfn >= page_lookup_size) {
        fail_msg("page lookup: pfn %x > max pfn %zx\n",
                 pfn, page_lookup_size);
        return;
    }

    lck_spin_lock(vm_page_lck);
    page = page_lookup[pfn];
    page_lookup[pfn] = NULL;
    lck_spin_unlock(vm_page_lck);

    if (page == NULL) {
        fail_msg("page for pfn %x not found", pfn);
        return;
    }

    xnu_vm_page_release(page);
}

/* same as struct page_info/page_list_entry */
struct page_list_entry {
    uint32_t next, prev;
};

int
kernel_alloc_mfn(uxen_pfn_t *mfn, int zeroed)
{
    vm_page_t page;
    int ret = 1;

    page = xnu_vm_page_grab();
    if (page == NULL) {
        fail_msg("xnu_vm_page_grab failed");
        goto out;
    }

    *mfn = vm_page_get_phys(page);
    if (zeroed)
        memset(physmap_pfn_to_va(*mfn), 0, PAGE_SIZE);

    lck_spin_lock(vm_page_lck);
    page_lookup[*mfn] = page;
    lck_spin_unlock(vm_page_lck);

    ret = 0;
  out:
    return ret;
}

int
_populate_frametable(uxen_pfn_t mfn)
{
    unsigned int offset;
    uintptr_t frametable_va;
    uxen_pfn_t frametable_mfn;
    int s = uxen_info->ui_sizeof_struct_page_info;

    offset = (s * mfn) >> PAGE_SHIFT;

    lck_mtx_lock(populate_frametable_lock);
    while (!(frametable_populated[offset / 8] & (1 << (offset % 8)))) {
        lck_mtx_unlock(populate_frametable_lock);
        if (kernel_alloc_mfn(&frametable_mfn, 0))
            return 1;
        lck_mtx_lock(populate_frametable_lock);
        if (frametable_populated[offset / 8] & (1 << (offset % 8)))
            break;
        frametable_va = (uintptr_t)frametable + (offset << PAGE_SHIFT);
        xnu_pmap_enter(kernel_pmap, frametable_va, frametable_mfn,
                       VM_PROT_READ|VM_PROT_WRITE, VM_PROT_NONE,
                       0, 1 /*wired*/);
        memset((void *)frametable_va, 0, PAGE_SIZE);
        frametable_populated[offset / 8] |= (1 << (offset % 8));
        break;
    }
    lck_mtx_unlock(populate_frametable_lock);

    /* Check if last byte of mfn's page_info is in same frametable
     * page, otherwise populate next mfn as well */
    if (((s * (mfn + 1) - 1) >> PAGE_SHIFT) != offset)
        return _populate_frametable(mfn + 1);
    return 0;
}

int frametable_check_populate = 0;

static uxen_pfn_t
populate_frametable_range(uxen_pfn_t start, uxen_pfn_t end)
{
    int s = uxen_info->ui_sizeof_struct_page_info;
    uxen_pfn_t mfn;

    for (mfn = start; mfn < end;) {
        if (_populate_frametable(mfn)) {
            fail_msg("failed to populate frametable for mfn %x", mfn);
            return 0;
        }
        mfn = (((((s * mfn) >> PAGE_SHIFT) + 1) << PAGE_SHIFT) + s - 1) / s;
    }

    return end;
}

int
populate_frametable_physical_memory(void)
{
    unsigned int count, i;
    uxen_pfn_t start, end;

    count = xnu_pmap_memory_region_count();
    if (!xnu_pmap_memory_regions() || !count) {
        frametable_check_populate = 1;
        goto out;
    }

    for (i = 0; i < count; i++) {
        start = pmap_memory_regions_get(i, base);
        end = pmap_memory_regions_get(i, end);

        if (!populate_frametable_range(start, end))
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
        if (!frametable_populated[offset / 8] & (1 << (offset % 8)))
            continue;
        frametable_va = (uintptr_t)frametable + (offset << PAGE_SHIFT);
        mfn = pmap_find_phys(kernel_pmap, frametable_va);
        if (mfn) {
            xnu_pmap_remove(kernel_pmap, frametable_va,
                            frametable_va + PAGE_SIZE);
            release_page(mfn);
            freed_pages++;
        }
    }

    dprintk("%s: freed %d frametable pages\n", __FUNCTION__, freed_pages);
}

int
kernel_malloc_mfns(uint32_t nr_pages, uint32_t *mfn_list, int zeroed)
{
    vm_page_t page;
    uint32_t i = 0;

    assert(vm_page_lck);

    while (idle_free_count > 0 && i < nr_pages) {
        int s = uxen_info->ui_sizeof_struct_page_info;
        struct page_list_entry *p;
        uint32_t *plist;

        lck_spin_lock(idle_free_lock);
        plist = &idle_free_list;
        while (*plist) {
            p = (struct page_list_entry *)(frametable + (*plist) * s);
            if (p->prev) {
                plist = &p->prev;
                continue;
            }
            if (zeroed)
                memset(physmap_pfn_to_va(*plist), 0, PAGE_SIZE);
            mfn_list[i] = *plist;
            i++;
            idle_free_count--;
            *plist = p->next;
            p->next = 0;
            if (i >= nr_pages)
                break;
        }
        lck_spin_unlock(idle_free_lock);
    }

    while (i < nr_pages) {
        page = xnu_vm_page_grab();
        if (page == NULL) {
            fail_msg("xnu_vm_page_grab failed");
            goto out;
        }

        mfn_list[i] = vm_page_get_phys(page);
        if (zeroed)
            memset(physmap_pfn_to_va(mfn_list[i]), 0, PAGE_SIZE);

        if (mfn_list[i] >= page_lookup_size || mfn_list[i] == 0) {
            fail_msg("invalid mfn %x\n", mfn_list[i]);
            continue;
        }
        if (populate_frametable(mfn_list[i])) {
            fail_msg("failed to populate frametable for mfn %x", mfn_list[i]);
            continue;
        }
        lck_spin_lock(vm_page_lck);
        page_lookup[mfn_list[i]] = page;
        lck_spin_unlock(vm_page_lck);
        i++;
    }

  out:
    return i;
}

void
kernel_free_mfn(uint32_t mfn)
{

    release_page(mfn);
}

void *
kernel_alloc_va(uint32_t num)
{
    kern_return_t rc = 0;
    vm_address_t addr = 0;

    rc = vm_allocate(xnu_kernel_map(), &addr, num << PAGE_SHIFT,
                     VM_FLAGS_ANYWHERE);
    if (rc != KERN_SUCCESS) {
        fail_msg("vm_allocate failed: %d pages", num);
        return NULL;
    }

    return (void *)addr;
}

int
kernel_free_va(void *va, uint32_t num)
{
    kern_return_t rc;

    rc = vm_deallocate(xnu_kernel_map(), (vm_offset_t)va, num << PAGE_SHIFT);
    if (rc != KERN_SUCCESS)
        fail_msg("vm_deallocate failed");
    return 0;
}

int
_uxen_pages_increase_reserve(preemption_t *i, uint32_t pages,
                             uint32_t extra_pages, uint32_t *increase,
                             const char *fn)
{
    int cpu = cpu_number();
    int needed, n;
    uxen_pfn_t mfn_list[INCREASE_RESERVE_BATCH];
    int s = uxen_info->ui_sizeof_struct_page_info;
    struct page_list_entry *p;
    int ret;

    if (pages < MIN_RESERVE)
        pages = MIN_RESERVE;

    disable_preemption(i);
    *increase = 0;
    if (pages <= uxen_info->ui_free_pages[cpu].free_count)
        return 0;

    pages += extra_pages ? extra_pages : EXTRA_RESERVE;
    pages_reserve[cpu] += pages;

    if (pages > uxen_info->ui_free_pages[cpu].free_count)
        mm_dprintk("%s: cpu%d %d -> %d from %s\n", __FUNCTION__, cpu,
                   uxen_info->ui_free_pages[cpu].free_count, pages, fn);

    while (1) {
        needed = pages - uxen_info->ui_free_pages[cpu].free_count;
        if (needed <= 0)
            break;
        enable_preemption(*i);
        if (needed > INCREASE_RESERVE_BATCH)
            needed = INCREASE_RESERVE_BATCH;
        ret = kernel_malloc_mfns(needed, &mfn_list[0], 0);
        disable_preemption(i);
        for (n = 0; n < ret; n++) {
            p = (struct page_list_entry *)(frametable + mfn_list[n] * s);
            p->next = uxen_info->ui_free_pages[cpu].free_list;
            p->prev = 0;
            uxen_info->ui_free_pages[cpu].free_list = mfn_list[n];
        }
        uxen_info->ui_free_pages[cpu].free_count += ret;
        if (ret != needed &&
            (pages - uxen_info->ui_free_pages[cpu].free_count) > 0) {
            enable_preemption(*i);
            mm_dprintk("kernel_malloc_mfns need to alloc %d pages\n",
                       pages - uxen_info->ui_free_pages[cpu].free_count);
            xnu_vm_page_wait(THREAD_ABORTSAFE);
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

    ASSERT(left < uxen_info->ui_free_pages[cpu].free_count);

#ifdef DBG
    plist = &uxen_info->ui_free_pages[cpu].free_list;
    for (n = 0; n < uxen_info->ui_free_pages[cpu].free_count; n++) {
        p = (struct page_list_entry *)(frametable + (*plist) * s);
        plist = &p->next;
        ASSERT(!p->prev);
    }
#endif

    plist = &uxen_info->ui_free_pages[cpu].free_list;
    for (n = 0; n < left; n++) {
        p = (struct page_list_entry *)(frametable + (*plist) * s);
        plist = &p->next;
    }

    free_list = *plist;
    *plist = 0;
    uxen_info->ui_free_pages[cpu].free_count = left;

    return free_list;
}

static int
uxen_pages_retire(preemption_t i, int cpu, uint32_t left)
{
    int s = uxen_info->ui_sizeof_struct_page_info;
    struct page_list_entry *p;
    uint32_t free_list, n;

    if (uxen_info->ui_free_pages[cpu].free_count <= left) {
        enable_preemption(i);
        return 0;
    }

    n = uxen_info->ui_free_pages[cpu].free_count - left;

    free_list = uxen_pages_retire_one_cpu(cpu, left);

    enable_preemption(i);

    lck_spin_lock(idle_free_lock);
    p = (struct page_list_entry *)(frametable + free_list * s);
    p->prev = idle_free_list;
    idle_free_list = free_list;
    mm_dprintk("adding %d pages to %d pages in idle free list\n", n,
               idle_free_count);
    idle_free_count += n;
    lck_spin_unlock(idle_free_lock);
    signal_idle_thread();
    return n;
}

int
idle_free_free_list(void)
{
    int s = uxen_info->ui_sizeof_struct_page_info;
    struct page_list_entry *p;
    struct vm_page *page = NULL;
    struct vm_page *tmp = NULL;
    uint32_t *plist;
    int more = 0;
    int n = 0;

    lck_spin_lock(idle_free_lock);
    plist = &idle_free_list;
    while (*plist) {
        p = (struct page_list_entry *)(frametable + (*plist) * s);
        if (p->prev) {
            plist = &p->prev;
            more = 1;
            continue;
        }
        lck_spin_lock(vm_page_lck);
        page = page_lookup[*plist];
        page_lookup[*plist] = NULL;
        lck_spin_unlock(vm_page_lck);
        if (!page)
            fail_msg("page %x not found", *plist);
        else {
            page->pageq.next = tmp ? &tmp->pageq : NULL;
            page->pageq.prev = NULL;
            tmp = page;
        }
        n++;
        *plist = p->next;
        p->next = 0;
        if (n >= INCREASE_RESERVE_BATCH) {
            more = 1;
            break;
        }
    }
    idle_free_count -= n;
    lck_spin_unlock(idle_free_lock);

    xnu_vm_page_free_list(page, 0);

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

    for (cpu = 0; cpu < MAX_CPUS; cpu++) {
        disable_preemption(&i);
        freed += uxen_pages_retire(i, cpu, 0);
    }

    dprintk("%s: freed %d pages\n", __FUNCTION__, freed);

    while (idle_free_list)
        idle_free_free_list();
}

static void
remove_host_mfns_mapping(uint64_t gmfn, size_t len, struct fd_assoc *fda)
{
    struct vm_info *vmi = fda->vmi;
    int i;

    if (gmfn == ~0ULL || len == 0)
        return;

    for (i = 0; i < (len >> PAGE_SHIFT); i++) {
        xen_add_to_physmap_t memop_arg = { };

        memop_arg.domid = vmi->vmi_shared.vmi_domid;
        memop_arg.size = 1;
        memop_arg.space = XENMAPSPACE_host_mfn;
        memop_arg.idx = ~0ULL;
        memop_arg.gpfn = gmfn + i;

        uxen_dom0_hypercall(&vmi->vmi_shared, &fda->user_mappings,
                            UXEN_UNRESTRICTED_ACCESS_HYPERCALL |
                            (fda->admin_access ? UXEN_ADMIN_HYPERCALL : 0) |
                            UXEN_VMI_OWNER, __HYPERVISOR_memory_op,
                            XENMEM_add_to_physmap, &memop_arg);
    }
}

static int
user_remove_host_mfns_user_mapping(struct user_mapping *um)
{
    vm_map_offset_t addr = (vm_map_offset_t)um->va.addr;
    kern_return_t rc;

    assert(um->type == USER_MAPPING_HOST_MFNS);

    remove_host_mfns_mapping(um->gmfn, um->va.size, um->fda);

    rc = xnu_vm_map_unwire(um->vm_map, addr, addr + um->va.size, 0);
    if (rc != KERN_SUCCESS) {
        fail_msg("vm_map_unwire failed");
        /* continue, the important thing
           is to remove the task map ref */
    }

    xnu_vm_map_deallocate(um->vm_map); /* put ref */
    return 0;
}

int
map_host_pages(void *va, size_t len, uint64_t gmfn,
               struct fd_assoc *fda)
{
    vm_map_offset_t addr = (vm_map_offset_t)va;
    struct user_mapping_info *umi = &fda->user_mappings;
    struct vm_info *vmi = fda->vmi;
    struct user_mapping *um = NULL;
    vm_map_t task_map = NULL;
    pmap_t task_pmap;
    int ret = EINVAL;
    int wired = 0;
    user_mapping_va key;
    kern_return_t rc;
    int i = 0;

    /* Only allow aligned va/len */
    if (((uintptr_t)va & ~PAGE_MASK) || (len & ~PAGE_MASK)) {
        fail_msg("va %p len %lx not aligned", va, len);
        return EINVAL;
    }

    /* Make sure the range hasn't been locked before */
    key.addr = va;
    key.size = len;

    lck_spin_lock(umi->lck);
    um = (struct user_mapping *)rb_tree_find_node(&umi->rbtree, &key);
    lck_spin_unlock(umi->lck);
    if (um) {
        fail_msg("va range already locked");
        return EINVAL;
    }

    task_map = xnu_get_task_map_reference(fda->task);
    if (task_map == NULL) {
        fail_msg("get_task_map_reference(%p) failed", fda->task);
        goto out;
    }

    task_pmap = xnu_get_map_pmap(task_map);
    if (task_pmap == NULL) {
        fail_msg("get_map_pmap failed");
        goto out;

    }

    rc = xnu_vm_map_wire(task_map, addr, addr + len, VM_PROT_DEFAULT, 0);
    if (rc != KERN_SUCCESS) {
        fail_msg("vm_map_wire failed");
        goto out;
    }
    wired = 1;

    for (i = 0; i < (len >> PAGE_SHIFT); i++) {
        ppnum_t pn;
        xen_add_to_physmap_t memop_arg = { };

        pn = pmap_find_phys(task_pmap, addr + (i << PAGE_SHIFT));
        if (pn == 0)
            goto out;

        /* use _populate_frametable, in case host pages being added
         * aren't part of the prepopulated memory regions */
        if (pn >= uxen_info->ui_max_page || _populate_frametable(pn)) {
            fail_msg("invalid mfn %x or failed to populate physmap:"
                     " gpfn=%"PRIx64", domid=%d",
                     pn, gmfn + i, vmi->vmi_shared.vmi_domid);
            ret = ENOMEM;
            goto out;
        }
        memop_arg.domid = vmi->vmi_shared.vmi_domid;
        memop_arg.size = 1;
        memop_arg.space = XENMAPSPACE_host_mfn;
        memop_arg.idx = (xen_ulong_t)pn;
        memop_arg.gpfn = gmfn + i;

        ret = (int)uxen_dom0_hypercall(&vmi->vmi_shared, &fda->user_mappings,
                                       UXEN_UNRESTRICTED_ACCESS_HYPERCALL |
                                       (fda->admin_access ?
                                        UXEN_ADMIN_HYPERCALL : 0) |
                                       UXEN_VMI_OWNER, __HYPERVISOR_memory_op,
                                       XENMEM_add_to_physmap, &memop_arg);
        if (ret)
            goto out;
    }

    um = (struct user_mapping *)kernel_malloc(sizeof(struct user_mapping));
    if (!um) {
        fail_msg("kernel_malloc(user_mapping) failed");
        goto out;
    }

    um->va.addr = va;
    um->va.size = len;
    um->vm_map = task_map;
    um->mfns = NULL;
    um->gmfn = gmfn;
    um->fda = fda;
    um->type = USER_MAPPING_HOST_MFNS;

    lck_spin_lock(umi->lck);
    rb_tree_insert_node(&umi->rbtree, um);
    lck_spin_unlock(umi->lck);

    ret = 0;
 out:

    if (ret) {
        if (um)
            kernel_free(um, sizeof(struct user_mapping));
        if (i != 0)
            remove_host_mfns_mapping(gmfn, i << PAGE_SHIFT, fda);
        if (wired)
            xnu_vm_map_unwire(task_map, addr, addr+len, 0);
        if (task_map)
            xnu_vm_map_deallocate(task_map); /* put ref */
    }

    return ret;
}

int
unmap_host_pages(void *va, size_t len, struct fd_assoc *fda)
{
    struct user_mapping_info *umi = &fda->user_mappings;
    user_mapping_va key;
    struct user_mapping *um;

    /* Only allow aligned va/len */
    if (((uintptr_t)va & ~PAGE_MASK) || (len & ~PAGE_MASK)) {
        fail_msg("va %p len %lx not aligned", va, len);
        return EINVAL;
    }

    key.addr = va;
    key.size = len;

    lck_spin_lock(umi->lck);
    um = (struct user_mapping *)rb_tree_find_node(&umi->rbtree, &key);
    if (um)
        rb_tree_remove_node(&umi->rbtree, um);
    lck_spin_unlock(umi->lck);
    if (!um) {
        fail_msg("va %p not locked", va);
        return EINVAL;
    }

    return user_free_user_mapping(um);
}

int
uxen_mem_init(void)
{
    uxen_pfn_t max_pfn = get_max_pfn();
    size_t size;

    if (max_pfn == -1) {
        fail_msg("get_max_pfn() error");
        return EINVAL;
    }
    size = get_max_pfn() * sizeof(struct vm_page *);
    vm_page_lck = lck_spin_alloc_init(uxen_lck_grp, LCK_ATTR_NULL);
    if (!vm_page_lck)
        return ENOMEM;

    page_lookup = (struct vm_page **)kernel_malloc(size);
    if (!page_lookup) {
        lck_spin_free(vm_page_lck, uxen_lck_grp);
        vm_page_lck = NULL;
        return ENOMEM;
    }

    memset(page_lookup, 0, size);
    page_lookup_size = size / sizeof(struct vm_page *);
    return 0;
}

void
uxen_mem_exit(void)
{
    size_t i;
    struct vm_page *page = NULL;
    struct vm_page *tmp = NULL;
#ifdef DEBUG
    int freed = 0;
#endif

    if (!vm_page_lck)
        return;

    for (i = 0; i < page_lookup_size; i++) {
        lck_spin_lock(vm_page_lck);
        page = page_lookup[i];
        page_lookup[i] = NULL;
        lck_spin_unlock(vm_page_lck);
        if (!page)
            continue;

        page->pageq.next = tmp ? &tmp->pageq : NULL;
        page->pageq.prev = NULL;
        tmp = page;
#ifdef DEBUG
        freed++;
#endif
    }

    xnu_vm_page_free_list(page, 0);

    lck_spin_free(vm_page_lck, uxen_lck_grp);
    vm_page_lck = NULL;

    kernel_free(page_lookup, page_lookup_size * sizeof(page_lookup[0]));

#ifdef DEBUG
    if (freed)
        dprintk("%s: freed %d leaked page%s\n", __FUNCTION__, freed,
                (freed != 1) ? "s" : "");
#endif
}

void *
uxen_mem_user_va_with_page(uint32_t num, uint32_t mfn,
                           struct fd_assoc *fda)
{
    uxen_pfn_t *r;
    unsigned int i;
    void *va;

    r = (uxen_pfn_t *)kernel_malloc(num * sizeof(uxen_pfn_t));
    if (!r)
        return NULL;

    for (i = 0; i < num; i++)
        r[i] = mfn;

    va = user_mmap_range(r, num, 0, fda);

    kernel_free(r, num * sizeof(uxen_pfn_t));
    return va;
}

void
uxen_mem_user_va_remove(uint32_t num, void *va, struct fd_assoc *fda)
{

    user_munmap_pages(num, va, fda);
}

void *
user_malloc(size_t size, enum user_mapping_type type, struct fd_assoc *fda)
{
    struct user_mapping_info *umi = &fda->user_mappings;
    struct user_mapping *um = NULL;
    vm_address_t addr = 0;
    vm_map_t task_map = NULL;
    kern_return_t rc;
    void *va = NULL;
    int wired = 0;

    size = (size + PAGE_SIZE - 1) & PAGE_MASK;
    if (!size) {
        fail_msg("invalid size requested");
        return NULL;
    }

    task_map = xnu_get_task_map_reference(fda->task);
    if (task_map == NULL) {
        fail_msg("get_task_map_reference(%p) failed", fda->task);
        goto out;
    }

    rc = vm_allocate(task_map, &addr, size, VM_FLAGS_ANYWHERE);
    if (rc != KERN_SUCCESS) {
        fail_msg("vm_allocate failed");
        goto out;
    }
    assert(addr != 0);

    rc = xnu_vm_map_wire(task_map, addr, addr + size, VM_PROT_DEFAULT, 0);
    if (rc != KERN_SUCCESS) {
        fail_msg("vm_map_wire failed");
        goto out;
    }
    wired = 1;

    um = (struct user_mapping *)kernel_malloc(sizeof(struct user_mapping));
    if (!um) {
        fail_msg("could not allocate user mapping");
        goto out;
    }

    um->va.addr = (void *)addr;
    um->va.size = size;
    um->fda = fda;
    um->vm_map = task_map;
    um->mfns = NULL;
    um->type = type;
    um->mapping_mode = USER_MMAP_RANGE_MODE_DEFAULT;
    lck_spin_lock(umi->lck);
    rb_tree_insert_node(&umi->rbtree, um);
    lck_spin_unlock(umi->lck);

    va = (void *)addr;

  out:
    if (!va) {
        if (um) {
            kernel_free(um, sizeof(struct user_mapping));
            um = NULL;
        }
        if (wired)
            xnu_vm_map_unwire(task_map, addr, addr + size, 0);
        if (addr) {
            rc = vm_deallocate(task_map, addr, size);
            if (rc != KERN_SUCCESS)
                fail_msg("vm_deallocate also failed");
            addr = 0;
        }
        if (task_map) {
            xnu_vm_map_deallocate(task_map); /* put ref */
            task_map = NULL;
        }
    }

    return va;
}

static int
user_free_user_mapping(struct user_mapping *um)
{
    vm_map_offset_t addr = (vm_map_offset_t)um->va.addr;
    kern_return_t rc;
    pmap_t task_pmap;
    int ret = 0;

    switch (um->type) {

    case USER_MAPPING_BUFFER:
    case USER_MAPPING_USER_MALLOC:
        rc = xnu_vm_map_unwire(um->vm_map, addr, addr + um->va.size, 0);
        if (rc != KERN_SUCCESS) {
            fail_msg("vm_map_unwire failed on freeing. Not nice.");
            ret = EINVAL;
            /* Keep going, vm_deallocate will fix this. */
        }
        rc = vm_deallocate(um->vm_map, addr, um->va.size);
        if (rc != KERN_SUCCESS) {
            fail_msg("vm_deallocate failed on freeing. Not good.");
            ret = EINVAL;
            /* Not the best of situations, but keep going. */
        }
        xnu_vm_map_deallocate(um->vm_map); /* put ref */
        break;

    case USER_MAPPING_MEMORY_MAP:
        task_pmap = xnu_get_map_pmap(um->vm_map);
        assert(task_pmap);
        xnu_pmap_remove(task_pmap, addr, addr + um->va.size);
        rc = vm_deallocate(um->vm_map, addr, um->va.size);
        if (rc != KERN_SUCCESS) {
            fail_msg("vm_deallocate failed on freeing. Not good.");
            ret = EINVAL;
            /* Not the best of situations, but keep going. */
        }

        if (um->mfns) {
            size_t num;
            assert(um->type == USER_MAPPING_MEMORY_MAP);
            num = ALIGN_PAGE_UP(um->va.size) >> PAGE_SHIFT;
            release_user_mapping_range(um->mfns, num, um->fda);
            kernel_free(um->mfns, num * sizeof(xen_pfn_t));
        }

        xnu_vm_map_deallocate(um->vm_map); /* put ref */
        break;

    case USER_MAPPING_HOST_MFNS:
        user_remove_host_mfns_user_mapping(um);
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

    va.addr = addr;
    va.size = 1;

    lck_spin_lock(umi->lck);
    um = (struct user_mapping *)rb_tree_find_node(&umi->rbtree, &va);
    if (um)
        rb_tree_remove_node(&umi->rbtree, um);
    lck_spin_unlock(umi->lck);

    if (!um)
        return;

    user_free_user_mapping(um);
}

void
user_free_all_user_mappings(struct fd_assoc *fda)
{
    struct user_mapping_info *umi = &fda->user_mappings;
    struct user_mapping *um;

    lck_spin_lock(umi->lck);
    while ((um = (struct user_mapping *)RB_TREE_MIN(&umi->rbtree))) {
        rb_tree_remove_node(&umi->rbtree, um);
        lck_spin_unlock(umi->lck);
        mm_dprintk("%s: freeing user mapping %p type %s\n", __FUNCTION__,
                   um->va.addr,
                   um->type == USER_MAPPING_MEMORY_MAP ? "mmap" : "malloc");
        user_free_user_mapping(um);
        lck_spin_lock(umi->lck);
    }
    lck_spin_unlock(umi->lck);
}

int
uxen_mem_malloc(struct uxen_malloc_desc *umd, struct fd_assoc *fda)
{
    int ret = 0;

    umd->umd_addr = (uint64_t)user_malloc(umd->umd_npages << PAGE_SHIFT,
                                          USER_MAPPING_USER_MALLOC, fda);
    if (!umd->umd_addr)
        ret = ENOMEM;

    return ret;
}

int
uxen_mem_free(struct uxen_free_desc *ufd, struct fd_assoc *fda)
{

    user_free((void *)ufd->ufd_addr, fda);

    return 0;
}

uint64_t __cdecl
uxen_mem_user_access_ok(void *_umi, void *addr, uint64_t size)
{
    struct user_mapping_info *umi = (struct user_mapping_info *)_umi;
    struct user_mapping *um;
    user_mapping_va va;

    if (!_umi || !umi->lck) {
        fail_msg("invalid user_access_opaque");
        return 0;
    }

    va.addr = addr;
    va.size = 1;

    lck_spin_lock(umi->lck);
    um = (struct user_mapping *)rb_tree_find_node(&umi->rbtree, &va);
    lck_spin_unlock(umi->lck);

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
        fail_msg("addr %p/%llx out of bounds of um %p-%p", addr, size,
                 USER_MAPPING_VA_START(um->va), USER_MAPPING_VA_END(um->va));
        return 0;
    }

    return 1;
}

#define HIGEST_USER_ADDRESS ((void *)(1ULL << 47))

int
uxen_mem_mmapbatch(struct uxen_mmapbatch_desc *ummapbd, struct fd_assoc *fda)
{
    struct vm_info *vmi = fda->vmi;
    void *addr, *buf = NULL;
    unsigned int i;
    union uxen_memop_arg umemopa;
    int *errs = NULL;
    xen_pfn_t *mfns = NULL, *gpfns = NULL;
    unsigned int n, done;
    int ret = ENOENT;
    size_t bufsz = ummapbd->umd_num * sizeof(errs[0]) +
                   XENMEM_TRANSLATE_MAX_BATCH * sizeof(gpfns[0]);

    OSIncrementAtomic(&vmi->vmi_running_vcpus);
    if (vmi->vmi_shared.vmi_runnable == 0)
        goto out;

    if ((void *)&ummapbd->umd_arr[0] >= HIGEST_USER_ADDRESS ||
        (void *)&ummapbd->umd_arr[ummapbd->umd_num] > HIGEST_USER_ADDRESS) {
        fail_msg("umd_arr invalid");
        ret = EFAULT;
        goto out;
    }

    if ((void *)&ummapbd->umd_err[0] >= HIGEST_USER_ADDRESS ||
        (void *)&ummapbd->umd_err[ummapbd->umd_num] > HIGEST_USER_ADDRESS) {
        fail_msg("umd_err invalid");
        ret = EFAULT;
        goto out;
    }

    mfns = kernel_malloc(sizeof(xen_pfn_t) * ummapbd->umd_num);
    if (mfns == NULL) {
        fail_msg("kernel_malloc(mfns) failed");
        ret = ENOMEM;
        goto out;
    }

    buf = kernel_malloc(bufsz);
    if (buf == NULL) {
        fail_msg("kernel_malloc(buf) failed");
        ret = ENOMEM;
        goto out;
    }

    gpfns = (xen_pfn_t *)buf;
    errs = (int *)(gpfns + XENMEM_TRANSLATE_MAX_BATCH);

    done = 0;
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
        ret = copyin((const user_addr_t)&ummapbd->umd_arr[done], gpfns,
                     n * sizeof(gpfns[0]));
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

    for (i = 0; i < ummapbd->umd_num; i++) {
        if (mfns[i] >= uxen_info->ui_max_page) {
            errs[i] = -ENOENT;
            mfns[i] = vmi->vmi_undefined_mfn;
        } else
            errs[i] = 0;
    }
    copyout(errs, (user_addr_t)ummapbd->umd_err,
            ummapbd->umd_num * sizeof(errs[0]));

    addr = user_mmap_xen_mfns(ummapbd->umd_num, mfns, fda);
    if (!addr) {
        ret = EINVAL;
        goto out;
    }

    ummapbd->umd_addr = (uint64_t)addr;

    ret = 0;
  out:
    if (ret && mfns) {
        release_user_mapping_range(mfns, done, fda);
        kernel_free(mfns, sizeof(mfns[0]) * ummapbd->umd_num);
    }
    if (buf)
        kernel_free(buf, bufsz);
    if (OSDecrementAtomic(&vmi->vmi_running_vcpus) == 1)
        fast_event_signal(&vmi->vmi_notexecuting);
    return ret;
}

int
uxen_mem_munmap(struct uxen_munmap_desc *umd, struct fd_assoc *fda)
{
    struct vm_info *vmi = fda->vmi;
    int ret = ENOENT;

    OSIncrementAtomic(&vmi->vmi_running_vcpus);
    if (vmi->vmi_shared.vmi_runnable == 0)
        goto out;

    user_free((void *)umd->umd_addr, fda);

    ret = 0;
  out:
    if (OSDecrementAtomic(&vmi->vmi_running_vcpus) == 1)
        fast_event_signal(&vmi->vmi_notexecuting);
    return 0;
}

void
uxen_mem_tlb_flush(void)
{

    uxen_cpu_on_selected_async(~0ULL, uxen_mem_tlb_flush_fn_global);
}
