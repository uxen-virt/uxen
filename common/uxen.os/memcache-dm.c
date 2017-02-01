/*
 * Copyright (c) 2012-2014, Christian Limpach <Christian.Limpach@gmail.com>
 * 
 * Permission to use, copy, modify, and/or distribute this software
 * for any purpose with or without fee is hereby granted, provided
 * that the above copyright notice and this permission notice appear
 * in all copies.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL
 * WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE
 * AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR
 * CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS
 * OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT,
 * NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
 * CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include "uxen.h"

#if defined(_WIN32)
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <xen/errno.h>
#elif defined(__APPLE__)
#include <libkern/OSAtomic.h>
#include <libkern/libkern.h>
#endif

#define UXEN_DEFINE_SYMBOLS_PROTO
#include <uxen/uxen_link.h>

#define MDM_MD_FREE_BITS 64
#define MDM_MD_FREE_BYTES 8
#define MDM_MD_FREE_SHIFT 6
#define MDM_MD_FREE_MASK ((1 << MDM_MD_FREE_SHIFT) - 1)

#define MDM_MFN_NONE (mdm_mfn_t)-1
#define MDM_MFN_EXISTING (mdm_mfn_t)-2

#define MDM_MAX_PAGE_SANE \
    ((size_t)(0x100000000ULL / sizeof(mdm_mfn_entry_t)) - PAGE_SIZE)

static void mdm_free_all(struct vm_info *);

static int
mdm_entry_get(struct mdm_info *mdm, mdm_mfn_t pfn)
{
    mdm_mfn_entry_t *entry;
    uint32_t y, x, nx;
    int count;
    int ret = 0;
    uxen_smap_state(smap);

    uxen_smap_preempt_disable(&smap);
    if (pfn < mdm->mdm_end_low_gpfn)
        entry = &mdm->mdm_mfn_to_entry[pfn];
    else if (pfn >= mdm->mdm_start_high_gpfn && pfn < mdm->mdm_end_high_gpfn)
        entry = &mdm->mdm_mfn_to_entry[pfn - (mdm->mdm_start_high_gpfn -
                                              mdm->mdm_end_low_gpfn)];
    else
        goto out;

    y = *entry;

    do {
	x = y;
        if (x == ~0U)
            goto out;
	nx = (x & ~MEMCACHE_ENTRY_COUNT_MASK);
	count = (x & MEMCACHE_ENTRY_COUNT_MASK) >> MEMCACHE_ENTRY_COUNT_SHIFT;
        /* remove lock-bit */
	count &= ~(1 << (MEMCACHE_ENTRY_COUNT_BITS - 1));
	if (count != MEMCACHE_ENTRY_COUNT_MAX)
	    count++;

	nx |= count << MEMCACHE_ENTRY_COUNT_SHIFT;
	if (x == nx)
	    break;
    } while ((y = cmpxchg(entry, x, nx)) != x);

    ret = 1;
out:
    uxen_smap_preempt_restore(&smap);
    return ret;
}

#define MDM_PAGE_PRESENT 0x1U

static mdm_mfn_t
mdm_unmap_mfn(void *va, uint32_t offset, mdm_mfn_t mfn)
{
    uint64_t pte;

    pte = map_mfn((uintptr_t)va + offset, mfn);
    ASSERT(pte);

    return (pte & MDM_PAGE_PRESENT) ?
        (mdm_mfn_t)((pte & ~0x8000000000000fff) >> PAGE_SHIFT) : MDM_MFN_NONE;
}

static void *
mdm_allocate_va(struct vm_info *vmi, uint32_t num)
{
    struct mdm_info *mdm = &vmi->vmi_shared.vmi_mdm;

    return uxen_mem_user_va_with_page(num,
                                      mdm->mdm_undefined_mfn,
                                      vmi->vmi_mdm_fda);
}

static int
mdm_allocate(struct vm_info *vmi)
{
    struct mdm_info *mdm = &vmi->vmi_shared.vmi_mdm;

    if (mdm->mdm_va)
        return 0;

    mdm->mdm_va = mdm_allocate_va(vmi, mdm->mdm_map_pfns);
    if (!mdm->mdm_va)
        return ENOMEM;
    dprintk("%s: vm%u allocated at %p/%x\n", __FUNCTION__,
            vmi->vmi_shared.vmi_domid, mdm->mdm_va,
            mdm->mdm_map_pfns << PAGE_SHIFT);

    return 0;
}

int
mdm_map(struct uxen_memcachemap_desc *umd, struct fd_assoc *fda)
{
    struct vm_info *vmi = fda->vmi;
    union uxen_memop_arg umemopa;
    xen_pfn_t *mfns, *pfns = NULL;
    unsigned int i;
    int ret = ENOENT;
    struct mdm_info *mdm;

    start_execution(vmi);
    if (vmi->vmi_shared.vmi_runnable == 0)
        goto out;

    mdm = &vmi->vmi_shared.vmi_mdm;

    if (!mdm->mdm_mfn_to_entry) {
        fail_msg("memcache not initialized");
        ret = EINVAL;
        goto out;
    }

    if ((umd->pfn >= mdm->mdm_end_low_gpfn &&
         umd->pfn < mdm->mdm_start_high_gpfn) ||
        umd->pfn >= mdm->mdm_end_high_gpfn) {
        fail_msg("pfn too large");
        ret = EINVAL;
        goto out;
    }

    if (mdm_entry_get(mdm, umd->pfn)) {
        ret = 0;
        goto out;
    }

    if (umd->nr_pfn > XENMEM_TRANSLATE_MAX_BATCH ||
        umd->nr_pfn > mdm->mdm_map_pfns){
        fail_msg("nr_pfn too big: %d", umd->nr_pfn);
        ret = EINVAL;
        goto out;
    }

    pfns = kernel_malloc(umd->nr_pfn * sizeof(xen_pfn_t) * 2);
    if (pfns == NULL) {
        fail_msg("kernel_malloc(%lu)", umd->nr_pfn * sizeof(xen_pfn_t) * 2);
	ret = ENOMEM;
	goto out;
    }
    /* mfns array is 2nd half of pfns array */
    mfns = &pfns[umd->nr_pfn];

    for (i = 0; i < umd->nr_pfn; i++)
	pfns[i] = umd->pfn + i;

    mdm->mdm_takeref = 1;
    umemopa.translate_gpfn_list_for_map.domid = fda->vmi->vmi_shared.vmi_domid;
    umemopa.translate_gpfn_list_for_map.prot = XENMEM_TRANSLATE_PROT_WRITE;
    umemopa.translate_gpfn_list_for_map.gpfns_start = 0;
    umemopa.translate_gpfn_list_for_map.gpfns_end = umd->nr_pfn;
    umemopa.translate_gpfn_list_for_map.map_mode = XENMEM_TRANSLATE_MAP_DM;
    set_xen_guest_handle(umemopa.translate_gpfn_list_for_map.gpfn_list, pfns);
    set_xen_guest_handle(umemopa.translate_gpfn_list_for_map.mfn_list, mfns);
    ret = (int)uxen_dom0_hypercall(
        &vmi->vmi_shared, &fda->user_mappings,
        UXEN_UNRESTRICTED_ACCESS_HYPERCALL |
        (fda->admin_access ? UXEN_ADMIN_HYPERCALL : 0) |
        UXEN_SYSTEM_HYPERCALL |
        (fda->vmi_owner ? UXEN_VMI_OWNER : 0), __HYPERVISOR_memory_op,
        (uintptr_t)XENMEM_translate_gpfn_list_for_map, (uintptr_t)&umemopa);
    uxen_mem_tlb_flush();       /* deferred from mdm_enter */
    if (ret) {
#if defined(_WIN32)
        /* fail_msg("XENMEM_translate_gpfn_list failed: %d", ret); */
#elif defined(__APPLE__)
        fail_msg("XENMEM_translate_gpfn_list failed: %d", ret);
#endif
	goto out;
    }

  out:
    if (pfns)
	kernel_free(pfns, umd->nr_pfn * sizeof(xen_pfn_t) * 2);
    end_execution(vmi);
    return ret;
}

static int
mdm_clear_cache(struct mdm_info *mdm)
{
    uint32_t offset;
    int count = 0;
    mdm_mfn_t omfn;

    offset = 0;
    while (offset < mdm->mdm_map_pfns) {
        omfn = mdm_unmap_mfn(mdm->mdm_va, offset << PAGE_SHIFT,
                             mdm->mdm_undefined_mfn);
        if (omfn != MDM_MFN_NONE && omfn != mdm->mdm_undefined_mfn)
	    count++;
	offset++;
    }

    return count;
}

int
mdm_init(struct uxen_memcacheinit_desc *umd, struct fd_assoc *fda)
{
    struct vm_info *vmi = fda->vmi;
    struct mdm_info *mdm = NULL;
    uint64_t nr_gpfn;
    size_t s;
    int ret = ENOENT;
    uxen_smap_state(smap);

    start_execution(vmi);
    if (vmi->vmi_shared.vmi_runnable == 0)
        goto out;

    if (vmi->vmi_mdm_fda) {
        ret = (vmi->vmi_mdm_fda != fda) ? EEXIST : 0;
        goto out;
    }

    if ((umd->end_low_gpfn > umd->start_high_gpfn) ||
        (umd->start_high_gpfn > umd->end_high_gpfn)) {
        ret = EINVAL;
        goto out;
    }

    nr_gpfn = (uint64_t)umd->end_low_gpfn +
               ((uint64_t)umd->end_high_gpfn -
                (uint64_t)umd->start_high_gpfn);
    if (nr_gpfn >= MDM_MAX_PAGE_SANE) {
        ret = EINVAL;
        goto out;
    }

    mdm = &vmi->vmi_shared.vmi_mdm;
    vmi->vmi_mdm_fda = fda;

    mdm->mdm_end_low_gpfn= umd->end_low_gpfn;
    mdm->mdm_start_high_gpfn = umd->start_high_gpfn;
    mdm->mdm_end_high_gpfn = umd->end_high_gpfn;
    mdm->mdm_undefined_mfn = vmi->vmi_undefined_mfn;

    s = ALIGN_PAGE_UP(nr_gpfn * sizeof(mdm_mfn_entry_t));
    mdm->mdm_mfn_to_entry = user_malloc(s, USER_MAPPING_BUFFER, fda);
    if (mdm->mdm_mfn_to_entry == NULL) {
	ret = ENOMEM;
	goto out;
    }

    uxen_smap_preempt_disable(&smap);
    memset((uint8_t *)mdm->mdm_mfn_to_entry, 0xff, s);
    uxen_smap_preempt_restore(&smap);

    mdm->mdm_map_pfns = (1ULL << (32 - MEMCACHE_ENTRY_OFFSET_SHIFT)) - 1;
    ret = mdm_allocate(vmi);
    if (ret)
        goto out;

    umd->va = mdm->mdm_va;
    umd->pfn_to_entry = mdm->mdm_mfn_to_entry;

    vmi->vmi_shared.vmi_mapcache_active = 1;

    ret = 0;
  out:
    if (ret && mdm)
        mdm_free_all(vmi);
    end_execution(vmi);
    return ret;
}

static void
mdm_free_all(struct vm_info *vmi)
{
    struct mdm_info *mdm = &vmi->vmi_shared.vmi_mdm;

    if (mdm->mdm_va) {
        uxen_mem_user_va_remove(mdm->mdm_map_pfns, mdm->mdm_va,
                                vmi->vmi_mdm_fda);
        mdm->mdm_va = NULL;
    }
    if (mdm->mdm_mfn_to_entry) {
        user_free((void *)mdm->mdm_mfn_to_entry, USER_MAPPING_BUFFER,
                  vmi->vmi_mdm_fda);
        mdm->mdm_mfn_to_entry = NULL;
    }
    vmi->vmi_mdm_fda = NULL;
}

void
mdm_clear_all(struct vm_info *vmi)
{
    struct mdm_info *mdm = &vmi->vmi_shared.vmi_mdm;
    int cleared;

    cleared = mdm_clear_cache(mdm);
    uxen_mem_tlb_flush();
    if (cleared)
        dprintk("%s: vm%u cleared %d entries\n", __FUNCTION__,
                vmi->vmi_shared.vmi_domid, cleared);

    vmi->vmi_shared.vmi_mapcache_active = 0;
    mdm_free_all(vmi);
}
