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

#include <xen/config.h>
#include <xen/types.h>
#include <xen/sched.h>
#include <asm/system.h>

#include <uxen/uxen.h>
#include <uxen/uxen_memcache_dm.h>

#define map_mfn(va, mfn) UI_HOST_CALL(ui_map_mfn, va, mfn)

#define MDM_MD_FREE_BITS 64
#define MDM_MD_FREE_BYTES 8
#define MDM_MD_FREE_SHIFT 6
#define MDM_MD_FREE_MASK ((1 << MDM_MD_FREE_SHIFT) - 1)

#define MDM_MFN_NONE (mdm_mfn_t)-1
#define MDM_MFN_EXISTING (mdm_mfn_t)-2

static int mdm_init_vm(struct domain *d);

static int
mdm_entry_get(struct domain *d, mdm_mfn_t pfn)
{
    mdm_mfn_entry_t *entry;
    uint32_t y, x, nx;
    int count;

    if (pfn < d->mdm_end_low_gpfn)
        entry = &d->mdm_mfn_to_entry[pfn];
    else if (pfn >= d->mdm_start_high_gpfn && pfn < d->mdm_end_high_gpfn)
        entry = &d->mdm_mfn_to_entry[pfn - (d->mdm_start_high_gpfn -
                                            d->mdm_end_low_gpfn)];
    else
        return 0;

    y = *entry;

    do {
	x = y;
        if (x == ~0U)
            return 0;
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

    return 1;
}

static void
mdm_entry_put(struct domain *d, mdm_mfn_t pfn)
{
    mdm_mfn_entry_t *entry;
    uint32_t y, x, nx;
    int count;

    if (pfn < d->mdm_end_low_gpfn)
        entry = &d->mdm_mfn_to_entry[pfn];
    else if (pfn >= d->mdm_start_high_gpfn && pfn < d->mdm_end_high_gpfn)
        entry = &d->mdm_mfn_to_entry[pfn - (d->mdm_start_high_gpfn -
                                            d->mdm_end_low_gpfn)];
    else
        return;

    y = *entry;

    do {
        x = y;
        nx = (x & ~MEMCACHE_ENTRY_COUNT_MASK);
        count = (x & MEMCACHE_ENTRY_COUNT_MASK) >> MEMCACHE_ENTRY_COUNT_SHIFT;
        /* remove lock-bit */
        count &= ~(1 << (MEMCACHE_ENTRY_COUNT_BITS - 1));
        if (count != MEMCACHE_ENTRY_COUNT_MAX) {
            ASSERT(count != 0);
            count--;
        }

        nx |= count << MEMCACHE_ENTRY_COUNT_SHIFT;
        if (x == nx)
            break;
    } while ((y = cmpxchg(entry, x, nx)) != x);
}

static uint32_t
mdm_entry_clear(struct domain *d, uint32_t pfn)
{
    mdm_mfn_entry_t *entry;
    uint32_t y, x, nx;
    int count;

    if (pfn < d->mdm_end_low_gpfn)
        entry = &d->mdm_mfn_to_entry[pfn];
    else if (pfn >= d->mdm_start_high_gpfn && pfn < d->mdm_end_high_gpfn)
        entry = &d->mdm_mfn_to_entry[pfn - (d->mdm_start_high_gpfn -
                                            d->mdm_end_low_gpfn)];
    else
        return 0;

    y = *entry;

    do {
	x = y;
	count = (x & MEMCACHE_ENTRY_COUNT_MASK) >> MEMCACHE_ENTRY_COUNT_SHIFT;
	if (count)
	    return 1;
	nx = ~0U;
	if (x == nx)
	    break;
    } while ((y = cmpxchg(entry, x, nx)) != x);

    return 0;
}

#define MDM_PAGE_PRESENT 0x1U

static mdm_mfn_t
mdm_map_mfn(void *va, uint32_t offset, mdm_mfn_t mfn)
{
    uint64_t pte;

    pte = map_mfn((uintptr_t)va + offset, mfn);

    return (pte & MDM_PAGE_PRESENT) ?
        (mdm_mfn_t)((pte & ~0x8000000000000fff) >> PAGE_SHIFT) : MDM_MFN_NONE;
}

static mdm_mfn_t
mdm_unmap_mfn(void *va, uint32_t offset, mdm_mfn_t mfn)
{
    uint64_t pte;

    pte = map_mfn((uintptr_t)va + offset, mfn);
    ASSERT(pte);

    return (pte & MDM_PAGE_PRESENT) ?
        (mdm_mfn_t)((pte & ~0x8000000000000fff) >> PAGE_SHIFT) : MDM_MFN_NONE;
}

uint64_t
mdm_enter(struct domain *d, xen_pfn_t pfn, xen_pfn_t mfn)
{
    struct vm_info_shared *vmis = d->vm_info_shared;
    struct mdm_info *mdm = &vmis->vmi_mdm;
    mdm_mfn_entry_t *entry;
    uint32_t offset;
    mdm_mfn_t opfn = MDM_MFN_NONE;
    __smap_state(aflags);

    if (!vmis->vmi_mapcache_active)
        return MDM_MFN_NONE;

    __smap_disable(&aflags);
  again:
    if (pfn < d->mdm_end_low_gpfn)
        entry = &d->mdm_mfn_to_entry[pfn];
    else if (pfn >= d->mdm_start_high_gpfn && pfn < d->mdm_end_high_gpfn)
        entry = &d->mdm_mfn_to_entry[pfn - (d->mdm_start_high_gpfn -
                                            d->mdm_end_low_gpfn)];
    else {
        if (!d->mdm_end_low_gpfn && !mdm_init_vm(d))
            goto again;

        opfn = MDM_MFN_NONE;
        goto out;
    }

    if (mdm_entry_get(d, pfn)) {
        if (mdm->mdm_takeref)
            mdm->mdm_takeref--;
        else
            mdm_entry_put(d, pfn);

        opfn = MDM_MFN_EXISTING;
        goto out;
    }

    offset = d->mdm_next_offset;
    while (mdm_entry_clear(d, d->mdm_mapped_pfn[offset])) {
	offset++;
        if (offset >= d->mdm_map_pfns)
	    offset = 0;
        ASSERT(offset != d->mdm_next_offset);
    }
    opfn = mdm_map_mfn(mdm->mdm_va, offset << PAGE_SHIFT, mfn);
    /* tlb flush -- deferred to mdm_map after all the mappings have
     * been added -- mapcache_map in uxendm is a critical section,
     * only one thread can lookup mappings at the time, i.e. a
     * concurrent lookup/use attempt will wait until this completes
     * entirely.  reference counting ensures that nothing is using the
     * old mapping in this slot until the tlb flush.  */
    d->mdm_mapped_pfn[offset] = pfn;
    wmb();
    *entry = (offset << MEMCACHE_ENTRY_OFFSET_SHIFT) +
	(mdm->mdm_takeref ? (1 << MEMCACHE_ENTRY_COUNT_SHIFT) : 0);
    if (mdm->mdm_takeref)
	mdm->mdm_takeref--;
    offset++;
    if (offset >= d->mdm_map_pfns)
	offset = 0;
    d->mdm_next_offset = offset;

    if (opfn == d->mdm_undefined_mfn)
        opfn = MDM_MFN_NONE;

out:
    __smap_restore(aflags);
    return opfn;
}

int
mdm_clear(struct domain *d, xen_pfn_t pfn, int force)
{
    struct vm_info_shared *vmis = d->vm_info_shared;
    struct mdm_info *mdm = &vmis->vmi_mdm;
    mdm_mfn_entry_t *entry;
    uint32_t offset;
    __smap_state(aflags);
    int ret;

    if (!vmis->vmi_mapcache_active)
        return -1;

    __smap_disable(&aflags);
  again:
    if (pfn < d->mdm_end_low_gpfn)
        entry = &d->mdm_mfn_to_entry[pfn];
    else if (pfn >= d->mdm_start_high_gpfn && pfn < d->mdm_end_high_gpfn)
        entry = &d->mdm_mfn_to_entry[pfn - (d->mdm_start_high_gpfn -
                                            d->mdm_end_low_gpfn)];
    else {
        if (!d->mdm_end_low_gpfn && !mdm_init_vm(d))
            goto again;

        ret = MDM_MFN_NONE;
        goto out;
    }

    offset = *entry;
    if (offset == ~0U) {
       ret = 0;
       goto out;
    }
    if (mdm_entry_clear(d, pfn) && !force) {
       ret = 1;
       goto out;
    }

    offset &= MEMCACHE_ENTRY_OFFSET_MASK;
    // offset <<= (PAGE_SHIFT - MEMCACHE_ENTRY_OFFSET_SHIFT);
    offset >>= (MEMCACHE_ENTRY_OFFSET_SHIFT - PAGE_SHIFT);

    mdm_unmap_mfn(mdm->mdm_va, offset, d->mdm_undefined_mfn);
    offset >>= PAGE_SHIFT;
    d->mdm_mapped_pfn[offset] = ~0U;
    ret = -1;

out:
    __smap_restore(aflags);
    return ret;
}

static int
mdm_init_vm(struct domain *d)
{
    struct vm_info_shared *vmis = d->vm_info_shared;
    struct mdm_info *mdm = &vmis->vmi_mdm;
    size_t s;

    if (!vmis->vmi_mapcache_active)
        return -1;

    if (d->mdm_end_low_gpfn)
        return -1;

    d->mdm_map_pfns = mdm->mdm_map_pfns;
    printk(XENLOG_INFO "%s:vm%u cache size %x\n", __FUNCTION__, d->domain_id,
           d->mdm_map_pfns << PAGE_SHIFT);
    s = ALIGN_PAGE_UP(sizeof(uint32_t) * d->mdm_map_pfns);
    d->mdm_mapped_pfn = alloc_host_pages(s >> PAGE_SHIFT, MEMF_multiok);
    if (!d->mdm_mapped_pfn) {
        printk(XENLOG_ERR "%s:vm%u failed to allocate mapped_pfn array\n",
               __FUNCTION__, d->domain_id);
        return -1;
    }
    memset(d->mdm_mapped_pfn, 0xff, s);
    d->mdm_next_offset = 0;
    d->mdm_mfn_to_entry = mdm->mdm_mfn_to_entry;
    d->mdm_end_low_gpfn = mdm->mdm_end_low_gpfn;
    d->mdm_start_high_gpfn = mdm->mdm_start_high_gpfn;
    d->mdm_end_high_gpfn = mdm->mdm_end_high_gpfn;
    d->mdm_undefined_mfn = mdm->mdm_undefined_mfn;
    printk(XENLOG_INFO "%s:vm%u mdm_mapped_pfn %p "
           "mdm_mfn_to_entry %p mdm_*_gpfn %x/%x/%x\n",
           __FUNCTION__, d->domain_id, d->mdm_mapped_pfn, d->mdm_mfn_to_entry,
           d->mdm_end_low_gpfn, d->mdm_start_high_gpfn, d->mdm_end_high_gpfn);

    return 0;
}

void
mdm_destroy_vm(struct domain *d)
{
    size_t s;

    if (d->mdm_mapped_pfn) {
        s = ALIGN_PAGE_UP(sizeof(uint32_t) * d->mdm_map_pfns);
        free_host_pages(d->mdm_mapped_pfn, s >> PAGE_SHIFT);
        d->mdm_mapped_pfn = NULL;
    }
}
