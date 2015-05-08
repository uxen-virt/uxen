/*
 * Copyright 2014-2016, Bromium, Inc.
 * Author: Julian Pidancet <julian@pidancet.net>
 * SPDX-License-Identifier: ISC
 */

#include "balloon.h"
#include "uXenPlatform.h"

#include <uxenvmlib/uxen_hypercall.h>
#include <xen/xen.h>
#include <xen/memory.h>

static struct balloon_pages *
alloc_pages(mach_vm_size_t length)
{
    struct balloon_pages *pages;

    pages = (struct balloon_pages *)IOMalloc(sizeof (*pages));
    if (!pages) {
        dprintk("%s: IOMalloc failed\n", __func__);
        return NULL;
    }
    pages->desc = IOBufferMemoryDescriptor::inTaskWithPhysicalMask(
                kernel_task,
                // kIOMemoryMapperNone bypasses IOMMU address translation:
                kIODirectionIn | kIOMemoryMapperNone,
                length,
                0x00000FFFFFFFF000UL);
    if (!pages->desc) {
        dprintk("%s: failed to allocate memory descriptor\n", __func__);
        IOFree(pages, sizeof (*pages));
        return NULL;
    }

    return pages;
}

static void
free_pages(struct balloon_pages *pages)
{
    pages->desc->release();
    IOFree(pages, sizeof (*pages));
}

IOReturn
uXenBalloon::share_pages(struct balloon_pages *pages)
{
    IOBufferMemoryDescriptor *pfn_list_desc;
    xen_pfn_t *pfn_list;
    xen_memory_share_zero_pages_t xmszp;
    addr64_t addr;
    IOByteCount offset;
    int rc;

    pfn_list_desc = IOBufferMemoryDescriptor::inTaskWithPhysicalMask(
            kernel_task,
            kIODirectionIn | kIODirectionOut | kIOMemoryMapperNone,
            PAGE_SIZE,
            0x00000FFFFFFFF000UL);
    if (!pfn_list_desc) {
        dprintk("%s: failed to allocate memory descriptor\n", __func__);
        return kIOReturnNoMemory;
    }

    pfn_list = (xen_pfn_t *)pfn_list_desc->getBytesNoCopy();
    if (!pfn_list) {
        dprintk("%s: failed to acquire pfn list pointer\n", __func__);
        pfn_list_desc->release();
        return kIOReturnNoMemory;
    }

    addr = pfn_list_desc->getPhysicalSegment(0, NULL);
    xmszp.gpfn_list_gpfn = (xen_pfn_t)(addr >> PAGE_SHIFT);
    xmszp.nr_gpfns = 0;

    for (offset = 0; offset < pages->desc->getLength(); offset += PAGE_SIZE) {
        addr = pages->desc->getPhysicalSegment(offset, NULL);

        pfn_list[xmszp.nr_gpfns++] = (xen_pfn_t)(addr >> PAGE_SHIFT);
        if (xmszp.nr_gpfns == (PAGE_SIZE / sizeof (xen_pfn_t))) {
            pfn_list_desc->prepare();
            rc = uxen_hypercall_memory_op(XENMEM_share_zero_pages,
                                               &xmszp);
            pfn_list_desc->complete();
            if (rc) {
                dprintk("%s: hypercall_memory_op failed rc=%d\n", __func__, rc);
                pfn_list_desc->release();
                return kIOReturnError;
            }
            xmszp.nr_gpfns = 0;
        }
    }

    if (xmszp.nr_gpfns) {
        pfn_list_desc->prepare();
        rc = uxen_hypercall_memory_op(XENMEM_share_zero_pages, &xmszp);
        pfn_list_desc->complete();
        if (rc) {
            dprintk("%s: hypercall_memory_op failed rc=%d\n", __func__, rc);
            pfn_list_desc->release();
            return kIOReturnError;
        }
    }

    pfn_list_desc->release();

    return kIOReturnSuccess;
}

IOReturn
uXenBalloon::add_pages(struct balloon_pages *pages)
{
    IOReturn ret;

    ret = pages->desc->prepare();
    if (ret != kIOReturnSuccess) {
        dprintk("%s: failed to prepare memory descriptor\n", __func__);
        return ret;
    }

    ret = share_pages(pages);
    if (ret != kIOReturnSuccess) {
        dprintk("%s: failed to share pages\n", __func__);
        pages->desc->complete();
        return ret;
    }

    TAILQ_INSERT_TAIL(&page_list, pages, entry);
    size += pages->desc->getLength();

    return kIOReturnSuccess;
}

void
uXenBalloon::remove_pages(struct balloon_pages *pages)
{
    TAILQ_REMOVE(&page_list, pages, entry);
    size -= pages->desc->getLength();
    pages->desc->complete();
}

bool
uXenBalloon::init(uXenPlatform *p)
{
    TAILQ_INIT(&page_list);
    lock = IOLockAlloc();
    if (!lock)
        return false;
    size = 0;
    platform = p;
    return true;
}

void
uXenBalloon::free(void)
{
    struct balloon_pages *pages, *next;

    IOLockLock(lock);

    TAILQ_FOREACH_SAFE(pages, &page_list, entry, next) {
        remove_pages(pages);
        free_pages(pages);
    }

    IOLockUnlock(lock);

    IOLockFree(lock);
}

IOReturn
uXenBalloon::set_size(size_t target_mb)
{
    IOReturn ret = kIOReturnSuccess;

    IOLockLock(lock);
    while ((size >> 20) < target_mb) {
        struct balloon_pages *pages = alloc_pages(1 << 20);

        if (!pages) {
            ret = kIOReturnNoMemory;
            break;
        }
        ret = add_pages(pages);
        if (ret != kIOReturnSuccess) {
            free_pages(pages);
            break;
        }
    }

    while ((size >> 20) > target_mb) {
        struct balloon_pages *pages = TAILQ_FIRST(&page_list);

        if (!pages)
            break;

        remove_pages(pages);
        free_pages(pages);
    }
    IOLockUnlock(lock);

    return ret;
}

size_t
uXenBalloon::get_size(void)
{
    return size >> 20;
}
