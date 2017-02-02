/*
 * Copyright 2016-2017, Bromium, Inc.
 * Author: Kris Uchronski <kuchronski@gmail.com>
 * SPDX-License-Identifier: ISC
 */

#include <wdm.h>
#include "user_vram.h"
#include "../common/debug.h"

#define NUM_SCRATCH_PAGES 1

UserVramMapper::UserVramMapper()
    : m_vram_mdl(0)
    , m_scratch_page_mdl(0)
    , m_scratch_vram_mdl(0)
    , m_bdd(0)
{
}

bool UserVramMapper::init(BASIC_DISPLAY_DRIVER *bdd, PHYSICAL_ADDRESS vram_start, SIZE_T vram_size)
{
    m_bdd = bdd;

    PVOID vram_mem = MmMapIoSpace(vram_start, vram_size, MmNonCached);

    PMDL vram_mdl = IoAllocateMdl(vram_mem, (ULONG)vram_size, FALSE, FALSE, NULL);
    if (!vram_mdl) {
        uxen_err("failed to allocate mdl\n");
        return false;
    }

    MmBuildMdlForNonPagedPool(vram_mdl);

    if (!init_scratch(vram_size)) {
        uxen_err("failed to init scratch fb\n");
        IoFreeMdl(vram_mdl);
        return false;
    }

    m_vram_mdl = vram_mdl;

    return true;
}

bool UserVramMapper::init_scratch(SIZE_T vram_size)
{
    int vram_pages = (int) ((vram_size + PAGE_SIZE - 1) >> PAGE_SHIFT);
    PHYSICAL_ADDRESS low  = { 0 };
    PHYSICAL_ADDRESS high = { 0 };
    PHYSICAL_ADDRESS skip = { 0 };

    high.QuadPart = -1;

    /* mdl to describe scratch page(s) */
    PMDL scratch_page_mdl = MmAllocatePagesForMdlEx(low, high, skip, NUM_SCRATCH_PAGES << PAGE_SHIFT,
        MmCached, MM_ALLOCATE_FULLY_REQUIRED);
    if (!scratch_page_mdl) {
        uxen_err("failed to allocate mdl\n");
        return false;
    }

    PFN_NUMBER *scratch_pfns = MmGetMdlPfnArray(scratch_page_mdl);

    /* mdl to describe scratch vram filled with scratch pages */
    PMDL scratch_vram_mdl = IoAllocateMdl(NULL, vram_pages << PAGE_SHIFT, FALSE, FALSE, NULL);

    if (!scratch_vram_mdl) {
        uxen_err("failed to allocate mdl\n");
        MmFreePagesFromMdl(scratch_page_mdl);
        ExFreePool(scratch_page_mdl);

        return false;
    }

    PFN_NUMBER *pfns = MmGetMdlPfnArray(scratch_vram_mdl);
    for (int i = 0; i < vram_pages; ++i) {
        pfns[i] = scratch_pfns[0];
    }

    m_scratch_page_mdl = scratch_page_mdl;
    m_scratch_vram_mdl = scratch_vram_mdl;

    return true;
}

void UserVramMapper::cleanup()
{
    if (m_scratch_page_mdl) {
        MmFreePagesFromMdl(m_scratch_page_mdl);
        ExFreePool(m_scratch_page_mdl);
        m_scratch_page_mdl = NULL;
    }

    if (m_scratch_vram_mdl) {
        IoFreeMdl(m_scratch_vram_mdl);
        m_scratch_vram_mdl = NULL;
    }

    if (m_vram_mdl) {
        IoFreeMdl(m_vram_mdl);
        m_vram_mdl = NULL;
    }
}

void *UserVramMapper::user_map()
{
    __try {
        PVOID p = MmMapLockedPagesSpecifyCache(m_vram_mdl, UserMode, MmNonCached,
                                               NULL, FALSE, NormalPagePriority);
        if (!p)
            uxen_err("error mapping user vram, not enough resources\n");
        return p;
    }
    __except ( EXCEPTION_EXECUTE_HANDLER ) {
        uxen_err("exception mapping user vram, code %x\n", (int)GetExceptionCode());
        return NULL;
    }
}

void UserVramMapper::user_unmap(void *mapped)
{
    MmUnmapLockedPages(mapped, m_vram_mdl);
}

void *UserVramMapper::scratch_map()
{
    __try {
        PVOID p = MmMapLockedPagesSpecifyCache(m_scratch_vram_mdl, UserMode, MmCached,
                                               NULL, FALSE, NormalPagePriority);
        if (!p)
            uxen_err("error mapping scratch vram, not enough resources\n");
        return p;
    }
    __except ( EXCEPTION_EXECUTE_HANDLER ) {
        uxen_err("exception mapping scratch vram, code %x\n", (int)GetExceptionCode());
        return NULL;
    }
}

void UserVramMapper::scratch_unmap(void *mapped)
{
    MmUnmapLockedPages(mapped, m_scratch_vram_mdl);
}


