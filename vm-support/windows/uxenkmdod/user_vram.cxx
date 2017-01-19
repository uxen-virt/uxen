/*
 * Copyright 2016-2017, Bromium, Inc.
 * Author: Kris Uchronski <kuchronski@gmail.com>
 * SPDX-License-Identifier: ISC
 */

#include <wdm.h>
#include "user_vram.h"
#include "../common/debug.h"

PMDL user_vram_init(PHYSICAL_ADDRESS vram_start, SIZE_T vram_size)
{
    PVOID vram_mem = MmMapIoSpace(vram_start, vram_size, MmNonCached);
    MDL *vram_mdl = IoAllocateMdl(vram_mem, (ULONG)vram_size, FALSE, FALSE, NULL);
    if (!vram_mdl)
        return NULL;

    MmBuildMdlForNonPagedPool(vram_mdl);

    return vram_mdl;
}


PVOID user_vram_map(PMDL vram_mdl)
{
    __try {
        PVOID p = MmMapLockedPagesSpecifyCache(vram_mdl, UserMode, MmNonCached,
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

void user_vram_unmap(PMDL vram_mdl, PVOID mapped)
{
    MmUnmapLockedPages(mapped, vram_mdl);
}

