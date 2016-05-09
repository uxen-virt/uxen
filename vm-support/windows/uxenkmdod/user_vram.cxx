/*
 * Copyright 2016, Bromium, Inc.
 * Author: Kris Uchronski <kuchronski@gmail.com>
 * SPDX-License-Identifier: ISC
 */

#include <wdm.h>
#include "user_vram.h"

PMDL user_vram_init(PHYSICAL_ADDRESS vram_start, SIZE_T vram_size)
{
    PVOID vram_mem = MmMapIoSpace(vram_start, vram_size, MmNonCached);
    MDL *vram_mdl = IoAllocateMdl(vram_mem, (ULONG)vram_size, FALSE, FALSE, NULL);
    if (!vram_mdl)
        return NULL;

    MmBuildMdlForNonPagedPool(vram_mdl);

    return vram_mdl;
}

static int user_map_exception(void)
{
    return EXCEPTION_CONTINUE_EXECUTION;
}

PVOID user_vram_map(PMDL vram_mdl)
{
    __try {
        return MmMapLockedPagesSpecifyCache(vram_mdl, UserMode, MmNonCached,
                NULL, FALSE, NormalPagePriority);
    }
    __except (user_map_exception()) {
        return NULL;
    }
}
