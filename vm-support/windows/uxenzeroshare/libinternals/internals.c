/*
 * Copyright 2013-2015, Bromium, Inc.
 * SPDX-License-Identifier: ISC
 */

//
//  uxenzeroshare: internals.c
//
                      
#ifdef UXENZEROSHARE_KERNEL_MODE                      
    #include <ntifs.h>
    #include <aux_klib.h>
    #include "uxenvmlib.h"
#else
    #include <windows.h>
    #include <stdio.h>
    #include <assert.h>
    #include <crtdbg.h>
#endif
                      
#include "uxenzeroshare.h"


void
int_validate_internals_info(const UXENZEROSHARE_INTERNALS_INFO * Internals)
{
    UXENZEROSHARE_ENTER();
    
    UXENZEROSHARE_ASSERT((Internals != 0));

    Internals;

    UXENZEROSHARE_ASSERT((Internals->BaseOfNtoskrnl != 0));
    UXENZEROSHARE_ASSERT((Internals->KeWaitForGate.Rva != 0));
    UXENZEROSHARE_ASSERT((Internals->KeWaitForGate.Va != 0));
    UXENZEROSHARE_ASSERT((Internals->MiInsertPageInFreeOrZeroedList.Rva != 0));
    UXENZEROSHARE_ASSERT((Internals->MiInsertPageInFreeOrZeroedList.Va != 0));
    UXENZEROSHARE_ASSERT((Internals->MiMapPageInHyperSpaceWorker.Rva != 0));
    UXENZEROSHARE_ASSERT((Internals->MiMapPageInHyperSpaceWorker.Va != 0));
    UXENZEROSHARE_ASSERT((Internals->MiRemoveAnyPage.Rva != 0));
    UXENZEROSHARE_ASSERT((Internals->MiRemoveAnyPage.Va != 0));
    UXENZEROSHARE_ASSERT((Internals->MiUnmapPageInHyperSpaceWorker.Rva != 0));
    UXENZEROSHARE_ASSERT((Internals->MiUnmapPageInHyperSpaceWorker.Va != 0));
    UXENZEROSHARE_ASSERT((Internals->MiZeroingDisabled.Rva != 0));
    UXENZEROSHARE_ASSERT((Internals->MiZeroingDisabled.Va != 0));
    UXENZEROSHARE_ASSERT((Internals->MmFreePageListHead.Rva != 0));
    UXENZEROSHARE_ASSERT((Internals->MmFreePageListHead.Va != 0));
    UXENZEROSHARE_ASSERT((Internals->MmZeroingPageGate.Rva != 0));
    UXENZEROSHARE_ASSERT((Internals->MmZeroingPageGate.Va != 0));

    return;
}

void
int_dump_internals_info(const UXENZEROSHARE_INTERNALS_INFO * Internals)
{
    UXENZEROSHARE_ENTER();
    
    UXENZEROSHARE_ASSERT((Internals != 0));

    Internals;

    UXENZEROSHARE_DUMP(("InternalsInfo:\n"));
    UXENZEROSHARE_DUMP(("                      BaseOfNtoskrnl: 0x%.016I64X\n", Internals->BaseOfNtoskrnl));

    UXENZEROSHARE_DUMP(("                   KeWaitForGate(VA): 0x%.016I64X\n", Internals->KeWaitForGate.Va));
    UXENZEROSHARE_DUMP(("  MiInsertPageInFreeOrZeroedList(VA): 0x%.016I64X\n", Internals->MiInsertPageInFreeOrZeroedList.Va));
    UXENZEROSHARE_DUMP(("     MiMapPageInHyperSpaceWorker(VA): 0x%.016I64X\n", Internals->MiMapPageInHyperSpaceWorker.Va));
    UXENZEROSHARE_DUMP(("                 MiRemoveAnyPage(VA): 0x%.016I64X\n", Internals->MiRemoveAnyPage.Va));
    UXENZEROSHARE_DUMP(("   MiUnmapPageInHyperSpaceWorker(VA): 0x%.016I64X\n", Internals->MiUnmapPageInHyperSpaceWorker.Va));
    UXENZEROSHARE_DUMP(("               MiZeroingDisabled(VA): 0x%.016I64X\n", Internals->MiZeroingDisabled.Va));
    UXENZEROSHARE_DUMP(("              MmFreePageListHead(VA): 0x%.016I64X\n", Internals->MmFreePageListHead.Va));
    UXENZEROSHARE_DUMP(("               MmZeroingPageGate(VA): 0x%.016I64X\n", Internals->MmZeroingPageGate.Va));

    UXENZEROSHARE_DUMP(("\n"));

    return;
}

//
//  uxenzeroshare: internals.c
//

