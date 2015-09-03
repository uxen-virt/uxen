/*
 * Copyright 2013-2015, Bromium, Inc.
 * SPDX-License-Identifier: ISC
 */

//
//  uxenzeroshare: zerothread.c
//

#include "zerothread.h"

//
//  Internal types
//

typedef enum ZEROING_CONSTANTS
{
    //
    //  Since we're only concerned with amd64, color is irrelevant, but we
    //  must pass something to routines that use it, as they still require
    //  it in order to keep their signatures the same as on x86.
    // 
    //  We'll always use this value.
    //

    DEFAULT_COLOR           =   1,

    //
    //  The end of list of page frame numbers is indicated by this value.
    //

    END_OF_PAGE_FRAME_LIST  = 0xFFFFFFFFFFFFFFFF
} ZEROING_CONSTANTS;


//
//  Internal prototypes
//

__drv_maxIRQL(APC_LEVEL)
__drv_sameIRQL
__checkReturn
static
int
zt_share_zero_pages(
    __in PFN_NUMBER * PageFrameNumbers,
    __in int          NumberOfPages
    );


//
//  Zeroes a physical page by mapping the page into hyperspace
//
//  Used for internal testing only
//

__drv_maxIRQL(APC_LEVEL)
__drv_sameIRQL
static
void
zt_zero_physical_page(
    __in UXENZEROSHARE_ZEROING_THREAD_CONTEXT * Context,
    __in PFN_NUMBER                             PageFrameNumber
    );

//
//  Global variables
//

UXENZEROSHARE_ZEROING_THREAD_CONTEXT       g_ZeroingThreadContext;


//
//  Implementation
//


//
//  zt_create_zeroing_thread
//

__drv_requiresIRQL(PASSIVE_LEVEL)
__drv_sameIRQL
__checkReturn
NTSTATUS
zt_create_zeroing_thread(
    __in PKSTART_ROUTINE                        Routine,
    __in UXENZEROSHARE_ZEROING_THREAD_CONTEXT * Context
    )
{
    NTSTATUS status;

    UXENZEROSHARE_ENTER();
    UXENZEROSHARE_ASSERT((Routine != 0));
    UXENZEROSHARE_ASSERT((Context != 0));

    //
    //  Make sure that nobody's trying to create more than one of our zeroing
    //  threads.
    //

    UXENZEROSHARE_ASSERT((Context->Thread == 0));
    UXENZEROSHARE_ASSERT((Context->ZeroingBatch == 0));
    

    //
    //  Allocate storage (NP) for our array of pfn's to batch up for
    //  hypervisor.
    //

    UXENZEROSHARE_ASSERT((XENMEM_SHARE_ZERO_PAGES_MAX_BATCH != 0));

    Context->ZeroingBatch = (PFN_NUMBER *)
        ExAllocatePoolWithTag(
            NonPagedPool,
            sizeof(xen_pfn_t) * XENMEM_SHARE_ZERO_PAGES_MAX_BATCH,
            UXENZEROSHARE_POOL_TAG
            );

    if (! Context->ZeroingBatch) {
        UXENZEROSHARE_DUMP((
            "  couldn't allocate memory for page frame number array!\n"
            ));

        //
        //  Given that our zeroing thread is not essential to Krypton, don't
        //  bugcheck here, even though getting here is by all accounts not
        //  going to end well.
        //

        return STATUS_INSUFFICIENT_RESOURCES;
    }

    //
    //  Initialize the notification event that gets signaled, should we wish
    //  to terminate (our) zeroing thread.
    //
    //  The initial state of said event should be cleared (FALSE, below).
    //

    KeInitializeEvent(
        & Context->TerminateZeroingThread,
          NotificationEvent,
          FALSE
          );
    Context->EventExtant = TRUE;

    //
    //  Create the zeroing thread.
    //
    //  Context contains the information required for zeroing.
    //
    //  See zerothread.h
    //

    status = PsCreateSystemThread(
        & Context->ThreadHandle,
          THREAD_ALL_ACCESS,
          0,                            //  ObjectAttributes
          0,                            //  ProcessHandle
          0,                            //  Client Id
          Routine,
          Context
          );

    if (! NT_SUCCESS(status)) {
        //
        //  If we couldn't create the thread, something is very likely
        //  seriously wrong with the system in general.
        //
        //  Normally, the best thing to do would be to give up and bugcheck,
        //  but as zeroing isn't essential to Krypton, I suppose we should
        //  just let it slide and hope for the best.
        //

        UXENZEROSHARE_DUMP(("  PsCreateSystemThread(): 0x%.08X\n", status));
        Context->EventExtant = 0;

        //
        //  We need to free the array we were going to use for storing pages.
        //

        ExFreePoolWithTag(Context->ZeroingBatch, UXENZEROSHARE_POOL_TAG);

        Context->ZeroingBatch = 0;
    }
    else {
        //
        //  Take out a reference on the zeroing thread so that it won't go away
        //  until we want it to.
        //

        ObReferenceObjectByHandle(
            Context->ThreadHandle,
            THREAD_ALL_ACCESS,
            0,                                  //  ObjectType        
            KernelMode,
            & Context->Thread,
            0                                   //  ObjectHandleInformation
            );

        //
        //  Close the thread handle as we'll never need it.
        //

        ZwClose(Context->ThreadHandle);
    }

    return status;
}

//
//  zt_enable_system_zeroing_thread
//

__drv_maxIRQL(APC_LEVEL)
__drv_sameIRQL
void
zt_enable_system_zeroing_thread(
    __in UXENZEROSHARE_ZEROING_THREAD_CONTEXT * Context,
    __in BOOLEAN                                Enable
    )
{
    ULONG       flags;
    KIRQL       irql;
    NTSTATUS    status;

    UXENZEROSHARE_ENTER();
    UXENZEROSHARE_ASSERT((Context));
    UXENZEROSHARE_ASSERT((Context->MiZeroingDisabled));
    UXENZEROSHARE_ASSERT((KeGetCurrentIrql() <= APC_LEVEL));

    //
    //  If it's already disabled, either we are running under driver verifier
    //  (special pool/pool tracking), or something is seriously amiss.
    //

    status = MmIsVerifierEnabled(& flags);

    KeRaiseIrql(DISPATCH_LEVEL, & irql);

    if (NT_SUCCESS(status)) {
        UXENZEROSHARE_DUMP((
            "\n\n\n\n  WARNING: Driver Verifier is running with Special "
            "Pool/Pool tracking enabled!\n\n\n\n"
            ));
    }
    else {
        UXENZEROSHARE_ASSERT((* Context->MiZeroingDisabled == Enable ? 1 : 0));

        if (* Context->MiZeroingDisabled != Enable) {
            //
            //  No good particularly appealing options here:
            //      BSOD'ing the guest doesn't really help us, as if we got this
            //      far, if we leave everything as is, the guest might well
            //      continue running without issue, especially if it is a
            //      short-lived browsing session.
            //
            //      Since we're using KdPrint (v. ETW) and we only get here
            //      in a FRE build, we can't log anything.
            //

            return;
        }
    }

    * Context->MiZeroingDisabled = Enable ? 0 : 1;

    KeLowerIrql(irql);

    return;
}

//
//  zt_share_zero_pages
//

__drv_maxIRQL(APC_LEVEL)
__drv_sameIRQL
__checkReturn
static
int
zt_share_zero_pages(
    __in PFN_NUMBER * PageFrameNumbers,
    __in int          NumberOfPages
    )
{
    unsigned int                      gpfn;
    static xen_pfn_t                * gpfn_list      = NULL;
    static xen_pfn_t                  gpfn_list_gpfn = 0;
    int                               i;
    int                               rc;
    xen_memory_share_zero_pages_t     xmszp;

    UXENZEROSHARE_ENTER();
    UXENZEROSHARE_ASSERT((PageFrameNumbers));

    if (gpfn_list == NULL) {
	    gpfn_list = (xen_pfn_t *) uxen_malloc_locked_pages(1, & gpfn, 0);
	    if (gpfn_list == NULL) {
            return 1;
        }

	    gpfn_list_gpfn = gpfn;
    }

    for (i = 0; i < NumberOfPages; i++) {
	    gpfn_list[i] = PageFrameNumbers[i];
    }

    xmszp.nr_gpfns       = NumberOfPages;
    xmszp.gpfn_list_gpfn = gpfn_list_gpfn;

    UXENZEROSHARE_DUMP(("  issuing zeroshare hypercall - "
        "%s(XENMEM_share_zero_pages, xmszp):\n",
        __FUNCTION__
    ));
    UXENZEROSHARE_DUMP(("    xmszp.nr_gpfns: %lu [0x%.08X]\n",
        xmszp.nr_gpfns,
        xmszp.nr_gpfns
    ));
    UXENZEROSHARE_DUMP(("    xmszp.gpfn_list_gpfn: %I64u [0x%.016I64X]\n",
        xmszp.gpfn_list_gpfn,
        xmszp.gpfn_list_gpfn
    ));

    rc = uxen_hypercall_memory_op(XENMEM_share_zero_pages, & xmszp);
    
    if (rc) {
        UXENZEROSHARE_DUMP((
            "%s:%d returned rc=%d\n",
            __FUNCTION__,
            __LINE__,
            rc
            ));
    }
    else {
        UXENZEROSHARE_DUMP(("  zeroshare hypercall completed successfully\n"));
    }

    return rc;
}

//
//  zt_stop_zeroing_thread
//

__drv_maxIRQL(APC_LEVEL)
__drv_sameIRQL
void
zt_stop_zeroing_thread(
    __in UXENZEROSHARE_ZEROING_THREAD_CONTEXT * Context
    )
{
    UXENZEROSHARE_ENTER();
    UXENZEROSHARE_ASSERT((Context != 0));
    
    if (Context->EventExtant) {
        UXENZEROSHARE_ASSERT((Context->Thread != 0));

        //
        //  Signal the termination event (initialized in create_zeroing_thread())
        //  to instruct the zeroing thread to terminate itself.
        //

        KeSetEvent(& Context->TerminateZeroingThread, 0, 0);

        //
        //  Wait for the thread to kill itself.  When it happens, the PKTHREAD
        //  (Context->Thread) will be signaled.
        //

        KeWaitForSingleObject(Context->Thread, Executive, KernelMode, 0, 0);

        if (Context->Thread) {
            //
            //  Get rid of our reference so that the thread goes away
            //  completely.
            //

            ObDereferenceObject(Context->Thread);
        }

        //
        //  Free the array of entries that we use to batch up for zeroing.
        //

        UXENZEROSHARE_ASSERT((Context->ZeroingBatch != 0));

        ExFreePoolWithTag(Context->ZeroingBatch, UXENZEROSHARE_POOL_TAG);

        //
        //  Clear our context just to be sure that nobody gets confused and
        //  thinks that our thread is still running.
        //

        Context->EventExtant  = FALSE;
        Context->Hypercall    = FALSE;
        Context->Thread       = 0;
        Context->ZeroingBatch = 0;
    }

    return;
}

//
//  zt_zero_physical_page
//

__drv_maxIRQL(APC_LEVEL)
__drv_sameIRQL
static
void
zt_zero_physical_page(
    __in UXENZEROSHARE_ZEROING_THREAD_CONTEXT * Context,
    __in PFN_NUMBER                             PageFrameNumber
    )
{
    ULONG   flags = 0;
    KIRQL   irql  = 0;
    void  * va    =
        Context->MiMapPageInHyperSpaceWorker(PageFrameNumber, & irql, flags);

    UXENZEROSHARE_ASSERT((PageFrameNumber != END_OF_PAGE_FRAME_LIST));
    UXENZEROSHARE_ASSERT((Context->MiMapPageInHyperSpaceWorker));
    UXENZEROSHARE_ASSERT((Context->MiUnmapPageInHyperSpaceWorker));
    UXENZEROSHARE_ASSERT((va != 0));

    RtlZeroMemory(va, PAGE_SIZE);

    Context->MiUnmapPageInHyperSpaceWorker(va, irql, flags);

    return;
}


//
//  THE ZEROING THREAD
//


//
//  zt_zeroing_thread
//

__drv_functionClass(KSTART_ROUTINE)
__drv_sameIRQL
void
zt_zeroing_thread(__in void * Context)
{
    //
    //  Basic flow of the original zeroing thread
    //
    //      <a bunch of stuff that only happens early in the boot process>
    //          set the base priority and thread priority = 0 (the only thread
    //          in the system like this).
    //          on a mp system, specify a thread affinity mask
    //          locate the os initialization code that is no longer necessary
    //          free it
    //
    //      <from here on out>
    //          wait for the zeroing gate to be signaled (KeWaitForGate)
    //          check to see if there are any pages available on the free list
    //          if not, delay execution for .5 ms and check again
    //          notify the hypervisor of <something> (not really sure what):
    //          HvlNotifyLongSpinWait()
    //          wait for lock chain ownership - KxWaitForLockOwnership()
    //          acquire the performance logging spinlock
    //          log some stuff
    //          release said spinlock -
    //              KeReleaseInStackQueuedSpinLockFromDpcLevel()
    //          loop:
    //              figure out which page to zero by examining
    //                  MmFreePagesByColor[FreePageList][Color==0]
    //              unlink it from the free page chain
    //                  (MiUnlinkFreeOrZeroedPage)
    //              wait for the lock chain to sync -
    //                  KxWaitForLockChainValid
    //          release performance spinlock - PerfLogSpinLockRelease
    //          synchronize commitment stats - MiSyncCommitSignals
    //          alter thread priority (not really sure why)
    //          zero pages - MiZeroPageChain
    //          notify the hypervisor again about some long wait -
    //              HvlNotifyLongSpinWait
    //          insert pages into zeroed list - MiInsertPageInFreeOrZeroedList
    //

    ULONG                                  i;
    ULONG64                                limit;
    PFN_NUMBER                             pfn;
    int                                    rc;
    NTSTATUS                               status;
    UXENZEROSHARE_ZEROING_THREAD_CONTEXT * zs;

    UXENZEROSHARE_ENTER();
    UXENZEROSHARE_ASSERT((Context != 0));

    zs = (UXENZEROSHARE_ZEROING_THREAD_CONTEXT *) Context;

    //
    //  Check to see that the kernel variable that we use is at least a valid
    //  address.
    //
    
    UXENZEROSHARE_ASSERT((
        MmIsAddressValid(zs->MiZeroingDisabled) != FALSE
        ));

    //
    //  Assign our thread the priorities of the normal zero thread:
    //      BasePriority: 0
    //      Priority: 0
    //
    //  The only thread in the system like this (normally)!
    //

    UXENZEROSHARE_DUMP(("  setting base priority to 0...\n"));
    KeSetBasePriorityThread(KeGetCurrentThread(), 0);
    UXENZEROSHARE_DUMP(("  setting priority to 0...\n"));
    KeSetPriorityThread(KeGetCurrentThread(), 0);
    
    //
    //  Prevent the original zero thread from running without having
    //  to terminate it.
    //

    UXENZEROSHARE_DUMP((
        "  preventing original zeroing thread from running while we party...\n"
        ));

    zt_enable_system_zeroing_thread(zs, FALSE);

    zs->ZeroIndex = 0;
    limit         = 0;

    do {

        //
        //  The combination of KeWaitForGate() and
        //  MiInsertPageInFreeOrZeroedList() is key to clearing the
        //  gate correctly in order to prevent being signaled
        //  constantly and/or a deadlock eventually.
        //
        //  Formerly, we used KeWaitForMultipleObjects() here in order
        //  to allow us to unload the BrHvZeroThread driver, which was
        //  nice, but in production we'll never do that and using
        //  KeWaitForGate() instead prevents us from having to
        //  reproduce the correct functionality reuqired in order to
        //  still use KeWaitForMultipleObjects().
        //

    	if (limit == 0) {
    	    status  = zs->KeWaitForGate(zs->MmZeroingPageGate, WrFreePage, 0);

    	    //
    	    //  The system wants us to zero some pages...
    	    //
    	    //  We could be asked to zero some pages, even if there is
    	    //  none on the free list (DEMAND ZERO).
    	    //
    	    //  We only enter this area if there is at least one page
    	    //  on the free list.
    	    //

            UXENZEROSHARE_DUMP((
                "  MmFreePageListHead->Total: %I64d\n",
                zs->MmFreePageListHead->Total
                ));

    	    limit = zs->MmFreePageListHead->Total;
    	}

    	while (limit > 0) {
    
            //
            //  MiRemoveAnyPage(COLOR, 0):
            //
            //  Give me the next available page to zero, and take care
            //  of locking for me, if you wouldn't mind.
            //
            //  Since this is on amd64, COLOR is basically not used,
            //  so any value will suffice.
            //
            //  It's possible that MiRemoveAnyPage() will remove a
            //  page from something other than the free list.  This
            //  should only happen on a heavily loaded system, and
            //  shouldn't affect us, as we want as much as possible to
            //  end up on the zeroed list.
            //
            
            pfn = zs->MiRemoveAnyPage(DEFAULT_COLOR, 0);

            //
            //  Check to see if we actually were given a pfn, or a sentinel
            //  saying that there are no more pages on the free list.
            //
            
            if (pfn == END_OF_PAGE_FRAME_LIST) {
                UXENZEROSHARE_DUMP(("  no more pfn's to zero...\n"));

                //
                //  We're done here.  Get out of this loop, and start
                //  waiting for the next event (gate or terminate thread).
                //
            
                break;
            }

            zs->ZeroingBatch[zs->ZeroIndex++] = pfn;

    	    limit--;

    	    if (zs->ZeroIndex >= XENMEM_SHARE_ZERO_PAGES_MAX_BATCH) {
    		    break;
            }
    	}

    	if (zs->ZeroIndex) {
    	    if (zs->Hypercall) {
    		    rc = zt_share_zero_pages(zs->ZeroingBatch, zs->ZeroIndex);
                UXENZEROSHARE_ASSERT((rc == 0));
                if (rc != 0) {
                    UXENZEROSHARE_DUMP((
                        "  zt_share_zero_pages() returned %d\n",
                        rc
                    ));
                }
            }
    	    else {
    		    for (i=0; i < zs->ZeroIndex; i++) {
    		        zt_zero_physical_page(zs, zs->ZeroingBatch[i]);
                }
            }

    	    for (i = 0; i < zs->ZeroIndex; ++i) {
    		    zs->MiInsertPageInFreeOrZeroedList(
                    zs->ZeroingBatch[i],
                    ZeroedPageList
                    );
            }

    	    zs->ZeroIndex = 0;
    	}

        //
        //  Just keep on going until we event for thread termination
        //  is received (TerminateZeroingThread).
        //

        //
        //  Have to #pragma this out for PreFAST.
        //

#pragma warning(disable: 6319)
    } while (1,1);
#pragma warning(default: 6319)

    UXENZEROSHARE_DUMP(("  zeroing thread apparently stopped"));

    UXENZEROSHARE_LEAVE();

    return;
}


//
//  uxenzeroshare: zerothread.c
//

