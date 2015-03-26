/*
 * Copyright 2013-2015, Bromium, Inc.
 * SPDX-License-Identifier: ISC
 */

//
//  uxenzeroshare: zerothread.h
//

#ifndef _ZEROTHREAD_H_
#define _ZEROTHREAD_H_

#include <ntddk.h>
#include <aux_klib.h>

#include "uxenvmlib.h"
#include "uxenzeroshare.h"

#include <xen/xen.h>

#define __XEN_TOOLS__
#include <xen/xen.h>
#include <xen/memory.h>

//
//  Function typedefs for internal system (Ke/Mi/Mm) routines used by our
//  zero thread.
//

typedef
int (* KeWaitForGate_t)(
    KGATE           * Gate,
    KWAIT_REASON      WaitReason,
    char              WaitMode
    );

typedef
void (* MiInsertPageInFreeOrZeroedList_t)(
    PFN_NUMBER        PageFrameNumber,
    MMLISTS           List
    );

typedef
void * (* MiMapPageInHyperSpaceWorker_t)(
    ULONG64           PageFrameIndex,
    KIRQL           * OldIrql,
    ULONG             Flags
    );

typedef
PFN_NUMBER   (* MiRemoveAnyPage_t)(
    ULONG             Color,
    ULONG             Flags
    );

typedef
void (* MiUnmapPageInHyperSpaceWorker_t)(
    void            * VirtualAddress,
    KIRQL             OldIrql,
    ULONG             Flags
    );

//
//  UXENZEROSHARE_ZEROING_THREAD_CONTEXT
//
//  This stucture is the represenation of all the information the zeroing
//  thread requires to operate.
//
//  It consists of three basic types of information: configuration
//  parameters, state information & internals information.
//
//  The configuration parameters control how our zero thread operates:
//      - batch mode v. one page at a time
//      - hypercall v. inline zeroing
//      - the maximum size of a batch.
//
//  The state information contains information about the thread (handles)
//  itself or used to control the thread (events), as well as the array of
//  pages to zero (in batch mode).
//
//  The internals information contains the virtual addresses of the
//  internals Windows routines/data that our zeroing thread requries to
//  function.
//
//  A global instance of this structure (g_ZeroingThreadContext) gets
//  initialized by the driver core code, based on a combination of
//  information determined by target OS version (interals information) and
//  settings passed from user mode via ioctl (configuration parameters).
//

typedef
struct UXENZEROSHARE_ZEROING_THREAD_CONTEXT
{
    //
    //  State Information
    //

    BOOLEAN                               EventExtant;
    KEVENT                                TerminateZeroingThread;
    PKTHREAD                              Thread;
    HANDLE                                ThreadHandle;
    PFN_NUMBER                          * ZeroingBatch;
    ULONG                                 ZeroIndex;

    //
    //  Configuration Parameters
    //

    BOOLEAN                               Hypercall;
    ULONG                                 ZeroingBatchSize;

    //
    //  Internals Information
    //
                                                              
    //
    //  Routines we use
    //

    KeWaitForGate_t                       KeWaitForGate;
    MiInsertPageInFreeOrZeroedList_t      MiInsertPageInFreeOrZeroedList;
    MiMapPageInHyperSpaceWorker_t         MiMapPageInHyperSpaceWorker;
    MiRemoveAnyPage_t                     MiRemoveAnyPage;
    MiUnmapPageInHyperSpaceWorker_t       MiUnmapPageInHyperSpaceWorker;

    //
    //  Globals variables we use
    //

    ULONG                               * MiZeroingDisabled;
    MMPFNLIST                           * MmFreePageListHead;
    KGATE                               * MmZeroingPageGate;
} UXENZEROSHARE_ZEROING_THREAD_CONTEXT;

//
//  External routines called by driver core.
//

//
//  Used to create the zeroing thread.
//

__drv_requiresIRQL(PASSIVE_LEVEL)
__drv_sameIRQL
__checkReturn
NTSTATUS
zt_create_zeroing_thread(
    __in PKSTART_ROUTINE                        StartRoutine,
    __in UXENZEROSHARE_ZEROING_THREAD_CONTEXT * Context
    );

//
//  Disable/enable the system's zero thread
//

__drv_maxIRQL(APC_LEVEL)
__drv_sameIRQL
void
zt_enable_system_zeroing_thread(
    __in UXENZEROSHARE_ZEROING_THREAD_CONTEXT * Context,
    __in BOOLEAN                                Enable
    );

//
//  Used to stop/terminate our zeroing thread.
//

__drv_maxIRQL(APC_LEVEL)
__drv_sameIRQL
void
zt_stop_zeroing_thread(
    __in UXENZEROSHARE_ZEROING_THREAD_CONTEXT * Context
    );

//
//  Our zeroing thread
//

__drv_functionClass(KSTART_ROUTINE)
__drv_sameIRQL
void
zt_zeroing_thread(__in void * Context);


//
//  External/global variables
//


//
//  This is the global variable that contains all the information used by
//  the zero thread.
//
//  From a Windows point of view, this should really be part of the device
//  extension; however, as the idea was to decouple the zeroing from the
//  driver so that we might integrate the zeroing with the balloon driver,
//  I broke it out separately, to make integration easier.
//
//  Since we are running ONLY on a UP, it makes no difference in terms of
//  synchronization/correctness.
//

extern  UXENZEROSHARE_ZEROING_THREAD_CONTEXT    g_ZeroingThreadContext;

#endif  // #ifdef _ZEROTHREAD_H_

//
//  uxenzeroshare: zerothread.h
//
