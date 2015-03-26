/*
 * Copyright 2013-2015, Bromium, Inc.
 * SPDX-License-Identifier: ISC
 */

//
//  uxenzeroshare: uxenzeroshare.h
//

#ifndef _UXENZEROSHARE_H_
#define _UXENZEROSHARE_H_

//
//  The base name of the uXen zeroshare device
//
//      Kernel Mode: \\Devices\\UXENZEROSHARE_DEVICE_NAME
//      Win32 Symbolic Link:  \\DosDevices\BRHVZERO_THREAD_DEVICE_NAME
//      User Mode: \\\\.\\UXENZEROSHARE_DEVICE_NAME
//

#define UXENZEROSHARE_DEVICE_NAME    L"uxenzeroshare"

typedef enum _SYMBOL_ID {
    SymIdKeWaitForGate                      = 0,
    SymIdMiInsertPageInFreeOrZeroedList,
    SymIdMiMapPageInHyperSpaceWorker,
    SymIdMiRemoveAnyPage,
    SymIdMiUnmapPageInHyperSpaceWorker,
    SymIdMiZeroingDisabled,
    SymIdMmFreePageListHead,
    SymIdMmZeroingPageGate,

    SymIdMax,
} SYMBOL_ID, *PSYMBOL_ID;

typedef struct _SYMBOL_INFORMATION_ENTRY {
    SYMBOL_ID                        symbolId;
    ULONG                            rva;
} SYMBOL_INFORMATION_ENTRY, *PSYMBOL_INFORMATION_ENTRY;

//
//  Representation of an internal symbols used by the zero thread
//

typedef struct UXENZEROSHARE_INTERNAL_SYMBOL
{
    const wchar_t                  * Name;
    ULONG                            Rva;
    ULONG_PTR                        Va;
} UXENZEROSHARE_INTERNAL_SYMBOL;

//
//  Output parameters for querying the base address of the kernel from
//  user mode via UXENZEROSHARE_IOCTL_GET_KERNEL_BASE
//

typedef struct UXENZEROSHARE_KERNEL_BASE_INFO
{
    ULONG_PTR                        Base;
} UXENZEROSHARE_KERNEL_BASE_INFO;

//
//  Input parameters for creating the zero thread from user mode
//  via UXENZEROSHARE_IOCTL_CREATE_ZEROING_THREAD.
//

typedef struct UXENZEROSHARE_CREATE_ZEROING_THREAD_INFO
{
    BOOLEAN                         Hypercall;
} UXENZEROSHARE_CREATE_ZEROING_THREAD_INFO;

//
//  Input parameters for setting the internals information used by the
//  zeroing thread from user mode via
//  UXENZEROSHARE_IOCTL_SET_INTERNALS_INFO.
//

typedef struct UXENZEROSHARE_INTERNALS_INFO
{
    ULONG64                         BaseOfNtoskrnl;

    UXENZEROSHARE_INTERNAL_SYMBOL   KeWaitForGate;
    UXENZEROSHARE_INTERNAL_SYMBOL   MiInsertPageInFreeOrZeroedList;
    UXENZEROSHARE_INTERNAL_SYMBOL   MiMapPageInHyperSpaceWorker;
    UXENZEROSHARE_INTERNAL_SYMBOL   MiRemoveAnyPage;
    UXENZEROSHARE_INTERNAL_SYMBOL   MiUnmapPageInHyperSpaceWorker;
    UXENZEROSHARE_INTERNAL_SYMBOL   MiZeroingDisabled;
    UXENZEROSHARE_INTERNAL_SYMBOL   MmFreePageListHead;
    UXENZEROSHARE_INTERNAL_SYMBOL   MmZeroingPageGate;
} UXENZEROSHARE_INTERNALS_INFO;

#define UXENZEROSHARE_IOCTL(ID)                                                \
        CTL_CODE(0x00040000, (ID), METHOD_BUFFERED, FILE_ANY_ACCESS)


//
//  Create our zeroing thread
//

#define UXENZEROSHARE_IOCTL_CREATE_ZEROING_THREAD       UXENZEROSHARE_IOCTL(1)

//
//  Get the base address of the kernel
//

#define UXENZEROSHARE_IOCTL_GET_KERNEL_BASE             UXENZEROSHARE_IOCTL(2)

//
//  Set the internals information used by the zeroing thread
//

#define UXENZEROSHARE_IOCTL_SET_INTERNALS_INFO          UXENZEROSHARE_IOCTL(3)

//
//  CHK builds only!
//

#if (DBG == 1)

//
//  Disable the conventional zeroing thread
//

#define UXENZEROSHARE_IOCTL_DISABLE_ZEROING             UXENZEROSHARE_IOCTL(10)

//
//  Enable the conventional zeroing thread
//
                                                                           
#define UXENZEROSHARE_IOCTL_ENABLE_ZEROING              UXENZEROSHARE_IOCTL(11)

//
//  Kill our zeroing thread.
//

#define UXENZEROSHARE_IOCTL_TERMINATE_ZEROING_THREAD    UXENZEROSHARE_IOCTL(12)

#endif


//
//  Tracing, asserts and stuff like that
//

#define UXENZEROSHARE_DO_NOTHING()          do {} while(0,0)

#define UXENZEROSHARE_UNREFERENCED(NAME)    UNREFERENCED_PARAMETER(NAME)

#ifdef UXENZEROSHARE_KERNEL_MODE

#define UXENZEROSHARE_POOL_TAG              (ULONG) 'szrb'

#ifdef DBG
#define UXENZEROSHARE_DEBUG 1
#endif

#ifdef UXENZEROSHARE_DEBUG

#define UXENZEROSHARE_ASSERT(_exp_)         NT_ASSERT _exp_
#define UXENZEROSHARE_ASSERTMSG(_exp_)      NT_ASSERTMSG _exp_
#define UXENZEROSHARE_ASSERTMSGW(_exp_)     NT_ASSERTMSGW _exp_
#define UXENZEROSHARE_DUMP(_exp_)           uxen_DbgPrint _exp_

#define UXENZEROSHARE_ENTER()                                                  \
        UXENZEROSHARE_DUMP((                                                   \
            "%s(%d)!%s(): ENTER\n",                                            \
            __FILE__,                                                          \
            __LINE__,                                                          \
            __FUNCSIG__                                                        \
            ))

#define UXENZEROSHARE_LEAVE()                                                  \
        UXENZEROSHARE_DUMP((                                                   \
            "%s(%d)!%s(): LEAVE\n",                                            \
            __FILE__,                                                          \
            __LINE__,                                                          \
            __FUNCSIG__                                                        \
            ))
#else   // #ifdef UXENZEROSHARE_DEBUG

#define UXENZEROSHARE_ASSERT(_exp_)         UXENZEROSHARE_DO_NOTHING()
#define UXENZEROSHARE_ASSERTMSG(_exp_)      UXENZEROSHARE_DO_NOTHING()
#define UXENZEROSHARE_ASSERTMSGW(_exp_)     UXENZEROSHARE_DO_NOTHING()
#define UXENZEROSHARE_DUMP(_exp_)           UXENZEROSHARE_DO_NOTHING()
#define UXENZEROSHARE_ENTER()               UXENZEROSHARE_DO_NOTHING()
#define UXENZEROSHARE_LEAVE()               UXENZEROSHARE_DO_NOTHING()

#endif  // #ifdef UXENZEROSHARE_DEBUG

#else   //  #ifdef UXENZEROSHARE_KERNEL_MODE

#define UXENZEROSHARE_ENTER()               UXENZEROSHARE_DO_NOTHING()
#define UXENZEROSHARE_LEAVE()               UXENZEROSHARE_DO_NOTHING()

#ifdef UXENZEROSHARE_DEBUG

#define UXENZEROSHARE_DUMP(_exp_)           printf _exp_
#define UXENZEROSHARE_ASSERT(_exp_)         assert _exp_

#else   // #ifdef UXENZEROSHARE_DEBUG

#define UXENZEROSHARE_DUMP(_exp_)           printf _exp_
#define UXENZEROSHARE_ASSERT(_exp_)         UXENZEROSHARE_DO_NOTHING()

#endif  // #ifdef UXENZEROSHARE_DEBUG

#endif  // #ifdef UXENZEROSHARE_KERNEL_MODE

#include "libinternals/internals.h"

#endif  // #ifdef _UXENZEROSHARE_H_

//
//  uxenzeroshare: uxenzeroshare.h
//

