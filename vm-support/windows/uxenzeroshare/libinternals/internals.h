/*
 * Copyright 2013-2015, Bromium, Inc.
 * SPDX-License-Identifier: ISC
 */

//
//  uxenzeroshare: internals.h
//

#ifndef _INTERNALS_H_
    #define _INTERNALS_H_
    #ifdef __cplusplus
        extern "C" {
    #endif

    #ifdef UXENZEROSHARE_KERNEL_MODE
        //
        //  MEMDIV_STUB_DEFINITION_XXX
        //
        //  These macros are used to provide temporary declarations of UDT fields
        //  whose types are known, but we're either not chosing to declare at this point
        //  in time, or depend on underlying types that we are chosing not to declare at
        //  this point in time.
        //
        //  They allow us to provide a correctly named, layout size correct member,
        //  while allowing us to postpone full declaration until we need to do so/
        //  feel like doing it, while also preserving (textually) the true underlying
        //  type so that we don't have to go look it up later.
        //
        //  The first parameter of each of these is the actual type.  It is not used
        //  at all.
        //
        //  The second parameter is the name of the member;
        //
        //  The third parameter, if present, is the number of elements
        //

        #define MEMDIV_STUB_DEFINITION_PTR(X,Y)             void        *   Y
        #define MEMDIV_STUB_DEFINITION_PTR_ARRAY(X, Y, Z)   MEMDIV_STUB_DEFINITION_PTR(X, Y[Z])
        #define MEMDIV_STUB_DEFINITION_SIZE(X, Y, Z)        unsigned char   Y[Z]

        //
        //  Convenience macros for disabling/enabling various compiler (CL) warnings.
        //

        //
        //  Warning (/W4) about the presence of a (nested) anonymous structure/union.
        //

        #define MEMDIV_WARNING_ANONYMOUS_UDT                            4201

        //
        //  Warning (/W4) about a bitfield being of a type other than 'int.'
        //

        #define MEMDIV_WARNING_BITFIELD_NOT_OF_TYPE_INT                 4214

        //
        //  Warning (/W4) about an anonymous union not declaring any members
        //

        #define MEMDIV_WARNING_ANONYMOUS_UNION_WITH_NO_MEMBERS          4408

        //
        //  START: Page table entry types
        //

        //
        //  These are used to represent the various forms of page directory/table entries
        //  used by windows.
        //

        //
        //  HARDWARE_PTE
        //

        #pragma warning(push)
        #pragma warning(disable: MEMDIV_WARNING_BITFIELD_NOT_OF_TYPE_INT)
        typedef struct HARDWARE_PTE
        {
            ULONGLONG	                    Valid:1;
            ULONGLONG	                    Write:1;
            ULONGLONG	                    Owner:1;
            ULONGLONG	                    WriteThrough:1;
            ULONGLONG	                    CacheDisable:1;
            ULONGLONG	                    Accessed:1;
            ULONGLONG	                    Dirty:1;
            ULONGLONG	                    LargePage:1;
            ULONGLONG	                    Global:1;
            ULONGLONG	                    CopyOnWrite:1;
            ULONGLONG	                    Prototype:1;
            ULONGLONG	                    reserved0:1;
            ULONGLONG	                    PageFrameNumber:36;
            ULONGLONG	                    reserved1:4;
            ULONGLONG	                    SoftwareWsIndex:11;
            ULONGLONG	                    NoExecute:1;
        } HARDWARE_PTE;

        //
        //  MMPTE_HARDWARE
        //

        typedef struct MMPTE_HARDWARE
        {
        	ULONGLONG						Valid:1;
        	ULONGLONG						Dirty1:1;
        	ULONGLONG						Owner:1;
        	ULONGLONG						WriteThrough:1;
        	ULONGLONG						CacheDisable:1;
        	ULONGLONG						Accessed:1;
        	ULONGLONG						Dirty:1;
        	ULONGLONG						LargePage:1;
        	ULONGLONG						Global:1;
        	ULONGLONG						CopyOnWrite:1;
        	ULONGLONG						Unused:1;
        	ULONGLONG						Write:1;
        	ULONGLONG						PageFrameNumber:36;
        	ULONGLONG						reserved1:4;
        	ULONGLONG						SoftwareWsIndex:11;
        	ULONGLONG						NoExecute:1;
        } MMPTE_HARDWARE;

        //
        //  MMPTE_LIST
        //

        typedef struct MMPTE_LIST
        {
        	ULONGLONG						Valid:1;
        	ULONGLONG						OneEntry:1;
        	ULONGLONG						filler0:3;
        	ULONGLONG						Protection:5;
        	ULONGLONG						Prototype:1;
        	ULONGLONG						Transition:1;
        	ULONGLONG						filler1:20;
        	ULONGLONG						NextEntry:32;
        } MMPTE_LIST;
        
        //
        //  MMPTE_PROTOTYPE
        //
        //  This is used to represent a prototype page table entry
        //

        typedef struct MMPTE_PROTOTYPE
        {
        	ULONGLONG						Valid:1;
        	ULONGLONG						Unused0:7;
        	ULONGLONG						ReadOnly:1;
        	ULONGLONG						Unused1:1;
        	ULONGLONG						Prototype:1;
        	ULONGLONG						Protection:5;
        	ULONGLONG						ProtoAddress:48;
        } MMPTE_PROTOTYPE;
        
        //
        //  MMPTE_SOFTWARE
        //

        typedef struct MMPTE_SOFTWARE
        {
        	ULONGLONG						Valid:1;
        	ULONGLONG						PageFileLow:4;
        	ULONGLONG						Protection:5;
        	ULONGLONG						Prototype:1;
        	ULONGLONG						Transition:1;
        	ULONGLONG						UsedPageTableEntries:10;
        	ULONGLONG						InStore:1;
        	ULONGLONG						Reserved:9;
        	ULONGLONG						PageFileHigh:32;
        } MMPTE_SOFTWARE;

        //
        //  MMPTE_SUBSECTION
        //

        typedef struct MMPTE_SUBSECTION
        {
        	ULONGLONG						Valid:1;
        	ULONGLONG						Unused0:4;
        	ULONGLONG						Protection:5;
        	ULONGLONG						Prototype:1;
        	ULONGLONG						Unused1:5;
        	ULONGLONG						SubsectionAddress:48;
        } MMPTE_SUBSECTION;

        //
        //  MMPTE_TIMESTAMP
        //

        typedef struct MMPTE_TIMESTAMP
        {
        	ULONGLONG						MustBeZero:1;
        	ULONGLONG						PageFileLow:4;
        	ULONGLONG						Protection:5;
        	ULONGLONG						Prototype:1;
        	ULONGLONG						Transition:1;
        	ULONGLONG						Reserved:20;
        	ULONGLONG						GlobalTimeStamp:32;
        } MMPTE_TIMESTAMP;
        
        //
        //  MMPTE_TRANSITION
        //

        typedef struct MMPTE_TRANSITION
        {
        	ULONGLONG						Valid:1;
        	ULONGLONG						Write:1;
        	ULONGLONG						Owner:1;
        	ULONGLONG						WriteThrough:1;
        	ULONGLONG						CacheDisable:1;
        	ULONGLONG						Protection:5;
        	ULONGLONG						Prototype:1;
        	ULONGLONG						Transition:1;
        	ULONGLONG						PageFrameNumber:36;
        	ULONGLONG						Unused:16;
        } MMPTE_TRANSITION;
        #pragma warning(pop)
        
        //
        //  MMPTE
        //

        typedef union MMPTE
        {
            ULONGLONG                       Long;
            ULONGLONG                       VolatileLong;
            MMPTE_HARDWARE                  Hard;
            HARDWARE_PTE                    Flush;
            MMPTE_PROTOTYPE                 Proto;
            MMPTE_SOFTWARE                  Soft;
            MMPTE_TIMESTAMP                 TimeStamp;
            MMPTE_TRANSITION                Trans;
            MMPTE_SUBSECTION                Subsect;
            MMPTE_LIST                      List;
        } MMPTE;
        
        //
        //  END: Page table entry types
        //

        //
        //  START: Page frame database types
        //

        //
        //  Page frame index
        //

#ifdef AMD64
        typedef ULONGLONG   PFN_NUMBER;
#endif

        //
        //  Working set list index
        //

        typedef ULONG       WSLE_NUMBER;

        //
        //  MMPFNENTRY
        //

        #pragma warning(push)
        #pragma warning(disable: MEMDIV_WARNING_BITFIELD_NOT_OF_TYPE_INT)

        typedef struct MMPFNENTRY
        {
            USHORT  PageLocation:3;
            USHORT  WriteInProgress:1;
            USHORT  Modified:1;
            USHORT  ReadInProgress:1;
            USHORT  CacheAttribute:2;
            USHORT  Priority:3;
            USHORT  Rom:1;
            USHORT  InPageError:1;
            USHORT  KernelStack:1;
            USHORT  RemovalRequested:1;
            USHORT  ParityError:1;
        } MMPFNENTRY;
        
        #pragma warning(pop)

        //
        //  MMLISTS
        //

        typedef enum MMLISTS
        {
            ZeroedPageList              =   0,
            FreePageList                =   1,
            StandbyPageList             =   2,
            ModifiedPageList            =   3,
            ModifiedNoWritePageList     =   4,
            BadPageList                 =   5,
            ActiveAndValid              =   6,
            TransitionPage              =   7,

            NumberOfPageLists           =   TransitionPage
        } MMLISTS;
        
        //
        //  struct MMPFNLIST
        //
        //  This is the representation for the head of all the various memory block
        //  lists - Zero, Active, etc.
        //
        //  Documented: no
        //      Public: yes
        //
        //  MMLISTS:
        //      nt!MmModifiedPageListHead
        //      nt!MmModifiedNoWritePageListHead
        //      nt!MmFreePageListHead
        //      nt!MmZeroedPageListHead
        //      nt!MmBadPageListHead
        //      nt!MmStandbyPageListHead
        //

        typedef struct MMPFNLIST
        {
            ULONGLONG               Total;
            MMLISTS                 ListName;
            PFN_NUMBER              Flink;
            PFN_NUMBER              Blink;
        } MMPFNLIST;

        //
        //  struct MMPFN
        //
        //  This is the represenation of a page frame.
        //
        //  Documented: no
        //      Public: yes
        //

        typedef struct MMPFN
        {
            union
            {
                PFN_NUMBER                      Flink;
                WSLE_NUMBER                     WsIndex;
                KEVENT                      *   Event;
                NTSTATUS                        ReadStatus;
                SINGLE_LIST_ENTRY               NextStackPfn;
            } u1;

            union
            {
                PFN_NUMBER                      Blink;
                ULONG_PTR                       ShareCount;
            } u2;

            #pragma warning(push)
            #pragma warning(disable: MEMDIV_WARNING_ANONYMOUS_UDT)
            #pragma warning(disable: MEMDIV_WARNING_BITFIELD_NOT_OF_TYPE_INT)

            union
            {
                MMPTE                       *   PteAddress;
                void                        *   VolatilePteAddress;
                ULONG                           Lock;
                ULONG64                         PteLong;
            };
            
            union
            {
                struct
                {
                    USHORT                      ReferenceCount;
                    MMPFNENTRY                  e1;
                };

                struct
                {
                    USHORT                      ShortFlags;
                    USHORT                      ReferenceCount;
                } e2;
            } u3;

            #if defined (_WIN64)
                USHORT                          UsedPageTableEntries;
                UCHAR                           VaType;
                UCHAR                           VaCount;
            #endif
            
            union
            {
                MMPTE                       *   OriginalPte;
                LONG                            AweReferenceCount;
            };

            union
            {
                ULONG_PTR                       EntireFrame;

                struct
                {
                    #if defined (_WIN64)
                        ULONG_PTR               PteFrame:58;
                    #else
                        ULONG_PTR               PteFrame:26;
                    #endif
                    ULONG_PTR                   InPageError:1;
                    ULONG_PTR                   VerifierAllocation:1;
                    ULONG_PTR                   AweAllocation:1;
                    ULONG_PTR                   LockCharged:1;
                    ULONG_PTR                   KernelStack:1;
                    ULONG_PTR                   MustBeCached:1;
                };
            } u4;
            #pragma warning(pop)
        } MMPFN;
        
        //
        //  END: Page frame database types
        //
    #endif

    void    int_dump_internals_info(const UXENZEROSHARE_INTERNALS_INFO * Internals);
    void    int_validate_internals_info(const UXENZEROSHARE_INTERNALS_INFO * Internals);

    #ifdef __cplusplus
        }
    #endif
#endif

//
//  uxenzeroshare: internals.h
//

