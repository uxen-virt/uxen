/*
 * Copyright 2013-2015, Bromium, Inc.
 * SPDX-License-Identifier: ISC
 */

/* uxenplatform: balloon.c */

#include <initguid.h>
#include <ntddk.h>
#include <wdf.h>

#include "uxenvmlib.h"

#include "platform.h"
#include "platform_public.h"
#include <uxen/platform_interface.h>

#include "balloon.h"

#ifdef DBG
#define UXENPLATFORM_BALLOON_MSG(_exp_) uxen_debug _exp_
#define DUMP_PAGES_LIST_NODE(_node_, _recursive_) \
        dump_pages_list_node((_node_), (_recursive_))
#else
#define UXENPLATFORM_BALLOON_MSG(_exp_)
#define DUMP_PAGES_LIST_NODE(_node_, _recursive_)
#endif

#define UXENPLATFORM_BALLOON_ASSERT(_exp_) ASSERT _exp_

#define UXENPLATFORM_BALLOON_ENTER() \
        UXENPLATFORM_BALLOON_MSG(( \
        "%s[%u]!%s\n", __FILE__, __LINE__, __FUNCTION__))

/*
    BALLOON_PAGES_LIST_NODE

    Describes and entry in the list of pages used in the balloon.
*/

struct balloon_pages_list_node {
    LIST_ENTRY                          list_entry;
    MDL                               * mdl;
};

/*
    BALLOON_STATE

    State information and preformance statistics about the balloon.
*/

struct balloon_state {
    ULONG                               current_size_mb;
    ULONG                               target_size_mb;
    ULONG                               maximum_number_of_retries;
    ULONG                               retry_delay_in_ms;

    /*  All purpose lock (I don't think this is actually necessary).    */
    KGUARDED_MUTEX                    * lock;
    
    /*
        List of physical pages used by the balloon.
    
        The list consists of MDL's connected by their "Next" field.
    */
    struct balloon_pages_list_node    * pages;

    /*  Timer used for allocation retries. */
    KTIMER                            * timer;
};

/*  Private function prototypes */

__drv_maxIRQL(APC_LEVEL)
__drv_sameIRQL
__checkReturn
static
NTSTATUS
add_pages(
        void
    );

__drv_sameIRQL
static
void
dump_pages_list_node(
    __in const struct balloon_pages_list_node * const node,
    __in BOOLEAN                               recursive
    );

__drv_sameIRQL
static
void
dump_statistics(
    __in const struct uxen_platform_balloon_statistics * const statistics
    );

__drv_sameIRQL
__checkReturn
static
BOOLEAN
is_initialized(void);

__drv_sameIRQL
__checkReturn
static
const struct balloon_pages_list_node *
pages_list_node(
    __in const LIST_ENTRY * const list_entry
    );

__drv_sameIRQL
__checkReturn
static
const struct balloon_pages_list_node *
pages_list_next_node(
    __in const struct balloon_pages_list_node * const node
    );

__drv_maxIRQL(APC_LEVEL)
__drv_sameIRQL
__checkReturn
static
NTSTATUS
remove_pages(
        void
    );

__drv_maxIRQL(APC_LEVEL)
__drv_sameIRQL
__checkReturn
static
int
share_pages(
    __in const MDL * const mdl
    );

/*
    UXENPLATFORM_BALLOON_INITIALIZATION_CHECK()

    Check to see if the balloon has been initialized.

    In FRE builds, return the specified status (if any) if not initialized.

    In CHK builds, assert() if not initialized.
*/

#define UXENPLATFORM_BALLOON_INITIALIZATION_CHECK(...)                        \
    {                                                                         \
        UXENPLATFORM_BALLOON_ASSERT((is_initialized()));                      \
        if (! is_initialized()) {                                             \
            UXENPLATFORM_BALLOON_MSG(("  balloon uninitialized - aborting")); \
            return __VA_ARGS__;                                               \
        }                                                                     \
    }

/*  
    UXENPLATFORM_BALLOON_DUMP_MDL_FLAG()

    Helper to test which mdl flags are set and dump that information.
*/

#define UXENPLATFORM_BALLOON_DUMP_MDL_FLAG(_flags_, _flag_)             \
        if ((_flags_) & (_flag_)) {                                     \
            UXENPLATFORM_BALLOON_MSG(("               " #_flag_ "\n")); \
            (_flags_) &= ~(_flag_);                                     \
        }


/*  Balloon state   */

static const ULONG             kBalloonMemoryTag = (ULONG) 'bpxu';
static struct balloon_state    state;

/*  Public interface    */

/*
    balloon_cleanup()

    Free all memory involved in ballooning.
*/

__drv_requiresIRQL(PASSIVE_LEVEL)
__drv_sameIRQL
__checkReturn
NTSTATUS
balloon_cleanup()
{
    NTSTATUS    status = STATUS_SUCCESS;

    UXENPLATFORM_BALLOON_ENTER();
    UXENPLATFORM_BALLOON_INITIALIZATION_CHECK(STATUS_INVALID_DEVICE_STATE);

    KeAcquireGuardedMutex(state.lock);
    state.target_size_mb = 0;
    status = remove_pages();
    KeReleaseGuardedMutex(state.lock);
    ExFreePool(state.lock);

    KeCancelTimer(state.timer);
    ExFreePool(state.timer);

    memset(& state, 0, sizeof(state));

    return status;
}

/*
    balloon_get_configuration()

    Retrieve the current balloon configuration.
*/

__drv_maxIRQL(APC_LEVEL)
__drv_sameIRQL
__checkReturn
NTSTATUS
balloon_get_configuration(
    __out struct uxen_platform_balloon_configuration * const configuration
    )
{
    UXENPLATFORM_BALLOON_INITIALIZATION_CHECK(STATUS_INVALID_DEVICE_STATE);

    KeAcquireGuardedMutex(state.lock);
    configuration->maximum_number_of_retries = state.maximum_number_of_retries;
    configuration->retry_delay_in_ms         = state.retry_delay_in_ms;
    configuration->target_size_mb            = state.target_size_mb;
    KeReleaseGuardedMutex(state.lock);

    return STATUS_SUCCESS;
}

/*
    balloon_get_statistics()

    Retrieves current balloon statistics.
*/

__drv_maxIRQL(APC_LEVEL)
__drv_sameIRQL
__checkReturn
NTSTATUS
balloon_get_statistics(
    __out struct uxen_platform_balloon_statistics * const statistics
    )
{
    UXENPLATFORM_BALLOON_ASSERT((statistics));
    UXENPLATFORM_BALLOON_INITIALIZATION_CHECK(STATUS_INVALID_DEVICE_STATE);

    memset(statistics, 0, sizeof(* statistics));

    KeAcquireGuardedMutex(state.lock);
    statistics->current_size_mb = state.current_size_mb;
    KeReleaseGuardedMutex(state.lock);

    return STATUS_SUCCESS;
}

/*
    balloon_init()

    Initializes the balloon.
*/

__drv_maxIRQL(APC_LEVEL)
__drv_sameIRQL
__checkReturn
NTSTATUS
balloon_init(void)
{
    UXENPLATFORM_BALLOON_ENTER();
    UXENPLATFORM_BALLOON_ASSERT((! is_initialized()));

    uxen_msg("begin");

    if (is_initialized()) {
        UXENPLATFORM_BALLOON_MSG(("  balloon already initialized\n"));

        return STATUS_INVALID_DEVICE_STATE;
    }

    memset(& state, 0, sizeof(state));

    state.lock = (KGUARDED_MUTEX *) ExAllocatePoolWithTag(NonPagedPool,
        sizeof(KGUARDED_MUTEX), kBalloonMemoryTag);
    UXENPLATFORM_BALLOON_ASSERT((state.lock != 0));
    if (! state.lock) {
        uxen_err("couldn't allocate memory for lock");

        return STATUS_INSUFFICIENT_RESOURCES;
    }

    KeInitializeGuardedMutex(state.lock);

    state.timer = (KTIMER *)
        ExAllocatePoolWithTag(NonPagedPool, sizeof(KTIMER), kBalloonMemoryTag);
    UXENPLATFORM_BALLOON_ASSERT((state.timer != 0));
    if (! state.timer) {
        uxen_err("couldn't allocate memory for timer");

        ExFreePool(state.lock);

        return STATUS_INSUFFICIENT_RESOURCES;
    }

    KeInitializeTimer(state.timer);

    uxen_msg("end");

    return STATUS_SUCCESS;
}

/*
    balloon_set_configuration()

    Configure operation of the balloon.
*/

__drv_maxIRQL(APC_LEVEL)
__drv_sameIRQL
__checkReturn
NTSTATUS
balloon_set_configuration(
    __in const struct uxen_platform_balloon_configuration * const configuration
    )
{
    NTSTATUS    status = STATUS_SUCCESS;

    UXENPLATFORM_BALLOON_ASSERT((configuration));
    UXENPLATFORM_BALLOON_INITIALIZATION_CHECK(STATUS_INVALID_DEVICE_STATE);


    KeAcquireGuardedMutex(state.lock);
    state.maximum_number_of_retries = configuration->maximum_number_of_retries;
    state.retry_delay_in_ms         = configuration->retry_delay_in_ms;
    state.target_size_mb            = configuration->target_size_mb;

    if (state.target_size_mb > state.current_size_mb) {
        status = add_pages();
    }
    else if (state.target_size_mb < state.current_size_mb) {
        status = remove_pages();
    }
    KeReleaseGuardedMutex(state.lock);

    return status;
}


/*  Private stuff   */


/*
    add_pages()

    Adds the specified number of pages to the balloon 
*/

__drv_maxIRQL(APC_LEVEL)
__drv_sameIRQL
__checkReturn
static
NTSTATUS
add_pages(void)
{
    PHYSICAL_ADDRESS    maximum_address;
    MDL               * mdl;
    PHYSICAL_ADDRESS    minimum_address;
    int                 rc;
    ULONG               retries = 0;
    LARGE_INTEGER       retry_delay;
    PHYSICAL_ADDRESS    skip_bytes;
    const SIZE_T        one_mb = 1 << 20;
    
    UXENPLATFORM_BALLOON_ENTER();
    UXENPLATFORM_BALLOON_INITIALIZATION_CHECK(STATUS_INVALID_DEVICE_STATE);
    
    maximum_address.QuadPart = (0x100000 << PAGE_SHIFT) -1 ;
    minimum_address.QuadPart = 0;
    skip_bytes.QuadPart = 0;

    while (state.current_size_mb < state.target_size_mb) {

        mdl = MmAllocatePagesForMdlEx(
            minimum_address,
            maximum_address,
            skip_bytes,
            one_mb,
            MmCached,
            MM_DONT_ZERO_ALLOCATION
            );

        if (!mdl || MmGetMdlByteCount(mdl) < one_mb) {
            if (!mdl) {
                UXENPLATFORM_BALLOON_MSG(("  warning no mdl returned\n"));
            } else {
                UXENPLATFORM_BALLOON_MSG((
                    "  warning: %u pages requested, only %u pages allocated!\n",   
                    one_mb / PAGE_SIZE, 
                    (ULONG) MmGetMdlByteCount(mdl) / PAGE_SIZE
                    ));
                /* We want nothing less than one_mb sized MDLs. */
                MmFreePagesFromMdl(mdl);
                ExFreePool(mdl);
            }

            if (retries++ >= state.maximum_number_of_retries) {
                return STATUS_INSUFFICIENT_RESOURCES;
            }

            UXENPLATFORM_BALLOON_MSG((
                        "  waiting for %u [0x%.08X] ms before trying to allocate again",
                        state.retry_delay_in_ms,
                        state.retry_delay_in_ms
                        ));

            retry_delay.QuadPart = - ((LONG64) state.retry_delay_in_ms * 10000);
            KeSetTimer(state.timer, retry_delay, NULL);
            KeWaitForSingleObject( state.timer, Executive, KernelMode, FALSE,
                    NULL);

            UXENPLATFORM_BALLOON_MSG(("  retry allocation\n"));

        } else {

            rc = share_pages(mdl);
            UXENPLATFORM_BALLOON_ASSERT((! rc));
            if (rc) {
                MmFreePagesFromMdl(mdl);
                ExFreePool(mdl);
                return rc;
            }

            state.current_size_mb++;
        }
    }

    return STATUS_SUCCESS;
}

/*
    dump_pages_list_node()

    Dumps information about a BALLOON_PAGES_LIST_NODE to the kd.
*/

__drv_sameIRQL
static
void
dump_pages_list_node(
    __in const struct balloon_pages_list_node * const node,
    __in BOOLEAN recursive
    )
{
    CSHORT                          flags;
    const MDL                     * mdl;
    const struct balloon_pages_list_node * next_node;
    
    UXENPLATFORM_BALLOON_ENTER();
    UXENPLATFORM_BALLOON_ASSERT((node));
    UXENPLATFORM_BALLOON_ASSERT((state.pages != 0));

    mdl   = node->mdl;
    UXENPLATFORM_BALLOON_ASSERT((mdl != 0));
    flags = mdl->MdlFlags;

    UXENPLATFORM_BALLOON_MSG(("  dumping mdl: 0x%.016p\n", mdl));
    UXENPLATFORM_BALLOON_MSG(("              Next: 0x%.016p\n", mdl->Next));
    UXENPLATFORM_BALLOON_MSG((
        "              Size: %hd [0x%.04hX]\n", mdl->Size, mdl->Size
    ));
    UXENPLATFORM_BALLOON_MSG(("             Flags: 0x%.04hX\n", flags));
    UXENPLATFORM_BALLOON_DUMP_MDL_FLAG(flags, MDL_ALLOCATED_FIXED_SIZE);
    UXENPLATFORM_BALLOON_DUMP_MDL_FLAG(flags, MDL_ALLOCATED_MUST_SUCCEED);
    UXENPLATFORM_BALLOON_DUMP_MDL_FLAG(flags, MDL_DESCRIBES_AWE);
    UXENPLATFORM_BALLOON_DUMP_MDL_FLAG(flags, MDL_FREE_EXTRA_PTES);
    UXENPLATFORM_BALLOON_DUMP_MDL_FLAG(flags, MDL_INTERNAL);
    UXENPLATFORM_BALLOON_DUMP_MDL_FLAG(flags, MDL_IO_PAGE_READ);
    UXENPLATFORM_BALLOON_DUMP_MDL_FLAG(flags, MDL_IO_SPACE);
    UXENPLATFORM_BALLOON_DUMP_MDL_FLAG(flags, MDL_MAPPED_TO_SYSTEM_VA);
    UXENPLATFORM_BALLOON_DUMP_MDL_FLAG(flags, MDL_MAPPING_CAN_FAIL);
    UXENPLATFORM_BALLOON_DUMP_MDL_FLAG(flags, MDL_NETWORK_HEADER);
    UXENPLATFORM_BALLOON_DUMP_MDL_FLAG(flags, MDL_PAGES_LOCKED);
    UXENPLATFORM_BALLOON_DUMP_MDL_FLAG(flags, MDL_PARENT_MAPPED_SYSTEM_VA);
    UXENPLATFORM_BALLOON_DUMP_MDL_FLAG(flags, MDL_PARTIAL);
    UXENPLATFORM_BALLOON_DUMP_MDL_FLAG(flags, MDL_PARTIAL_HAS_BEEN_MAPPED);
    UXENPLATFORM_BALLOON_DUMP_MDL_FLAG(flags, MDL_SOURCE_IS_NONPAGED_POOL);
    UXENPLATFORM_BALLOON_DUMP_MDL_FLAG(flags, MDL_WRITE_OPERATION);

    if (flags) {
        UXENPLATFORM_BALLOON_MSG((
            "               UNKNOWN FLAGS: 0x%.04hX\n", flags
        ));
    }

    UXENPLATFORM_BALLOON_MSG(("           Process: 0x%.016p\n", mdl->Process));
    UXENPLATFORM_BALLOON_MSG((
        "    MappedSystemVa: 0x%.016p\n", mdl->MappedSystemVa));
    UXENPLATFORM_BALLOON_MSG(("           StartVa: 0x%.016p\n", mdl->StartVa));
    UXENPLATFORM_BALLOON_MSG((
        "         ByteCount: %u [0x%.08X]\n", mdl->ByteCount, mdl->ByteCount
    ));
    UXENPLATFORM_BALLOON_MSG((
        "        ByteOffset: %u [0x%.08X]\n", mdl->ByteOffset, mdl->ByteOffset
    ));
    UXENPLATFORM_BALLOON_MSG(("\n"));

    if (recursive && node->list_entry.Flink != & state.pages->list_entry) {
        next_node = pages_list_next_node(node);
        dump_pages_list_node(next_node, recursive);
    }
}

/*
    dump_statistics()

    Dump balloon statistics to the KD.
*/

__drv_sameIRQL
static
void
dump_statistics(
    __in const struct uxen_platform_balloon_statistics * const statistics
    )
{
    UXENPLATFORM_BALLOON_ASSERT((statistics != 0));

    statistics;

    UXENPLATFORM_BALLOON_MSG(("\nballoon statistics:\n"));
    UXENPLATFORM_BALLOON_MSG((
        "       current_size_mb: %u [0x%.08X]\n",
        statistics->current_size_mb,
        statistics->current_size_mb
    ));
    UXENPLATFORM_BALLOON_MSG(("\n"));
}

/*
    is_initialized()

    Returns whether the balloon has been initialized or not.
*/

__drv_sameIRQL
__checkReturn
static
BOOLEAN
is_initialized(void)
{
    return state.lock != 0;
}

/*
    pages_list_node()

    Returns the node entry for a give LIST_ENTRY.
*/

__drv_sameIRQL
__checkReturn
static
const struct balloon_pages_list_node *
pages_list_node(__in const LIST_ENTRY * const list_entry)
{
    UXENPLATFORM_BALLOON_ASSERT((list_entry != 0));

    return CONTAINING_RECORD(list_entry, struct balloon_pages_list_node,
        list_entry);
}

/*
    pages_list_next_node()

    Returns the next node in the pages list.

    Returns NULL if there are no more entries.
*/

__drv_sameIRQL
__checkReturn
static
const struct balloon_pages_list_node *
pages_list_next_node(__in const struct balloon_pages_list_node * const node)
{
    UXENPLATFORM_BALLOON_ASSERT((node != 0));

    if (node->list_entry.Flink == & state.pages->list_entry) {
        return NULL;
    }

    return pages_list_node(node->list_entry.Flink);
}

/*
    remove_pages()

    Removes the specified number of pages from the balloon after
    informing the hypervisor.
*/

__drv_maxIRQL(APC_LEVEL)
__drv_sameIRQL
__checkReturn
static
NTSTATUS
remove_pages(void)
{
    MDL                     * mdl;
    struct balloon_pages_list_node * node;

    UXENPLATFORM_BALLOON_ENTER();

    UXENPLATFORM_BALLOON_INITIALIZATION_CHECK(STATUS_INVALID_DEVICE_STATE);

    while (state.current_size_mb > state.target_size_mb) {
        node = (struct balloon_pages_list_node *)
            pages_list_node(RemoveTailList(& state.pages->list_entry));
        UXENPLATFORM_BALLOON_ASSERT((node != 0));
        mdl = node->mdl;
        UXENPLATFORM_BALLOON_ASSERT((mdl));

        MmFreePagesFromMdl(mdl);
        ExFreePool(mdl);
        ExFreePool(node);
        if (node == state.pages) {
            state.pages = 0;
        }

        state.current_size_mb--;
    }

    return STATUS_SUCCESS;
}

/*
    share_pages()

    Tells the hypervisor which pages are being used by the
    balloon.
*/

__drv_maxIRQL(APC_LEVEL)
__drv_sameIRQL
__checkReturn
static
int
share_pages(__in const MDL * const mdl)
{
    static xen_pfn_t                * gpfn_list      = NULL;
    static xen_pfn_t                  gpfn_list_gpfn = 0;
    static const ULONG                batch_size     = 
        PAGE_SIZE / sizeof(PFN_NUMBER);
    unsigned int                      gpfn;
    const PFN_NUMBER                * gpfns;
    //ULONG                             i;
    ULONG                             batch_number;
    struct balloon_pages_list_node  * node;
    ULONG                             number_of_pages;
    int                               rc            = 0;

    UXENPLATFORM_BALLOON_ENTER();
    UXENPLATFORM_BALLOON_ASSERT((mdl));
    UXENPLATFORM_BALLOON_INITIALIZATION_CHECK(1);
    UXENPLATFORM_BALLOON_ASSERT((
        batch_size == XENMEM_SHARE_ZERO_PAGES_MAX_BATCH));

    gpfns           = MmGetMdlPfnArray(mdl);
    UXENPLATFORM_BALLOON_ASSERT((gpfns));
    number_of_pages = (MmGetMdlByteCount(mdl) >> PAGE_SHIFT);

    UXENPLATFORM_BALLOON_MSG(("  MmGetMdlByteCount(Mdl)==%lu [0x%.08lX]\n",
        MmGetMdlByteCount(mdl),
        MmGetMdlByteCount(mdl)
    ));
    UXENPLATFORM_BALLOON_MSG(("  number_of_pages==%lu [0x%.08lX]\n",
        number_of_pages,
        number_of_pages
    ));
    UXENPLATFORM_BALLOON_ASSERT((number_of_pages));

    if (gpfn_list == NULL) {
        UXENPLATFORM_BALLOON_MSG(("  no gpfn list allocated.  allocating\n"));
	    gpfn_list = (xen_pfn_t *) uxen_malloc_locked_pages(1, & gpfn, 0);
	    if (gpfn_list == NULL) {
            UXENPLATFORM_BALLOON_MSG(("  couldn't allocate gpfn_list\n"));
            return (int) STATUS_INSUFFICIENT_RESOURCES;
        }

	    gpfn_list_gpfn = gpfn;
    }

    batch_number = 0;

    node = (struct balloon_pages_list_node *)
        ExAllocatePoolWithTag(NonPagedPool, sizeof(* node), kBalloonMemoryTag);
    UXENPLATFORM_BALLOON_ASSERT((node != 0));
    if (! node) {
        UXENPLATFORM_BALLOON_MSG((
            "  couldn't allocate memory for balloon pages list node\n"
        ));

        return (int) STATUS_INSUFFICIENT_RESOURCES;
    }

    while (number_of_pages) {
        xen_memory_share_zero_pages_t xmszp;
        ULONG i;

        UXENPLATFORM_BALLOON_MSG((
            "  batch[%u]: %u pages\n",
            batch_number,
            min(batch_size, number_of_pages)
        ));
        for (i = 0; i < min(batch_size, number_of_pages); i++) {
            UXENPLATFORM_BALLOON_MSG((" pfn: 0x%.016I64X\n",
                gpfns[batch_number * batch_size + i]));
    	    gpfn_list[i] = gpfns[batch_number * batch_size + i];
        }

        xmszp.nr_gpfns       = min(batch_size, number_of_pages);
        xmszp.gpfn_list_gpfn = gpfn_list_gpfn;

        UXENPLATFORM_BALLOON_MSG(("  issuing ballooning hypercall - "
            "%s(XENMEM_share_zero_pages, xmszp):\n",
            __FUNCTION__
        ));
        UXENPLATFORM_BALLOON_MSG(("    xmszp.nr_gpfns: %lu [0x%.08X]\n",
            xmszp.nr_gpfns,
            xmszp.nr_gpfns
        ));
        UXENPLATFORM_BALLOON_MSG((
            "    xmszp.gpfn_list_gpfn: %I64u [0x%.016I64X]\n",
            xmszp.gpfn_list_gpfn,
            xmszp.gpfn_list_gpfn
        ));

        rc = uxen_hypercall_memory_op(XENMEM_share_zero_pages, & xmszp);
        if (rc) {
            UXENPLATFORM_BALLOON_MSG((
                "  ballooning hypercall returned %d\n", rc));

            ExFreePoolWithTag(node, kBalloonMemoryTag);

            return rc;
        }
        else {
            UXENPLATFORM_BALLOON_MSG((
                "  ballooning hypercall returned successfully\n"));
        }

        batch_number++;
        number_of_pages -= min(batch_size, number_of_pages);
    }

    node->mdl = (MDL *) mdl;

    if (state.pages == 0) {
        InitializeListHead(& node->list_entry);
        state.pages = node;
        InsertHeadList(& state.pages->list_entry, & node->list_entry);
    }
    else {
        InsertTailList(& state.pages->list_entry, & node->list_entry);
    }

    //DUMP_PAGES_LIST_NODE(state.pages, TRUE);

    return rc;
}

/*  uxenplatform: balloon.c */

