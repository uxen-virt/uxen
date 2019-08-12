/******************************************************************************
 * memory.h
 * 
 * Memory reservation and information.
 * 
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to
 * deal in the Software without restriction, including without limitation the
 * rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
 * sell copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 *
 * Copyright (c) 2005, Keir Fraser <keir@xensource.com>
 */
/*
 * uXen changes:
 *
 * Copyright 2011-2019, Bromium, Inc.
 * Author: Christian Limpach <Christian.Limpach@gmail.com>
 * SPDX-License-Identifier: ISC
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
 * SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION
 * OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
 * CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#ifndef __XEN_PUBLIC_MEMORY_H__
#define __XEN_PUBLIC_MEMORY_H__

#include "xen.h"

/*
 * Increase or decrease the specified domain's memory reservation. Returns the
 * number of extents successfully allocated or freed.
 * arg == addr of struct xen_memory_reservation.
 */
#define XENMEM_increase_reservation 0
#define XENMEM_decrease_reservation 1
#define XENMEM_populate_physmap     6

#if __XEN_INTERFACE_VERSION__ >= 0x00030209
/*
 * Maximum # bits addressable by the user of the allocated region (e.g., I/O 
 * devices often have a 32-bit limitation even in 64-bit systems). If zero 
 * then the user has no addressing restriction. This field is not used by 
 * XENMEM_decrease_reservation.
 */
#define XENMEMF_address_bits(x)     (x)
#define XENMEMF_get_address_bits(x) ((x) & 0xffu)
/* NUMA node to allocate from. */
#define XENMEMF_node(x)     (((x) + 1) << 8)
#define XENMEMF_get_node(x) ((((x) >> 8) - 1) & 0xffu)
/* Flag to populate physmap with populate-on-demand entries */
#define XENMEMF_populate_on_demand (1<<16)
#ifndef __UXEN__
/* Flag to request allocation only from the node specified */
#define XENMEMF_exact_node_request  (1<<17)
#define XENMEMF_exact_node(n) (XENMEMF_node(n) | XENMEMF_exact_node_request)
#endif   /* __UXEN__ */
#define XENMEMF_populate_from_buffer (1<<17)
#define XENMEMF_populate_from_buffer_compressed (1<<18)
#endif

struct xen_memory_reservation {

    /*
     * XENMEM_increase_reservation:
     *   OUT: MFN (*not* GMFN) bases of extents that were allocated
     * XENMEM_decrease_reservation:
     *   IN:  GMFN bases of extents to free
     * XENMEM_populate_physmap:
     *   IN:  GPFN bases of extents to populate with memory
     *   OUT: GMFN bases of extents that were allocated
     *   (NB. This command also updates the mach_to_phys translation table)
     */
    XEN_GUEST_HANDLE(xen_pfn_t) extent_start;

    /* Number of extents, and size/alignment of each (2^extent_order pages). */
    xen_ulong_t    nr_extents;
    unsigned int   extent_order;

#if __XEN_INTERFACE_VERSION__ >= 0x00030209
    /* XENMEMF flags. */
    unsigned int   mem_flags;
#else
    unsigned int   address_bits;
#endif

    /*
     * Domain whose reservation is being changed.
     * Unprivileged domains can specify only DOMID_SELF.
     */
    domid_t        domid;

    XEN_GUEST_HANDLE(uint8) buffer;
};
typedef struct xen_memory_reservation xen_memory_reservation_t;
DEFINE_XEN_GUEST_HANDLE(xen_memory_reservation_t);

#define XENMEM_capture 47
struct xen_memory_capture_gpfn_info {
    union {
        struct {                /* in */
            uint32_t gpfn;
            uint32_t flags;
        };
        struct {                /* out */
            uint32_t type;
            uint32_t offset;
        };
    };
};
typedef struct xen_memory_capture_gpfn_info xen_memory_capture_gpfn_info_t;
DEFINE_XEN_GUEST_HANDLE(xen_memory_capture_gpfn_info_t);
#define XENMEM_MCGI_FLAGS_VM         0x0000
#define XENMEM_MCGI_FLAGS_TEMPLATE   0x0001

#define XENMEM_MCGI_FLAGS_REMOVE_PFN 0x0010

/* page type */
#define XENMEM_MCGI_TYPE_MASK        0x000f
#define XENMEM_MCGI_TYPE_NOT_PRESENT 0x0000
#define XENMEM_MCGI_TYPE_NORMAL      0x0001
#define XENMEM_MCGI_TYPE_POD         0x0002
#define XENMEM_MCGI_TYPE_ZERO        0x0003
#define XENMEM_MCGI_TYPE_XEN         0x0004
#define XENMEM_MCGI_TYPE_HOST        0x0005
#define XENMEM_MCGI_TYPE_ERROR       0x0006

/* page data type */
#define XENMEM_MCGI_TYPE_COMPRESSED  0x0010

/* errors */
#define XENMEM_MCGI_TYPE_BUFFER_FULL 0xff01
#define XENMEM_MCGI_TYPE_NO_TEMPLATE 0xff02

struct xen_memory_capture {
    domid_t domid;

    uint32_t nr_done;
    uint32_t nr_gpfns;
    XEN_GUEST_HANDLE(xen_memory_capture_gpfn_info_t) gpfn_info_list;

    uint32_t buffer_size;
    XEN_GUEST_HANDLE(uint8) buffer;
};
typedef struct xen_memory_capture xen_memory_capture_t;
DEFINE_XEN_GUEST_HANDLE(xen_memory_capture_t);

#define XENMEM_clone_physmap        49
struct xen_memory_clone_physmap {
    domid_t             domid;
    xen_domain_handle_t parentuuid;
};
typedef struct xen_memory_clone_physmap xen_memory_clone_physmap_t;
DEFINE_XEN_GUEST_HANDLE(xen_memory_clone_physmap_t);

/*
 * An atomic exchange of memory pages. If return code is zero then
 * @out.extent_list provides GMFNs of the newly-allocated memory.
 * Returns zero on complete success, otherwise a negative error code.
 * On complete success then always @nr_exchanged == @in.nr_extents.
 * On partial success @nr_exchanged indicates how much work was done.
 */
#define XENMEM_exchange             11
struct xen_memory_exchange {
    /*
     * [IN] Details of memory extents to be exchanged (GMFN bases).
     * Note that @in.address_bits is ignored and unused.
     */
    struct xen_memory_reservation in;

    /*
     * [IN/OUT] Details of new memory extents.
     * We require that:
     *  1. @in.domid == @out.domid
     *  2. @in.nr_extents  << @in.extent_order == 
     *     @out.nr_extents << @out.extent_order
     *  3. @in.extent_start and @out.extent_start lists must not overlap
     *  4. @out.extent_start lists GPFN bases to be populated
     *  5. @out.extent_start is overwritten with allocated GMFN bases
     */
    struct xen_memory_reservation out;

    /*
     * [OUT] Number of input extents that were successfully exchanged:
     *  1. The first @nr_exchanged input extents were successfully
     *     deallocated.
     *  2. The corresponding first entries in the output extent list correctly
     *     indicate the GMFNs that were successfully exchanged.
     *  3. All other input and output extents are untouched.
     *  4. If not all input exents are exchanged then the return code of this
     *     command will be non-zero.
     *  5. THIS FIELD MUST BE INITIALISED TO ZERO BY THE CALLER!
     */
    xen_ulong_t nr_exchanged;
};
typedef struct xen_memory_exchange xen_memory_exchange_t;
DEFINE_XEN_GUEST_HANDLE(xen_memory_exchange_t);

/*
 * Returns the maximum machine frame number of mapped RAM in this system.
 * This command always succeeds (it never returns an error code).
 * arg == NULL.
 */
#define XENMEM_maximum_ram_page     2

/*
 * Returns the current or maximum memory reservation, in pages, of the
 * specified domain (may be DOMID_SELF). Returns -ve errcode on failure.
 * arg == addr of domid_t.
 */
#define XENMEM_current_reservation  3
#define XENMEM_maximum_reservation  4

/*
 * Returns the maximum GPFN in use by the guest, or -ve errcode on failure.
 */
#define XENMEM_maximum_gpfn         14

/*
 * Returns a list of MFN bases of 2MB extents comprising the machine_to_phys
 * mapping table. Architectures which do not have a m2p table do not implement
 * this command.
 * arg == addr of xen_machphys_mfn_list_t.
 */
#define XENMEM_machphys_mfn_list    5
struct xen_machphys_mfn_list {
    /*
     * Size of the 'extent_start' array. Fewer entries will be filled if the
     * machphys table is smaller than max_extents * 2MB.
     */
    unsigned int max_extents;

    /*
     * Pointer to buffer to fill with list of extent starts. If there are
     * any large discontiguities in the machine address space, 2MB gaps in
     * the machphys table will be represented by an MFN base of zero.
     */
    XEN_GUEST_HANDLE(xen_pfn_t) extent_start;

    /*
     * Number of extents written to the above array. This will be smaller
     * than 'max_extents' if the machphys table is smaller than max_e * 2MB.
     */
    unsigned int nr_extents;
};
typedef struct xen_machphys_mfn_list xen_machphys_mfn_list_t;
DEFINE_XEN_GUEST_HANDLE(xen_machphys_mfn_list_t);

/*
 * Returns the location in virtual address space of the machine_to_phys
 * mapping table. Architectures which do not have a m2p table, or which do not
 * map it by default into guest address space, do not implement this command.
 * arg == addr of xen_machphys_mapping_t.
 */
#define XENMEM_machphys_mapping     12
struct xen_machphys_mapping {
    xen_ulong_t v_start, v_end; /* Start and end virtual addresses.   */
    xen_ulong_t max_mfn;        /* Maximum MFN that can be looked up. */
};
typedef struct xen_machphys_mapping xen_machphys_mapping_t;
DEFINE_XEN_GUEST_HANDLE(xen_machphys_mapping_t);

/*
 * Sets the GPFN at which a particular page appears in the specified guest's
 * pseudophysical address space.
 * arg == addr of xen_add_to_physmap_t.
 */
#define XENMEM_add_to_physmap      7
struct xen_add_to_physmap {
    /* Which domain to change the mapping for. */
    domid_t domid;

    /* Number of pages to go through for gmfn_range */
    uint16_t    size;

    /* Source mapping space. */
#define XENMAPSPACE_shared_info 0 /* shared info page */
#define XENMAPSPACE_grant_table 1 /* grant table page */
#define XENMAPSPACE_gmfn        2 /* GMFN */
#define XENMAPSPACE_gmfn_range  3 /* GMFN range */
#define XENMAPSPACE_host_mfn    4 /* Host frame (MFN) */
    unsigned int space;

#define XENMAPIDX_grant_table_status 0x80000000

    /* Index into source mapping space. */
    xen_ulong_t idx;

    /* GPFN where the source mapping page should appear. */
    xen_pfn_t     gpfn;
};
typedef struct xen_add_to_physmap xen_add_to_physmap_t;
DEFINE_XEN_GUEST_HANDLE(xen_add_to_physmap_t);

/*** REMOVED ***/
/*#define XENMEM_translate_gpfn_list  8*/

#define XENMEM_TRANSLATE_PROT_READ  0x1
#define XENMEM_TRANSLATE_PROT_WRITE 0x2
#define XENMEM_TRANSLATE_MAX_BATCH 1024
#define XENMEM_TRANSLATE_MAP        0x0
#define XENMEM_TRANSLATE_RELEASE    0x1
#define XENMEM_translate_gpfn_list_for_map  48
struct xen_translate_gpfn_list_for_map {
    domid_t domid;
    uint16_t prot;
    uint32_t gpfns_start;
    uint32_t gpfns_end;
    uint32_t map_mode;
    XEN_GUEST_HANDLE(xen_pfn_t) gpfn_list;
    XEN_GUEST_HANDLE(xen_pfn_t) mfn_list;
};
typedef struct xen_translate_gpfn_list_for_map
xen_translate_gpfn_list_for_map_t;
DEFINE_XEN_GUEST_HANDLE(xen_translate_gpfn_list_for_map_t);

/*
 * Returns the pseudo-physical memory map as it was when the domain
 * was started (specified by XENMEM_set_memory_map).
 * arg == addr of xen_memory_map_t.
 */
#define XENMEM_memory_map           9
struct xen_memory_map {
    /*
     * On call the number of entries which can be stored in buffer. On
     * return the number of entries which have been stored in
     * buffer.
     */
    unsigned int nr_entries;

    /*
     * Entries in the buffer are in the same format as returned by the
     * BIOS INT 0x15 EAX=0xE820 call.
     */
    XEN_GUEST_HANDLE(void) buffer;
};
typedef struct xen_memory_map xen_memory_map_t;
DEFINE_XEN_GUEST_HANDLE(xen_memory_map_t);

/*
 * Returns the real physical memory map. Passes the same structure as
 * XENMEM_memory_map.
 * arg == addr of xen_memory_map_t.
 */
#define XENMEM_machine_memory_map   10

/*
 * Set the pseudo-physical memory map of a domain, as returned by
 * XENMEM_memory_map.
 * arg == addr of xen_foreign_memory_map_t.
 */
#define XENMEM_set_memory_map       13
struct xen_foreign_memory_map {
    domid_t domid;
    struct xen_memory_map map;
};
typedef struct xen_foreign_memory_map xen_foreign_memory_map_t;
DEFINE_XEN_GUEST_HANDLE(xen_foreign_memory_map_t);

#define XENMEM_set_pod_target       16
#define XENMEM_get_pod_target       17
struct xen_pod_target {
    /* IN */
    uint64_t target_pages;
    /* OUT */
    uint64_t tot_pages;
    uint64_t pod_cache_pages;
    uint64_t pod_entries;
    /* IN */
    domid_t domid;
};
typedef struct xen_pod_target xen_pod_target_t;

/*
 * Get the number of MFNs saved through memory sharing.
 * The call never fails. 
 */
#define XENMEM_get_sharing_freed_pages    18

#define XENMEM_share_zero_pages           50
struct xen_memory_share_zero_pages {
    xen_pfn_t gpfn_list_gpfn;
    uint32_t nr_gpfns;
};
typedef struct xen_memory_share_zero_pages xen_memory_share_zero_pages_t;
DEFINE_XEN_GUEST_HANDLE(xen_memory_share_zero_pages_t);

#define XENMEM_SHARE_ZERO_PAGES_MAX_BATCH (PAGE_SIZE / sizeof(xen_pfn_t))

#define XENMEM_set_zero_page_ctxt         51
struct xen_memory_set_zero_page_desc {
    uint64_t entry;
    uint64_t ret;
    union {
        uint64_t zero_thread_addr;
        uint64_t zero_thread_paging_base;
    };
    uint8_t nr_gpfns_mode;
    uint8_t gva_mode;
    uint8_t prologue_mode;
    uint8_t zero_thread_mode;
};
#define XEN_MEMORY_SET_ZERO_PAGE_DESC_MAX 2
struct xen_memory_set_zero_page_ctxt {
    uint32_t nr_desc;
    struct xen_memory_set_zero_page_desc zp[XEN_MEMORY_SET_ZERO_PAGE_DESC_MAX];
};
typedef struct xen_memory_set_zero_page_ctxt xen_memory_set_zero_page_ctxt_t;

#define XEN_MEMORY_SET_ZERO_PAGE_NR_GPFN_MODE_single 0
#define XEN_MEMORY_SET_ZERO_PAGE_NR_GPFN_MODE_edx_shift_5 1
#define XEN_MEMORY_SET_ZERO_PAGE_NR_GPFN_MODE_edx_shift_6 2
#define XEN_MEMORY_SET_ZERO_PAGE_NR_GPFN_MODE_ecx_shift_10 3
#define XEN_MEMORY_SET_ZERO_PAGE_GVA_MODE_single 0
#define XEN_MEMORY_SET_ZERO_PAGE_GVA_MODE_ecx 1
#define XEN_MEMORY_SET_ZERO_PAGE_GVA_MODE_edi 2
#define XEN_MEMORY_SET_ZERO_PAGE_PROLOGUE_none 0
#define XEN_MEMORY_SET_ZERO_PAGE_PROLOGUE_clear_edx 1
#define XEN_MEMORY_SET_ZERO_PAGE_ZERO_THREAD_MODE_none 0
#define XEN_MEMORY_SET_ZERO_PAGE_ZERO_THREAD_MODE_gs_pcr_188 1
#define XEN_MEMORY_SET_ZERO_PAGE_ZERO_THREAD_MODE_fs_pcr_124 2
#define XEN_MEMORY_SET_ZERO_PAGE_ZERO_THREAD_MODE_cr3 3

#endif /* __XEN_PUBLIC_MEMORY_H__ */

/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
