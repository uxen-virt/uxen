/*
 * uXen changes:
 *
 * Copyright 2011-2016, Bromium, Inc.
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

#ifndef __ASM_X86_MM_H__
#define __ASM_X86_MM_H__

#include <xen/config.h>
#include <xen/list.h>
#include <xen/spinlock.h>
#include <asm/io.h>
#include <asm/uaccess.h>

#ifndef __UXEN__
/*
 * Per-page-frame information.
 * 
 * Every architecture must ensure the following:
 *  1. 'struct page_info' contains a 'struct page_list_entry list'.
 *  2. Provide a PFN_ORDER() macro for accessing the order of a free page.
 */
#define PFN_ORDER(_pfn) ((_pfn)->v.free.order)
#endif  /* __UXEN__ */

/*
 * This definition is solely for the use in struct page_info (and
 * struct page_list_head), intended to allow easy adjustment once x86-64
 * wants to support more than 16TB.
 * 'unsigned long' should be used for MFNs everywhere else.
 */
#define __pdx_t unsigned int

#undef page_list_entry
struct page_list_entry
{
    __pdx_t next, prev;
};

#ifdef __UXEN__
/* __UXEN__ version of page_info */
struct page_info
{
    /* Each frame can be threaded onto a doubly-linked list.
     */
    struct page_list_entry list;

    /* Reference count and various PGC_xxx flags and fields. */
    unsigned long count_info;

    /* Owner of this page. */
    domid_t domain;

#ifdef DEBUG_MAPCACHE
    atomic_t mapped;
    void *lastmap;
    void *lastmap0;
#endif  /* DEBUG_MAPCACHE */
};
#else  /* __UXEN__ */
// struct page_info
// {
//     union {
//         /* Each frame can be threaded onto a doubly-linked list.
//          *
//          * For unused shadow pages, a list of free shadow pages;
//          * for multi-page shadows, links to the other pages in this shadow;
//          * for pinnable shadows, if pinned, a list of all pinned shadows
//          * (see sh_type_is_pinnable() for the definition of "pinnable" 
//          * shadow types).  N.B. a shadow may be both pinnable and multi-page.
//          * In that case the pages are inserted in order in the list of
//          * pinned shadows and walkers of that list must be prepared 
//          * to keep them all together during updates. 
//          */
//         struct page_list_entry list;
//         /* For non-pinnable single-page shadows, a higher entry that points
//          * at us. */
//         paddr_t up;
//         /* For shared/sharable pages the sharing handle */
//         uint64_t shr_handle; 
//     };
// 
//     /* Reference count and various PGC_xxx flags and fields. */
//     unsigned long count_info;
// 
//     /* Context-dependent fields follow... */
//     union {
// 
//         /* Page is in use: ((count_info & PGC_count_mask) != 0). */
//         struct {
//             /* Type reference count and various PGT_xxx flags and fields. */
//             unsigned long type_info;
//         } inuse;
// 
//         /* Page is in use as a shadow: count_info == 0. */
//         struct {
//             unsigned long type:5;   /* What kind of shadow is this? */
//             unsigned long pinned:1; /* Is the shadow pinned? */
//             unsigned long head:1;   /* Is this the first page of the shadow? */
//             unsigned long count:25; /* Reference count */
//         } sh;
// 
//         /* Page is on a free list: ((count_info & PGC_count_mask) == 0). */
//         struct {
//             /* Do TLBs need flushing for safety before next page use? */
//             bool_t need_tlbflush;
//         } free;
// 
//     } u;
// 
//     union {
// 
//         /* Page is in use, but not as a shadow. */
//         struct {
//             /* Owner of this page (zero if page is anonymous). */
//             __pdx_t _domain;
//         } inuse;
// 
//         /* Page is in use as a shadow. */
//         struct {
//             /* GMFN of guest page we're a shadow of. */
//             __pdx_t back;
//         } sh;
// 
//         /* Page is on a free list. */
//         struct {
//             /* Order-size of the free chunk this page is the head of. */
//             unsigned int order;
//         } free;
// 
//     } v;
// 
//     union {
//         /*
//          * Timestamp from 'TLB clock', used to avoid extra safety flushes.
//          * Only valid for: a) free pages, and b) pages with zero type count
//          * (except page table pages when the guest is in shadow mode).
//          */
//         u32 tlbflush_timestamp;
// 
//         /*
//          * When PGT_partial is true then this field is valid and indicates
//          * that PTEs in the range [0, @nr_validated_ptes) have been validated.
//          * An extra page reference must be acquired (or not dropped) whenever
//          * PGT_partial gets set, and it must be dropped when the flag gets
//          * cleared. This is so that a get() leaving a page in partially
//          * validated state (where the caller would drop the reference acquired
//          * due to the getting of the type [apparently] failing [-EAGAIN])
//          * would not accidentally result in a page left with zero general
//          * reference count, but non-zero type reference count (possible when
//          * the partial get() is followed immediately by domain destruction).
//          * Likewise, the ownership of the single type reference for partially
//          * (in-)validated pages is tied to this flag, i.e. the instance
//          * setting the flag must not drop that reference, whereas the instance
//          * clearing it will have to.
//          *
//          * If @partial_pte is positive then PTE at @nr_validated_ptes+1 has
//          * been partially validated. This implies that the general reference
//          * to the page (acquired from get_page_from_lNe()) would be dropped
//          * (again due to the apparent failure) and hence must be re-acquired
//          * when resuming the validation, but must not be dropped when picking
//          * up the page for invalidation.
//          *
//          * If @partial_pte is negative then PTE at @nr_validated_ptes+1 has
//          * been partially invalidated. This is basically the opposite case of
//          * above, i.e. the general reference to the page was not dropped in
//          * put_page_from_lNe() (due to the apparent failure), and hence it
//          * must be dropped when the put operation is resumed (and completes),
//          * but it must not be acquired if picking up the page for validation.
//          */
//         struct {
//             u16 nr_validated_ptes;
//             s8 partial_pte;
//         };
// 
//         /*
//          * Guest pages with a shadow.  This does not conflict with
//          * tlbflush_timestamp since page table pages are explicitly not
//          * tracked for TLB-flush avoidance when a guest runs in shadow mode.
//          */
//         u32 shadow_flags;
// 
//         /* When in use as a shadow, next shadow in this hash chain. */
//         __pdx_t next_shadow;
//     };
// };
#endif  /* __UXEN__ */

#undef __pdx_t

#define PG_shift(idx)   (BITS_PER_LONG - (idx))
#define PG_mask(x, idx) (x ## UL << PG_shift(idx))

#ifndef __UXEN__
//  /* The following page types are MUTUALLY EXCLUSIVE. */
// #define PGT_none          PG_mask(0, 4)  /* no special uses of this page   */
// #define PGT_l1_page_table PG_mask(1, 4)  /* using as an L1 page table?     */
// #define PGT_l2_page_table PG_mask(2, 4)  /* using as an L2 page table?     */
// #define PGT_l3_page_table PG_mask(3, 4)  /* using as an L3 page table?     */
// #define PGT_l4_page_table PG_mask(4, 4)  /* using as an L4 page table?     */
// #define PGT_seg_desc_page PG_mask(5, 4)  /* using this page in a GDT/LDT?  */
// #define PGT_writable_page PG_mask(7, 4)  /* has writable mappings?         */
// #define PGT_shared_page   PG_mask(8, 4)  /* CoW sharable page              */
// #define PGT_type_mask     PG_mask(15, 4) /* Bits 28-31 or 60-63.           */
// 
//  /* Owning guest has pinned this page to its current type? */
// #define _PGT_pinned       PG_shift(5)
// #define PGT_pinned        PG_mask(1, 5)
//  /* Has this page been validated for use as its current type? */
// #define _PGT_validated    PG_shift(6)
// #define PGT_validated     PG_mask(1, 6)
//  /* PAE only: is this an L2 page directory containing Xen-private mappings? */
// #define _PGT_pae_xen_l2   PG_shift(7)
// #define PGT_pae_xen_l2    PG_mask(1, 7)
// /* Has this page been *partially* validated for use as its current type? */
// #define _PGT_partial      PG_shift(8)
// #define PGT_partial       PG_mask(1, 8)
//  /* Page is locked? */
// #define _PGT_locked       PG_shift(9)
// #define PGT_locked        PG_mask(1, 9)
// 
//  /* Count of uses of this frame as its current type. */
// #define PGT_count_width   PG_shift(9)
// #define PGT_count_mask    ((1UL<<PGT_count_width)-1)
#endif  /* __UXEN__ */

#ifdef __UXEN__
/* __UXEN__ PGC flags */

#define _PGC_xen_page     PG_shift(2)
#define PGC_xen_page      PG_mask(1, 2)

#define _PGC_mapcache     PG_shift(3)
#define PGC_mapcache      PG_mask(1, 3)

 /* 3-bit PAT/PCD/PWT cache-attribute hint. */
#define PGC_cacheattr_base PG_shift(6)
#define PGC_cacheattr_mask PG_mask(7, 6)

#define _PGC_host_page     PG_shift(7)
#define PGC_host_page      PG_mask(1, 7)

 /* Mutually-exclusive page states: { host, inuse, free, dirty }. */
#define PGC_state         PG_mask(3, 9)
#define PGC_state_host    PG_mask(0, 9)
#define PGC_state_inuse   PG_mask(1, 9)
#define PGC_state_free    PG_mask(2, 9)
#define PGC_state_dirty   PG_mask(3, 9)
#define page_state_is(pg, st) (((pg)->count_info&PGC_state) == PGC_state_##st)

 /* Count of references to this frame. */
#define PGC_count_width   PG_shift(9)
#define PGC_count_mask    ((1UL<<PGC_count_width)-1)

#else  /* __UXEN__ */
//  /* Cleared when the owning guest 'frees' this page. */
// #define _PGC_allocated    PG_shift(1)
// #define PGC_allocated     PG_mask(1, 1)
//  /* Page is Xen heap? */
// #define _PGC_xen_heap     PG_shift(2)
// #define PGC_xen_heap      PG_mask(1, 2)
//  /* Set when is using a page as a page table */
// #define _PGC_page_table   PG_shift(3)
// #define PGC_page_table    PG_mask(1, 3)
//  /* 3-bit PAT/PCD/PWT cache-attribute hint. */
// #define PGC_cacheattr_base PG_shift(6)
// #define PGC_cacheattr_mask PG_mask(7, 6)
//  /* Page is broken? */
// #define _PGC_broken       PG_shift(7)
// #define PGC_broken        PG_mask(1, 7)
//  /* Mutually-exclusive page states: { host, inuse, free }. */
// #define PGC_state         PG_mask(3, 9)
// #define PGC_state_host    PG_mask(0, 9)
// #define PGC_state_inuse   PG_mask(1, 9)
// #define PGC_state_free    PG_mask(2, 9)
// #define PGC_state_dirty   PG_mask(3, 9)
// /* #define PGC_state_offlining PG_mask(1, 9) */
// /* #define PGC_state_offlined PG_mask(2, 9) */
// #define page_state_is(pg, st) (((pg)->count_info&PGC_state) == PGC_state_##st)
// 
//  /* Count of references to this frame. */
// #define PGC_count_width   PG_shift(9)
// #define PGC_count_mask    ((1UL<<PGC_count_width)-1)
#endif  /* __UXEN__ */

#ifndef __UXEN__
// #ifdef __x86_64__
// struct spage_info
// {
//        unsigned long type_info;
// };
// 
//  /* The following page types are MUTUALLY EXCLUSIVE. */
// #define SGT_none          PG_mask(0, 2)  /* superpage not in use */
// #define SGT_mark          PG_mask(1, 2)  /* Marked as a superpage */
// #define SGT_dynamic       PG_mask(2, 2)  /* has been dynamically mapped as a superpage */
// #define SGT_type_mask     PG_mask(3, 2)  /* Bits 30-31 or 62-63. */
// 
//  /* Count of uses of this superpage as its current type. */
// #define SGT_count_width   PG_shift(3)
// #define SGT_count_mask    ((1UL<<SGT_count_width)-1)
// #endif
#endif  /* __UXEN__ */

#ifndef __UXEN__
#if defined(__i386__)
#define is_xen_heap_page(page) is_xen_heap_mfn(page_to_mfn(page))
#define is_xen_heap_mfn(mfn) ({                         \
    unsigned long _mfn = (mfn);                         \
    (_mfn < paddr_to_pfn(xenheap_phys_end));            \
})
#define is_xen_fixed_mfn(mfn) is_xen_heap_mfn(mfn)
#else
#define is_xen_heap_page(page) ((page)->count_info & PGC_xen_heap)
#define is_xen_heap_mfn(mfn) \
    (__mfn_valid_page(mfn) && is_xen_heap_page(__mfn_to_page(mfn)))
#define is_xen_fixed_mfn(mfn)                     \
    ((((mfn) << PAGE_SHIFT) >= __pa(&_start)) &&  \
     (((mfn) << PAGE_SHIFT) <= __pa(&_end)))
#endif
#else  /* __UXEN__ */
#define is_xen_page(page) ((page)->count_info & PGC_xen_page)
#define is_xen_mfn(mfn) \
    (__mfn_valid_page(mfn) && is_xen_page(__mfn_to_page(mfn)))
#define is_host_page(page) ((page)->count_info & PGC_host_page)
#define is_host_mfn(mfn) \
    (__mfn_valid_page(mfn) && is_host_page(__mfn_to_page(mfn)))
#define is_mapcache_page(page) ((page)->count_info & PGC_mapcache)
#define is_mapcache_mfn(mfn) \
    (__mfn_valid_page(mfn) && is_mapcache_page(__mfn_to_page(mfn)))

/* not any of the above */
#define is_dom_page(page) \
    (!((page)->count_info & (PGC_xen_page | PGC_host_page | PGC_mapcache)))
#endif  /* __UXEN__ */

#if defined(__i386__)
#define PRtype_info "08lx" /* should only be used for printk's */
#elif defined(__x86_64__)
#define PRtype_info "016lx"/* should only be used for printk's */
#endif

/* The number of out-of-sync shadows we allow per vcpu (prime, please) */
#define SHADOW_OOS_PAGES 3

/* OOS fixup entries */
#define SHADOW_OOS_FIXUPS 2

#ifndef __UXEN__
#define page_get_owner(_p)                                      \
    ((struct domain *)((_p)->_domain ?                          \
                       pdx_to_virt((_p)->_domain) : NULL))
#define page_set_owner(_p,_d)                           \
    ((_p)->_domain = (_d) ? virt_to_pdx(_d) : 0)
#else   /* __UXEN__ */
#define page_get_owner(_p)                                              \
    ((_p)->domain < DOMID_FIRST_RESERVED ? domain_array[(_p)->domain] : NULL)
#define page_set_owner(_p,_d)                                           \
    ((_p)->domain = (_d) ? ((struct domain *)(_d))->domain_id : DOMID_ANON)
#endif  /* __UXEN__ */

#define maddr_get_owner(ma)   (page_get_owner(maddr_to_page((ma))))
#define vaddr_get_owner(va)   (page_get_owner(virt_to_page((va))))

#define XENSHARE_writable 0
#define XENSHARE_readonly 1
extern void share_xen_page_with_guest(
    struct page_info *page, struct domain *d, int readonly);
extern void share_xen_page_with_privileged_guests(
    struct page_info *page, int readonly);

#ifndef __UXEN__
#define frame_table ((struct page_info *)FRAMETABLE_VIRT_START)
#ifdef __x86_64__
#define spage_table ((struct spage_info *)SPAGETABLE_VIRT_START)
int get_superpage(unsigned long mfn, struct domain *d);
#endif
#else   /* __UXEN__ */
extern struct page_info *frame_table;
#endif  /* __UXEN__ */
extern unsigned long max_page;
extern unsigned long total_pages;
void init_frametable(void);

#define PDX_GROUP_COUNT ((1 << L2_PAGETABLE_SHIFT) / \
                         (sizeof(*frame_table) & -sizeof(*frame_table)))
extern unsigned long pdx_group_valid[];

#ifndef __UXEN__
/* Convert between Xen-heap virtual addresses and page-info structures. */
static inline struct page_info *__virt_to_page(const void *v)
{
    unsigned long va = (unsigned long)v;

#ifdef __x86_64__
    ASSERT(va >= XEN_VIRT_START);
    ASSERT(va < DIRECTMAP_VIRT_END);
    if ( va < XEN_VIRT_END )
        va += DIRECTMAP_VIRT_START - XEN_VIRT_START + xen_phys_start;
    else
        ASSERT(va >= DIRECTMAP_VIRT_START);
#else
    ASSERT(va - DIRECTMAP_VIRT_START < DIRECTMAP_VIRT_END);
#endif
    return frame_table + ((va - DIRECTMAP_VIRT_START) >> PAGE_SHIFT);
}
#else   /* __UXEN__ */
#define __virt_to_page(v) mfn_to_page(virt_to_mfn(v))
#endif  /* __UXEN__ */

#ifndef __UXEN__
static inline void *__page_to_virt(const struct page_info *pg)
{
    ASSERT((unsigned long)pg - FRAMETABLE_VIRT_START < FRAMETABLE_VIRT_END);
    return (void *)(DIRECTMAP_VIRT_START +
                    ((unsigned long)pg - FRAMETABLE_VIRT_START) /
                    (sizeof(*pg) / (sizeof(*pg) & -sizeof(*pg))) *
                    (PAGE_SIZE / (sizeof(*pg) & -sizeof(*pg))));
}
#endif  /* __UXEN__ */

int free_page_type(struct page_info *page, unsigned long type,
                   int preemptible);
int _shadow_mode_refcounts(struct domain *d);

int is_iomem_page(unsigned long mfn);

void clear_superpage_mark(struct page_info *page);

struct domain *page_get_owner_and_reference(struct page_info *page);
void put_page(struct page_info *page);
#define put_allocated_page(d, p) put_page(p)
int  get_page(struct page_info *page, struct domain *domain);
int _get_page_fast(struct page_info *page
#ifndef NDEBUG
                   , struct domain *domain
#endif
    );
#ifndef NDEBUG
#define get_page_fast(p, d) _get_page_fast(p, d)
#else
#define get_page_fast(p, d) ((void)d, _get_page_fast(p))
#endif
void put_page_type(struct page_info *page);
int  get_page_type(struct page_info *page, unsigned long type);
int  put_page_type_preemptible(struct page_info *page);
int  get_page_type_preemptible(struct page_info *page, unsigned long type);
int  get_page_from_l1e(
    l1_pgentry_t l1e, struct domain *l1e_owner, struct domain *pg_owner);
void put_page_from_l1e(l1_pgentry_t l1e, struct domain *l1e_owner);

int
change_page_owner(struct page_info *page, struct domain *to,
                  struct domain *from, int refs);

#ifndef __UXEN__
static inline void put_page_and_type(struct page_info *page)
{
    put_page_type(page);
    put_page(page);
}

static inline int put_page_and_type_preemptible(struct page_info *page,
                                                int preemptible)
{
    int rc = 0;

    if ( preemptible )
        rc = put_page_type_preemptible(page);
    else
        put_page_type(page);
    if ( likely(rc == 0) )
        put_page(page);
    return rc;
}

static inline int get_page_and_type(struct page_info *page,
                                    struct domain *domain,
                                    unsigned long type)
{
    int rc = get_page(page, domain);

    if ( likely(rc) && unlikely(!get_page_type(page, type)) )
    {
        put_page(page);
        rc = 0;
    }

    return rc;
}

#define ASSERT_PAGE_IS_TYPE(_p, _t)                            \
    ASSERT(((_p)->u.inuse.type_info & PGT_type_mask) == (_t)); \
    ASSERT(((_p)->u.inuse.type_info & PGT_count_mask) != 0)
#else  /* __UXEN__ */
#define put_page_and_type(page) put_page(page)
#define put_page_and_type_preemptible(page, preemptible) put_page(page)
#define get_page_and_type(page, domain, type) get_page(page, domain)

#define ASSERT_PAGE_IS_TYPE(_p, _t) do { /* */ } while (0)
#endif  /* __UXEN__ */
#define ASSERT_PAGE_IS_DOMAIN(_p, _d)                          \
    ASSERT(((_p)->count_info & PGC_count_mask) != 0);          \
    ASSERT(page_get_owner(_p) == (_d))

// Quick test for whether a given page can be represented directly in CR3.
//
#if CONFIG_PAGING_LEVELS == 3
#define MFN_FITS_IN_CR3(_MFN) !(mfn_x(_MFN) >> 20)

/* returns a lowmem machine address of the copied L3 root table */
unsigned long
pae_copy_root(struct vcpu *v, l3_pgentry_t *l3tab);
#endif /* CONFIG_PAGING_LEVELS == 3 */

int check_descriptor(const struct domain *, struct desc_struct *d);

extern bool_t opt_allow_superpage;
extern bool_t mem_hotplug;

/******************************************************************************
 * With shadow pagetables, the different kinds of address start 
 * to get get confusing.
 * 
 * Virtual addresses are what they usually are: the addresses that are used 
 * to accessing memory while the guest is running.  The MMU translates from 
 * virtual addresses to machine addresses. 
 * 
 * (Pseudo-)physical addresses are the abstraction of physical memory the
 * guest uses for allocation and so forth.  For the purposes of this code, 
 * we can largely ignore them.
 *
 * Guest frame numbers (gfns) are the entries that the guest puts in its
 * pagetables.  For normal paravirtual guests, they are actual frame numbers,
 * with the translation done by the guest.  
 * 
 * Machine frame numbers (mfns) are the entries that the hypervisor puts
 * in the shadow page tables.
 *
 * Elsewhere in the xen code base, the name "gmfn" is generally used to refer
 * to a "machine frame number, from the guest's perspective", or in other
 * words, pseudo-physical frame numbers.  However, in the shadow code, the
 * term "gmfn" means "the mfn of a guest page"; this combines naturally with
 * other terms such as "smfn" (the mfn of a shadow page), gl2mfn (the mfn of a
 * guest L2 page), etc...
 */

/* With this defined, we do some ugly things to force the compiler to
 * give us type safety between mfns and gfns and other integers.
 * TYPE_SAFE(int foo) defines a foo_t, and _foo() and foo_x() functions 
 * that translate beween int and foo_t.
 * 
 * It does have some performance cost because the types now have 
 * a different storage attribute, so may not want it on all the time. */

#ifndef NDEBUG
#define TYPE_SAFETY 1
#endif

#ifdef TYPE_SAFETY
#define TYPE_SAFE(_type,_name)                                  \
typedef struct { _type _name; } _name##_t;                      \
static inline _name##_t _##_name(_type n) { return (_name##_t) { n }; } \
static inline _type _name##_x(_name##_t n) { return n._name; }
#else
#define TYPE_SAFE(_type,_name)                                          \
typedef _type _name##_t;                                                \
static inline _name##_t _##_name(_type n) { return n; }                 \
static inline _type _name##_x(_name##_t n) { return n; }
#endif

/* define mfn_t / _mfn / mfn_x */
TYPE_SAFE(unsigned long,mfn);

/* Macro for printk formats: use as printk("%"PRI_mfn"\n", mfn_x(foo)); */
#define PRI_mfn "05lx"


#ifndef __UXEN__
/*
 * The MPT (machine->physical mapping table) is an array of word-sized
 * values, indexed on machine frame number. It is expected that guest OSes
 * will use it to store a "physical" frame number to give the appearance of
 * contiguous (or near contiguous) physical memory.
 */
#ifndef __UXEN__
#undef  machine_to_phys_mapping
#define machine_to_phys_mapping  ((unsigned long *)RDWR_MPT_VIRT_START)
#define INVALID_M2P_ENTRY        (~0UL)
#define VALID_M2P(_e)            (!((_e) & (1UL<<(BITS_PER_LONG-1))))
#define SHARED_M2P_ENTRY         (~0UL - 1UL)
#define SHARED_M2P(_e)           ((_e) == SHARED_M2P_ENTRY)
#endif  /* __UXEN__ */

#ifdef CONFIG_COMPAT
#define compat_machine_to_phys_mapping ((unsigned int *)RDWR_COMPAT_MPT_VIRT_START)
#define _set_gpfn_from_mfn(mfn, pfn) ({                        \
    struct domain *d = page_get_owner(__mfn_to_page(mfn));     \
    unsigned long entry = (d && (d == dom_cow)) ?              \
        SHARED_M2P_ENTRY : (pfn);                              \
    ((void)((mfn) >= (RDWR_COMPAT_MPT_VIRT_END - RDWR_COMPAT_MPT_VIRT_START) / 4 || \
            (compat_machine_to_phys_mapping[(mfn)] = (unsigned int)(entry))), \
     machine_to_phys_mapping[(mfn)] = (entry));                \
    })
#else
#ifndef __UXEN__
#define _set_gpfn_from_mfn(mfn, pfn) ({                        \
    struct domain *d = page_get_owner(__mfn_to_page(mfn));     \
    if(d && (d == dom_cow))                                    \
        machine_to_phys_mapping[(mfn)] = SHARED_M2P_ENTRY;     \
    else                                                       \
        machine_to_phys_mapping[(mfn)] = (pfn);                \
    })
#endif  /* __UXEN__ */
#endif

/*
 * Disable some users of set_gpfn_from_mfn() (e.g., free_heap_pages()) until
 * the machine_to_phys_mapping is actually set up.
 */
extern bool_t machine_to_phys_mapping_valid;
#define set_gpfn_from_mfn(mfn, pfn) do {        \
    if ( machine_to_phys_mapping_valid )        \
        _set_gpfn_from_mfn(mfn, pfn);           \
} while (0)

#define get_gpfn_from_mfn(mfn)      (machine_to_phys_mapping[(mfn)])

#define mfn_to_gmfn(_d, mfn)                            \
    ( (paging_mode_translate(_d))                       \
      ? get_gpfn_from_mfn(mfn)                          \
      : (mfn) )
#endif  /* __UXEN__ */

#ifdef __x86_64__
/* 40 bits */
#define INVALID_MFN             (0xffffffffffUL)
#define SHARED_ZERO_MFN         (0xfffffffffeUL)
#define COMPRESSED_MFN          (0xfffffffffdUL)
#define ERROR_MFN               (0xfffffffffcUL)
#define DMREQ_MFN               (0xfffffffffbUL)
#define P2M_MFN_MFN_BITS        28
#define P2M_MFN_SPECIAL_BITS    4
#define P2M_MFN_PAGE_STORE_OFFSET_BITS 8
#define P2M_MFN_PAGE_STORE_OFFSET_INDEX 32
#else  /* __x86_64__ */
/* 32 bits */
#define INVALID_MFN             (0xffffffffUL)
#define SHARED_ZERO_MFN         (0xfffffffeUL)
#define COMPRESSED_MFN          (0xfffffffdUL)
#define ERROR_MFN               (0xfffffffcUL)
#define DMREQ_MFN               (0xfffffffbUL)
#define P2M_MFN_MFN_BITS        22
#define P2M_MFN_SPECIAL_BITS    4
#define P2M_MFN_PAGE_STORE_OFFSET_BITS 6
#define P2M_MFN_PAGE_STORE_OFFSET_INDEX 26
#endif /* __x86_64__ */
#define PAGE_STORE_DATA_ALIGN   (PAGE_SHIFT - P2M_MFN_PAGE_STORE_OFFSET_BITS)

#define __mfn_retry(mfn) ((mfn) == DMREQ_MFN)
#define mfn_retry(mfn) (__mfn_retry(mfn_x((mfn))))

#define P2M_MFN_MFN_MASK        ((1UL << P2M_MFN_MFN_BITS) - 1)
#define p2m_mfn_mfn(mfn) _mfn(mfn_x((mfn)) & P2M_MFN_MFN_MASK)
#define P2M_MFN_SPECIAL_MASK                                    \
    (((1UL << P2M_MFN_SPECIAL_BITS) - 1) << P2M_MFN_MFN_BITS)
#define P2M_MFN_PAGE_DATA       (1UL << P2M_MFN_MFN_BITS)
#define p2m_mfn_is_page_data(mfn)                               \
    (((mfn) & P2M_MFN_SPECIAL_MASK) == P2M_MFN_PAGE_DATA)

#define compat_pfn_to_cr3(pfn) (((unsigned)(pfn) << 12) | ((unsigned)(pfn) >> 20))
#define compat_cr3_to_pfn(cr3) (((unsigned)(cr3) >> 12) | ((unsigned)(cr3) << 20))

#ifdef MEMORY_GUARD
void memguard_init(void);
void memguard_guard_range(void *p, unsigned long l);
void memguard_unguard_range(void *p, unsigned long l);
#else
#define memguard_init()                ((void)0)
#define memguard_guard_range(_p,_l)    ((void)0)
#define memguard_unguard_range(_p,_l)  ((void)0)
#endif

void memguard_guard_stack(void *p);
void memguard_unguard_stack(void *p);

int  ptwr_do_page_fault(struct vcpu *, unsigned long,
                        struct cpu_user_regs *);

int audit_adjust_pgtables(struct domain *d, int dir, int noisy);

#ifdef CONFIG_X86_64
extern int pagefault_by_memadd(unsigned long addr, struct cpu_user_regs *regs);
extern int handle_memadd_fault(unsigned long addr, struct cpu_user_regs *regs);
#else
static inline int pagefault_by_memadd(unsigned long addr,
                                      struct cpu_user_regs *regs)
{
    return 0;
}

static inline int handle_memadd_fault(unsigned long addr,
                                      struct cpu_user_regs *regs)
{
    return 0;
}
#endif

#ifndef NDEBUG

#define AUDIT_SHADOW_ALREADY_LOCKED ( 1u << 0 )
#define AUDIT_ERRORS_OK             ( 1u << 1 )
#define AUDIT_QUIET                 ( 1u << 2 )

void _audit_domain(struct domain *d, int flags);
#define audit_domain(_d) _audit_domain((_d), AUDIT_ERRORS_OK)
void audit_domains(void);

#else

#define _audit_domain(_d, _f) ((void)0)
#define audit_domain(_d)      ((void)0)
#define audit_domains()       ((void)0)

#endif

int new_guest_cr3(unsigned long pfn);
#ifndef __UXEN__
void make_cr3(struct vcpu *v, unsigned long mfn);
#else   /* __UXEN__ */
void make_cr3(struct vcpu *v, uint64_t cr3);
#endif  /* __UXEN__ */
void update_cr3(struct vcpu *v);
void propagate_page_fault(unsigned long addr, u16 error_code);
void *do_page_walk(struct vcpu *v, unsigned long addr);

int __sync_local_execstate(void);

/* Arch-specific portion of memory_op hypercall. */
long arch_memory_op(int op, XEN_GUEST_HANDLE(void) arg);
long subarch_memory_op(int op, XEN_GUEST_HANDLE(void) arg);
int compat_arch_memory_op(int op, XEN_GUEST_HANDLE(void));
int compat_subarch_memory_op(int op, XEN_GUEST_HANDLE(void));

int steal_page(
    struct domain *d, struct page_info *page, unsigned int memflags);
int donate_page(
    struct domain *d, struct page_info *page, unsigned int memflags);
int page_make_sharable(struct domain *d, 
                       struct page_info *page, 
                       int expected_refcnt);
int page_make_private(struct domain *d, struct page_info *page);

int map_ldt_shadow_page(unsigned int);

#ifdef CONFIG_X86_64
extern int memory_add(unsigned long spfn, unsigned long epfn, unsigned int pxm);
#else
static inline int memory_add(uint64_t spfn, uint64_t epfn, uint32_t pxm)
{
    return -ENOSYS;
}
#endif

#ifdef CONFIG_COMPAT
void domain_set_alloc_bitsize(struct domain *d);
unsigned int domain_clamp_alloc_bitsize(struct domain *d, unsigned int bits);
#else
# define domain_set_alloc_bitsize(d) ((void)0)
# define domain_clamp_alloc_bitsize(d, b) (b)
#endif

unsigned long domain_get_maximum_gpfn(struct domain *d);

extern struct domain *dom_xen, *dom_io, *dom_cow;	/* for vmcoreinfo */

extern mfn_t shared_zero_page;

/* Definition of an mm lock: spinlock with extra fields for debugging */
typedef struct mm_lock {
    spinlock_t         lock; 
    int                unlock_level;
    int                locker;          /* processor which holds the lock */
    const char        *locker_function; /* func that took it */
} mm_lock_t;

#endif /* __ASM_X86_MM_H__ */
