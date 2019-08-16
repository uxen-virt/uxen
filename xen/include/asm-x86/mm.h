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

#ifndef __ASM_X86_MM_H__
#define __ASM_X86_MM_H__

#include <xen/config.h>
#include <xen/list.h>
#include <xen/spinlock.h>
#include <asm/io.h>
#include <asm/uaccess.h>

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

// #define DEBUG_STRAY_PAGES 1
// #define DEBUG_MAPCACHE 1

/* __UXEN__ version of page_info */
struct page_info
{
    union {
        /* Each frame can be threaded onto a doubly-linked list. */
        struct page_list_entry list;

        /* vframe containing page data */
        struct {
            __pdx_t page;
            uint16_t offset;
        } __attribute__ ((packed)) page_data;
    };

    /* Reference count and various PGC_xxx flags and fields. */
    uint32_t count_info;

    /* Owner of this page. */
    domid_t domain;

#ifdef DEBUG_STRAY_PAGES
    void *alloc0;
    void *alloc1;
#endif  /* DEBUG_STRAY_PAGES */

#ifdef DEBUG_MAPCACHE
    atomic_t mapped;
    void *lastmap;
    void *lastmap0;
#endif  /* DEBUG_MAPCACHE */
};

#undef __pdx_t

#define PG_shift(idx)   (32 /* BITS_PER_UINT32_T */ - (idx))
#define PG_mask(x, idx) (x ## UL << PG_shift(idx))

/* __UXEN__ PGC flags */

#define _PGC_xen_page     PG_shift(2)
#define PGC_xen_page      PG_mask(1, 2)

/* #define _PGC_     PG_shift(3) */
/* #define PGC_      PG_mask(1, 3) */

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

#define is_vframe_mfn(mfn) (__mfn_valid_vframe(mfn))
#define is_vframe_page(page) (is_vframe_mfn(page_to_mfn(page)))

#if defined(__i386__)
#define PRtype_info "08lx" /* should only be used for printk's */
#elif defined(__x86_64__)
#define PRtype_info "016lx"/* should only be used for printk's */
#endif

/* The number of out-of-sync shadows we allow per vcpu (prime, please) */
#define SHADOW_OOS_PAGES 3

/* OOS fixup entries */
#define SHADOW_OOS_FIXUPS 2

#define page_get_owner(_p)                                              \
    ((_p)->domain < DOMID_FIRST_RESERVED ? domain_array[(_p)->domain] : NULL)
#define page_set_owner(_p,_d)                                           \
    ((_p)->domain = (_d) ? ((struct domain *)(_d))->domain_id : DOMID_ANON)

#define maddr_get_owner(ma)   (page_get_owner(maddr_to_page((ma))))
#define vaddr_get_owner(va)   (page_get_owner(virt_to_page((va))))

#define XENSHARE_writable 0
#define XENSHARE_readonly 1
extern void share_xen_page_with_guest(
    struct page_info *page, struct domain *d, int readonly);
extern void share_xen_page_with_privileged_guests(
    struct page_info *page, int readonly);

extern struct page_info *frame_table;
extern unsigned long max_page;
extern unsigned long max_vframe;
extern unsigned long total_pages;
void init_frametable(void);

#define PDX_GROUP_COUNT ((1 << L2_PAGETABLE_SHIFT) / \
                         (sizeof(*frame_table) & -sizeof(*frame_table)))
extern unsigned long pdx_group_valid[];

#define __virt_to_page(v) mfn_to_page(virt_to_mfn(v))

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

void
put_page_destructor(struct page_info *page,
                    void (*destructor)(struct page_info *, va_list), ...);
int
change_page_owner(struct page_info *page, struct domain *to,
                  struct domain *from, int refs);

#define put_page_and_type(page) put_page(page)
#define put_page_and_type_preemptible(page, preemptible) put_page(page)
#define get_page_and_type(page, domain, type) get_page(page, domain)

#define ASSERT_PAGE_IS_TYPE(_p, _t) do { /* */ } while (0)
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


#ifdef __x86_64__
/* 40 bits */
#define INVALID_MFN             (0xffffffffffUL)
#define SHARED_ZERO_MFN         (0xfffffffffeUL)
#define COMPRESSED_MFN          (0xfffffffffdUL)
#define ERROR_MFN               (0xfffffffffcUL)
#else  /* __x86_64__ */
/* 32 bits */
#define INVALID_MFN             (0xffffffffUL)
#define SHARED_ZERO_MFN         (0xfffffffeUL)
#define COMPRESSED_MFN          (0xfffffffdUL)
#define ERROR_MFN               (0xfffffffcUL)
#endif /* __x86_64__ */

#define p2m_mfn_is_vframe(mfn) mfn_valid_vframe(mfn)
#define p2m_mfn_is_page_data(mfn) p2m_mfn_is_vframe(mfn)

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
void make_cr3(struct vcpu *v, uint64_t cr3);
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
