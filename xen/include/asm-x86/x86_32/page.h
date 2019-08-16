
#ifndef __X86_32_PAGE_H__
#define __X86_32_PAGE_H__

#define L1_PAGETABLE_SHIFT      12
#define L2_PAGETABLE_SHIFT      21
#define L3_PAGETABLE_SHIFT      30
#define PAGE_SHIFT              L1_PAGETABLE_SHIFT
#define SUPERPAGE_SHIFT         L2_PAGETABLE_SHIFT
#define ROOT_PAGETABLE_SHIFT    L3_PAGETABLE_SHIFT

#define PAGETABLE_ORDER         9
#define L1_PAGETABLE_ENTRIES    (1<<PAGETABLE_ORDER)
#define L2_PAGETABLE_ENTRIES    (1<<PAGETABLE_ORDER)
#define L3_PAGETABLE_ENTRIES    4
#define ROOT_PAGETABLE_ENTRIES  L3_PAGETABLE_ENTRIES
#define SUPERPAGE_ORDER         PAGETABLE_ORDER
#define SUPERPAGE_PAGES         (1<<SUPERPAGE_ORDER)

/*
 * Architecturally, physical addresses may be up to 52 bits. However, the
 * page-frame number (pfn) of a 52-bit address will not fit into a 32-bit
 * word. Instead we treat bits 44-51 of a pte as flag bits which are never
 * allowed to be set by a guest kernel. This 'limits' us to addressing 16TB
 * of physical memory on a 32-bit PAE system.
 */
#define PADDR_BITS              44
#define PADDR_MASK              ((1ULL << PADDR_BITS)-1)

#define __PAGE_OFFSET           (0xFF000000)
#define __XEN_VIRT_START        __PAGE_OFFSET

#define VADDR_BITS              32
#define VADDR_MASK              (~0UL)

#define is_canonical_address(x) 1

/* Given a virtual address, get an entry offset into a linear page table. */
#define l1_linear_offset(_a) ((_a) >> L1_PAGETABLE_SHIFT)
#define l2_linear_offset(_a) ((_a) >> L2_PAGETABLE_SHIFT)

#ifndef __ASSEMBLY__

#include <xen/config.h>
#include <xen/perfc.h>
#include <asm/types.h>

#define max_pdx                 max_page
#define pfn_to_pdx(pfn)         (pfn)
#define pdx_to_pfn(pdx)         (pdx)

#ifdef DEBUG_MAPCACHE
#define DEBUG_inc_mapped(_v, _pg) do {                   \
        if (_v) {                                        \
            atomic_inc(&_pg->mapped);                    \
            _pg->lastmap = current_text_addr();          \
            _pg->lastmap0 = __builtin_return_address(0); \
        }                                                \
    } while (0)
#define DEBUG_dec_mapped(_mfn) do {                 \
        if (_mfn != INVALID_MFN)                    \
            atomic_dec(&mfn_to_page(_mfn)->mapped); \
    } while (0)
#define DEBUG_check_mapped(_pg) do {        \
        ASSERT(atomic_read(&_pg->mapped));  \
    } while (0)
#else  /* DEBUG_MAPCACHE */
#define DEBUG_inc_mapped(_v, _pg) do { /* nothing */; } while (0)
#define DEBUG_dec_mapped(_mfn) do { /* nothing */; } while (0)
#define DEBUG_check_mapped(_pg) do { /* nothing */; } while (0)
#endif  /* DEBUG_MAPCACHE */
#define map_xen_page(mfn) (({                                   \
                struct page_info *_pg;                          \
                void *_v;                                       \
                _pg = __mfn_to_page(mfn);                       \
                if (!(_pg->count_info & PGC_xen_page)) DEBUG(); \
                perfc_incr(map_xen_page_count);                 \
                _v = UI_HOST_CALL(ui_map_page_global, mfn);     \
                DEBUG_inc_mapped(_v, _pg);                      \
                _v;                                             \
            }))
#define unmap_xen_page(va) (({                                     \
                unsigned long _mfn;                                \
                _mfn = UI_HOST_CALL(ui_unmap_page_global_va, va);  \
                DEBUG_dec_mapped(_mfn);                            \
                perfc_incr(unmap_xen_page_count);                  \
                _mfn;                                              \
            }))
#define __virt_to_maddr(va)                                 \
    (((paddr_t)UI_HOST_CALL(ui_mapped_global_va_pfn,        \
                            (void *)(va)) << PAGE_SHIFT) +  \
     ((va) & (PAGE_SIZE - 1)))

typedef union {
    struct {
        u64 present : 1,  /* bit 0 - present */
            rw      : 1,  /* bit 1 - rw */
            user    : 1,  /* bit 2 - user */
                    : 6,  /* bits 8:3 - global/pse/pat/dirty/accessed/pcd/pwt */
                    : 3,  /* bits 11:9 - avail[210] */
            mfn     : 40, /* bits 51:12 - Machine physical frame number */
                    : 6,  /* bits 57:52 - */
                    : 4,  /* bits 61:58 - */
                    : 1,  /* bit 62 - */
                    : 1;  /* bit 63 - */
    };
    u64 e;
    struct {
        u64 : 9,
            ptp_idx: PTP_IDX_BITS_amd_x86,
            : 40,
            : 12;
    };
} pt_entry_t;

/* read access (should only be used for debug printk's) */
typedef u64 intpte_t;
#define PRIpte "016llx"

typedef union { intpte_t l1; pt_entry_t pte; } l1_pgentry_t;
typedef union { intpte_t l2; pt_entry_t pte; } l2_pgentry_t;
typedef union { intpte_t l3; pt_entry_t pte; } l3_pgentry_t;
typedef l3_pgentry_t root_pgentry_t;

extern unsigned int PAGE_HYPERVISOR;
extern unsigned int PAGE_HYPERVISOR_NOCACHE;

#endif

#define pte_read_atomic(ptep)       atomic_read64(ptep)
#define pte_write_atomic(ptep, pte) atomic_write64(ptep, pte)
#define pte_write(ptep, pte) do {                             \
    u32 *__ptep_words = (u32 *)(ptep);                        \
    atomic_write32(&__ptep_words[0], 0);                      \
    wmb();                                                    \
    atomic_write32(&__ptep_words[1], (pte) >> 32);            \
    wmb();                                                    \
    atomic_write32(&__ptep_words[0], (pte) >>  0);            \
} while ( 0 )

/* root table */
#define root_get_pfn              l3e_get_pfn
#define root_get_flags            l3e_get_flags
#define root_get_intpte           l3e_get_intpte
#define root_empty                l3e_empty
#define root_from_paddr           l3e_from_paddr
#define PGT_root_page_table       PGT_l3_page_table

/* misc */
#define is_guest_l1_slot(s)    (1)
#define is_guest_l2_slot(d,t,s)                                            \
    ( !((t) & PGT_pae_xen_l2) ||                                           \
      ((s) < (L2_PAGETABLE_FIRST_XEN_SLOT & (L2_PAGETABLE_ENTRIES - 1))) )
#define is_guest_l3_slot(s)    (1)

/*
 * PTE pfn and flags:
 *  32-bit pfn   = (pte[43:12])
 *  32-bit flags = (pte[63:44],pte[11:0])
 */

/* Extract flags into 32-bit integer, or turn 32-bit flags into a pte mask. */
#define get_pte_flags(x) (((int)((x) >> 32) & ~0xFFF) | ((int)(x) & 0xFFF))
#define put_pte_flags(x) (((intpte_t)((x) & ~0xFFF) << 32) | ((x) & 0xFFF))

/* Bit 31 of a 32-bit flag mask. This corresponds to bit 63 of a pte.*/
#define _PAGE_NX_BIT (1U<<31)

#endif /* __X86_32_PAGE_H__ */

/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
