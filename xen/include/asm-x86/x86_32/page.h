
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

#ifndef __UXEN__
#define __mfn_valid(mfn)        ({                                            \
    unsigned long __m_f_n = (mfn);                                            \
    likely(__m_f_n < max_page) &&                                             \
    likely(test_bit(pfn_to_pdx(__m_f_n) / PDX_GROUP_COUNT, pdx_group_valid)); \
})
#endif  /* __UXEN__ */

#define max_pdx                 max_page
#define pfn_to_pdx(pfn)         (pfn)
#define pdx_to_pfn(pdx)         (pdx)
#ifndef __UXEN__
#define virt_to_pdx(va)         virt_to_mfn(va)
#define pdx_to_virt(pdx)        mfn_to_virt(pdx)
#endif  /* __UXEN__ */

#ifndef __UXEN__
#define pfn_to_sdx(pfn)         ((pfn)>>(SUPERPAGE_SHIFT-PAGE_SHIFT))
#define sdx_to_pfn(sdx)         ((sdx)<<(SUPERPAGE_SHIFT-PAGE_SHIFT))
#endif  /* __UXEN__ */

#ifndef __UXEN__
static inline unsigned long __virt_to_maddr(unsigned long va)
{
    ASSERT(va >= DIRECTMAP_VIRT_START && va < DIRECTMAP_VIRT_END);
    return va - DIRECTMAP_VIRT_START;
}

static inline void *__maddr_to_virt(unsigned long ma)
{
    ASSERT(ma < DIRECTMAP_VIRT_END - DIRECTMAP_VIRT_START);
    return (void *)(ma + DIRECTMAP_VIRT_START);
}
#else   /* __UXEN__ */
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
#endif  /* __UXEN__ */

/* read access (should only be used for debug printk's) */
typedef u64 intpte_t;
#define PRIpte "016llx"

typedef struct { intpte_t l1; } l1_pgentry_t;
typedef struct { intpte_t l2; } l2_pgentry_t;
typedef struct { intpte_t l3; } l3_pgentry_t;
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
