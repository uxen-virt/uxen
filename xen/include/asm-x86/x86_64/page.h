
#ifndef __X86_64_PAGE_H__
#define __X86_64_PAGE_H__

#define L1_PAGETABLE_SHIFT      12
#define L2_PAGETABLE_SHIFT      21
#define L3_PAGETABLE_SHIFT      30
#define L4_PAGETABLE_SHIFT      39
#define PAGE_SHIFT              L1_PAGETABLE_SHIFT
#define SUPERPAGE_SHIFT         L2_PAGETABLE_SHIFT
#define ROOT_PAGETABLE_SHIFT    L4_PAGETABLE_SHIFT

#define PAGETABLE_ORDER         9
#define L1_PAGETABLE_ENTRIES    (1<<PAGETABLE_ORDER)
#define L2_PAGETABLE_ENTRIES    (1<<PAGETABLE_ORDER)
#define L3_PAGETABLE_ENTRIES    (1<<PAGETABLE_ORDER)
#define L4_PAGETABLE_ENTRIES    (1<<PAGETABLE_ORDER)
#define ROOT_PAGETABLE_ENTRIES  L4_PAGETABLE_ENTRIES
#define SUPERPAGE_ORDER         PAGETABLE_ORDER
#define SUPERPAGE_PAGES         (1<<SUPERPAGE_ORDER)

#define __PAGE_OFFSET           DIRECTMAP_VIRT_START
#define __XEN_VIRT_START        XEN_VIRT_START

/* These are architectural limits. Current CPUs support only 40-bit phys. */
#define PADDR_BITS              52
#define VADDR_BITS              48
#define PADDR_MASK              ((1UL << PADDR_BITS)-1)
#define VADDR_MASK              ((1UL << VADDR_BITS)-1)

#define is_canonical_address(x) (((long)(x) >> 47) == ((long)(x) >> 63))

#ifndef __ASSEMBLY__

#include <xen/config.h>
#include <xen/perfc.h>
#include <asm/types.h>

extern unsigned long xen_virt_end;

extern unsigned long max_pdx;
extern unsigned long pfn_pdx_bottom_mask, ma_va_bottom_mask;
extern unsigned int pfn_pdx_hole_shift;
extern unsigned long pfn_hole_mask;
extern unsigned long pfn_top_mask, ma_top_mask;
extern void pfn_pdx_hole_setup(unsigned long);

#define page_to_pdx(pg)  ((pg) - frame_table)
#define pdx_to_page(pdx) (frame_table + (pdx))
#define spage_to_pdx(spg) ((spg>>(SUPERPAGE_SHIFT-PAGE_SHIFT)) - spage_table)
#define pdx_to_spage(pdx) (spage_table + ((pdx)<<(SUPERPAGE_SHIFT-PAGE_SHIFT)))
/*
 * Note: These are solely for the use by page_{get,set}_owner(), and
 *       therefore don't need to handle the XEN_VIRT_{START,END} range.
 */
#define virt_to_pdx(va)         virt_to_mfn(va)
#define pdx_to_virt(pdx)        mfn_to_virt(pdx)

#define pfn_to_pdx(pfn)         ((unsigned long)(pfn))
#define pdx_to_pfn(pdx)         ((unsigned long)(pdx))

#define map_xen_page(mfn) (({                                   \
                struct page_info *_pg;                          \
                _pg = __mfn_to_page(mfn);                       \
                if (!(_pg->count_info & PGC_xen_page)) DEBUG(); \
                perfc_incr(map_xen_page_count);                 \
                UI_HOST_CALL(ui_map_page_global, mfn);          \
            }))
#define unmap_xen_page(va) (({                                    \
                unsigned long _mfn;                               \
                _mfn = UI_HOST_CALL(ui_unmap_page_global_va, va); \
                perfc_incr(unmap_xen_page_count);                 \
                _mfn;                                             \
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
        u64 : 12,
            : 40,
            ptp_idx: PTP_IDX_BITS,
            : 2;
    };
} pt_entry_t;

/* read access (should only be used for debug printk's) */
typedef u64 intpte_t;
#define PRIpte "016lx"

typedef union { intpte_t l1; pt_entry_t pte; } l1_pgentry_t;
typedef union { intpte_t l2; pt_entry_t pte; } l2_pgentry_t;
typedef union { intpte_t l3; pt_entry_t pte; } l3_pgentry_t;
typedef union { intpte_t l4; pt_entry_t pte; } l4_pgentry_t;
typedef l4_pgentry_t root_pgentry_t;

#endif /* !__ASSEMBLY__ */

#define pte_read_atomic(ptep)       atomic_read64(ptep)
#define pte_write_atomic(ptep, pte) atomic_write64(ptep, pte)
#define pte_write(ptep, pte)        atomic_write64(ptep, pte)

/* Given a virtual address, get an entry offset into a linear page table. */
#define l1_linear_offset(_a) (((_a) & VADDR_MASK) >> L1_PAGETABLE_SHIFT)
#define l2_linear_offset(_a) (((_a) & VADDR_MASK) >> L2_PAGETABLE_SHIFT)
#define l3_linear_offset(_a) (((_a) & VADDR_MASK) >> L3_PAGETABLE_SHIFT)
#define l4_linear_offset(_a) (((_a) & VADDR_MASK) >> L4_PAGETABLE_SHIFT)

#define is_guest_l1_slot(_s) (1)
#define is_guest_l2_slot(_d, _t, _s)                   \
    ( !is_pv_32bit_domain(_d) ||                       \
      !((_t) & PGT_pae_xen_l2) ||                      \
      ((_s) < COMPAT_L2_PAGETABLE_FIRST_XEN_SLOT(_d)) )
#define is_guest_l3_slot(_s) (1)
#define is_guest_l4_slot(_d, _s)                    \
    ( is_pv_32bit_domain(_d)                        \
      ? ((_s) == 0)                                 \
      : (((_s) < ROOT_PAGETABLE_FIRST_XEN_SLOT) ||  \
         ((_s) > ROOT_PAGETABLE_LAST_XEN_SLOT)))

#define root_get_pfn              l4e_get_pfn
#define root_get_flags            l4e_get_flags
#define root_get_intpte           l4e_get_intpte
#define root_empty                l4e_empty
#define root_from_paddr           l4e_from_paddr
#define PGT_root_page_table       PGT_l4_page_table

/*
 * PTE pfn and flags:
 *  40-bit pfn   = (pte[51:12])
 *  24-bit flags = (pte[63:52],pte[11:0])
 */

/* Extract flags into 24-bit integer, or turn 24-bit flags into a pte mask. */
#define get_pte_flags(x) (((int)((x) >> 40) & ~0xFFF) | ((int)(x) & 0xFFF))
#define put_pte_flags(x) (((intpte_t)((x) & ~0xFFF) << 40) | ((x) & 0xFFF))

/* Bit 23 of a 24-bit flag mask. This corresponds to bit 63 of a pte.*/
#define _PAGE_NX_BIT (1U<<23)

/* Bit 22 of a 24-bit flag mask. This corresponds to bit 62 of a pte.*/
#define _PAGE_GNTTAB (1U<<22)

#define PAGE_HYPERVISOR         (__PAGE_HYPERVISOR         | _PAGE_GLOBAL)
#define PAGE_HYPERVISOR_NOCACHE (__PAGE_HYPERVISOR_NOCACHE | _PAGE_GLOBAL)

#define USER_MAPPINGS_ARE_GLOBAL
#ifdef USER_MAPPINGS_ARE_GLOBAL
/*
 * Bit 12 of a 24-bit flag mask. This corresponds to bit 52 of a pte.
 * This is needed to distinguish between user and kernel PTEs since _PAGE_USER
 * is asserted for both.
 */
#define _PAGE_GUEST_KERNEL (1U<<12)
#else
#define _PAGE_GUEST_KERNEL 0
#endif

#endif /* __X86_64_PAGE_H__ */

/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
