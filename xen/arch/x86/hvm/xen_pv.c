/*
 * Copyright 2017, Bromium, Inc.
 * SPDX-License-Identifier: ISC
 */

#include <xen/lib.h>
#include <asm/hvm/xen_pv.h>
#include <asm/hvm/vmx/vmx.h>

#define PV_VMX_XEN_CPUID_LEAF_BASE 0x40000000
#define PV_VMX_XEN_CPUID_LEAF_RANGE 0x10000
#define PV_VMX_XEN_CPUID_LEAD_SKIP 0x100

int xen_pv_ept = 0;


void xen_pv_ept_flush(struct p2m_domain *p2m)
{
    uint64_t ept_base;

    ept_base = (size_t)pagetable_get_pfn(p2m_get_pagetable(p2m)) << PAGE_SHIFT;

    __invept(INVEPT_SINGLE_CONTEXT, ept_base, 0);

    p2m->virgin = 1;
}


static inline void xen_pv_ept_write_invept(struct p2m_domain *p2m, 
                                           int level,
                                           uint64_t gfn,
                                           uint64_t new_entry,
                                           int invept)
{
    int type = XEN_PV_INVEPT_PVEPT_CONTEXT;
    struct xen_pv_invept_desc desc;

    desc.eptp = (size_t)pagetable_get_pfn(p2m_get_pagetable(p2m)) << PAGE_SHIFT;
    desc.L2_gpa = gfn << PAGE_SHIFT;
    desc.L2_gpa |= level;
    desc.L2_gpa |= XEN_PV_INVEPT_PVEPT_VALID;

    if (invept)
        desc.L2_gpa |= XEN_PV_INVEPT_PVEPT_INVALIDATE;

    desc.L21e = new_entry;

    if (!desc.eptp)
        BUG();

    asm volatile ( INVEPT_OPCODE
                   MODRM_EAX_08
                   /* CF==1 or ZF==1 --> crash (ud2) */
                   "ja 1f ; ud2 ; 1:\n"
                   :
                   : "a" (&desc), "c" (type)
                   : "memory" );
}


void xen_pv_ept_write(struct p2m_domain *p2m, int level, uint64_t gfn,
                      uint64_t new_entry, int invept)
{
    if (p2m->virgin)
        return;

    if (!invept)
        return;

    xen_pv_ept_write_invept(p2m, level, gfn, new_entry, invept);
}


uint32_t running_on_xen(uint32_t *eax)
{
    uint32_t leaf;
    char signature[13];

    *eax = 0;
    for (leaf = 0; leaf < PV_VMX_XEN_CPUID_LEAF_RANGE;
         leaf += PV_VMX_XEN_CPUID_LEAD_SKIP) {
        cpuid(PV_VMX_XEN_CPUID_LEAF_BASE + leaf, eax,
              (uint32_t *)&signature[0], (uint32_t *)&signature[4],
              (uint32_t *)&signature[8]);
        signature[12] = 0;

        if (!strcmp(signature, "XenVMMXenVMM"))
            break;
    }

    if (leaf >= PV_VMX_XEN_CPUID_LEAF_RANGE ||
        (*eax - (PV_VMX_XEN_CPUID_LEAF_BASE + leaf)) < 2)
        return (uint32_t)-1;

    return leaf;
}


void xen_pv_ept_probe(void)
{
    int type = XEN_PV_INVEPT_PVEPT_CONTEXT;
    uint32_t eax;
    int present = 1;
    struct xen_pv_invept_desc desc;

    if (running_on_xen(&eax) == (uint32_t)-1) {
        dprintk(XENLOG_INFO, "uXen Xen PV EPT disabled as not running on Xen\n");
        return;
    }

    desc.eptp = 0;
    desc.L2_gpa = 0;
    desc.L2_gpa |= 0;
    desc.L2_gpa |= XEN_PV_INVEPT_PVEPT_VALID;

    asm volatile ( INVEPT_OPCODE
                   MODRM_EAX_08
                   /* CF==1 or ZF==1 --> set present 0 */
                   "ja 1f ; xor %0,%0 ; 1:\n"
                   : "+r" (present)
                   : "a" (&desc), "c" (type)
                   : "memory" );

    if (!present) {
        printk("uXen Xen PV EPT disabled as this version of Xen lacks support\n");
        return;
    }

    printk("uXen Xen PV EPT enabled\n");
    xen_pv_ept = 1;
}
