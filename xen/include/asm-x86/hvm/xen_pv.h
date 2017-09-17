/*
 * Copyright 2017, Bromium, Inc.
 * SPDX-License-Identifier: ISC
 */

#ifndef __ASM_X86_HVM_XEN_PV_H__
#define __ASM_X86_HVM_XEN_PV_H__

#include <asm/msr-index.h>
#include <asm/p2m.h>
#include <asm/hvm/hvm.h>
#include <asm/hvm/support.h>
#include <asm/hvm/vmx/vmx.h>
#include <asm/hvm/vmx/vmcs.h>

#define XEN_PV_INVEPT_PVEPT_CONTEXT    0x88d8

struct xen_pv_invept_desc
{
    u64 eptp;
    union {
        u64 L2_gpa; /* Metadata in the low 12 bits. */
        struct {
            unsigned int lvl:3, valid:1, inv:1;
        };
    };
    u64 L21e;
};

#define XEN_PV_INVEPT_PVEPT_VALID (1ULL << 3)
#define XEN_PV_INVEPT_PVEPT_INVALIDATE (1ULL << 4)


extern int xen_pv_ept;

void xen_pv_ept_write(struct p2m_domain *p2m, int level, uint64_t gfn,
                     uint64_t new_entry, int invept);

void xen_pv_ept_flush(struct p2m_domain *p2m);

void xen_pv_ept_probe(void);

#endif /* __ASM_X86_HVM_XEN_PV_H__ */
