/*
 * mtrr.c: MTRR/PAT virtualization
 *
 * Copyright (c) 2007, Intel Corporation.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 59 Temple
 * Place - Suite 330, Boston, MA 02111-1307 USA.
 */

#include <xen/config.h>
#include <xen/types.h>
#include <xen/mm.h>
#include <asm/e820.h>
#include <asm/mm.h>
#include <asm/paging.h>
#include <asm/p2m.h>
#include <xen/domain_page.h>
#include <asm/mtrr.h>
#include <asm/hvm/support.h>
#include <asm/hvm/cacheattr.h>
#include <public/hvm/e820.h>

static uint32_t size_or_mask;

static void get_mtrr_range(uint64_t base_msr, uint64_t mask_msr,
                           uint64_t *base, uint64_t *end)
{
    uint32_t mask_lo = (uint32_t)mask_msr;
    uint32_t mask_hi = (uint32_t)(mask_msr >> 32);
    uint32_t base_lo = (uint32_t)base_msr;
    uint32_t base_hi = (uint32_t)(base_msr >> 32);
    uint32_t size;

    if ( (mask_lo & 0x800) == 0 )
    {
        /* Invalid (i.e. free) range */
        *base = 0;
        *end = 0;
        return;
    }

    /* Work out the shifted address mask. */
    mask_lo = (size_or_mask | (mask_hi << (32 - PAGE_SHIFT)) |
               (mask_lo >> PAGE_SHIFT));

    /* This works correctly if size is a power of two (a contiguous range). */
    size = -mask_lo;
    *base = base_hi << (32 - PAGE_SHIFT) | base_lo >> PAGE_SHIFT;
    *end = *base + size - 1;
}

bool_t is_var_mtrr_overlapped(struct mtrr_state *m)
{
    int32_t seg, i;
    uint64_t phys_base, phys_mask, phys_base_pre, phys_mask_pre;
    uint64_t base_pre, end_pre, base, end;
    uint8_t num_var_ranges = (uint8_t)m->mtrr_cap;

    for ( i = 0; i < num_var_ranges; i++ )
    {
        phys_base_pre = ((uint64_t*)m->hvm_var_ranges)[i*2];
        phys_mask_pre = ((uint64_t*)m->hvm_var_ranges)[i*2 + 1];

        get_mtrr_range(phys_base_pre, phys_mask_pre,
                        &base_pre, &end_pre);

        for ( seg = i + 1; seg < num_var_ranges; seg ++ )
        {
            phys_base = ((uint64_t*)m->hvm_var_ranges)[seg*2];
            phys_mask = ((uint64_t*)m->hvm_var_ranges)[seg*2 + 1];

            get_mtrr_range(phys_base, phys_mask,
                            &base, &end);

            if ( ((base_pre != end_pre) && (base != end))
                 || ((base >= base_pre) && (base <= end_pre))
                 || ((end >= base_pre) && (end <= end_pre))
                 || ((base_pre >= base) && (base_pre <= end))
                 || ((end_pre >= base) && (end_pre <= end)) )
            {
                /* MTRR is overlapped. */
                return 1;
            }
        }
    }
    return 0;
}

#define MTRRphysBase_MSR(reg) (0x200 + 2 * (reg))
#define MTRRphysMask_MSR(reg) (0x200 + 2 * (reg) + 1)

int hvm_vcpu_cacheattr_init(struct vcpu *v)
{
    struct mtrr_state *m = &v->arch.hvm_vcpu.mtrr;

    BUILD_BUG_ON(HVM_MTRR_VCNT != MTRR_VCNT);

    memset(m, 0, sizeof(*m));

    m->mtrr_cap = (1u << 10) | (1u << 8) | MTRR_VCNT;

    v->arch.hvm_vcpu.pat_cr =
        ((uint64_t)PAT_TYPE_WRBACK) |               /* PAT0: WB */
        ((uint64_t)PAT_TYPE_WRTHROUGH << 8) |       /* PAT1: WT */
        ((uint64_t)PAT_TYPE_UC_MINUS << 16) |       /* PAT2: UC- */
        ((uint64_t)PAT_TYPE_UNCACHABLE << 24) |     /* PAT3: UC */
        ((uint64_t)PAT_TYPE_WRBACK << 32) |         /* PAT4: WB */
        ((uint64_t)PAT_TYPE_WRTHROUGH << 40) |      /* PAT5: WT */
        ((uint64_t)PAT_TYPE_UC_MINUS << 48) |       /* PAT6: UC- */
        ((uint64_t)PAT_TYPE_UNCACHABLE << 56);      /* PAT7: UC */

    return 0;
}

void hvm_vcpu_cacheattr_destroy(struct vcpu *v)
{
}

/* Helper funtions for seting mtrr/pat */
bool_t pat_msr_set(uint64_t *pat, uint64_t msr_content)
{
    uint8_t *value = (uint8_t*)&msr_content;
    int32_t i;

    if ( *pat != msr_content )
    {
        for ( i = 0; i < 8; i++ )
            if ( unlikely(!(value[i] == 0 || value[i] == 1 ||
                            value[i] == 4 || value[i] == 5 ||
                            value[i] == 6 || value[i] == 7)) )
                return 0;

        *pat = msr_content;
    }

    return 1;
}

bool_t mtrr_def_type_msr_set(struct mtrr_state *m, uint64_t msr_content)
{
    uint8_t def_type = msr_content & 0xff;
    uint8_t enabled = (msr_content >> 10) & 0x3;

    if ( unlikely(!(def_type == 0 || def_type == 1 || def_type == 4 ||
                    def_type == 5 || def_type == 6)) )
    {
         HVM_DBG_LOG(DBG_LEVEL_MSR, "invalid MTRR def type:%x\n", def_type);
         return 0;
    }

    if ( unlikely(msr_content && (msr_content & ~0xcffUL)) )
    {
         HVM_DBG_LOG(DBG_LEVEL_MSR, "invalid msr content:%"PRIx64"\n",
                     msr_content);
         return 0;
    }

    m->enabled = enabled;
    m->def_type = def_type;

    return 1;
}

bool_t mtrr_fix_range_msr_set(struct mtrr_state *m, uint32_t row,
                              uint64_t msr_content)
{
    uint64_t *fixed_range_base = (uint64_t *)m->fixed_ranges;

    if ( fixed_range_base[row] != msr_content )
    {
        uint8_t *range = (uint8_t*)&msr_content;
        int32_t i, type;

        for ( i = 0; i < 8; i++ )
        {
            type = range[i];
            if ( unlikely(!(type == 0 || type == 1 ||
                            type == 4 || type == 5 || type == 6)) )
                return 0;
        }

        fixed_range_base[row] = msr_content;
    }

    return 1;
}

bool_t mtrr_var_range_msr_set(
    struct domain *d, struct mtrr_state *m, uint32_t msr, uint64_t msr_content)
{
    uint32_t index, type, phys_addr, eax, ebx, ecx, edx;
    uint64_t msr_mask;
    uint64_t *var_range_base = (uint64_t*)m->hvm_var_ranges;

    index = msr - MSR_IA32_MTRR_PHYSBASE0;
    if ( var_range_base[index] == msr_content )
        return 1;

    type = (uint8_t)msr_content;
    if ( unlikely(!(type == 0 || type == 1 ||
                    type == 4 || type == 5 || type == 6)) )
        return 0;

    phys_addr = 36;
    domain_cpuid(d, 0x80000000, 0, &eax, &ebx, &ecx, &edx);
    if ( eax >= 0x80000008 )
    {
        domain_cpuid(d, 0x80000008, 0, &eax, &ebx, &ecx, &edx);
        phys_addr = (uint8_t)eax;
    }
    msr_mask = ~((((uint64_t)1) << phys_addr) - 1);
    msr_mask |= (index & 1) ? 0x7ffUL : 0xf00UL;
    if ( unlikely(msr_content && (msr_content & msr_mask)) )
    {
        HVM_DBG_LOG(DBG_LEVEL_MSR, "invalid msr content:%"PRIx64"\n",
                    msr_content);
        return 0;
    }

    var_range_base[index] = msr_content;

    m->overlapped = is_var_mtrr_overlapped(m);

    return 1;
}

bool_t mtrr_pat_not_equal(struct vcpu *vd, struct vcpu *vs)
{
    BUG(); return 0;
}

static int hvm_save_mtrr_msr(struct domain *d, hvm_domain_context_t *h)
{
    int i;
    struct vcpu *v;
    struct hvm_hw_mtrr hw_mtrr;
    struct mtrr_state *mtrr_state;
    /* save mtrr&pat */
    for_each_vcpu(d, v)
    {
        mtrr_state = &v->arch.hvm_vcpu.mtrr;

        hw_mtrr.msr_pat_cr = v->arch.hvm_vcpu.pat_cr;

        hw_mtrr.msr_mtrr_def_type = mtrr_state->def_type
                                | (mtrr_state->enabled << 10);
        hw_mtrr.msr_mtrr_cap = mtrr_state->mtrr_cap;

        for ( i = 0; i < MTRR_VCNT; i++ )
        {
            /* save physbase */
            hw_mtrr.msr_mtrr_var[i*2] =
                ((uint64_t*)mtrr_state->hvm_var_ranges)[i*2];
            /* save physmask */
            hw_mtrr.msr_mtrr_var[i*2+1] =
                ((uint64_t*)mtrr_state->hvm_var_ranges)[i*2+1];
        }

        for ( i = 0; i < NUM_FIXED_MSR; i++ )
            hw_mtrr.msr_mtrr_fixed[i] =
                ((uint64_t*)mtrr_state->fixed_ranges)[i];

        if ( hvm_save_entry(MTRR, v->vcpu_id, h, &hw_mtrr) != 0 )
            return 1;
    }
    return 0;
}

static int hvm_load_mtrr_msr(struct domain *d, hvm_domain_context_t *h)
{
    int vcpuid, i;
    struct vcpu *v;
    struct mtrr_state *mtrr_state;
    struct hvm_hw_mtrr hw_mtrr;

    vcpuid = hvm_load_instance(h);
    if (vcpuid >= d->max_vcpus) {
      no_vcpu:
        gdprintk(XENLOG_ERR, "HVM restore: no vcpu vm%u.%u\n", d->domain_id,
                 vcpuid);
        return -EINVAL;
    }
    vcpuid = array_index_nospec(vcpuid, d->max_vcpus);
    if ((v = d->vcpu[vcpuid]) == NULL)
        goto no_vcpu;

    if ( hvm_load_entry(MTRR, h, &hw_mtrr) != 0 )
        return -EINVAL;

    mtrr_state = &v->arch.hvm_vcpu.mtrr;

    pat_msr_set(&v->arch.hvm_vcpu.pat_cr, hw_mtrr.msr_pat_cr);

    mtrr_state->mtrr_cap = hw_mtrr.msr_mtrr_cap;

    for ( i = 0; i < NUM_FIXED_MSR; i++ )
        mtrr_fix_range_msr_set(mtrr_state, i, hw_mtrr.msr_mtrr_fixed[i]);

    for ( i = 0; i < MTRR_VCNT; i++ )
    {
        mtrr_var_range_msr_set(d, mtrr_state,
                MTRRphysBase_MSR(i), hw_mtrr.msr_mtrr_var[i*2]);
        mtrr_var_range_msr_set(d, mtrr_state,
                MTRRphysMask_MSR(i), hw_mtrr.msr_mtrr_var[i*2+1]);
    }

    mtrr_def_type_msr_set(mtrr_state, hw_mtrr.msr_mtrr_def_type);

    return 0;
}

HVM_REGISTER_SAVE_RESTORE(MTRR, hvm_save_mtrr_msr, hvm_load_mtrr_msr,
                          1, HVMSR_PER_VCPU);

uint8_t epte_get_entry_emt(struct domain *d, unsigned long gfn, mfn_t mfn,
                           uint8_t *ipat, bool_t direct_mmio)
{
    struct vcpu *v = current;

    *ipat = 0;

    if ( (current->domain != d) &&
         ((d->vcpu == NULL) || ((v = d->vcpu[0]) == NULL)) )
        return MTRR_TYPE_WRBACK;

    if ( !v->domain->arch.hvm_domain.params[HVM_PARAM_IDENT_PT] )
        return MTRR_TYPE_WRBACK;

    if ( (v == current) && v->domain->arch.hvm_domain.is_in_uc_mode )
        return MTRR_TYPE_UNCACHABLE;

    if ( !mfn_valid(mfn_x(mfn)) )
        return MTRR_TYPE_UNCACHABLE;

    {
        *ipat = 1;
        return MTRR_TYPE_WRBACK;
    }

}
