
#ifndef __ARCH_LDT_H
#define __ARCH_LDT_H

#ifndef __ASSEMBLY__

static inline void load_LDT(struct vcpu *v)
{
    BUG();
}

#endif /* !__ASSEMBLY__ */

#endif

/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
