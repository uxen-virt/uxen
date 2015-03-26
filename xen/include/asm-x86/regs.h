
#ifndef __X86_REGS_H__
#define __X86_REGS_H__

#ifdef __x86_64__
#include <asm/x86_64/regs.h>
#else
#include <asm/x86_32/regs.h>
#endif

#define return_reg(v) ((v)->arch.user_regs.eax)

#ifndef __UXEN__
#define guest_mode(r)                                                         \
({                                                                            \
    unsigned long diff = (char *)guest_cpu_user_regs() - (char *)(r);         \
    /* Frame pointer must point into current CPU stack. */                    \
    ASSERT(diff < STACK_SIZE);                                                \
    /* If not a guest frame, it must be a hypervisor frame. */                \
    ASSERT((diff == 0) || (!vm86_mode(r) && (r->cs == __HYPERVISOR_CS)));     \
    /* Return TRUE if it's a guest frame. */                                  \
    (diff == 0);                                                              \
})
#else   /* __UXEN__ */
/* Return TRUE if it's a guest frame. */
#define guest_mode(r) ((char *)guest_cpu_user_regs() == (char *)(r))
#endif  /* __UXEN__ */

#endif /* __X86_REGS_H__ */
