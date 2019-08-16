
#ifndef __X86_REGS_H__
#define __X86_REGS_H__

#ifdef __x86_64__
#include <asm/x86_64/regs.h>
#else
#include <asm/x86_32/regs.h>
#endif

#define return_reg(v) ((v)->arch.user_regs.eax)

/* Return TRUE if it's a guest frame. */
#define guest_mode(r) ((char *)guest_cpu_user_regs() == (char *)(r))

#endif /* __X86_REGS_H__ */
