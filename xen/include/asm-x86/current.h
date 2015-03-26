/******************************************************************************
 * current.h
 * 
 * Information structure that lives at the bottom of the per-cpu Xen stack.
 */

#ifndef __X86_CURRENT_H__
#define __X86_CURRENT_H__

#include <xen/config.h>
#include <xen/percpu.h>
#include <public/xen.h>
#include <asm/page.h>

struct vcpu;

struct cpu_info {
#ifndef __UXEN__
    struct cpu_user_regs guest_cpu_user_regs;
#endif  /* __UXEN__ */
    unsigned int processor_id;
#ifndef __UXEN__
    struct vcpu *current_vcpu;
#endif  /* __UXEN__ */
    unsigned long per_cpu_offset;
#ifndef __UXEN__
#ifdef __x86_64__ /* get_stack_bottom() must be 16-byte aligned */
    unsigned long __pad_for_stack_bottom;
#endif
#endif  /* __UXEN__ */
};

#ifdef __UXEN__

extern struct cpu_info uxen_cpu_info[];

static inline int
host_processor_id(void)
{
    uint8_t cpu;
#ifdef __x86_64__
#ifdef UXEN_GS_CPU_OFFSET
    __asm__ ("movb %%gs:"STR(UXEN_GS_CPU_OFFSET)", %0"
             : "=q" (cpu));
#else
    __asm__ ("movb %%gs:0(%1), %0" : "=q" (cpu)
             : "r" ((uint64_t)uxen_info->ui_host_gsoff_cpu) : "memory");
#endif
#else
    __asm__ ("movb %%fs:"STR(UXEN_FS_CPU_OFFSET)", %0"
             : "=q" (cpu));
#endif
    return cpu;
}

static inline struct vcpu *
host_current(void)
{
    struct vcpu *vcpu;
#ifdef __x86_64__
#ifdef UXEN_GS_CURRENT_OFFSET
    __asm__ ("movq %%gs:"STR(UXEN_GS_CURRENT_OFFSET)", %0"
             : "=r" (vcpu));
#else
    __asm__ ("movq %%gs:0(%1), %0" : "=r" (vcpu)
             : "r" ((uint64_t)uxen_info->ui_host_gsoff_current) : "memory");
#endif
#else
    __asm__ ("movl %%fs:"STR(UXEN_FS_CURRENT_OFFSET)", %0"
             : "=r" (vcpu));
#endif
    return vcpu;
}

static inline void
set_host_current(struct vcpu *vcpu)
{
#ifdef __x86_64__
#ifdef UXEN_GS_CURRENT_OFFSET
    __asm__ ("movq %0, %%gs:"STR(UXEN_GS_CURRENT_OFFSET)
             : : "r" (vcpu));
#else
    __asm__ ("movq %0, %%gs:0(%1)" : : "r" (vcpu),
             "r" ((uint64_t)uxen_info->ui_host_gsoff_current) : "memory" );
#endif
#else
    __asm__ ("movl %0, %%fs:"STR(UXEN_FS_CURRENT_OFFSET)
             : : "r" (vcpu));
#endif
}

#define get_cpu_info() (&uxen_cpu_info[host_processor_id()])

#define get_current()         host_current()
#define uxen_set_current(vcpu) set_host_current(vcpu)

#endif

#ifndef __UXEN__
static inline struct cpu_info *get_cpu_info(void)
{
    struct cpu_info *cpu_info;
    __asm__ ( "and %%"__OP"sp,%0; or %2,%0"
              : "=r" (cpu_info)
              : "0" (~(STACK_SIZE-1)), "i" (STACK_SIZE-sizeof(struct cpu_info))
        );
    return cpu_info;
}
#endif  /* __UXEN__ */

#ifndef __UXEN__
#define get_current()         (get_cpu_info()->current_vcpu)
#define set_current(vcpu)     (get_cpu_info()->current_vcpu = (vcpu))
#endif  /* __UXEN__ */

#define current               (get_current())

#define get_processor_id()    (get_cpu_info()->processor_id)
#define set_processor_id(id)  do {                                      \
    struct cpu_info *ci__ = get_cpu_info();                             \
    ci__->per_cpu_offset = __per_cpu_offset[ci__->processor_id = (id)]; \
} while (0)

#ifndef __UXEN__
#define guest_cpu_user_regs() (&get_cpu_info()->guest_cpu_user_regs)
#else   /* __UXEN__ */
#define guest_cpu_user_regs() (&current->arch.user_regs)
#endif  /* __UXEN__ */

#ifndef __UXEN__
/*
 * Get the bottom-of-stack, as stored in the per-CPU TSS. This actually points
 * into the middle of cpu_info.guest_cpu_user_regs, at the section that
 * precisely corresponds to a CPU trap frame.
 */
#define get_stack_bottom()                      \
    ((unsigned long)&get_cpu_info()->guest_cpu_user_regs.es)

#define reset_stack_and_jump(__fn)              \
    __asm__ __volatile__ (                      \
        "mov %0,%%"__OP"sp; jmp "STR(__fn)      \
        : : "r" (guest_cpu_user_regs()) : "memory" )

#define schedule_tail(vcpu) (((vcpu)->arch.schedule_tail)(vcpu))
#endif  /* __UXEN__ */

/*
 * Which VCPU's state is currently running on each CPU?
 * This is not necesasrily the same as 'current' as a CPU may be
 * executing a lazy state switch.
 */
DECLARE_PER_CPU(struct vcpu *, curr_vcpu);

#endif /* __X86_CURRENT_H__ */
