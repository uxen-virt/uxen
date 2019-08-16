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
    unsigned int processor_id;
    unsigned long per_cpu_offset;
};

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

#define current               (get_current())

#define get_processor_id()    (get_cpu_info()->processor_id)
#define set_processor_id(id)  do {                                      \
    struct cpu_info *ci__ = get_cpu_info();                             \
    ci__->per_cpu_offset = __per_cpu_offset[ci__->processor_id = (id)]; \
} while (0)

#define guest_cpu_user_regs() (&current->arch.user_regs)

/*
 * Which VCPU's state is currently running on each CPU?
 * This is not necesasrily the same as 'current' as a CPU may be
 * executing a lazy state switch.
 */
DECLARE_PER_CPU(struct vcpu *, curr_vcpu);

#endif /* __X86_CURRENT_H__ */
