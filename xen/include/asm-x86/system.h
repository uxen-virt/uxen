#ifndef __ASM_SYSTEM_H
#define __ASM_SYSTEM_H

#include <xen/lib.h>
#include <asm/bitops.h>

#define read_segment_register(name)                             \
({  u16 __sel;                                                  \
    asm volatile ( "movw %%" STR(name) ",%0" : "=r" (__sel) );  \
    __sel;                                                      \
})

#define wbinvd() \
    asm volatile ( "wbinvd" : : : "memory" )

#define clflush(a) \
    asm volatile ( "clflush (%0)" : : "r"(a) )

#define nop() \
    asm volatile ( "nop" )

#define xchg(ptr,v) \
    ((__typeof__(*(ptr)))__xchg((unsigned long)(v),(ptr),sizeof(*(ptr))))

struct __xchg_dummy { unsigned long a[100]; };
#define __xg(x) ((volatile struct __xchg_dummy *)(x))

#if defined(__i386__)
# include <asm/x86_32/system.h>
#elif defined(__x86_64__)
# include <asm/x86_64/system.h>
#endif

/*
 * Note: no "lock" prefix even on SMP: xchg always implies lock anyway
 * Note 2: xchg has side effect, so that attribute volatile is necessary,
 *   but generally the primitive is invalid, *ptr is output argument. --ANK
 */
static always_inline unsigned long __xchg(
    unsigned long x, volatile void *ptr, int size)
{
    switch ( size )
    {
    case 1:
        asm volatile ( "xchgb %b0,%1"
                       : "=q" (x)
                       : "m" (*__xg((volatile void *)ptr)), "0" (x)
                       : "memory" );
        break;
    case 2:
        asm volatile ( "xchgw %w0,%1"
                       : "=r" (x)
                       : "m" (*__xg((volatile void *)ptr)), "0" (x)
                       : "memory" );
        break;
#if defined(__i386__)
    case 4:
        asm volatile ( "xchgl %0,%1"
                       : "=r" (x)
                       : "m" (*__xg((volatile void *)ptr)), "0" (x)
                       : "memory" );
        break;
#elif defined(__x86_64__)
    case 4:
        asm volatile ( "xchgl %k0,%1"
                       : "=r" (x)
                       : "m" (*__xg((volatile void *)ptr)), "0" (x)
                       : "memory" );
        break;
    case 8:
        asm volatile ( "xchgq %0,%1"
                       : "=r" (x)
                       : "m" (*__xg((volatile void *)ptr)), "0" (x)
                       : "memory" );
        break;
#endif
    }
    return x;
}

/*
 * Atomic compare and exchange.  Compare OLD with MEM, if identical,
 * store NEW in MEM.  Return the initial value in MEM.  Success is
 * indicated by comparing RETURN with OLD.
 */

static always_inline unsigned long __cmpxchg(
    volatile void *ptr, unsigned long old, unsigned long new, int size)
{
    unsigned long prev;
    switch ( size )
    {
    case 1:
        asm volatile ( "lock; cmpxchgb %b1,%2"
                       : "=a" (prev)
                       : "q" (new), "m" (*__xg((volatile void *)ptr)),
                       "0" (old)
                       : "memory" );
        return prev;
    case 2:
        asm volatile ( "lock; cmpxchgw %w1,%2"
                       : "=a" (prev)
                       : "r" (new), "m" (*__xg((volatile void *)ptr)),
                       "0" (old)
                       : "memory" );
        return prev;
#if defined(__i386__)
    case 4:
        asm volatile ( "lock; cmpxchgl %1,%2"
                       : "=a" (prev)
                       : "r" (new), "m" (*__xg((volatile void *)ptr)),
                       "0" (old)
                       : "memory" );
        return prev;
#elif defined(__x86_64__)
    case 4:
        asm volatile ( "lock; cmpxchgl %k1,%2"
                       : "=a" (prev)
                       : "r" (new), "m" (*__xg((volatile void *)ptr)),
                       "0" (old)
                       : "memory" );
        return prev;
    case 8:
        asm volatile ( "lock; cmpxchgq %1,%2"
                       : "=a" (prev)
                       : "r" (new), "m" (*__xg((volatile void *)ptr)),
                       "0" (old)
                       : "memory" );
        return prev;
#endif
    }
    return old;
}

#define cmpxchgptr(ptr,o,n) ({                                          \
    const __typeof__(**(ptr)) *__o = (o);                               \
    __typeof__(**(ptr)) *__n = (n);                                     \
    ((__typeof__(*(ptr)))__cmpxchg((ptr),(unsigned long)__o,            \
                                   (unsigned long)__n,sizeof(*(ptr)))); \
})

/*
 * Both Intel and AMD agree that, from a programmer's viewpoint:
 *  Loads cannot be reordered relative to other loads.
 *  Stores cannot be reordered relative to other stores.
 * 
 * Intel64 Architecture Memory Ordering White Paper
 * <http://developer.intel.com/products/processor/manuals/318147.pdf>
 * 
 * AMD64 Architecture Programmer's Manual, Volume 2: System Programming
 * <http://www.amd.com/us-en/assets/content_type/\
 *  white_papers_and_tech_docs/24593.pdf>
 */
#define rmb()           barrier()
#define wmb()           barrier()

#ifdef CONFIG_SMP
#define smp_mb()        mb()
#define smp_rmb()       rmb()
#define smp_wmb()       wmb()
#else
#define smp_mb()        barrier()
#define smp_rmb()       barrier()
#define smp_wmb()       barrier()
#endif

#define set_mb(var, value) do { xchg(&var, value); } while (0)
#define set_wmb(var, value) do { var = value; wmb(); } while (0)

#define lfence() asm volatile("lfence":::"memory")

asmlinkage_abi void _cpu_irq_disable(void);
asmlinkage_abi void _cpu_irq_enable(void);
int _cpu_irq_is_enabled(void);
void _cpu_irq_save(unsigned long *x);
void _cpu_irq_restore(unsigned long x);

#define cpu_irq_disable()     _cpu_irq_disable()
#define cpu_irq_enable()      _cpu_irq_enable()
#define cpu_irq_is_enabled()  _cpu_irq_is_enabled()
#define cpu_irq_save(x)       _cpu_irq_save(&(x))
#define cpu_irq_restore(x)    _cpu_irq_restore(x)

void vmexec_irq_enable(void);

#define local_irq_disable()     host_preemption_irq_disable()
#define local_irq_enable()      host_preemption_irq_enable()

/* used in the idle loop; sti takes one instruction cycle to complete */
#define safe_halt()     asm volatile ( "sti; hlt" : : : "memory" )
/* used when interrupts are already enabled or to shutdown the processor */
#define halt()          asm volatile ( "hlt" : : : "memory" )

#define X86_EFLAGS_IF     0x00000200 /* Interrupt Flag */
/* this toggles X86_EFLAGS_IF if it doesn't match local_irq_is_enabled() */
/* it uses X86_EFLAGS_SIF to indicate the toggle to restore */
#define __set_eflags_if(x)                                          \
    ({                                                              \
        if ((!!local_irq_is_enabled()) ^ (!!((x) & X86_EFLAGS_IF))) \
            (x) ^= (X86_EFLAGS_IF | X86_EFLAGS_SIF);                \
    })
#define __restore_eflags_if(x)                          \
    ({                                                  \
	if ((x) & X86_EFLAGS_IF)                        \
	    host_preemption_irq_enable();               \
        if ((x) & X86_EFLAGS_SIF)                       \
            (x) ^= (X86_EFLAGS_IF | X86_EFLAGS_SIF);    \
    })

#define local_save_flags(x)                                      \
({                                                               \
    BUILD_BUG_ON(sizeof(x) != sizeof(long));                     \
    asm volatile ( "pushf" __OS " ; pop" __OS " %0" : "=g" (x)); \
    __set_eflags_if(x);						 \
})
#define local_irq_save(x)                                        \
({                                                               \
    local_save_flags(x);                                         \
    local_irq_disable();                                         \
})
#define local_irq_restore(x)                                     \
({                                                               \
    BUILD_BUG_ON(sizeof(x) != sizeof(long));                     \
    __restore_eflags_if(x);					 \
})

#include <asm/current.h>

#if 0
DECLARE_PER_CPU(uint32_t, host_cpu_preemption);
#define host_cpu_preemption() (this_cpu(host_cpu_preemption))
#else
extern uint32_t _host_cpu_preemption[];
#define host_cpu_preemption() _host_cpu_preemption[host_processor_id()]
#endif

#define HOST_CPU_PREEMPTION_IRQ_DISABLED 0x80000000
#define HOST_CPU_PREEMPTION_COUNT_MASK					\
    ~(HOST_CPU_PREEMPTION_IRQ_DISABLED)

static inline int local_irq_is_enabled(void)
{
    return !(host_cpu_preemption() & HOST_CPU_PREEMPTION_IRQ_DISABLED);
}

static inline void host_preemption_irq_enable(void)
{
    host_cpu_preemption() &= ~HOST_CPU_PREEMPTION_IRQ_DISABLED;
}

static inline void host_preemption_irq_disable(void)
{
    host_cpu_preemption() |= HOST_CPU_PREEMPTION_IRQ_DISABLED;
}

static inline void host_preemption_preempt_enable(void)
{
    ASSERT((host_cpu_preemption() & HOST_CPU_PREEMPTION_COUNT_MASK) >= 2);
    host_cpu_preemption() -= 2;
}

static inline int host_preemption_preempt_count(void)
{
    return (host_cpu_preemption() & HOST_CPU_PREEMPTION_COUNT_MASK) >> 1;
}

static inline void host_preemption_preempt_disable(void)
{
    host_cpu_preemption() += 2;
}

#define BROKEN_ACPI_Sx          0x0001
#define BROKEN_INIT_AFTER_S1    0x0002

void trap_init(void);
void percpu_traps_init(void);
void subarch_percpu_traps_init(void);

#endif
