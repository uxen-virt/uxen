#if !defined(__XEN_SOFTIRQ_H__) && !defined(__ASSEMBLY__)
#define __XEN_SOFTIRQ_H__

/* Low-latency softirqs come first in the following list. */
enum {
    TIMER_SOFTIRQ = 0,
    SCHEDULE_SOFTIRQ,
#ifndef __UXEN__
    NEW_TLBFLUSH_CLOCK_PERIOD_SOFTIRQ,
#endif  /* __UXEN__ */
    RCU_SOFTIRQ,
    TASKLET_SOFTIRQ,
    P2M_L1_CACHE_SOFTIRQ,
    NR_COMMON_SOFTIRQS
};

#include <xen/config.h>
#include <xen/lib.h>
#include <xen/smp.h>
#include <asm/bitops.h>
#include <asm/current.h>
#include <asm/hardirq.h>
#include <asm/softirq.h>

#define NR_SOFTIRQS (NR_COMMON_SOFTIRQS + NR_ARCH_SOFTIRQS)

typedef void (*softirq_handler)(void);
typedef void (*softirq_handler_vcpu)(struct vcpu *);

void do_run_idle_thread(uint32_t had_timeout);

/* asmlinkage */ void do_softirq(void);
/* asmlinkage */ void do_softirq_vcpu(struct vcpu *);
void open_softirq(int nr, softirq_handler handler);
void open_softirq_vcpu(int nr, softirq_handler_vcpu handler);
void softirq_init(void);

void cpumask_raise_softirq(const cpumask_t *, unsigned int nr);
void cpu_raise_softirq(unsigned int cpu, unsigned int nr);
void raise_softirq(unsigned int nr);

/*
 * Process pending softirqs on this CPU. This should be called periodically
 * when performing work that prevents softirqs from running in a timely manner.
 * Use this instead of do_softirq() when you do not want to be preempted.
 */
void process_pending_softirqs(void);

void process_pending_cpu_softirqs(void);

#endif /* __XEN_SOFTIRQ_H__ */
