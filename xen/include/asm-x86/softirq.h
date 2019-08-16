#ifndef __ASM_SOFTIRQ_H__
#define __ASM_SOFTIRQ_H__

enum {
    /* vcpu */
    KICK_VCPU_SOFTIRQ = NR_COMMON_SOFTIRQS,
    SYNC_TSC_VCPU_SOFTIRQ,

    /* cpu */
    P2M_L1_CACHE_CPU_SOFTIRQ,

    NR_ARCH_SOFTIRQS
};

#define VCPU_SOFTIRQ_WITH_VMCS_MASK (1ul << SYNC_TSC_VCPU_SOFTIRQ)

#endif /* __ASM_SOFTIRQ_H__ */
