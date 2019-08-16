/******************************************************************************
 * preempt.h
 * 
 * Track atomic regions in the hypervisor which disallow sleeping.
 * 
 * Copyright (c) 2010, Keir Fraser <keir@xen.org>
 */

#ifndef __XEN_PREEMPT_H__
#define __XEN_PREEMPT_H__

#include <xen/config.h>
#include <xen/types.h>
#include <asm/hardirq.h>
#include <xen/smp.h>

#define preempt_count() host_preemption_preempt_count()
#define preempt_disable() host_preemption_preempt_disable()
#define preempt_enable() host_preemption_preempt_enable()
static inline bool_t in_atomic(void) {
    return preempt_count() || in_irq() || !local_irq_is_enabled();
}

#endif /* __XEN_PREEMPT_H__ */
