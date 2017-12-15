/*
 *	Intel SMP support routines.
 *
 *	(c) 1995 Alan Cox, Building #3 <alan@redhat.com>
 *	(c) 1998-99, 2000 Ingo Molnar <mingo@redhat.com>
 *
 *	This code is released under the GNU General Public License version 2 or
 *	later.
 */
/*
 * uXen changes:
 *
 * Copyright 2011-2018, Bromium, Inc.
 * Author: Christian Limpach <Christian.Limpach@gmail.com>
 * SPDX-License-Identifier: ISC
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
 * SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION
 * OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
 * CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include <xen/config.h>
#include <xen/irq.h>
#include <xen/sched.h>
#include <xen/delay.h>
#include <xen/gdbstub.h>
#include <xen/perfc.h>
#include <xen/softirq.h>
#include <xen/spinlock.h>
#include <asm/current.h>
#include <asm/smp.h>
#include <asm/mc146818rtc.h>
#include <asm/flushtlb.h>
#include <asm/hardirq.h>
#include <asm/hvm/support.h>
#include <mach_apic.h>

#include <uxen/uxen_link.h>

int hard_smp_processor_id(void)
{
#ifndef __UXEN__
    return get_apic_id();
#else   /* __UXEN__ */
    return host_processor_id();
#endif  /* __UXEN__ */
}

#ifndef __UXEN__
int logical_smp_processor_id(void)
{
    return get_logical_apic_id();
}
#endif  /* __UXEN__ */

/*
 * send_IPI_mask(cpumask, vector): sends @vector IPI to CPUs in @cpumask,
 * excluding the local CPU. @cpumask may be empty.
 */

#ifndef __UXEN__
void send_IPI_mask(const cpumask_t *mask, int vector)
{
    genapic->send_IPI_mask(mask, vector);
}
#endif  /* __UXEN__ */

#ifndef __UXEN__
/*
 *	Some notes on x86 processor bugs affecting SMP operation:
 *
 *	Pentium, Pentium Pro, II, III (and all CPUs) have bugs.
 *	The Linux implications for SMP are handled as follows:
 *
 *	Pentium III / [Xeon]
 *		None of the E1AP-E3AP errata are visible to the user.
 *
 *	E1AP.	see PII A1AP
 *	E2AP.	see PII A2AP
 *	E3AP.	see PII A3AP
 *
 *	Pentium II / [Xeon]
 *		None of the A1AP-A3AP errata are visible to the user.
 *
 *	A1AP.	see PPro 1AP
 *	A2AP.	see PPro 2AP
 *	A3AP.	see PPro 7AP
 *
 *	Pentium Pro
 *		None of 1AP-9AP errata are visible to the normal user,
 *	except occasional delivery of 'spurious interrupt' as trap #15.
 *	This is very rare and a non-problem.
 *
 *	1AP.	Linux maps APIC as non-cacheable
 *	2AP.	worked around in hardware
 *	3AP.	fixed in C0 and above steppings microcode update.
 *		Linux does not use excessive STARTUP_IPIs.
 *	4AP.	worked around in hardware
 *	5AP.	symmetric IO mode (normal Linux operation) not affected.
 *		'noapic' mode has vector 0xf filled out properly.
 *	6AP.	'noapic' mode might be affected - fixed in later steppings
 *	7AP.	We do not assume writes to the LVT deassering IRQs
 *	8AP.	We do not enable low power mode (deep sleep) during MP bootup
 *	9AP.	We do not use mixed mode
 */

/*
 * The following functions deal with sending IPIs between CPUs.
 */

static inline int __prepare_ICR (unsigned int shortcut, int vector)
{
    return APIC_DM_FIXED | shortcut | vector;
}

static inline int __prepare_ICR2 (unsigned int mask)
{
    return SET_xAPIC_DEST_FIELD(mask);
}

void apic_wait_icr_idle(void)
{
    if ( x2apic_enabled )
        return;

    while ( apic_read( APIC_ICR ) & APIC_ICR_BUSY )
        cpu_relax();
}

static void __default_send_IPI_shortcut(unsigned int shortcut, int vector,
                                    unsigned int dest)
{
    unsigned int cfg;

    /*
     * Wait for idle.
     */
    apic_wait_icr_idle();

    /*
     * prepare target chip field
     */
    cfg = __prepare_ICR(shortcut, vector) | dest;
    /*
     * Send the IPI. The write to APIC_ICR fires this off.
     */
    apic_write_around(APIC_ICR, cfg);
}

void send_IPI_self_flat(int vector)
{
    __default_send_IPI_shortcut(APIC_DEST_SELF, vector, APIC_DEST_PHYSICAL);
}

void send_IPI_self_phys(int vector)
{
    __default_send_IPI_shortcut(APIC_DEST_SELF, vector, APIC_DEST_PHYSICAL);
}

void send_IPI_self_x2apic(int vector)
{
    apic_write(APIC_SELF_IPI, vector);    
}

void send_IPI_mask_flat(const cpumask_t *cpumask, int vector)
{
    unsigned long mask = cpumask_bits(cpumask)[0];
    unsigned long cfg;
    unsigned long flags;

    mask &= cpumask_bits(&cpu_online_map)[0];
    mask &= ~(1UL << smp_processor_id());
    if ( mask == 0 )
        return;

    local_irq_save(flags);

    /*
     * Wait for idle.
     */
    apic_wait_icr_idle();

    /*
     * prepare target chip field
     */
    cfg = __prepare_ICR2(mask);
    apic_write_around(APIC_ICR2, cfg);

    /*
     * program the ICR
     */
    cfg = __prepare_ICR(0, vector) | APIC_DEST_LOGICAL;

    /*
     * Send the IPI. The write to APIC_ICR fires this off.
     */
    apic_write_around(APIC_ICR, cfg);
    
    local_irq_restore(flags);
}

void send_IPI_mask_phys(const cpumask_t *mask, int vector)
{
    unsigned long cfg, flags;
    unsigned int query_cpu;

    local_irq_save(flags);

    for_each_cpu ( query_cpu, mask )
    {
        if ( !cpu_online(query_cpu) || (query_cpu == smp_processor_id()) )
            continue;

        /*
         * Wait for idle.
         */
        apic_wait_icr_idle();

        /*
         * prepare target chip field
         */
        cfg = __prepare_ICR2(cpu_physical_id(query_cpu));
        apic_write_around(APIC_ICR2, cfg);

        /*
         * program the ICR
         */
        cfg = __prepare_ICR(0, vector) | APIC_DEST_PHYSICAL;

        /*
         * Send the IPI. The write to APIC_ICR fires this off.
         */
        apic_write_around(APIC_ICR, cfg);
    }

    local_irq_restore(flags);
}
#endif  /* __UXEN__ */

static DEFINE_SPINLOCK(flush_lock);
static cpumask_t flush_cpumask;
static const void *flush_va;
static unsigned int flush_flags;

DEFINE_PER_CPU(unsigned int, irq_count);

fastcall void smp_invalidate_interrupt(void)
{
#ifndef __UXEN__
    ack_APIC_irq();
#endif  /* __UXEN__ */
    perfc_incr(ipis);
    this_cpu(irq_count)++;
    irq_enter();
#ifndef __UXEN__
    if ( !__sync_local_execstate() ||
         (flush_flags & (FLUSH_TLB_GLOBAL | FLUSH_CACHE)) )
#endif  /* __UXEN__ */
        flush_area_local(flush_va, flush_flags);
    cpumask_clear_cpu(smp_processor_id(), &flush_cpumask);
    irq_exit();
}

static __interface_fn_fn uintptr_t
__uxen_smp_invalidate_interrupt(uintptr_t arg)
{
    uintptr_t old_stack_top;
    unsigned long flags;

    local_irq_save(flags);
    save_stack_top(old_stack_top);

    if (cpumask_test_cpu(smp_processor_id(), &flush_cpumask))
	smp_invalidate_interrupt();

    restore_stack_top(old_stack_top);
    local_irq_restore(flags);

    return 0;
}

void flush_area_mask(const cpumask_t *mask, const void *va, unsigned int flags)
{
    ASSERT(local_irq_is_enabled());

    if ( cpumask_test_cpu(smp_processor_id(), mask) )
        flush_area_local(va, flags);

    if ( !cpumask_subset(mask, cpumask_of(smp_processor_id())) )
    {
        spin_lock(&flush_lock);
        cpumask_and(&flush_cpumask, mask, &cpu_online_map);
        cpumask_clear_cpu(smp_processor_id(), &flush_cpumask);
        flush_va      = va;
        flush_flags   = flags;
        send_IPI_mask(&flush_cpumask, INVALIDATE_TLB_VECTOR);
        while ( !cpumask_empty(&flush_cpumask) )
            cpu_relax();
        spin_unlock(&flush_lock);
    }
}

#ifndef __UXEN__
/* Call with no locks held and interrupts enabled (e.g., softirq context). */
void new_tlbflush_clock_period(void)
{
    cpumask_t allbutself;

    /* Flush everyone else. We definitely flushed just before entry. */
    cpumask_andnot(&allbutself, &cpu_online_map,
                   cpumask_of(smp_processor_id()));
    flush_mask(&allbutself, FLUSH_TLB);

    /* No need for atomicity: we are the only possible updater. */
    ASSERT(tlbflush_clock == 0);
    tlbflush_clock++;
}

void smp_send_event_check_mask(const cpumask_t *mask)
{
    send_IPI_mask(mask, EVENT_CHECK_VECTOR);
}
#endif  /* __UXEN__ */

/*
 * Structure and data for smp_call_function()/on_selected_cpus().
 */

static void __smp_call_function_interrupt(void);
static DEFINE_SPINLOCK(call_lock);
static struct call_data_struct {
    void (*func) (void *info);
    void *info;
    int wait;
    cpumask_t selected;
} call_data;

void smp_call_function(
    void (*func) (void *info),
    void *info,
    int wait)
{
    cpumask_t allbutself;

    cpumask_andnot(&allbutself, &cpu_online_map,
                   cpumask_of(smp_processor_id()));
    on_selected_cpus(&allbutself, func, info, wait);
}

static __interface_fn_fn uintptr_t
__uxen_smp_call_function_interrupt(uintptr_t arg)
{
    uintptr_t old_stack_top;
    unsigned long flags;

    local_irq_save(flags);
    save_stack_top(old_stack_top);

    /* __smp_call_function_interrupt checks if this cpu was targeted */
    __smp_call_function_interrupt();

    restore_stack_top(old_stack_top);
    local_irq_restore(flags);

    return 0;
}

void on_selected_cpus(
    const cpumask_t *selected,
    void (*func) (void *info),
    void *info,
    int wait)
{
    unsigned int nr_cpus;

    ASSERT(local_irq_is_enabled());

    spin_lock(&call_lock);

    cpumask_copy(&call_data.selected, selected);

    nr_cpus = cpumask_weight(&call_data.selected);
    if ( nr_cpus == 0 )
        goto out;

    call_data.func = func;
    call_data.info = info;
    call_data.wait = wait;

    /* wait == 1 -- deprecated,
       wait == 2 -- use send_IPI_mask, but wait for function completion */
    if (wait == 1) {
	if (cpumask_equal(&call_data.selected, cpumask_of(smp_processor_id())))
	    goto this_cpu;
        /* KeIpiGenericCall canary */
	WARNISH();
        UI_HOST_CALL(ui_on_selected_cpus, &call_data.selected,
                     __uxen_smp_call_function_interrupt);
	goto wait;
    }
#ifndef NDEBUG
    else if (wait && wait != 2)
	WARN();
#endif	/* NDEBUG */

    send_IPI_mask(&call_data.selected, CALL_FUNCTION_VECTOR);

  this_cpu:
    if ( cpumask_test_cpu(smp_processor_id(), &call_data.selected) )
    {
        local_irq_disable();
        smp_call_function_interrupt(NULL);
        local_irq_enable();
    }

  wait:
    while ( !cpumask_empty(&call_data.selected) )
        cpu_relax();

 out:
    spin_unlock(&call_lock);
}

void __stop_this_cpu(void)
{
    ASSERT(!local_irq_is_enabled());

#ifndef __UXEN__
    disable_local_APIC();
#endif  /* __UXEN__ */

    hvm_cpu_down();

#ifndef __UXEN__
    /*
     * Clear FPU, zapping any pending exceptions. Needed for warm reset with
     * some BIOSes.
     */
    clts();
    asm volatile ( "fninit" );
#endif  /* __UXEN__ */
}

#ifndef __UXEN__
static void
__uxen_stop_this_cpu(void *arg)
{
    uintptr_t old_stack_top;
    unsigned long flags;

    local_irq_save(flags);
    save_stack_top(old_stack_top);

    __stop_this_cpu();

    restore_stack_top(old_stack_top);
    local_irq_restore(flags);
}

/*
 * Stop all CPUs and turn off local APICs and the IO-APIC, so other OSs see a 
 * clean IRQ state.
 */
void smp_send_stop(void)
{

    on_selected_cpus(&cpu_online_map, __uxen_stop_this_cpu, NULL, 1);
}

void smp_send_nmi_allbutself(void)
{
    send_IPI_mask(&cpu_online_map, APIC_DM_NMI);
}

fastcall void smp_event_check_interrupt(struct cpu_user_regs *regs)
{
    struct cpu_user_regs *old_regs = set_irq_regs(regs);
    ack_APIC_irq();
    perfc_incr(ipis);
    this_cpu(irq_count)++;
    set_irq_regs(old_regs);
}
#endif  /* __UXEN__ */

static void __smp_call_function_interrupt(void)
{
    void (*func)(void *info) = call_data.func;
    void *info = call_data.info;
    unsigned int cpu = smp_processor_id();

    if ( !cpumask_test_cpu(cpu, &call_data.selected) )
        return;

    irq_enter();

    if ( call_data.wait )
    {
        (*func)(info);
        mb();
        cpumask_clear_cpu(cpu, &call_data.selected);
    }
    else
    {
        mb();
        cpumask_clear_cpu(cpu, &call_data.selected);
        (*func)(info);
    }

    irq_exit();
}

fastcall void smp_call_function_interrupt(struct cpu_user_regs *regs)
{
#ifndef __UXEN__
    struct cpu_user_regs *old_regs = set_irq_regs(regs);
#endif  /* __UXEN__ */

#ifndef __UXEN__
    ack_APIC_irq();
#endif  /* __UXEN__ */
    perfc_incr(ipis);
    this_cpu(irq_count)++;
    __smp_call_function_interrupt();
#ifndef __UXEN__
    set_irq_regs(old_regs);
#endif  /* __UXEN__ */
}

#ifdef __UXEN__
void UXEN_INTERFACE_FN(
__uxen_dispatch_ipi)(int vector)
{
    unsigned long flags;
    int cpu = smp_processor_id();
    uintptr_t ostack_top;
    /* struct _uxen_info *oinfo; */
    struct vcpu *ocurrent;

    save_stack_top(ostack_top);
    /* set and leave uxen_info set, since the rest of the code relies on it */
    /* oinfo = get_uxen_info(); */
    set_uxen_info(&_uxen_info);

    local_irq_save(flags);

    ocurrent = get_current();
    uxen_set_current(idle_vcpu[cpu]);

    perfc_incr(dpc_ipis);
    switch ( vector )
    {
    case UXEN_RESUME_VECTOR:
        do_hvm_cpu_up(NULL);
        break;
    case CALL_FUNCTION_VECTOR:
	smp_call_function_interrupt(NULL);
        break;
#ifdef CRASH_DEBUG
    case GDB_STOP_VECTOR:
        gdb_pause_this_cpu(NULL);
        break;
#endif
    default:
        WARN_ONCE();
	printk("uxen_ipi cpu %d vector %d\n", smp_processor_id(), vector);
        break;
    }

    local_irq_restore(flags);

    uxen_set_current(ocurrent);
    /* set_uxen_info(oinfo); */
    restore_stack_top(ostack_top);
}

void
uxen_ipi(unsigned int cpu, int vector)
{
    UI_HOST_CALL(ui_kick_cpu, cpu, vector);
}

void
uxen_ipi_mask(const cpumask_t *cpumask, int vector)
{
    unsigned int cpu;
    unsigned long flags;

    switch (vector) {
    case INVALIDATE_TLB_VECTOR:
        spin_lock(&call_lock);
        UI_HOST_CALL(ui_on_selected_cpus, cpumask,
                     __uxen_smp_invalidate_interrupt);
        spin_unlock(&call_lock);
	break;
    default:
	WARN_ONCE();
	printk("uxen_ipi_mask vector %d\n", vector);
	/* fallthrough */
    case UXEN_RESUME_VECTOR:
    case CALL_FUNCTION_VECTOR:
#ifdef CRASH_DEBUG
    case GDB_STOP_VECTOR:
#endif
	local_irq_save(flags);
	for_each_cpu(cpu, cpumask) {
	    if (cpu == smp_processor_id())
		continue;
	    uxen_ipi(cpu, vector);
	}
	local_irq_restore(flags);
	break;
    }
}
#endif  /* __UXEN__ */
