/*
 * x86 SMP booting functions
 *
 * This inherits a great deal from Linux's SMP boot code:
 *  (c) 1995 Alan Cox, Building #3 <alan@redhat.com>
 *  (c) 1998, 1999, 2000 Ingo Molnar <mingo@redhat.com>
 * 
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */
/*
 * uXen changes:
 *
 * Copyright 2011-2019, Bromium, Inc.
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
#include <xen/init.h>
#include <xen/kernel.h>
#include <xen/mm.h>
#include <xen/domain.h>
#include <xen/sched.h>
#include <xen/sched-if.h>
#include <xen/irq.h>
#include <xen/delay.h>
#include <xen/softirq.h>
#include <xen/tasklet.h>
#include <xen/serial.h>
#include <xen/numa.h>
#include <xen/cpu.h>
#include <asm/current.h>
#include <asm/mc146818rtc.h>
#include <asm/desc.h>
#include <asm/div64.h>
#include <asm/flushtlb.h>
#include <asm/msr.h>
#include <asm/mtrr.h>
#include <asm/time.h>
#include <mach_apic.h>
#include <mach_wakecpu.h>

cpumask_t cpu_online_map __read_mostly;
EXPORT_SYMBOL(cpu_online_map);

struct cpuinfo_x86 cpu_data[NR_CPUS];

u32 x86_cpu_to_apicid[NR_CPUS] __read_mostly =
	{ [0 ... NR_CPUS-1] = BAD_APICID };

static int cpu_error;
static enum cpu_state {
    CPU_STATE_DYING,    /* slave -> master: I am dying */
    CPU_STATE_DEAD,     /* slave -> master: I am completely dead */
    CPU_STATE_INIT,     /* master -> slave: Early bringup phase 1 */
    CPU_STATE_CALLOUT,  /* master -> slave: Early bringup phase 2 */
    CPU_STATE_CALLIN,   /* slave -> master: Completed phase 2 */
    CPU_STATE_ONLINE    /* master -> slave: Go fully online now. */
} cpu_state;
#define set_cpu_state(state) do { mb(); cpu_state = (state); } while (0)

static void smp_store_cpu_info(int id)
{
    struct cpuinfo_x86 *c = cpu_data + id;

    *c = boot_cpu_data;
    if ( id != 0 )
        identify_cpu(c);

    /*
     * Certain Athlons might work (for various values of 'work') in SMP
     * but they are not certified as MP capable.
     */
    if ( (c->x86_vendor == X86_VENDOR_AMD) && (c->x86 == 6) )
    {
        /* Athlon 660/661 is valid. */ 
        if ( (c->x86_model==6) && ((c->x86_mask==0) || (c->x86_mask==1)) )
            goto valid_k7;

        /* Duron 670 is valid */
        if ( (c->x86_model==7) && (c->x86_mask==0) )
            goto valid_k7;

        /*
         * Athlon 662, Duron 671, and Athlon >model 7 have capability bit.
         * It's worth noting that the A5 stepping (662) of some Athlon XP's
         * have the MP bit set.
         * See http://www.heise.de/newsticker/data/jow-18.10.01-000 for more.
         */
        if ( ((c->x86_model==6) && (c->x86_mask>=2)) ||
             ((c->x86_model==7) && (c->x86_mask>=1)) ||
             (c->x86_model> 7) )
            if (cpu_has_mp)
                goto valid_k7;

        /* If we get here, it's not a certified SMP capable AMD system. */
        add_taint(TAINT_UNSAFE_SMP);
    }

 valid_k7:
    ;
}

/*
 * TSC's upper 32 bits can't be written in earlier CPUs (before
 * Prescott), there is no way to resync one AP against BP.
 */
bool_t disable_tsc_sync;

void smp_callin(void)
{
    unsigned int cpu = smp_processor_id();
    int rc;

    /* Save our processor parameters. */
    smp_store_cpu_info(cpu);

    if ( (rc = hvm_cpu_up(hvmon_default)) != 0 )
    {
        printk("CPU%d: Failed to initialise HVM. Not coming online.\n", cpu);
        cpu_error = rc;
        BUG();
    }

    /* Allow the master to continue. */
    set_cpu_state(CPU_STATE_CALLIN);

    /* And wait for our final Ack. */
    while ( cpu_state != CPU_STATE_ONLINE )
        cpu_relax();
}

static int booting_cpu;

void start_secondary(void *unused)
{
    /*
     * Dont put anything before smp_callin(), SMP booting is so fragile that we
     * want to limit the things done here to the most necessary things.
     */
    unsigned int cpu = booting_cpu;

    set_processor_id(cpu);
    uxen_set_current(idle_vcpu[cpu]);
    this_cpu(curr_vcpu) = idle_vcpu[cpu];
    if ( cpu_has_efer )
        rdmsrl(MSR_EFER, this_cpu(efer));
    asm volatile ( "mov %%cr4,%0" : "=r" (this_cpu(cr4)) );
    /* Set cr4 features that we're missing on this cpu. */
    set_in_cr4((X86_CR4_VMXE) & mmu_cr4_features);

    /*
     * Just as during early bootstrap, it is convenient here to disable
     * spinlock checking while we have IRQs disabled. This allows us to
     * acquire IRQ-unsafe locks when it would otherwise be disallowed.
     * 
     * It is safe because the race we are usually trying to avoid involves
     * a group of CPUs rendezvousing in an IPI handler, where one cannot
     * join because it is spinning with IRQs disabled waiting to acquire a
     * lock held by another in the rendezvous group (the lock must be an
     * IRQ-unsafe lock since the CPU took the IPI after acquiring it, and
     * hence had IRQs enabled). This is a deadlock scenario.
     * 
     * However, no CPU can be involved in rendezvous until it is online,
     * hence no such group can be waiting for this CPU until it is
     * visible in cpu_online_map. Hence such a deadlock is not possible.
     */
    spin_debug_disable();

    percpu_traps_init();

    smp_callin();

    /* This must be done before setting cpu_online_map */
    spin_debug_enable();
    notify_cpu_starting(cpu);
    wmb();

    /*
     * We need to hold vector_lock so there the set of online cpus
     * does not change while we are assigning vectors to cpus.  Holding
     * this lock ensures we don't half assign or remove an irq from a cpu.
     */
    cpumask_set_cpu(cpu, &cpu_online_map);

    wmb();

    hvm_cpu_off();
}

int alloc_cpu_id(void)
{
    cpumask_t tmp_map;
    int cpu;

    cpumask_complement(&tmp_map, &cpu_present_map);
    cpu = cpumask_first(&tmp_map);
    return (cpu < nr_cpu_ids) ? cpu : -ENODEV;
}

void __init smp_prepare_cpus(unsigned int max_cpus)
{
    /* Setup boot CPU information */
    smp_store_cpu_info(0); /* Final full version of the data */
    print_cpu_info(0);
}

void __init smp_prepare_boot_cpu(void)
{
    cpumask_set_cpu(smp_processor_id(), &cpu_online_map);
    cpumask_set_cpu(smp_processor_id(), &cpu_present_map);
}


int __cpu_up(unsigned int cpu)
{
    set_cpu_state(CPU_STATE_CALLOUT);
    booting_cpu = cpu;
    on_selected_cpus(cpumask_of(cpu), start_secondary, NULL, 0);
    while ( cpu_state == CPU_STATE_CALLOUT ) {
        cpu_relax();
        if (local_irq_is_enabled())
            process_pending_softirqs();
    }
    print_cpu_info(cpu);

    set_cpu_state(CPU_STATE_ONLINE);
    while ( !cpu_online(cpu) )
    {
        cpu_relax();
        if (local_irq_is_enabled())
            process_pending_softirqs();
    }

    return 0;
}


