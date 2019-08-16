/******************************************************************************
 * keyhandler.c
 */
/*
 * uXen changes:
 *
 * Copyright 2011-2019, Bromium, Inc.
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

#include <asm/regs.h>
#include <xen/keyhandler.h> 
#include <xen/shutdown.h>
#include <xen/event.h>
#include <xen/console.h>
#include <xen/serial.h>
#include <xen/sched.h>
#include <xen/tasklet.h>
#include <xen/domain.h>
#include <xen/rangeset.h>
#include <xen/ctype.h>
#include <xen/perfc.h>
#include <xen/version.h>
#include <asm/debugger.h>
#include <asm/div64.h>

static struct keyhandler *key_table[256];
static DEFINE_PER_CPU(unsigned char, keypress_key);
static bool_t alt_key_handling;

char keyhandler_scratch[1024];

static void keypress_action(unsigned long unused)
{
    handle_keypress(this_cpu(keypress_key), NULL);
}

#ifdef run_in_exception_handler
static void
handle_keypress_eh(struct cpu_user_regs *regs)
{
    struct keyhandler *h = key_table[this_cpu(keypress_key)];

    if (!h)
        return;

    (*h->u.irq_fn)(this_cpu(keypress_key), regs);
}
#endif

static DECLARE_TASKLET(keypress_tasklet, keypress_action, 0);

void handle_keypress(unsigned char key, struct cpu_user_regs *regs)
{
    struct keyhandler *h;

    if ( (h = key_table[key]) == NULL )
        return;

    if ( !in_irq() || h->irq_callback )
    {
        console_start_log_everything();
#ifdef run_in_exception_handler
        if (h->irq_callback && !regs) {
            this_cpu(keypress_key) = key;
            run_in_exception_handler(handle_keypress_eh);
        } else
#endif
        h->irq_callback ? (*h->u.irq_fn)(key, regs) : (*h->u.fn)(key);
        console_end_log_everything();
    }
    else
    {
        this_cpu(keypress_key) = key;
        tasklet_schedule(&keypress_tasklet);
    }
}

void register_keyhandler(unsigned char key, struct keyhandler *handler)
{
    ASSERT(key_table[key] == NULL);
    key_table[key] = handler;
}

static void show_handlers(unsigned char key)
{
    int i;
    printk("'%c' pressed -> showing installed handlers\n", key);
    for ( i = 0; i < ARRAY_SIZE(key_table); i++ ) 
        if ( key_table[i] != NULL ) 
            printk(" key '%c' (ascii '%02x') => %s\n", 
                   isprint(i) ? i : ' ', i, key_table[i]->desc);
}

static struct keyhandler show_handlers_keyhandler = {
    .u.fn = show_handlers,
    .desc = "show this message"
};

static cpumask_t dump_execstate_mask;

void dump_execstate(struct cpu_user_regs *regs)
{
    unsigned int cpu = smp_processor_id();

    if ( !is_hvm_vcpu(current) || !guest_mode(regs) )
    {
        printk("*** Dumping CPU%u host state: ***\n", cpu);
        show_execution_state(regs);
    }

    if ( !is_idle_vcpu(current) )
    {
        printk("*** Dumping CPU%u guest state (vm%u.%u): ***\n",
               smp_processor_id(), current->domain->domain_id,
               current->vcpu_id);
        show_execution_state(guest_cpu_user_regs());
        printk("\n");
    }

    cpumask_clear_cpu(cpu, &dump_execstate_mask);
    if ( !alt_key_handling )
        return;

    console_end_sync();
    watchdog_enable();
}

static void dump_registers(unsigned char key, struct cpu_user_regs *regs)
{

    /* We want to get everything out that we possibly can. */
    watchdog_disable();
    console_start_sync();

    printk("'%c' pressed -> dumping registers\n\n", key);

    if (!regs)
        goto out;

    cpumask_copy(&dump_execstate_mask, &cpu_online_map);

    /* Get local execution state out immediately, in case we get stuck. */
    dump_execstate(regs);

    /* Alt. handling: remaining CPUs are dumped asynchronously one-by-one. */
    if ( alt_key_handling )
        return;

  out:
    console_end_sync();
    watchdog_enable();
}

static struct keyhandler dump_registers_keyhandler = {
    .irq_callback = 1,
    .diagnostic = 1,
    .u.irq_fn = dump_registers,
    .desc = "dump registers"
};

static void cpuset_print(char *set, int size, const cpumask_t *mask)
{
    *set++ = '{';
    set += cpulist_scnprintf(set, size-2, mask);
    *set++ = '}';
    *set++ = '\0';
}

static void dump_domains(unsigned char key)
{
    struct domain *d;
    struct vcpu   *v;
    s_time_t       now = NOW();
#define tmpstr keyhandler_scratch

    printk("'%c' pressed -> dumping domain info (now=0x%X:%08X)\n", key,
           (u32)(now>>32), (u32)now);

    rcu_read_lock(&domlist_read_lock);

    for_each_domain ( d )
    {
        xen_domain_handle_t handle;

        atomic_read_domain_handle(&d->handle_atomic, (uint128_t *)handle);

        printk("General information for vm%u:\n", d->domain_id);
        cpuset_print(tmpstr, sizeof(tmpstr), d->domain_dirty_cpumask);
        printk("    refcnt=%d dying=%d dirty_cpus=%s\n",
               atomic_read(&d->refcnt), d->is_dying, tmpstr);
        printk("    nr_pages=%d xenheap=%u max=%u vframes=%u"
#ifdef __i386__
               " hidden=%d"
#endif
               "\n", d->tot_pages, d->xenheap_pages, d->max_pages, d->vframes
#ifdef __i386__
               , atomic_read(&d->hidden_pages)
#endif
            );
        if (is_hvm_domain(d)) {
            printk("    pod_pages=%d zero_shared=%d tmpl_shared=%d\n",
                   atomic_read(&d->pod_pages),
                   atomic_read(&d->zero_shared_pages),
                   atomic_read(&d->tmpl_shared_pages));
            if (!is_template_domain(d) && atomic_read(&d->clone.l1_pod_pages))
                printk("    l1_pod_pages=%d\n",
                       atomic_read(&d->clone.l1_pod_pages));
            if (is_template_domain(d) &&
                atomic_read(&d->template.compressed_pdata))
                printk("    comp_pages=%d comp_pdata=%d"
                       " decomp_shared=%d decomp_perm=%d\n",
                       atomic_read(&d->template.compressed_pages),
                       atomic_read(&d->template.compressed_pdata),
                       atomic_read(&d->template.decompressed_shared),
                       atomic_read(&d->template.decompressed_permanent));
        }
        printk("    handle=%" PRIuuid " vm_assist=%08lx\n",
               PRIuuid_arg(handle), d->vm_assist);

        arch_dump_domain_info(d);

        rangeset_domain_printk(d);

        printk("VCPU information and callbacks for vm%u:\n",
               d->domain_id);
        for_each_vcpu ( d, v )
        {
            printk("    VCPU:vm%u.%u: CPU%d [has=%c] flags=%lx poll=%d "
                   "upcall_pend = %02x, upcall_mask = %02x ",
                   d->domain_id, v->vcpu_id, v->processor,
                   v->is_running ? 'T':'F',
                   v->pause_flags, v->poll_evtchn,
                   vcpu_info(v, evtchn_upcall_pending),
                   vcpu_info(v, evtchn_upcall_mask));
            cpuset_print(tmpstr, sizeof(tmpstr), v->vcpu_dirty_cpumask);
            printk("dirty_cpus=%s ", tmpstr);
            cpuset_print(tmpstr, sizeof(tmpstr), v->cpu_affinity);
            printk("cpu_affinity=%s\n", tmpstr);
            arch_dump_vcpu_info(v);
            {
                void hostsched_dump_vcpu(struct vcpu *, int);
                hostsched_dump_vcpu(v, key == 'Q');
            }
        }
    }

    {
        int cpu;
        printk("host pages allocated: %d\n",
               atomic_read(&host_pages_allocated));
#ifdef __i386__
        printk("hidden pages allocated: %d available: %d/%d\n",
               atomic_read(&hidden_pages_allocated),
               atomic_read(&hidden_pages_available) -
               atomic_read(&hidden_pages_allocated),
               atomic_read(&hidden_pages_available));
#endif
        printk("vframes allocated: %d free: %d\n",
               atomic_read(&vframes_allocated),
               _uxen_info.ui_vframes.count);
        printk("cpu pool pages:");
        for_each_present_cpu(cpu)
            printk(" %d:%d", cpu, _uxen_info.ui_free_pages[cpu].count);
        printk("\n");
    }

    rcu_read_unlock(&domlist_read_lock);
#undef tmpstr
}

static struct keyhandler dump_domains_keyhandler = {
    .diagnostic = 1,
    .u.fn = dump_domains,
    .desc = "dump domain (and guest debug) info"
};

#ifdef PERF_COUNTERS
static struct keyhandler perfc_printall_keyhandler = {
    .diagnostic = 1,
    .u.fn = perfc_printall,
    .desc = "print performance counters"
};
static struct keyhandler perfc_reset_keyhandler = {
    .u.fn = perfc_reset,
    .desc = "reset performance counters"
};
static struct keyhandler perfc_all_cpus_keyhandler = {
    .u.fn = perfc_all_cpus,
    .desc = "print per-cpu performance counters (0=totals only, 1=all)"
};
#endif

#ifdef LOCK_PROFILE
static struct keyhandler spinlock_printall_keyhandler = {
    .diagnostic = 1,
    .u.fn = spinlock_profile_printall,
    .desc = "print lock profile info"
};
static struct keyhandler spinlock_reset_keyhandler = {
    .u.fn = spinlock_profile_reset,
    .desc = "reset lock profile info"
};
#endif

static void do_debug_key(unsigned char key, struct cpu_user_regs *regs)
{
    printk("'%c' pressed -> trapping into debugger\n", key);
    (void)debugger_trap_fatal(0xf001, regs);
    nop(); /* Prevent the compiler doing tail call
                             optimisation, as that confuses xendbg a
                             bit. */
}

static struct keyhandler do_debug_key_keyhandler = {
    .irq_callback = 1,
    .u.irq_fn = do_debug_key,
    .desc = "trap to xendbg"
};

static void dump_version(unsigned char key)
{
    printk("uXen version %d.%d%s (%s@%s) (%s) %s\n",
           xen_major_version(), xen_minor_version(), xen_extra_version(),
           xen_compile_by(), xen_compile_domain(),
           xen_compiler(), xen_compile_date());
    printk("Latest ChangeSet: %s\n", xen_changeset());
}

static struct keyhandler dump_version_keyhandler = {
    .diagnostic = 1,
    .u.fn = dump_version,
    .desc = "dump version info"
};

static void do_toggle_alt_key(unsigned char key, struct cpu_user_regs *regs)
{
    alt_key_handling = !alt_key_handling;
    printk("'%c' pressed -> using %s key handling\n", key,
           alt_key_handling ? "alternative" : "normal");
}

static struct keyhandler toggle_alt_keyhandler = {
    .irq_callback = 1,
    .u.irq_fn = do_toggle_alt_key,
    .desc = "toggle alternative key handling"
};

void __init initialize_keytable(void)
{
    if ( num_present_cpus() > 16 )
    {
        alt_key_handling = 1;
        printk(XENLOG_INFO "Defaulting to alternative key handling; "
               "send 'A' to switch to normal mode.\n");
    }
    register_keyhandler('A', &toggle_alt_keyhandler);
    register_keyhandler('d', &dump_registers_keyhandler);
    register_keyhandler('h', &show_handlers_keyhandler);
    register_keyhandler('q', &dump_domains_keyhandler);
    register_keyhandler('Q', &dump_domains_keyhandler);
    register_keyhandler('V', &dump_version_keyhandler);
    register_keyhandler('%', &do_debug_key_keyhandler);

#ifdef PERF_COUNTERS
    register_keyhandler('p', &perfc_printall_keyhandler);
    register_keyhandler('P', &perfc_reset_keyhandler);
    register_keyhandler('0', &perfc_all_cpus_keyhandler);
    register_keyhandler('1', &perfc_all_cpus_keyhandler);
#endif

#ifdef LOCK_PROFILE
    register_keyhandler('l', &spinlock_printall_keyhandler);
    register_keyhandler('L', &spinlock_reset_keyhandler);
#endif

}

/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
