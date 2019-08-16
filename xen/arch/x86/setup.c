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
#include <xen/lib.h>
#include <xen/sched.h>
#include <xen/sched-if.h>
#include <xen/domain.h>
#include <xen/serial.h>
#include <xen/softirq.h>
#include <xen/acpi.h>
#include <xen/efi.h>
#include <xen/console.h>
#include <xen/serial.h>
#include <xen/trace.h>
#include <xen/multiboot.h>
#include <xen/domain_page.h>
#include <xen/version.h>
#include <xen/gdbstub.h>
#include <xen/percpu.h>
#include <xen/hypercall.h>
#include <xen/keyhandler.h>
#include <xen/numa.h>
#include <xen/rcupdate.h>
#include <xen/vga.h>
#include <xen/dmi.h>
#include <xen/pfn.h>
#include <xen/nodemask.h>
#include <public/version.h>
#ifdef CONFIG_COMPAT
#include <compat/platform.h>
#include <compat/xen.h>
#endif
#include <asm/bitops.h>
#include <asm/smp.h>
#include <asm/processor.h>
#include <asm/mpspec.h>
#include <asm/apic.h>
#include <asm/desc.h>
#include <asm/paging.h>
#include <asm/e820.h>
#include <xen/kexec.h>
#include <asm/edd.h>
#include <xsm/xsm.h>
#include <asm/tboot.h>
#include <asm/bzimage.h> /* for bzimage_headroom */
#include <asm/mach-generic/mach_apic.h> /* for generic_apic_probe */
#include <asm/setup.h>
#include <xen/cpu.h>
#include <xen/symbols.h>
#include <asm/hvm/pvnested.h>

#include <uxen/uxen.h>
#include <uxen/uxen_desc.h>
#include <uxen/uxen_link.h>
#include <uxen/mapcache.h>

/* maxcpus: maximum number of CPUs to activate. */
static unsigned int __initdata max_cpus;
#ifdef __UXEN_todo__
integer_param("maxcpus", max_cpus);
#endif  /* __UXEN_todo__ */

#ifdef __UXEN_todo__
/* smep: Enable/disable Supervisor Mode Execution Protection (default on). */
static bool_t __initdata disable_smep;
invbool_param("smep", disable_smep);
#endif  /* __UXEN_todo__ */

/* free form debug option string */
char opt_debug[XEN_OPT_DEBUG_LEN] = "";
string_param("debug", opt_debug);

/* verbose information (regs,trace) about bulk vmexits */
bool_t verbose_exit_reason = 0;

bool_t __read_mostly early_boot = 1;

cpumask_t __read_mostly cpu_present_map;

DEFINE_PER_CPU(struct tss_struct, init_tss);

struct cpuinfo_x86 __read_mostly boot_cpu_data = { 0, 0, 0, 0, -1 };

unsigned long __read_mostly mmu_cr4_features = X86_CR4_PSE | X86_CR4_PGE | X86_CR4_PAE;

bool_t __read_mostly pv_msr = 0;

#define EARLY_FAIL(f, a...) do {                \
    printk( f , ## a );                         \
    for ( ; ; ) BUG();                          \
} while (0)

extern char __init_begin[], __init_end[], __bss_start[];

static void __init init_idle_domain(void)
{
    scheduler_init();
    uxen_set_current(idle_vcpu[0]);
    this_cpu(curr_vcpu) = current;
}

void __devinit srat_detect_node(int cpu)
{
    unsigned node;
    node = 0;
    numa_set_node(cpu, node);

}

intptr_t __init UXEN_INTERFACE_FN(
__uxen_start_xen)(
    const struct uxen_init_desc *uid,
    uint64_t uid_len,
    struct vm_info_shared *vmis,
    struct vm_vcpu_info_shared **vcis
    )
{
    int i;
    struct ns16550_defaults ns16550 = {
        .data_bits = 8,
        .parity    = 'n',
        .stop_bits = 1
    };
    struct vcpu *v;
    int ret;

    set_stack_top();
    set_uxen_info(&_uxen_info);

    percpu_init_areas();

    set_host_current(NULL);
    local_irq_disable();

    if (uid && uid_len)
        options_parse(uid, uid_len);

    ASSERT(host_processor_id() ==
           find_first_bit((unsigned long *)&_uxen_info.ui_cpu_active_mask,
                          UXEN_MAXIMUM_PROCESSORS));
    uxen_set_current(NULL);
    /* update boot_cpu_data.x86_capability[1] for cpu_has_efer */
    if ((cpuid_eax(0x80000000) & 0xffff0000) == 0x80000000 &&
        cpuid_eax(0x80000000) >= 0x80000001)
        boot_cpu_data.x86_capability[1] = cpuid_edx(0x80000001);
    idle_vcpu[0] = current;
    set_processor_id(0); /* needed early, for smp_processor_id() */
    if ( cpu_has_efer )
        rdmsrl(MSR_EFER, this_cpu(efer));
    mmu_cr4_features = read_cr4_cpu();
    this_cpu(cr4) = mmu_cr4_features;

#if defined(__x86_64__)
    pvnested_setup();
#endif  /* __x86_64__ */

    smp_prepare_boot_cpu();

    /* We initialise the serial devices very early so we can get debugging. */
    ns16550.io_base = 0x3f8;
    ns16550.irq     = 4;
    ns16550_init(0, &ns16550);
    ns16550.io_base = 0x2f8;
    ns16550.irq     = 3;
    ns16550_init(1, &ns16550);
    console_init_preirq();

    if (opt_debug[0]) {
        printk("opt debug: %s\n", opt_debug);
        if (strstr(opt_debug, ",verbexitreason,"))
            verbose_exit_reason = 1;
    }

    max_page = _uxen_info.ui_max_page;
    max_vframe = _uxen_info.ui_max_vframe;

    /* Sanity check for unwanted bloat of certain hypercall structures. */
    BUILD_BUG_ON(sizeof(((struct xen_platform_op *)0)->u) !=
                 sizeof(((struct xen_platform_op *)0)->u.pad));
    BUILD_BUG_ON(sizeof(((struct xen_domctl *)0)->u) !=
                 sizeof(((struct xen_domctl *)0)->u.pad));
    BUILD_BUG_ON(sizeof(((struct xen_sysctl *)0)->u) !=
                 sizeof(((struct xen_sysctl *)0)->u.pad));

    BUILD_BUG_ON(sizeof(start_info_t) > PAGE_SIZE);
    BUILD_BUG_ON(sizeof(shared_info_t) > PAGE_SIZE);
    BUILD_BUG_ON(sizeof(struct vcpu_info) != 64);

#ifdef CONFIG_COMPAT
    BUILD_BUG_ON(sizeof(((struct compat_platform_op *)0)->u) !=
                 sizeof(((struct compat_platform_op *)0)->u.pad));
    BUILD_BUG_ON(sizeof(start_info_compat_t) > PAGE_SIZE);
    BUILD_BUG_ON(sizeof(struct compat_vcpu_info) != 64);
#endif

    /* Check definitions in public headers match internal defs. */
    BUILD_BUG_ON(__HYPERVISOR_VIRT_START != HYPERVISOR_VIRT_START);
#ifdef HYPERVISOR_VIRT_END
    BUILD_BUG_ON(__HYPERVISOR_VIRT_END   != HYPERVISOR_VIRT_END);
#endif

    BUILD_BUG_ON(MAX_VIRT_CPUS < NR_CPUS);
    BUILD_BUG_ON(MAX_VIRT_CPUS != MAX_HVM_VCPUS);
    BUILD_BUG_ON(NR_CPUS > UXEN_MAXIMUM_PROCESSORS);

    BUILD_BUG_ON(sizeof(_uxen_info) > PAGE_SIZE);

    init_frametable();

    numa_initmem_init(0, max_page);

    early_boot = 0;

    softirq_init();
    tasklet_subsys_init();

    early_cpu_init();

    fpu_early_init();

    {
        nr_cpu_ids = 0;
        for (i = find_first_bit((unsigned long *)&_uxen_info.ui_cpu_active_mask,
                                UXEN_MAXIMUM_PROCESSORS);
             i < sizeof(_uxen_info.ui_cpu_active_mask) * 8;
             i = find_next_bit((unsigned long *)&_uxen_info.ui_cpu_active_mask,
                               UXEN_MAXIMUM_PROCESSORS, i + 1)) {
            int cpu;
            if (nr_cpu_ids >= NR_CPUS) {
                printk(KERN_WARNING "WARNING: NR_CPUS limit of %i reached."
                       "  Processor ignored.\n", NR_CPUS);
                break;
            }
            nr_cpu_ids++;
            if (nr_cpu_ids == 1)
                cpu = 0;
            else
                cpu = alloc_cpu_id();
            if (cpu < 0) {
                printk(KERN_WARNING "WARNING: Can't alloc cpu_id."
                       " Processor with hostid %i ignored\n", i);
                continue;
            }
            cpumask_set_cpu(cpu, &cpu_present_map);
            uxen_cpu_info[i].processor_id = cpu;
            x86_cpu_to_apicid[cpu] = i;
        }
        max_cpus = nr_cpu_ids;
        printk(KERN_INFO "Processors: %d\n", nr_cpu_ids);
#ifndef nr_cpumask_bits
        nr_cpumask_bits = (max_cpus + (BITS_PER_LONG - 1)) &
            ~(BITS_PER_LONG - 1);
        printk(XENLOG_DEBUG "NR_CPUS:%u nr_cpumask_bits:%u\n",
               NR_CPUS, nr_cpumask_bits);
#endif
    }

    init_cpu_to_node();

    timer_init();

    init_idle_domain();

    init_host_pages();

    rcu_init();
    
    early_time_init();

    arch_init_memory();

    identify_cpu(&boot_cpu_data);

    local_irq_enable();

    smp_prepare_cpus(max_cpus);

    spin_debug_enable();

    /*
     * Initialise higher-level timer functions. We do this fairly late
     * (after interrupts got enabled) because the time bases and scale
     * factors need to be updated regularly.
     */
    init_xen_time();

    initialize_keytable();

    console_init_postirq();

    do_presmp_initcalls();

    for_each_present_cpu ( i )
    {
        /* Set up cpu_to_node[]. */
        srat_detect_node(i);
        /* Set up node_to_cpumask based on cpu_to_node[]. */
        numa_add_cpu(i);        

        if ( (num_online_cpus() < max_cpus) && !cpu_online(i) )
        {
            ret = cpu_up(i);
            if ( ret != 0 )
                printk("Failed to bring up CPU %u (error %d)\n", i, ret);
        }
    }

    printk("Brought up %ld CPUs\n", (long)num_online_cpus());

    /* increase requested number of vframes by number of cpus */
    _uxen_info.ui_vframes_fill *= max_cpus;

    do_initcalls();

    /* Create initial domain 0. */
    dom0 = domain_create_internal(0, DOMCRF_s3_integrity, 0, vmis);
    if ( (dom0 == NULL) || (alloc_dom0_vcpu0() == NULL) )
        panic("Error creating domain 0\n");

    vmis->vmi_domid = dom0->domain_id;
    atomic_read_domain_handle(&dom0->handle_atomic,
                              (uint128_t *)vmis->vmi_uuid);
    ret = hostsched_setup_vm(dom0, vmis);
    if (ret)
        panic("Error setting up dom0 hostsched\n");

    for_each_vcpu(dom0, v) {
        struct vm_vcpu_info_shared *vci = vcis[v->vcpu_id];
        vci->vci_vcpuid = v->vcpu_id;

        hostsched_setup_vcpu(v, vci);
    }

    dom0->target = NULL;

#ifdef __UXEN_console__
    console_endboot();

    /* Hide UART from DOM0 if we're using it */
    serial_endboot();
#endif  /* __UXEN_console__ */

    hvm_cpu_off();

    uxen_set_current(NULL);

    return 0;
}

void arch_get_xen_caps(xen_capabilities_info_t *info)
{
    /* Interface name is always xen-3.0-* for Xen-3.x. */
    int major = 3, minor = 0;
    char s[32];

    (*info)[0] = '\0';

#ifdef CONFIG_X86_64
    snprintf(s, sizeof(s), "xen-%d.%d-x86_64 ", major, minor);
    safe_strcat(*info, s);
#endif
    snprintf(s, sizeof(s), "xen-%d.%d-x86_32p ", major, minor);
    safe_strcat(*info, s);
    if ( hvm_enabled )
    {
        snprintf(s, sizeof(s), "hvm-%d.%d-x86_32 ", major, minor);
        safe_strcat(*info, s);
        snprintf(s, sizeof(s), "hvm-%d.%d-x86_32p ", major, minor);
        safe_strcat(*info, s);
#ifdef CONFIG_X86_64
        snprintf(s, sizeof(s), "hvm-%d.%d-x86_64 ", major, minor);
        safe_strcat(*info, s);
#endif
    }
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
