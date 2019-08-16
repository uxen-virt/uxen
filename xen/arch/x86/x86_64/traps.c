
#include <xen/config.h>
#include <xen/version.h>
#include <xen/init.h>
#include <xen/sched.h>
#include <xen/lib.h>
#include <xen/errno.h>
#include <xen/mm.h>
#include <xen/irq.h>
#include <xen/symbols.h>
#include <xen/console.h>
#include <xen/sched.h>
#include <xen/shutdown.h>
#include <xen/nmi.h>
#include <xen/guest_access.h>
#include <asm/current.h>
#include <asm/flushtlb.h>
#include <asm/traps.h>
#include <asm/event.h>
#include <asm/msr.h>
#include <asm/page.h>
#include <asm/shared.h>
#include <asm/hvm/hvm.h>
#include <asm/hvm/support.h>
#include <public/callback.h>


static void print_xen_info(void)
{
    char taint_str[TAINT_STRING_MAX_LEN];
    char debug = 'n';

#ifndef NDEBUG
    debug = 'y';
#endif

    printk("----[ uXen-%d.%d%s  x86_64  debug=%c  %s ]----\n",
           xen_major_version(), xen_minor_version(), xen_extra_version(),
           debug, print_tainted(taint_str));
}

enum context { CTXT_hypervisor, CTXT_hvm_host, CTXT_hvm_guest };

static void _show_registers(
    const struct cpu_user_regs *regs, unsigned long crs[8],
    enum context context, const struct vcpu *v)
{
    const static char *context_names[] = {
        [CTXT_hypervisor] = "hypervisor",
        [CTXT_hvm_host]   = "hvm host",
        [CTXT_hvm_guest]  = "hvm guest"
    };

    printk("RIP:    %04x:[<%016lx>]", regs->cs, regs->rip);
    if ( context == CTXT_hypervisor )
        printk(" %S", (printk_symbol)regs->rip);
    printk("\nRFLAGS: %016lx   ", regs->rflags);
    printk("CONTEXT: %s\n", context_names[context]);

    printk("rax: %016lx   rbx: %016lx   rcx: %016lx\n",
           regs->rax, regs->rbx, regs->rcx);
    printk("rdx: %016lx   rsi: %016lx   rdi: %016lx\n",
           regs->rdx, regs->rsi, regs->rdi);
    printk("rbp: %016lx   rsp: %016lx   r8:  %016lx\n",
           regs->rbp, regs->rsp, regs->r8);
    printk("r9:  %016lx   r10: %016lx   r11: %016lx\n",
           regs->r9,  regs->r10, regs->r11);
    printk("r12: %016lx   r13: %016lx   r14: %016lx\n",
           regs->r12, regs->r13, regs->r14);
    printk("r15: %016lx   cr0: %016lx   cr4: %016lx\n",
           regs->r15, crs[0], crs[4]);
    printk("cr3: %016lx   cr2: %016lx\n", crs[3], crs[2]);
    printk("ds: %04x   es: %04x   fs: %04x   gs: %04x   "
           "ss: %04x   cs: %04x\n",
           regs->ds, regs->es, regs->fs,
           regs->gs, regs->ss, regs->cs);
}

void show_registers(struct cpu_user_regs *regs)
{
    struct cpu_user_regs fault_regs = *regs;
    unsigned long fault_crs[8];
    enum context context;
    struct vcpu *v = current;

    if ( v && is_hvm_vcpu(v) && guest_mode(regs) )
    {
        struct segment_register sreg;
        context = (v->domain == dom0) ? CTXT_hvm_host : CTXT_hvm_guest;
        fault_crs[0] = v->arch.hvm_vcpu.guest_cr[0];
        fault_crs[2] = v->arch.hvm_vcpu.guest_cr[2];
        fault_crs[3] = v->arch.hvm_vcpu.guest_cr[3];
        fault_crs[4] = v->arch.hvm_vcpu.guest_cr[4];
        if (v->context_loaded) {
            hvm_get_segment_register(v, x86_seg_cs, &sreg);
            fault_regs.cs = sreg.sel;
            hvm_get_segment_register(v, x86_seg_ds, &sreg);
            fault_regs.ds = sreg.sel;
            hvm_get_segment_register(v, x86_seg_es, &sreg);
            fault_regs.es = sreg.sel;
            hvm_get_segment_register(v, x86_seg_fs, &sreg);
            fault_regs.fs = sreg.sel;
            hvm_get_segment_register(v, x86_seg_gs, &sreg);
            fault_regs.gs = sreg.sel;
            hvm_get_segment_register(v, x86_seg_ss, &sreg);
            fault_regs.ss = sreg.sel;
        } else {
            fault_regs.cs = 0;
            fault_regs.ds = 0;
            fault_regs.es = 0;
            fault_regs.fs = 0;
            fault_regs.gs = 0;
            fault_regs.ss = 0;
        }
    }
    else
    {
        {
            context = CTXT_hypervisor;
            fault_crs[2] = read_cr2();
        }

        fault_crs[0] = read_cr0();
        fault_crs[3] = read_cr3();
        fault_crs[4] = read_cr4();
        fault_regs.ds = read_segment_register(ds);
        fault_regs.es = read_segment_register(es);
        fault_regs.fs = read_segment_register(fs);
        fault_regs.gs = read_segment_register(gs);
    }

    print_xen_info();
    printk("CPU:    %d\n", smp_processor_id());
    _show_registers(&fault_regs, fault_crs, context, v);

    if ( this_cpu(ler_msr) && !guest_mode(regs) )
    {
        u64 from, to;
        rdmsrl(this_cpu(ler_msr), from);
        rdmsrl(this_cpu(ler_msr) + 1, to);
        printk("ler: %016lx -> %016lx\n", from, to);
    }
}

void show_page_walk(unsigned long addr)
{
}

asmlinkage_abi void do_double_fault(struct cpu_user_regs *regs)
{
    unsigned int cpu;

    watchdog_disable();

    console_force_unlock();

    /* asm ( "lsll %1, %0" : "=r" (cpu) : "rm" (PER_CPU_GDT_ENTRY << 3) ); */
    cpu = 0;                    /* XXX */

    /* Find information saved during fault and dump it to the console. */
    printk("*** DOUBLE FAULT ***\n");
    print_xen_info();
    printk("CPU:    %d\nRIP:    %04x:[<%016lx>] %S\n",
           cpu, regs->cs, regs->rip, (printk_symbol)regs->rip);
    printk("RFLAGS: %016lx\n", regs->rflags);
    printk("rax: %016lx   rbx: %016lx   rcx: %016lx\n",
           regs->rax, regs->rbx, regs->rcx);
    printk("rdx: %016lx   rsi: %016lx   rdi: %016lx\n",
           regs->rdx, regs->rsi, regs->rdi);
    printk("rbp: %016lx   rsp: %016lx   r8:  %016lx\n",
           regs->rbp, regs->rsp, regs->r8);
    printk("r9:  %016lx   r10: %016lx   r11: %016lx\n",
           regs->r9,  regs->r10, regs->r11);
    printk("r12: %016lx   r13: %016lx   r14: %016lx\n",
           regs->r12, regs->r13, regs->r14);
    printk("r15: %016lx    cs: %016lx    ss: %016lx\n",
           regs->r15, (long)regs->cs, (long)regs->ss);

    panic("DOUBLE FAULT -- system shutdown\n");
}

void hypercall_page_initialise(struct domain *d, void *hypercall_page)
{
    memset(hypercall_page, 0xCC, PAGE_SIZE);
    if ( is_hvm_domain(d) )
        hvm_hypercall_page_initialise(d, hypercall_page);
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
