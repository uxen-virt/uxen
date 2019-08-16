
#include <xen/config.h>
#include <xen/version.h>
#include <xen/domain_page.h>
#include <xen/init.h>
#include <xen/sched.h>
#include <xen/lib.h>
#include <xen/console.h>
#include <xen/mm.h>
#include <xen/irq.h>
#include <xen/symbols.h>
#include <xen/shutdown.h>
#include <xen/nmi.h>
#include <xen/cpu.h>
#include <xen/guest_access.h>
#include <asm/current.h>
#include <asm/flushtlb.h>
#include <asm/traps.h>
#include <asm/hvm/hvm.h>
#include <asm/hvm/support.h>

#include <public/callback.h>

static void print_xen_info(void)
{
    char taint_str[TAINT_STRING_MAX_LEN];
    char debug = 'n', *arch = "x86_32p";

#ifndef NDEBUG
    debug = 'y';
#endif

    printk("----[ Xen-%d.%d%s  %s  debug=%c  %s ]----\n",
           xen_major_version(), xen_minor_version(), xen_extra_version(),
           arch, debug, print_tainted(taint_str));
}

enum context { CTXT_hypervisor, CTXT_pv_guest, CTXT_hvm_guest };

static void _show_registers(
    const struct cpu_user_regs *regs, unsigned long crs[8],
    enum context context, const struct vcpu *v)
{
    const static char *context_names[] = {
        [CTXT_hypervisor] = "hypervisor",
        [CTXT_pv_guest]   = "pv guest",
        [CTXT_hvm_guest]  = "hvm guest"
    };

    printk("EIP:    %04x:[<%08x>]", regs->cs, regs->eip);
    if ( context == CTXT_hypervisor )
        printk(" %S", (printk_symbol)regs->eip);
    printk("\nEFLAGS: %08x   ", regs->eflags);
    if ( (context == CTXT_pv_guest) && v && v->vcpu_info )
        printk("EM: %d   ", !!v->vcpu_info->evtchn_upcall_mask);
    printk("CONTEXT: %s\n", context_names[context]);

    printk("eax: %08x   ebx: %08x   ecx: %08x   edx: %08x\n",
           regs->eax, regs->ebx, regs->ecx, regs->edx);
    printk("esi: %08x   edi: %08x   ebp: %08x   esp: %08x\n",
           regs->esi, regs->edi, regs->ebp, regs->esp);
    printk("cr0: %08lx   cr4: %08lx   cr3: %08lx   cr2: %08lx\n",
           crs[0], crs[4], crs[3], crs[2]);
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
        context = CTXT_hvm_guest;
        fault_crs[0] = v->arch.hvm_vcpu.guest_cr[0];
        fault_crs[2] = v->arch.hvm_vcpu.guest_cr[2];
        fault_crs[3] = v->arch.hvm_vcpu.guest_cr[3];
        fault_crs[4] = v->arch.hvm_vcpu.guest_cr[4];
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
    }
    else
    {
        {
            context = CTXT_hypervisor;
            fault_regs.esp = (unsigned long)&regs->esp;
            fault_regs.ss = read_segment_register(ss);
            fault_regs.ds = read_segment_register(ds);
            fault_regs.es = read_segment_register(es);
            fault_regs.fs = read_segment_register(fs);
            fault_regs.gs = read_segment_register(gs);
            fault_crs[2] = read_cr2();
        }

        fault_crs[0] = read_cr0();
        fault_crs[3] = read_cr3();
        fault_crs[4] = read_cr4();
    }

    print_xen_info();
    printk("CPU:    %d\n", smp_processor_id());
    _show_registers(&fault_regs, fault_crs, context, v);

    if ( this_cpu(ler_msr) && !guest_mode(regs) )
    {
        u32 from, to, hi;
        rdmsr(this_cpu(ler_msr), from, hi);
        rdmsr(this_cpu(ler_msr) + 1, to, hi);
        printk("ler: %08x -> %08x\n", from, to);
    }
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
