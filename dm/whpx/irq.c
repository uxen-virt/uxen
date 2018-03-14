/*
 * Copyright 2018, Bromium, Inc.
 * Author: Tomasz Wroblewski <tomasz.wroblewski@gmail.com>
 * SPDX-License-Identifier: ISC
 */

#include <dm/qemu_glue.h>
#include <dm/cpu.h>
#include <dm/whpx/apic.h>
#include "whpx.h"

#ifdef DEBUG_IRQ
#define IRQLOG(fmt, ...) debug_printf("IRQ: " fmt, ## __VA_ARGS__)
#else
#define IRQLOG(...)
#endif

#define GSI_NUM_PINS IOAPIC_NUM_PINS
#define ISA_NUM_IRQS 16
// support extra ioapic pins like xen
#define IOAPIC_NUM_PINS 48

struct gsi_state {
    qemu_irq i8259_irq[ISA_NUM_IRQS];
    qemu_irq ioapic_irq[IOAPIC_NUM_PINS];
};

struct irq_state {
    struct gsi_state gsi;
    uint8_t pci_route[4];
    qemu_irq *pic_irq, *gsi_irq;
};

static struct irq_state irq;

static
void hvm_set_pci_link_route(uint8_t link, uint8_t isa_irq)
{
    uint8_t old_isa_irq;

    assert((link <= 3) && (isa_irq <= 15));

    old_isa_irq = irq.pci_route[link];
    if ( old_isa_irq == isa_irq )
        goto out;
    irq.pci_route[link] = isa_irq;
    // FIXME: move irq assertion state if the link changes on the fly
    // (not particularly critical since believe only hvmloader changes the routes)
/*
    if (old_isa_irq)
        gsi_set_irq(&irq.gsi, old_isa_irq, 0);
    if (isa_irq)
        gsi_set_irq(&irq.gsi, isa_irq, 1);
*/
#if 0
    if ( hvm_irq->pci_link_assert_count[link] == 0 )
        goto out;

    if ( old_isa_irq && (--hvm_irq->gsi_assert_count[old_isa_irq] == 0) )
        vpic_irq_negative_edge(d, old_isa_irq);

    if ( isa_irq && (hvm_irq->gsi_assert_count[isa_irq]++ == 0) )
    {
        vioapic_irq_positive_edge(d, isa_irq, VCPUID_ANY);
        vpic_irq_positive_edge(d, isa_irq);
    }
#endif
out:
    IRQLOG("PCI link %u changed %u -> %u\n",
                 link, old_isa_irq, isa_irq);
}


void whpx_piix_pci_write_config_client(uint32_t address, uint32_t val, int len)
{
    int i;

    /* Scan for updates to PCI link routes (0x60-0x63). */
    for (i = 0; i < len; i++) {
        uint8_t v = (val >> (8 * i)) & 0xff;
        if (v & 0x80) {
            v = 0;
        }
        v &= 0xf;
        if (((address + i) >= 0x60) && ((address + i) <= 0x63)) {
            hvm_set_pci_link_route(address+i-0x60, v);
        }
    }
}

static
void gsi_set_irq(void *opaque, int n, int level)
{
    struct gsi_state *s = opaque;

    IRQLOG("%s GSI %d\n", level ? "raising" : "lowering", n);
    if (n < ISA_NUM_IRQS)
        qemu_set_irq(s->i8259_irq[n], level);
    qemu_set_irq(s->ioapic_irq[n], level);
}

void whpx_piix3_set_irq(void *opaque, int irq_num, int level)
{
#define hvm_pci_intx_gsi(dev, intx)     (((((dev)<<2) + ((dev)>>3) + (intx)) & 31) + 16)
#define hvm_pci_intx_link(dev, intx)    (((dev) + (intx)) & 3)

    uint8_t dev = irq_num >> 2;
    uint8_t intx = irq_num & 3;
    uint8_t gsi_irq = hvm_pci_intx_gsi(dev, intx);
    uint8_t isa_irq;
    uint8_t link;

    IRQLOG("piix set irq %d level %d\n", irq_num, level);

    /* FIXME: should use assert/deassert refcnt like does uxen, possibly?? */
    /* set GSI */
    gsi_irq = hvm_pci_intx_gsi(dev, intx);
    gsi_set_irq(&irq.gsi, gsi_irq, level);
    link = hvm_pci_intx_link(dev, intx);
    assert(link <= 3);
    /* set ISA irq */
    isa_irq = irq.pci_route[link];
    if (isa_irq)
        qemu_set_irq(irq.gsi.i8259_irq[isa_irq], level);
}

static void pic_irq_request(void *opaque, int irq, int level)
{
    CPUState *env = first_cpu;

    IRQLOG("pic_irq_request: %s irq %d\n", level? "raise" : "lower", irq);
    if (env->apic_state) {
        while (env) {
            if (apic_accept_pic_intr(env->apic_state)) {
                apic_deliver_pic_intr(env->apic_state, level);
            }
            env = env->next_cpu;
        }
    } else {
        if (level)
            cpu_interrupt(env, CPU_INTERRUPT_HARD);
        else
            cpu_reset_interrupt(env, CPU_INTERRUPT_HARD);
    }
}

int whpx_cpu_get_pic_interrupt(CPUState *env)
{
    int intno;

    assert(env->apic_state);

    intno = apic_get_interrupt(env->apic_state);
    if (intno >= 0) {
#ifdef DEBUG_IRQ
        debug_printf("get_pic_interrupt (apic): %x\n", intno);
#endif
        return intno;
    }
    /* read the irq from the PIC */
    if (!apic_accept_pic_intr(env->apic_state)) {
        return -1;
    }

    intno = pic_read_irq(isa_pic);
#ifdef DEBUG_IRQ
    debug_printf("get_pic_interrupt (pic): %x\n", intno);
#endif
    return intno;
}

qemu_irq *whpx_interrupt_controller_init(void)
{
    qemu_irq *i8259_irq, *ioapic_irq;
    int i;
    CPUState *cpu;

    memset(&irq, 0, sizeof(irq));

    //FIXME: leak?
    irq.pic_irq = qemu_allocate_irqs(pic_irq_request, NULL, 1);
    i8259_irq = i8259_init(*irq.pic_irq);
    ioapic_irq = ioapic_init();

    for (i = 0; i < ISA_NUM_IRQS; i++)
        irq.gsi.i8259_irq[i] = i8259_irq[i];
    for (i = 0; i < IOAPIC_NUM_PINS; i++)
        irq.gsi.ioapic_irq[i] = ioapic_irq[i];
    irq.gsi_irq = qemu_allocate_irqs(gsi_set_irq, &irq.gsi, GSI_NUM_PINS);

    cpu = first_cpu;
    while (cpu) {
      debug_printf("init apic %d\n", cpu->cpu_index);
      apic_init(cpu);
      cpu = cpu->next_cpu;
    }

    return irq.gsi_irq;
}


