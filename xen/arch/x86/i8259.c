/******************************************************************************
 * i8259.c
 * 
 * Well, this is required for SMP systems as well, as it build interrupt
 * tables for IO APICS as well as uniprocessor 8259-alikes.
 */

#include <xen/config.h>
#include <xen/init.h>
#include <xen/types.h>
#include <asm/regs.h>
#include <xen/errno.h>
#include <xen/sched.h>
#include <xen/irq.h>
#include <asm/atomic.h>
#include <asm/system.h>
#include <asm/io.h>
#include <asm/desc.h>
#include <asm/bitops.h>
#include <xen/delay.h>
#include <asm/apic.h>
#include <asm/asm_defns.h>
#include <io_ports.h>

/*
 * Not all IRQs can be routed through the IO-APIC, eg. on certain (older)
 * boards the timer interrupt is not really connected to any IO-APIC pin,
 * it's fed to the master 8259A's IR0 line only.
 *
 * Any '1' bit in this mask means the IRQ is routed through the IO-APIC.
 * this 'mixed mode' IRQ handling costs nothing because it's only used
 * at IRQ setup time.
 */
unsigned int __read_mostly io_apic_irqs;

