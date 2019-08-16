/******************************************************************************
 * arch/x86/shutdown.c
 *
 * x86-specific shutdown handling.
 */

#include <xen/config.h>
#include <xen/init.h>
#include <xen/lib.h>
#include <xen/sched.h>
#include <xen/smp.h>
#include <xen/delay.h>
#include <xen/dmi.h>
#include <xen/irq.h>
#include <xen/console.h>
#include <xen/shutdown.h>
#include <xen/acpi.h>
#include <xen/efi.h>
#include <asm/msr.h>
#include <asm/regs.h>
#include <asm/mc146818rtc.h>
#include <asm/system.h>
#include <asm/io.h>
#include <asm/processor.h>
#include <asm/mpspec.h>
#include <asm/tboot.h>
#include <asm/apic.h>

void machine_restart(unsigned int delay_millisecs)
{
    BUG();
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
