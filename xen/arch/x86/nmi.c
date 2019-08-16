/*
 *  linux/arch/i386/nmi.c
 *
 *  NMI watchdog support on APIC systems
 *
 *  Started by Ingo Molnar <mingo@redhat.com>
 *
 *  Fixes:
 *  Mikael Pettersson : AMD K7 support for local APIC NMI watchdog.
 *  Mikael Pettersson : Power Management for local APIC NMI watchdog.
 *  Mikael Pettersson : Pentium 4 support for local APIC NMI watchdog.
 *  Pavel Machek and
 *  Mikael Pettersson : PM converted to driver model. Disable/enable API.
 */

#include <xen/config.h>
#include <xen/init.h>
#include <xen/lib.h>
#include <xen/mm.h>
#include <xen/irq.h>
#include <xen/delay.h>
#include <xen/time.h>
#include <xen/sched.h>
#include <xen/console.h>
#include <xen/smp.h>
#include <xen/keyhandler.h>
#include <xen/cpu.h>
#include <asm/current.h>
#include <asm/mc146818rtc.h>
#include <asm/msr.h>
#include <asm/mpspec.h>
#include <asm/debugger.h>
#include <asm/div64.h>
#include <asm/apic.h>

static atomic_t watchdog_disable_count = ATOMIC_INIT(1);

void watchdog_disable(void)
{
    atomic_inc(&watchdog_disable_count);
}

void watchdog_enable(void)
{
    atomic_dec(&watchdog_disable_count);
}

/*
 * For some reason the destination shorthand for self is not valid
 * when used with the NMI delivery mode. This is documented in Tables
 * 8-3 and 8-4 in IA32 Reference Manual Volume 3. We send the IPI to
 * our own APIC ID explicitly which is valid.
 */
void self_nmi(void) 
{
#if defined(__x86_64__)
    asm volatile ( "int $2" );
#else	/* __x86_64__ */
    BUG();
#endif	/* __x86_64__ */
}

