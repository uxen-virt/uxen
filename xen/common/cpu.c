#include <xen/config.h>
#include <xen/cpumask.h>
#include <xen/cpu.h>
#include <xen/event.h>
#include <xen/init.h>
#include <xen/sched.h>
#include <xen/stop_machine.h>

unsigned int __read_mostly nr_cpu_ids = NR_CPUS;
#ifndef nr_cpumask_bits
unsigned int __read_mostly nr_cpumask_bits
    = BITS_TO_LONGS(NR_CPUS) * BITS_PER_LONG;
#endif

/*
 * cpu_bit_bitmap[] is a special, "compressed" data structure that
 * represents all NR_CPUS bits binary values of 1<<nr.
 *
 * It is used by cpumask_of() to get a constant address to a CPU
 * mask value that has a single bit set only.
 */

/* cpu_bit_bitmap[0] is empty - so we can back into it */
#define MASK_DECLARE_1(x) [x+1][0] = 1UL << (x)
#define MASK_DECLARE_2(x) MASK_DECLARE_1(x), MASK_DECLARE_1(x+1)
#define MASK_DECLARE_4(x) MASK_DECLARE_2(x), MASK_DECLARE_2(x+2)
#define MASK_DECLARE_8(x) MASK_DECLARE_4(x), MASK_DECLARE_4(x+4)

const unsigned long cpu_bit_bitmap[BITS_PER_LONG+1][BITS_TO_LONGS(NR_CPUS)] = {

    MASK_DECLARE_8(0),  MASK_DECLARE_8(8),
    MASK_DECLARE_8(16), MASK_DECLARE_8(24),
#if BITS_PER_LONG > 32
    MASK_DECLARE_8(32), MASK_DECLARE_8(40),
    MASK_DECLARE_8(48), MASK_DECLARE_8(56),
#endif
};

static DEFINE_SPINLOCK(cpu_add_remove_lock);

static NOTIFIER_HEAD(cpu_chain);

void __init register_cpu_notifier(struct notifier_block *nb)
{
    if ( !spin_trylock(&cpu_add_remove_lock) )
        BUG(); /* Should never fail as we are called only during boot. */
    notifier_chain_register(&cpu_chain, nb);
    spin_unlock(&cpu_add_remove_lock);
}

int cpu_up(unsigned int cpu)
{
    int notifier_rc, err = 0;
    void *hcpu = (void *)(long)cpu;
    struct notifier_block *nb = NULL;

    if ( (cpu >= nr_cpu_ids) || cpu_online(cpu) || !cpu_present(cpu) )
    {
        return -EINVAL;
    }

    notifier_rc = notifier_call_chain(&cpu_chain, CPU_UP_PREPARE, hcpu, &nb);
    if ( notifier_rc != NOTIFY_DONE )
    {
        err = notifier_to_errno(notifier_rc);
        goto fail;
    }

    err = __cpu_up(cpu);
    if ( err < 0 )
        goto fail;

    notifier_rc = notifier_call_chain(&cpu_chain, CPU_ONLINE, hcpu, NULL);
    BUG_ON(notifier_rc != NOTIFY_DONE);

    return 0;

 fail:
    notifier_rc = notifier_call_chain(&cpu_chain, CPU_UP_CANCELED, hcpu, &nb);
    BUG_ON(notifier_rc != NOTIFY_DONE);
    return err;
}

void notify_cpu_starting(unsigned int cpu)
{
    void *hcpu = (void *)(long)cpu;
    int notifier_rc = notifier_call_chain(
        &cpu_chain, CPU_STARTING, hcpu, NULL);
    BUG_ON(notifier_rc != NOTIFY_DONE);
}

