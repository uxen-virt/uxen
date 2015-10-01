/******************************************************************************
 * uxen/time.c
 *
 * based arch/x86/time.c
 * 
 * Per-CPU time calibration and management.
 * 
 * Copyright (c) 2002-2005, K A Fraser
 * 
 * Portions from Linux are:
 * Copyright (c) 1991, 1992, 1995  Linus Torvalds
 */
/*
 * uXen changes:
 *
 * Copyright 2012-2015, Bromium, Inc.
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
#include <xen/errno.h>
#include <xen/event.h>
#include <xen/sched.h>
#include <xen/lib.h>
#include <xen/config.h>
#include <xen/init.h>
#include <xen/time.h>
#include <xen/timer.h>
#include <xen/smp.h>
#include <xen/irq.h>
#include <xen/softirq.h>
#include <xen/efi.h>
#include <xen/cpuidle.h>
#include <xen/symbols.h>
#include <xen/keyhandler.h>
#include <xen/guest_access.h>
#include <asm/io.h>
#include <asm/msr.h>
#include <asm/mpspec.h>
#include <asm/processor.h>
#include <asm/fixmap.h>
#include <asm/mc146818rtc.h>
#include <asm/div64.h>
#include <asm/acpi.h>
#include <asm/hpet.h>
#include <io_ports.h>
#include <asm/setup.h> /* for early_time_init */
#include <public/arch-x86/cpuid.h>


/*
 *
 * There are three clocks
 * 1 - the cpu tsc, the code here assumes it's consistent accross all cpus
 * 2 - the host timer, the window performance counter, it notionally has a 
 *     fixed known frequencey but doesn't track real time
 * 3 - the host RTC which has a low precision
 *
 * in early time init we use upcalls to read the host timer to get a guestimate
 * of the TSC frequency.
 *
 * we then set plt_scale to be the host purported host timer frequency and 
 * schedule periodic calls to time_calibration
 *
 * in time_calibration, we measure the cumulative slip between xen's s_time
 * and the host RTC, we adjust the host counter frequency linearly.
 * This has the effect that the guest time will have an offset from the host
 * time that is proportional to the error in the host reported counter
 * frequency, however this algorythm is much more stable than the equivalent
 * pll, and a failure to lock isn't fatal.
 *
 */

unsigned long __read_mostly cpu_khz;  /* CPU clock frequency in kHz. */

uint32_t unixtime_generation;


struct time_scale tsc_scale_inital_guess;
u64 stime_to_unixtime_offset;

struct cpu_time {
    u64 tsc_offset;
    u64 s_time_offset;
    struct time_scale tsc_scale;
};

struct platform_timesource {
    char *id;
    char *name;
};

/* For the moment these are LIES */
struct cpu_time global_cpu_time;

static int last_slip = 0;

static void atomic_get_global_time(struct cpu_time *t)
{
    *t = global_cpu_time;
}

static void atomic_set_global_time(struct cpu_time *t)
{
    global_cpu_time = *t;
}


/* Calibrate all CPUs to platform timer every EPOCH. */
#define EPOCH MILLISECS(20000)
static u64 calibration_epoch;
static struct timer calibration_timer;

/* Time after which a slip is an error */
#define SECONDS_TO_STABALIZE 60

/*
 * 32-bit division of integer dividend and integer divisor yielding
 * 32-bit fractional quotient.
 */
static inline u32 div_frac(u32 dividend, u32 divisor)
{
    u32 quotient, remainder;
    ASSERT(dividend < divisor);
    asm (
        "divl %4"
        : "=a" (quotient), "=d" (remainder)
        : "0" (0), "1" (dividend), "r" (divisor) );
    return quotient;
}

/*
 * 32-bit multiplication of multiplicand and fractional multiplier
 * yielding 32-bit product (radix point at same position as in multiplicand).
 */
static inline u32 mul_frac(u32 multiplicand, u32 multiplier)
{
    u32 product_int, product_frac;
    asm (
        "mul %3"
        : "=a" (product_frac), "=d" (product_int)
        : "0" (multiplicand), "r" (multiplier) );
    return product_int;
}

/*
 * XXX: Inlining this generated bad code on x86_64 - JMM
 *
 * Scale a 64-bit delta by scaling and multiplying by a 32-bit fraction,
 * yielding a 64-bit result.
 */
static u64 scale_delta(u64 delta, struct time_scale *scale)
{
    u64 product;
#ifdef CONFIG_X86_32
    u32 tmp1, tmp2;
#endif

    if ( scale->shift < 0 )
        delta >>= -scale->shift;
    else
        delta <<= scale->shift;

#ifdef CONFIG_X86_32
    asm (
        "mul  %5       ; "
        "mov  %4,%%eax ; "
        "mov  %%edx,%4 ; "
        "mul  %5       ; "
        "xor  %5,%5    ; "
        "add  %4,%%eax ; "
        "adc  %5,%%edx ; "
        : "=A" (product), "=r" (tmp1), "=r" (tmp2)
        : "a" ((u32)delta), "1" ((u32)(delta >> 32)), "2" (scale->mul_frac) );
#else
    asm (
        "mul %%rdx ; shrd $32,%%rdx,%%rax"
        : "=a" (product) : "0" (delta), "d" ((u64)scale->mul_frac) );
#endif

    return product;
}

#define _TS_MUL_FRAC_IDENTITY 0x80000000UL

/* Compute the reciprocal of the given time_scale. */
static inline struct time_scale scale_reciprocal(struct time_scale scale)
{
    struct time_scale reciprocal;
    u32 dividend;

    ASSERT(scale.mul_frac != 0);
    dividend = _TS_MUL_FRAC_IDENTITY;
    reciprocal.shift = 1 - scale.shift;
    while ( unlikely(dividend >= scale.mul_frac) )
    {
        dividend >>= 1;
        reciprocal.shift++;
    }

    asm (
        "divl %4"
        : "=a" (reciprocal.mul_frac), "=d" (dividend)
        : "0" (0), "1" (dividend), "r" (scale.mul_frac) );

    return reciprocal;
}

static void set_time_scale(struct time_scale *ts, u64 tps64, u64 period)
{
    u32 tps32;
    int shift = 0;

    while (period >= (1ULL << 31)) {
        tps64 >>= 1;
        period >>= 1;
    }

    if (tps64 == 0)
        return;

    while ( tps64 > (period * 2) )
    {
        tps64 >>= 1;
        shift--;
    }

    tps32 = (u32)tps64;
    while ( tps32 <= (u32)period )
    {
        tps32 <<= 1;
        shift++;
    }

    ts->mul_frac = div_frac(period, tps32);
    ts->shift    = shift;
}

static char *freq_string(u64 freq)
{
    static char s[20];
    unsigned int x, y;
    y = (unsigned int)do_div(freq, 1000000) / 1000;
    x = (unsigned int)freq;
    snprintf(s, sizeof(s), "%u.%03uMHz", x, y);
    return s;
}


/************************************************************
 * PLATFORM TIMER: Host OS counter
 */

/* scale: nanosecs -> host timer */
static struct time_scale __read_mostly inv_timer_scale;

u64 delta_s_time_to_platform_timer(s_time_t s_time)
{
    return scale_delta(s_time, &inv_timer_scale);
}

static u64 init_host_counter_and_calibrate_tsc(uint64_t *period)
{
    u64 start, end, tzero, tlast, ticks;
    struct time_scale scale, scale_r;

    set_time_scale(&scale, _uxen_info.ui_host_timer_frequency,
                   MILLISECS(1000));
    inv_timer_scale = scale_reciprocal(scale);

    set_time_scale(&scale, _uxen_info.ui_host_counter_frequency,
                   MILLISECS(1000));
    scale_r = scale_reciprocal(scale);

    /* Calibrate for period. */
    ticks = scale_delta(*period, &scale_r);

    rdtscll(start);
    tzero = UI_HOST_CALL(ui_get_host_counter);
    while (((tlast = UI_HOST_CALL(ui_get_host_counter)) - tzero) < ticks)
        continue;
    rdtscll(end);

    *period = scale_delta(tlast - tzero, &scale);

    /* Returns tsc per period. */
    return end - start;
}

#ifndef Dprintk
#define Dprintk(x...)
#endif

int reprogram_timer(s_time_t timeout, struct vcpu *v)
{
    s_time_t now;
    s_time_t expire;
    u64 ticks;

    if (timeout == 0)
        return 1;

    now = NOW();

    expire = timeout - now;     /* value from now */

    if (expire <= 0) {
        Dprintk("HOSTCOUNTER[%02d] "
                "Timeout in the past 0x%08X%08X > 0x%08X%08X\n",
                smp_processor_id(), (u32)(now>>32),
                (u32)now, (u32)(timeout>>32), (u32)timeout);
        return 0;
    }

    ticks = delta_s_time_to_platform_timer(expire) + 1;

    if (!v) {

        ASSERT(smp_processor_id() == 0);

        _uxen_info.ui_host_idle_timeout = ticks;
        if (!is_idle_vcpu(current))
            UI_HOST_CALL(ui_signal_idle_thread);
    } else {
        extern void hostsched_set_timer_vcpu(struct vcpu *, uint64_t);
        hostsched_set_timer_vcpu(v, ticks);
    }
    return 1;
}


/************************************************************
 * GENERIC PLATFORM TIMER INFRASTRUCTURE
 */

/* scale: platform counter -> nanosecs */
static struct time_scale __read_mostly plt_scale;


/* NB: This also sets the global cpu_khz which is used elsewhere in uxen */
static void announce_cpu_speed(void)
{
    struct cpu_time t;
    struct time_scale scale_r;
    struct time_scale i_plt_scale;
    u64 cpu_freq, host_freq;

    atomic_get_global_time(&t);

    scale_r = scale_reciprocal(t.tsc_scale);
    cpu_freq = MILLISECS(1);
    cpu_freq = scale_delta(cpu_freq, &scale_r);

    /* XXX: no lock */
    cpu_khz = cpu_freq;

    if (plt_scale.mul_frac) {
        i_plt_scale = scale_reciprocal(plt_scale);
        host_freq = scale_delta(MILLISECS(1000), &i_plt_scale);
    } else
        host_freq = 0;

    printk(KERN_WARNING "time: cpu: %"PRIu64".%03"PRIu64" MHz, "
           "host counter: %"PRIu64".%06"PRIu64" MHz, "
           "lag: %d us\n", cpu_freq / 1000, cpu_freq % 1000,
           host_freq / 1000000, host_freq % 1000000, last_slip);
}

static int sanity_check_frequency(u64 freq)
{
    u64 a = _uxen_info.ui_host_counter_frequency;
    u64 b = a >> 2;

    if (freq < (a - b)) return 0;
    if (freq > (a + b)) return 0;

    return 1;
}


static int calibrate_host_counter(int init)
{
    static u64 last_unixtime;
    static u64 last_host_counter;
    static s64 start_stime_offset;

    struct cpu_time t;
    s64 slip;
    u64 then;
    s64 w;

    atomic_get_global_time(&t);

    then = t.s_time_offset + scale_delta(_uxen_info.ui_host_counter_tsc -
                                         t.tsc_offset, &t.tsc_scale);

    last_slip = 0;

    do {
        if (init)
            break;

        /* check that long enough has elapsed that we're happy to use
         * the data */
        w = _uxen_info.ui_host_counter_unixtime - last_unixtime;
        if (w < (EPOCH / 8)) {
            printk(KERN_INFO "time: only ran for %d ms - bailing\n",
                   (int)(w / MILLISECS(1)));
            break;
        }

        w = scale_delta(_uxen_info.ui_host_counter - last_host_counter,
                        &plt_scale);
        if (w < (EPOCH / 8)) {
            printk(KERN_INFO "time: host timer only ran for %d ms - bailing\n",
                   (int)(w / MILLISECS(1)));
            break;
        }

        /* calulate the slip, +ve means that the xen clock is running slow, */
        /* and therefore the host clock frequency is too fast */
        slip = (_uxen_info.ui_host_counter_unixtime - then) -
            start_stime_offset;

        if ((slip > MILLISECS(500)) || (slip < -(s64)MILLISECS(500))) {
             /* Slip is too much to slew, we'll step the timer */
             printk(KERN_WARNING "time: uxen lags by %d ms - bailing\n",
                    (int)(slip / MILLISECS(1)));
             last_slip = (int)(slip / MICROSECS(1));
             break;
        }

        slip = slip / MICROSECS(1);
        last_slip = (int)slip;

        slip *= _uxen_info.ui_host_counter_frequency;
        slip /= 20000000;

        w = _uxen_info.ui_host_counter_frequency;
        w -= slip;

        if (!sanity_check_frequency(w)) {
            printk(KERN_WARNING
                   "time: host counter frequency out of bounds - bailing\n");
            break;
        }

        set_time_scale(&plt_scale, w, MILLISECS(1000));

        last_host_counter = _uxen_info.ui_host_counter;
        last_unixtime = _uxen_info.ui_host_counter_unixtime;

        return 0;

    } while (0);

    /* Something went wrong, set the platform timer to the nominal frequency */
    /* and let time slip. */
    /* XXX: we should notify the platform device so it can sync the time */

    set_time_scale(&plt_scale, _uxen_info.ui_host_counter_frequency,
                   MILLISECS(1000));
    start_stime_offset = _uxen_info.ui_host_counter_unixtime - then;
    last_host_counter =_uxen_info.ui_host_counter;
    last_unixtime = _uxen_info.ui_host_counter_unixtime;

    w = then / MILLISECS(1000);

    /* put something in the log that the tests can easily find if we */
    /* didn't expect the guest time to slip */
    if (w > SECONDS_TO_STABALIZE)
        printk(KERN_ERR "time: FAILED - letting guest time slip\n");
    else if (!init)
        printk(KERN_INFO "time: letting guest time slip (expected)\n");

    return 1;
}


static void re_calibrate_tsc(int init)
{
    static u64 last_host_counter;
    static u64 last_host_counter_tsc;
    struct cpu_time t, nt;
    u64 host_time;
    u64 tsc_ticks;
    u64 tsc_time;
    u64 delta;
    s_time_t s_time;

    if (init) {
        last_host_counter = _uxen_info.ui_host_counter;
        last_host_counter_tsc = _uxen_info.ui_host_counter_tsc;
        return;
    }

    atomic_get_global_time(&t);

    /* This calibrates the tsc -> s_time mapping using the platform counter */
    /* as a reference and trusting plt_scale is correct */

    host_time = scale_delta(_uxen_info.ui_host_counter - last_host_counter,
                            &plt_scale);
    tsc_ticks = _uxen_info.ui_host_counter_tsc - last_host_counter_tsc;
    tsc_time = scale_delta(tsc_ticks, &t.tsc_scale);

    if ((host_time > (2 * EPOCH)) || (tsc_time > (2 * EPOCH)) ||
        (!host_time) || (!tsc_ticks)) {
        last_host_counter = _uxen_info.ui_host_counter;
        last_host_counter_tsc = _uxen_info.ui_host_counter_tsc;
        return;
    }

    /* Set the new time scale so that _uxen_info.ui_host_counter_tsc
     * is the same in both */

    delta = _uxen_info.ui_host_counter_tsc - t.tsc_offset;

    /* XXX: inlineing scale_delta, makes this expresison return zero */
    s_time = t.s_time_offset + scale_delta(delta, &t.tsc_scale);

    stime_to_unixtime_offset = _uxen_info.ui_host_counter_unixtime - s_time;

    set_time_scale(&nt.tsc_scale, tsc_ticks, host_time);

    nt.tsc_offset = t.tsc_offset;
    nt.s_time_offset = s_time - scale_delta(delta, &nt.tsc_scale);

    atomic_set_global_time(&nt);

    last_host_counter = _uxen_info.ui_host_counter;
    last_host_counter_tsc = _uxen_info.ui_host_counter_tsc;
}

void suspend_platform_time(void)
{
    suspend_timers();
}

void resume_platform_time(void)
{
    struct cpu_time nt;

    if ( _uxen_info.ui_host_counter_unixtime < stime_to_unixtime_offset)  {
	printk(KERN_ERR "Host time has gone backwards - expect misery\n");
	nt.s_time_offset = 0;
    } else {
        nt.s_time_offset = _uxen_info.ui_host_counter_unixtime - stime_to_unixtime_offset;
    }

    nt.tsc_offset = _uxen_info.ui_host_counter_tsc;
    nt.tsc_scale = tsc_scale_inital_guess;

    atomic_set_global_time(&nt);

    re_calibrate_tsc(1);
    calibrate_host_counter(1);

    set_time_scale(&plt_scale, _uxen_info.ui_host_counter_frequency,
                   MILLISECS(1000));

    resume_timers();

    calibration_epoch = MILLISECS(1000);
    set_timer(&calibration_timer, NOW() + calibration_epoch);

    announce_cpu_speed();

    printk(KERN_WARNING "Rejigged all the timers\n");
}


static void __init init_platform_time(void)
{
    re_calibrate_tsc(1);
    calibrate_host_counter(1);

    set_time_scale(&plt_scale, _uxen_info.ui_host_counter_frequency,
                   MILLISECS(1000));

    printk(KERN_WARNING "Platform timer is %s HOSTCOUNTER\n",
           freq_string(_uxen_info.ui_host_counter_frequency));
}

/***************************************************************************
 * System Time
 ***************************************************************************/

/* s_time is: stime_stamp + (tsc - tsc_stamp) * tsc_scale
 *          = ui_host_counter * plt_scale + (tsc - tsc_stamp) * tsc_scale
 */
s_time_t get_s_time(void)
{
    struct cpu_time t;
    u64 tsc, delta;
    s_time_t now;

    atomic_get_global_time(&t);

    rdtscll(tsc);
    delta = tsc - t.tsc_offset;
    now = t.s_time_offset + scale_delta(delta, &t.tsc_scale);

    return now;
}

void platform_time_sync(void)
{
}

static void time_calibration(void *unused)
{
    u64 then;
    int reinit;
    ASSERT(is_idle_vcpu(current));

    then = NOW();

    ASSERT(smp_processor_id() == 0);

    if (calibration_epoch < EPOCH) {
        calibration_epoch *= 2;
        if (calibration_epoch > EPOCH)
            calibration_epoch = EPOCH;
    }
    then += calibration_epoch;
    set_timer(&calibration_timer, then);

    reinit = calibrate_host_counter(0);
    re_calibrate_tsc(reinit);

    announce_cpu_speed();
}

/* Late init function (after interrupts are enabled). */
int __init init_xen_time(void)
{

    if (!boot_cpu_has(X86_FEATURE_TSC_RELIABLE) ||
        !boot_cpu_has(X86_FEATURE_CONSTANT_TSC))
        BUG();

    init_platform_time();

    ASSERT(smp_processor_id() == 0);

    init_timer(&calibration_timer, time_calibration, NULL, 0);
    calibration_epoch = MILLISECS(1000);
    set_timer(&calibration_timer, NOW() + calibration_epoch);

    update_xen_time();

    return 0;
}

void
update_xen_time(void)
{
    uint64_t unixtime;

    unixtime_generation = _uxen_info.ui_unixtime_generation;

    unixtime = UI_HOST_CALL(ui_get_unixtime);
    do_settime(unixtime / 1000000000, unixtime % 1000000000, NOW());

    update_domain_rtc();
}


/* Early init function. */
void __init early_time_init(void)
{
    uint64_t calibration_period = MILLISECS(100);
    u64 tmp = init_host_counter_and_calibrate_tsc(&calibration_period);
    struct cpu_time t;

    t.tsc_offset = _uxen_info.ui_host_counter_tsc;
    t.s_time_offset = 0;
    set_time_scale(&t.tsc_scale, tmp, calibration_period);

    tsc_scale_inital_guess = t.tsc_scale;

    atomic_set_global_time(&t);

    announce_cpu_speed();
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
