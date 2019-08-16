/******************************************************************************
 * arch/x86/time.c
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

static u32 wc_sec, wc_nsec; /* UTC time at last 'time update'. */
static DEFINE_SPINLOCK(wc_lock);

struct cpu_time {
    u64 local_tsc_stamp;
    s_time_t stime_local_stamp;
    struct time_scale tsc_scale;
};

extern struct cpu_time global_cpu_time;
#define THIS_CPU_TIME (&global_cpu_time)

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
 * Scale a 64-bit delta by scaling and multiplying by a 32-bit fraction,
 * yielding a 64-bit result.
 */
static inline u64 scale_delta(u64 delta, struct time_scale *scale)
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

static void set_time_scale(struct time_scale *ts, u64 ticks, u64 period)
{
    u64 tps64;
    u32 tps32;
    int shift = 0;

    while (period > (1ULL << 31)) {
        ticks >>= 1;
        period >>= 1;
    }

    tps64 = ticks;
    ASSERT(tps64 != 0);

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

/***************************************************************************
 * CMOS Timer functions
 ***************************************************************************/

/* Converts Gregorian date to seconds since 1970-01-01 00:00:00.
 * Assumes input in normal date format, i.e. 1980-12-31 23:59:59
 * => year=1980, mon=12, day=31, hour=23, min=59, sec=59.
 *
 * [For the Julian calendar (which was used in Russia before 1917,
 * Britain & colonies before 1752, anywhere else before 1582,
 * and is still in use by some communities) leave out the
 * -year/100+year/400 terms, and add 10.]
 *
 * This algorithm was first published by Gauss (I think).
 *
 * WARNING: this function will overflow on 2106-02-07 06:28:16 on
 * machines were long is 32-bit! (However, as time_t is signed, we
 * will already get problems at other places on 2038-01-19 03:14:08)
 */
unsigned long
mktime (unsigned int year, unsigned int mon,
        unsigned int day, unsigned int hour,
        unsigned int min, unsigned int sec)
{
    /* 1..12 -> 11,12,1..10: put Feb last since it has a leap day. */
    if ( 0 >= (int) (mon -= 2) )
    {
        mon += 12;
        year -= 1;
    }

    return ((((unsigned long)(year/4 - year/100 + year/400 + 367*mon/12 + day)+
              year*365 - 719499
        )*24 + hour /* now have hours */
        )*60 + min  /* now have minutes */
        )*60 + sec; /* finally seconds */
}

/* Explicitly OR with 1 just in case version number gets out of sync. */
#define version_update_begin(v) (((v)+1)|1)
#define version_update_end(v)   ((v)+1)

static void __update_vcpu_system_time(struct vcpu *v, int force)
{
    struct cpu_time       *t;
    struct vcpu_time_info *u, _u;
    XEN_GUEST_HANDLE(vcpu_time_info_t) user_u;
    struct domain *d = v->domain;
    s_time_t tsc_stamp = 0;

    if ( v->vcpu_info == NULL )
        return;

    t = THIS_CPU_TIME;
    u = &vcpu_info(v, time);

    if ( d->arch.vtsc )
    {
        u64 stime = t->stime_local_stamp;
        if ( is_hvm_domain(d) )
        {
            struct pl_time *pl = &v->domain->arch.hvm_domain.pl_time;
            stime += pl->stime_offset + v->arch.hvm_vcpu.stime_offset;
        }
        tsc_stamp = gtime_to_gtsc(d, stime);
    }
    else
    {
        tsc_stamp = t->local_tsc_stamp;
    }

    memset(&_u, 0, sizeof(_u));

    if ( d->arch.vtsc )
    {
        _u.tsc_timestamp     = tsc_stamp;
        _u.system_time       = t->stime_local_stamp;
        _u.tsc_to_system_mul = d->arch.vtsc_to_ns.mul_frac;
        _u.tsc_shift         = d->arch.vtsc_to_ns.shift;
    }
    else
    {
        _u.tsc_timestamp     = t->local_tsc_stamp;
        _u.system_time       = t->stime_local_stamp;
        _u.tsc_to_system_mul = t->tsc_scale.mul_frac;
        _u.tsc_shift         = (s8)t->tsc_scale.shift;
    }
    if ( is_hvm_domain(d) )
        _u.tsc_timestamp += v->arch.hvm_vcpu.cache_tsc_offset;

    /* Don't bother unless timestamp record has changed or we are forced. */
    _u.version = u->version; /* make versions match for memcmp test */
    if ( !force && !memcmp(u, &_u, sizeof(_u)) )
        return;

    /* 1. Update guest kernel version. */
    _u.version = u->version = version_update_begin(u->version);
    wmb();
    /* 2. Update all other guest kernel fields. */
    *u = _u;
    wmb();
    /* 3. Update guest kernel version. */
    u->version = version_update_end(u->version);

    user_u = v->arch.time_info_guest;
    if ( !guest_handle_is_null(user_u) )
    {
        /* 1. Update userspace version. */
        __copy_field_to_guest(user_u, &_u, version);
        wmb();
        /* 2. Update all other userspavce fields. */
        __copy_to_guest(user_u, &_u, 1);
        wmb();
        /* 3. Update userspace version. */
        _u.version = version_update_end(_u.version);
        __copy_field_to_guest(user_u, &_u, version);
    }
}

void update_vcpu_system_time(struct vcpu *v)
{
    __update_vcpu_system_time(v, 0);
}

void update_domain_wallclock_time(struct domain *d)
{
    uint32_t *wc_version;

    spin_lock(&wc_lock);

    wc_version = &shared_info(d, wc_version);
    *wc_version = version_update_begin(*wc_version);
    wmb();

    shared_info(d, wc_sec)  = wc_sec + d->time_offset_seconds;
    shared_info(d, wc_nsec) = wc_nsec;
    shared_info(d, wc_time_offset) = d->time_offset_seconds;

    wmb();
    *wc_version = version_update_end(*wc_version);

    spin_unlock(&wc_lock);
}

void update_domain_rtc(void)
{
    struct domain *d;

    rcu_read_lock(&domlist_read_lock);

    for_each_domain ( d )
        if ( is_hvm_domain(d) )
            rtc_update_clock(d);

    rcu_read_unlock(&domlist_read_lock);

    uxen_info->ui_exception_event_all = 1;
}

void domain_set_time_offset(struct domain *d, int32_t time_offset_seconds)
{
    d->time_offset_seconds = time_offset_seconds;
    if ( is_hvm_domain(d) ) {
        rtc_update_clock(d);
        update_domain_wallclock_time(d);
    }
}

/* Set clock to <secs,usecs> after 00:00:00 UTC, 1 January, 1970. */
void do_settime(unsigned long secs, unsigned long nsecs, u64 system_time_base)
{
    u64 x;
    u32 y, _wc_sec, _wc_nsec;
    struct domain *d;

    x = (secs * 1000000000ULL) + (u64)nsecs - system_time_base;
    y = do_div(x, 1000000000);

    spin_lock(&wc_lock);
    wc_sec  = _wc_sec  = (u32)x;
    wc_nsec = _wc_nsec = (u32)y;
    spin_unlock(&wc_lock);

    rcu_read_lock(&domlist_read_lock);
    for_each_domain ( d )
        update_domain_wallclock_time(d);
    rcu_read_unlock(&domlist_read_lock);
}

/* Return secs after 00:00:00 localtime, 1 January, 1970. */
unsigned long get_localtime(struct domain *d)
{
    return wc_sec + (wc_nsec + NOW()) / 1000000000ULL 
        + d->time_offset_seconds;
}

/* Return microsecs after 00:00:00 localtime, 1 January, 1970. */
uint64_t get_localtime_us(struct domain *d)
{
    return (SECONDS(wc_sec + d->time_offset_seconds) + wc_nsec + NOW())
           / 1000UL;
}

int dom0_pit_access(struct ioreq *ioreq)
{
    BUG(); return 0;
}

struct tm wallclock_time(void)
{
    uint64_t seconds;

    if ( !wc_sec )
        return (struct tm) { 0 };

    seconds = NOW() + (wc_sec * 1000000000ull) + wc_nsec;
    do_div(seconds, 1000000000);
    return gmtime(seconds);
}

u64 gtime_to_gtsc(struct domain *d, u64 time)
{
    if ( !is_hvm_domain(d) )
        time = max_t(s64, time - d->arch.vtsc_offset, 0);
    return scale_delta(time, &d->arch.ns_to_vtsc);
}

u64 gtsc_to_gtime(struct domain *d, u64 tsc)
{
    u64 time = scale_delta(tsc, d->arch.vtsc ? &d->arch.vtsc_to_ns :
                           &THIS_CPU_TIME->tsc_scale);

    if ( !is_hvm_domain(d) )
        time += d->arch.vtsc_offset;
    return time;
}

int host_tsc_is_safe(void)
{
    WARN_ON(!boot_cpu_has(X86_FEATURE_TSC_RELIABLE)); /* XXX */
    return boot_cpu_has(X86_FEATURE_TSC_RELIABLE);
}

void cpuid_time_leaf(uint32_t sub_idx, uint32_t *eax, uint32_t *ebx,
                      uint32_t *ecx, uint32_t *edx)
{
    struct domain *d = current->domain;
    uint64_t offset;

    switch ( sub_idx )
    {
    case 0: /* features */
        *eax = ( ( (!!d->arch.vtsc) << 0 ) |
                 ( (!!host_tsc_is_safe()) << 1 ) |
                 ( (!!(boot_cpu_has(X86_FEATURE_RDTSCP) &&
                       (!is_hvm_domain(d) || hvm_has_rdtscp(d) ||
                        hvm_has_pvrdtscp(d)))) << 2 ) |
               0 );
        *ebx = d->arch.tsc_mode;
        *ecx = d->arch.tsc_khz;
        *edx = d->arch.incarnation;
        break;
    case 1: /* scale and offset */
        if ( !d->arch.vtsc )
            offset = d->arch.vtsc_offset;
        else
            /* offset already applied to value returned by virtual rdtscp */
            offset = 0;
        *eax = (uint32_t)offset;
        *ebx = (uint32_t)(offset >> 32);
        *ecx = d->arch.vtsc_to_ns.mul_frac;
        *edx = (s8)d->arch.vtsc_to_ns.shift;
        break;
    case 2: /* physical cpu_khz */
        *eax = cpu_khz;
        *ebx = *ecx = *edx = 0;
        break;
    default:
        *eax = *ebx = *ecx = *edx = 0;
    }
}

/*
 * called to collect tsc-related data only for save file or live
 * migrate; called after last rdtsc is done on this incarnation
 */
void tsc_get_info(struct domain *d, uint32_t *tsc_mode,
                  uint64_t *elapsed_nsec, uint32_t *gtsc_khz,
                  uint32_t *incarnation)
{
    *incarnation = d->arch.incarnation;
    *tsc_mode = d->arch.tsc_mode;

    switch ( *tsc_mode )
    {
    case TSC_MODE_NEVER_EMULATE:
        *elapsed_nsec =  *gtsc_khz = 0;
        break;
    case TSC_MODE_ALWAYS_EMULATE:
        *elapsed_nsec = get_s_time() - d->arch.vtsc_offset;
        *gtsc_khz =  d->arch.tsc_khz;
         break;
    case TSC_MODE_DEFAULT:
        if ( d->arch.vtsc )
        {
            *elapsed_nsec = get_s_time() - d->arch.vtsc_offset;
            *gtsc_khz =  d->arch.tsc_khz;
        }
        else
        {
            uint64_t tsc = 0;
            rdtscll(tsc);
            *elapsed_nsec = scale_delta(tsc,&d->arch.vtsc_to_ns);
            *gtsc_khz =  cpu_khz;
        }
        break;
    case TSC_MODE_PVRDTSCP:
        if ( d->arch.vtsc )
        {
            *elapsed_nsec = get_s_time() - d->arch.vtsc_offset;
            *gtsc_khz =  cpu_khz;
        }
        else
        {
            uint64_t tsc = 0;
            rdtscll(tsc);
            *elapsed_nsec = (scale_delta(tsc,&d->arch.vtsc_to_ns) -
                             d->arch.vtsc_offset);
            *gtsc_khz = 0; /* ignored by tsc_set_info */
        }
        break;
    }

    if ( (int64_t)*elapsed_nsec < 0 )
        *elapsed_nsec = 0;
}

/*
 * This may be called as many as three times for a domain, once when the
 * hypervisor creates the domain, once when the toolstack creates the
 * domain and, if restoring/migrating, once when saved/migrated values
 * are restored.  Care must be taken that, if multiple calls occur,
 * only the last "sticks" and all are completed before the guest executes
 * an rdtsc instruction
 */
void tsc_set_info(struct domain *d,
                  uint32_t tsc_mode, uint64_t elapsed_nsec,
                  uint32_t gtsc_khz, uint32_t incarnation)
{
    if ( is_idle_domain(d) || (d->domain_id == 0) )
    {
        d->arch.vtsc = 0;
        return;
    }

    switch ( d->arch.tsc_mode = tsc_mode )
    {
    case TSC_MODE_NEVER_EMULATE:
        d->arch.vtsc = 0;
        break;
    case TSC_MODE_ALWAYS_EMULATE:
        d->arch.vtsc = 1;
        d->arch.vtsc_offset = get_s_time() - elapsed_nsec;
        d->arch.tsc_khz = gtsc_khz ? gtsc_khz : cpu_khz;
        set_time_scale(&d->arch.vtsc_to_ns, d->arch.tsc_khz * 1000,
                       MILLISECS(1000));
        d->arch.ns_to_vtsc = scale_reciprocal(d->arch.vtsc_to_ns);
        break;
    case TSC_MODE_DEFAULT:
        d->arch.vtsc = 1;
        d->arch.vtsc_offset = get_s_time() - elapsed_nsec;
        d->arch.tsc_khz = gtsc_khz ? gtsc_khz : cpu_khz;
        set_time_scale(&d->arch.vtsc_to_ns, d->arch.tsc_khz * 1000,
                       MILLISECS(1000));
        /* use native TSC if initial host has safe TSC, has not migrated
         * yet and tsc_khz == cpu_khz */
        if ( host_tsc_is_safe() && incarnation == 0 &&
                d->arch.tsc_khz == cpu_khz )
            d->arch.vtsc = 0;
        else 
            d->arch.ns_to_vtsc = scale_reciprocal(d->arch.vtsc_to_ns);
        break;
    case TSC_MODE_PVRDTSCP:
        d->arch.vtsc =  boot_cpu_has(X86_FEATURE_RDTSCP) && !is_hvm_domain(d) &&
                        host_tsc_is_safe() ?  0 : 1;
        d->arch.tsc_khz = cpu_khz;
        set_time_scale(&d->arch.vtsc_to_ns, d->arch.tsc_khz * 1000,
                       MILLISECS(1000));
        d->arch.ns_to_vtsc = scale_reciprocal(d->arch.vtsc_to_ns);
        if ( d->arch.vtsc )
            d->arch.vtsc_offset = get_s_time() - elapsed_nsec;
        else {
            /* when using native TSC, offset is nsec relative to power-on
             * of physical machine */
            uint64_t tsc = 0;
            rdtscll(tsc);
            d->arch.vtsc_offset = scale_delta(tsc,&d->arch.vtsc_to_ns) -
                                  elapsed_nsec;
        }
        break;
    }
    d->arch.incarnation = incarnation + 1;
    if ( is_hvm_domain(d) )
        hvm_set_rdtsc_exiting(d, d->arch.vtsc);
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
