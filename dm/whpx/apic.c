/*
 *  APIC support
 *
 *  Copyright (c) 2004-2005 Fabrice Bellard
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, see <http://www.gnu.org/licenses/>
 */
/*
 * uXen changes:
 *
 * Copyright 2018, Bromium, Inc.
 * Author: Tomasz Wroblewski <tomasz.wroblewski@gmail.com>
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

#include <dm/qemu_glue.h>
#include <dm/qemu/hw/sysbus.h>
#include <dm/qemu/host-utils.h>
#include <dm/whpx/apic.h>
#include <dm/whpx/ioapic.h>
#include <dm/timer.h>
#include <dm/debug.h>

/* APIC Local Vector Table */
#define APIC_LVT_TIMER   0
#define APIC_LVT_THERMAL 1
#define APIC_LVT_PERFORM 2
#define APIC_LVT_LINT0   3
#define APIC_LVT_LINT1   4
#define APIC_LVT_ERROR   5
#define APIC_LVT_NB      6

/* APIC delivery modes */
#define APIC_DM_FIXED	0
#define APIC_DM_LOWPRI	1
#define APIC_DM_SMI	2
#define APIC_DM_NMI	4
#define APIC_DM_INIT	5
#define APIC_DM_SIPI	6
#define APIC_DM_EXTINT	7

/* APIC destination mode */
#define APIC_DESTMODE_FLAT	0xf
#define APIC_DESTMODE_CLUSTER	1

#define APIC_TRIGGER_EDGE  0
#define APIC_TRIGGER_LEVEL 1

#define	APIC_LVT_TIMER_PERIODIC		(1<<17)
#define	APIC_LVT_MASKED			(1<<16)
#define	APIC_LVT_LEVEL_TRIGGER		(1<<15)
#define	APIC_LVT_REMOTE_IRR		(1<<14)
#define	APIC_INPUT_POLARITY		(1<<13)
#define	APIC_SEND_PENDING		(1<<12)

#define ESR_ILLEGAL_ADDRESS (1 << 7)

#define APIC_SV_DIRECTED_IO             (1<<12)
#define APIC_SV_ENABLE                  (1<<8)

#define MAX_APICS 255
#define MAX_APIC_WORDS 8

/* Intel APIC constants: from include/asm/msidef.h */
#define MSI_DATA_VECTOR_SHIFT		0
#define MSI_DATA_VECTOR_MASK		0x000000ff
#define MSI_DATA_DELIVERY_MODE_SHIFT	8
#define MSI_DATA_TRIGGER_SHIFT		15
#define MSI_DATA_LEVEL_SHIFT		14
#define MSI_ADDR_DEST_MODE_SHIFT	2
#define MSI_ADDR_DEST_ID_SHIFT		12
#define	MSI_ADDR_DEST_ID_MASK		0x00ffff0

#define MSI_ADDR_SIZE                   0x100000

typedef struct APICState APICState;

struct APICState {
    SysBusDevice busdev;
    MemoryRegion io_memory;
    void *cpu_env;
    uint32_t apicbase;
    uint8_t id;
    uint8_t arb_id;
    uint8_t tpr;
    uint32_t spurious_vec;
    uint8_t log_dest;
    uint8_t dest_mode;
    uint32_t isr[8];  /* in service register */
    uint32_t tmr[8];  /* trigger mode register */
    uint32_t irr[8]; /* interrupt request register */
    uint32_t lvt[APIC_LVT_NB];
    uint32_t esr; /* error register */
    uint32_t icr[2];

    uint32_t divide_conf;
    int count_shift;
    uint32_t initial_count;
    int64_t initial_count_load_time, next_time;
    uint32_t idx;
    QEMUTimer *timer;
    int64_t timer_expiry;
    int sipi_vector;
    int wait_for_sipi;
};

static APICState *local_apics[MAX_APICS + 1];
static int apic_irq_delivered;

static void apic_set_irq(APICState *s, int vector_num, int trigger_mode);
static void apic_update_irq(APICState *s);
static void apic_get_delivery_bitmask(uint32_t *deliver_bitmask,
                                      uint8_t dest, uint8_t dest_mode);

bool apic_report_tpr_access = false;

void apic_enable_tpr_access_reporting(DeviceState *dev, bool enable)
{
    apic_report_tpr_access = enable;
}

/* Find first bit starting from msb */
static int apic_fls_bit(uint32_t value)
{
    return 31 - clz32(value);
}

/* Find first bit starting from lsb */
static int apic_ffs_bit(uint32_t value)
{
    return ctz32(value);
}

static inline void apic_reset_bit(uint32_t *tab, int index)
{
    int i, mask;
    i = index >> 5;
    mask = 1 << (index & 0x1f);
    tab[i] &= ~mask;
}

static inline void apic_set_bit(uint32_t *tab, int index)
{
    int i, mask;
    i = index >> 5;
    mask = 1 << (index & 0x1f);
    tab[i] |= mask;
}


static inline int apic_get_bit(uint32_t *tab, int index)
{
    int i, mask;
    i = index >> 5;
    mask = 1 << (index & 0x1f);
    return !!(tab[i] & mask);
}

/* return -1 if no bit is set */
static int get_highest_priority_int(uint32_t *tab)
{
    int i;
    for (i = 7; i >= 0; i--) {
        if (tab[i] != 0) {
            return i * 32 + apic_fls_bit(tab[i]);
        }
    }
    return -1;
}

static void apic_local_deliver(APICState *s, int vector)
{
    uint32_t lvt = s->lvt[vector];
    int trigger_mode;

#ifndef QEMU_UXEN
    trace_apic_local_deliver(vector, (lvt >> 8) & 7);
#endif

    if (lvt & APIC_LVT_MASKED)
        return;

    switch ((lvt >> 8) & 7) {
    case APIC_DM_SMI:
        cpu_interrupt(s->cpu_env, CPU_INTERRUPT_SMI);
        break;

    case APIC_DM_NMI:
        cpu_interrupt(s->cpu_env, CPU_INTERRUPT_NMI);
        break;

    case APIC_DM_EXTINT:
        cpu_interrupt(s->cpu_env, CPU_INTERRUPT_HARD);
        break;

    case APIC_DM_FIXED:
        trigger_mode = APIC_TRIGGER_EDGE;
        if ((vector == APIC_LVT_LINT0 || vector == APIC_LVT_LINT1) &&
            (lvt & APIC_LVT_LEVEL_TRIGGER))
            trigger_mode = APIC_TRIGGER_LEVEL;
        apic_set_irq(s, lvt & 0xff, trigger_mode);
    }
}

void apic_deliver_pic_intr(DeviceState *d, int level)
{
    APICState *s = DO_UPCAST(APICState, busdev.qdev, d);

    if (level) {
        apic_local_deliver(s, APIC_LVT_LINT0);
    } else {
        uint32_t lvt = s->lvt[APIC_LVT_LINT0];

        switch ((lvt >> 8) & 7) {
        case APIC_DM_FIXED:
            if (!(lvt & APIC_LVT_LEVEL_TRIGGER))
                break;
            apic_reset_bit(s->irr, lvt & 0xff);
            /* fall through */
        case APIC_DM_EXTINT:
            apic_update_irq(s);
            break;
        }
    }
}

#ifndef QEMU_UXEN
static void apic_external_nmi(APICState *s)
{
    apic_local_deliver(s, APIC_LVT_LINT1);
}
#endif

#define foreach_apic(apic, deliver_bitmask, code) \
{\
    int __i, __j, __mask;\
    for(__i = 0; __i < MAX_APIC_WORDS; __i++) {\
        __mask = deliver_bitmask[__i];\
        if (__mask) {\
            for(__j = 0; __j < 32; __j++) {\
                if (__mask & (1 << __j)) {\
                    apic = local_apics[__i * 32 + __j];\
                    if (apic) {\
                        code;\
                    }\
                }\
            }\
        }\
    }\
}

static void apic_bus_deliver(const uint32_t *deliver_bitmask,
                             uint8_t delivery_mode, uint8_t vector_num,
                             uint8_t trigger_mode)
{
    APICState *apic_iter;

    switch (delivery_mode) {
        case APIC_DM_LOWPRI:
            /* XXX: search for focus processor, arbitration */
            {
                int i, d;
                d = -1;
                for(i = 0; i < MAX_APIC_WORDS; i++) {
                    if (deliver_bitmask[i]) {
                        d = i * 32 + apic_ffs_bit(deliver_bitmask[i]);
                        break;
                    }
                }
                if (d >= 0) {
                    apic_iter = local_apics[d];
                    if (apic_iter) {
                        apic_set_irq(apic_iter, vector_num, trigger_mode);
                    }
                }
            }
            return;

        case APIC_DM_FIXED:
            break;

        case APIC_DM_SMI:
            foreach_apic(apic_iter, deliver_bitmask,
                cpu_interrupt(apic_iter->cpu_env, CPU_INTERRUPT_SMI) );
            return;

        case APIC_DM_NMI:
            foreach_apic(apic_iter, deliver_bitmask,
                cpu_interrupt(apic_iter->cpu_env, CPU_INTERRUPT_NMI) );
            return;

        case APIC_DM_INIT:
            /* normal INIT IPI sent to processors */
            foreach_apic(apic_iter, deliver_bitmask,
                         cpu_interrupt(apic_iter->cpu_env, CPU_INTERRUPT_INIT) );
            return;

        case APIC_DM_EXTINT:
            /* handled in I/O APIC code */
            break;

        default:
            return;
    }

    foreach_apic(apic_iter, deliver_bitmask,
                 apic_set_irq(apic_iter, vector_num, trigger_mode) );
}

void apic_deliver_irq(uint8_t dest, uint8_t dest_mode, uint8_t delivery_mode,
                      uint8_t vector_num, uint8_t trigger_mode)
{
    uint32_t deliver_bitmask[MAX_APIC_WORDS];

#ifndef QEMU_UXEN
    trace_apic_deliver_irq(dest, dest_mode, delivery_mode, vector_num,
                           trigger_mode);
#endif

    apic_get_delivery_bitmask(deliver_bitmask, dest, dest_mode);
    apic_bus_deliver(deliver_bitmask, delivery_mode, vector_num, trigger_mode);
}

void cpu_set_apic_base(DeviceState *d, uint64_t val)
{
    APICState *s = DO_UPCAST(APICState, busdev.qdev, d);

    s->apicbase = (val & 0xfffff000) |
        (s->apicbase & (MSR_IA32_APICBASE_BSP | MSR_IA32_APICBASE_ENABLE));
    /* if disabled, cannot be enabled again */
    if (!(val & MSR_IA32_APICBASE_ENABLE)) {
#ifdef QEMU_UXEN
      errx(1, "%s:%d: not supported\n", __FUNCTION__, __LINE__);
#else
        s->apicbase &= ~MSR_IA32_APICBASE_ENABLE;
        cpu_clear_apic_feature(&s->cpu->env);
        s->spurious_vec &= ~APIC_SV_ENABLE;
#endif
    }
}

uint64_t cpu_get_apic_base(DeviceState *d)
{
    APICState *s = DO_UPCAST(APICState, busdev.qdev, d);

#ifndef QEMU_UXEN
    trace_cpu_get_apic_base(s ? (uint64_t)s->apicbase: 0);
#endif

    return s ? s->apicbase : 0;
}

void cpu_set_apic_tpr(DeviceState *d, uint8_t val)
{
    APICState *s = DO_UPCAST(APICState, busdev.qdev, d);

    if (!s)
        return;
    s->tpr = (val & 0xf) << 4;
    apic_update_irq(s);
}

int apic_get_highest_priority_irr(DeviceState *dev)
{
    if (!dev) {
        /* no interrupts */
        return -1;
    }
    APICState *s = DO_UPCAST(APICState, busdev.qdev, dev);
    return get_highest_priority_int(s->irr);
}

uint8_t cpu_get_apic_tpr(DeviceState *d)
{
    APICState *s = DO_UPCAST(APICState, busdev.qdev, d);

    return s ? s->tpr >> 4 : 0;
}

static int apic_get_ppr(APICState *s)
{
    int tpr, isrv, ppr;

    tpr = (s->tpr >> 4);
    isrv = get_highest_priority_int(s->isr);
    if (isrv < 0)
        isrv = 0;
    isrv >>= 4;
    if (tpr >= isrv)
        ppr = s->tpr;
    else
        ppr = isrv << 4;
    return ppr;
}

static int apic_get_arb_pri(APICState *s)
{
    /* XXX: arbitration */
    return 0;
}


/*
 * <0 - low prio interrupt,
 * 0  - no interrupt,
 * >0 - interrupt number
 */
static int apic_irq_pending(APICState *s)
{
    int irrv, ppr;

    if (!(s->spurious_vec & APIC_SV_ENABLE)) {
        return 0;
    }

    irrv = get_highest_priority_int(s->irr);
    if (irrv < 0) {
        return 0;
    }
    ppr = apic_get_ppr(s);
    if (ppr && (irrv & 0xf0) <= (ppr & 0xf0)) {
        return -1;
    }

    return irrv;
}

/* signal the CPU if an irq is pending */
static void apic_update_irq(APICState *s)
{
    if (!qemu_cpu_is_self(s->cpu_env)) {
        cpu_interrupt(s->cpu_env, CPU_INTERRUPT_POLL);
    } else if (apic_irq_pending(s) > 0) {
        cpu_interrupt(s->cpu_env, CPU_INTERRUPT_HARD);
    } else if (!apic_accept_pic_intr(&s->busdev.qdev) || !pic_get_output(isa_pic)) {
        cpu_reset_interrupt(s->cpu_env, CPU_INTERRUPT_HARD);
    }
}

void apic_poll_irq(DeviceState *dev)
{
    APICState *s = DO_UPCAST(APICState, busdev.qdev, dev);

    apic_update_irq(s);
}

void apic_reset_irq_delivered(void)
{
#ifndef QEMU_UXEN
    trace_apic_reset_irq_delivered(apic_irq_delivered);
#endif

    apic_irq_delivered = 0;
}

int apic_get_irq_delivered(void)
{
#ifndef QEMU_UXEN
    trace_apic_get_irq_delivered(apic_irq_delivered);
#endif

    return apic_irq_delivered;
}

static void apic_set_irq(APICState *s, int vector_num, int trigger_mode)
{
    apic_irq_delivered += !apic_get_bit(s->irr, vector_num);

#ifndef QEMU_UXEN
    trace_apic_set_irq(apic_irq_delivered);
#endif

    apic_set_bit(s->irr, vector_num);
    if (trigger_mode)
        apic_set_bit(s->tmr, vector_num);
    else
        apic_reset_bit(s->tmr, vector_num);
    apic_update_irq(s);
}

static void apic_eoi(APICState *s)
{
    int isrv;
    isrv = get_highest_priority_int(s->isr);
    if (isrv < 0)
        return;
    apic_reset_bit(s->isr, isrv);
    if (!(s->spurious_vec & APIC_SV_DIRECTED_IO) && apic_get_bit(s->tmr, isrv)) {
        ioapic_eoi_broadcast(isrv);
    }
    apic_update_irq(s);
}

static int apic_find_dest(uint8_t dest)
{
    APICState *apic = local_apics[dest];
    int i;

    if (apic && apic->id == dest)
        return dest;  /* shortcut in case apic->id == apic->idx */

    for (i = 0; i < MAX_APICS; i++) {
        apic = local_apics[i];
	if (apic && apic->id == dest)
            return i;
        if (!apic)
            break;
    }

    return -1;
}

static void apic_get_delivery_bitmask(uint32_t *deliver_bitmask,
                                      uint8_t dest, uint8_t dest_mode)
{
    APICState *apic_iter;
    int i;

    if (dest_mode == 0) {
        if (dest == 0xff) {
            memset(deliver_bitmask, 0xff, MAX_APIC_WORDS * sizeof(uint32_t));
        } else {
            int idx = apic_find_dest(dest);
            memset(deliver_bitmask, 0x00, MAX_APIC_WORDS * sizeof(uint32_t));
            if (idx >= 0)
                apic_set_bit(deliver_bitmask, idx);
        }
    } else {
        /* XXX: cluster mode */
        memset(deliver_bitmask, 0x00, MAX_APIC_WORDS * sizeof(uint32_t));
        for(i = 0; i < MAX_APICS; i++) {
            apic_iter = local_apics[i];
            if (apic_iter) {
                if (apic_iter->dest_mode == 0xf) {
                    if (dest & apic_iter->log_dest)
                        apic_set_bit(deliver_bitmask, i);
                } else if (apic_iter->dest_mode == 0x0) {
                    if ((dest & 0xf0) == (apic_iter->log_dest & 0xf0) &&
                        (dest & apic_iter->log_dest & 0x0f)) {
                        apic_set_bit(deliver_bitmask, i);
                    }
                }
            } else {
                break;
            }
        }
    }
}

static void apic_startup(APICState *s, int vector_num)
{
    s->sipi_vector = vector_num;
    cpu_interrupt(s->cpu_env, CPU_INTERRUPT_SIPI);
}

void apic_sipi(DeviceState *d)
{
    APICState *s = DO_UPCAST(APICState, busdev.qdev, d);

    cpu_reset_interrupt(s->cpu_env, CPU_INTERRUPT_SIPI);

    if (!s->wait_for_sipi)
        return;
    cpu_x86_load_seg_cache_sipi(s->cpu_env, s->sipi_vector);
    s->wait_for_sipi = 0;
}

static void apic_deliver(DeviceState *d, uint8_t dest, uint8_t dest_mode,
                         uint8_t delivery_mode, uint8_t vector_num,
                         uint8_t trigger_mode)
{
    APICState *s = DO_UPCAST(APICState, busdev.qdev, d);
    uint32_t deliver_bitmask[MAX_APIC_WORDS];
    int dest_shorthand = (s->icr[0] >> 18) & 3;
    APICState *apic_iter;
    int idx;

    switch (dest_shorthand) {
    case 0:
        apic_get_delivery_bitmask(deliver_bitmask, dest, dest_mode);
        break;
    case 1:
        memset(deliver_bitmask, 0x00, sizeof(deliver_bitmask));
        /* upstream bugged when s->id != vcpu_id */
#ifndef QEMU_UXEN
        apic_set_bit(deliver_bitmask, s->id);
#else
        idx = apic_find_dest(s->id);
        if (idx >= 0)
            apic_set_bit(deliver_bitmask, idx);
#endif
        break;
    case 2:
        memset(deliver_bitmask, 0xff, sizeof(deliver_bitmask));
        break;
    case 3:
        memset(deliver_bitmask, 0xff, sizeof(deliver_bitmask));
        /* upstream bugged when s->id != vcpu_id */
#ifndef QEMU_UXEN
        apic_reset_bit(deliver_bitmask, s->id);
#else
        idx = apic_find_dest(s->id);
        if (idx >= 0)
            apic_reset_bit(deliver_bitmask, idx);
#endif
        break;
    }

    switch (delivery_mode) {
        case APIC_DM_INIT:
            {
                int trig_mode = (s->icr[0] >> 15) & 1;
                int level = (s->icr[0] >> 14) & 1;
                if (level == 0 && trig_mode == 1) {
                    foreach_apic(apic_iter, deliver_bitmask,
                                 apic_iter->arb_id = apic_iter->id );
                    return;
                }
            }
            break;

        case APIC_DM_SIPI:
            foreach_apic(apic_iter, deliver_bitmask,
                         apic_startup(apic_iter, vector_num) );
            return;
    }

    apic_bus_deliver(deliver_bitmask, delivery_mode, vector_num, trigger_mode);
}

static bool apic_check_pic(APICState *s)
{
    if (!apic_accept_pic_intr(&s->busdev.qdev) || !pic_get_output(isa_pic)) {
        return false;
    }
    apic_deliver_pic_intr(&s->busdev.qdev, 1);
    return true;
}

int apic_get_interrupt(DeviceState *d)
{
    APICState *s = DO_UPCAST(APICState, busdev.qdev, d);
    int intno;

    /* if the APIC is installed or enabled, we let the 8259 handle the
       IRQs */
    if (!s)
        return -1;
    if (!(s->spurious_vec & APIC_SV_ENABLE))
        return -1;

    intno = apic_irq_pending(s);

    /* if there is an interrupt from the 8259, let the caller handle
     * that first since ExtINT interrupts ignore the priority.
     */
    if (intno == 0 || apic_check_pic(s)) {
        return -1;
    } else if (intno < 0) {
        return s->spurious_vec & 0xff;
    }
    apic_reset_bit(s->irr, intno);
    apic_set_bit(s->isr, intno);

    apic_update_irq(s);

    return intno;
}

int apic_accept_pic_intr(DeviceState *d)
{
    APICState *s = DO_UPCAST(APICState, busdev.qdev, d);
    uint32_t lvt0;

    if (!s)
        return -1;

    lvt0 = s->lvt[APIC_LVT_LINT0];

    if ((s->apicbase & MSR_IA32_APICBASE_ENABLE) == 0 ||
        (lvt0 & APIC_LVT_MASKED) == 0)
        return 1;

    return 0;
}

static uint32_t apic_get_current_count(APICState *s)
{
    int64_t d;
    uint32_t val;
    d = (qemu_get_clock_ns(vm_clock) - s->initial_count_load_time) >>
        s->count_shift;
    if (s->lvt[APIC_LVT_TIMER] & APIC_LVT_TIMER_PERIODIC) {
        /* periodic */
        val = s->initial_count - (d % ((uint64_t)s->initial_count + 1));
    } else {
        if (d >= s->initial_count)
            val = 0;
        else
            val = s->initial_count - d;
    }
    return val;
}

bool apic_next_timer(APICState *s, int64_t current_time)
{
    int64_t d;

    /* We need to store the timer state separately to support APIC
     * implementations that maintain a non-QEMU timer, e.g. inside the
     * host kernel. This open-coded state allows us to migrate between
     * both models. */
    s->timer_expiry = -1;

    if (s->lvt[APIC_LVT_TIMER] & APIC_LVT_MASKED) {
        return false;
    }

    d = (current_time - s->initial_count_load_time) >> s->count_shift;

    if (s->lvt[APIC_LVT_TIMER] & APIC_LVT_TIMER_PERIODIC) {
        if (!s->initial_count) {
            return false;
        }
        d = ((d / ((uint64_t)s->initial_count + 1)) + 1) *
            ((uint64_t)s->initial_count + 1);
    } else {
        if (d >= s->initial_count) {
            return false;
        }
        d = (uint64_t)s->initial_count + 1;
    }
    s->next_time = s->initial_count_load_time + (d << s->count_shift);
    s->timer_expiry = s->next_time;
    return true;
}

static void apic_timer_update(APICState *s, int64_t current_time)
{
    if (apic_next_timer(s, current_time)) {
        qemu_mod_timer(s->timer, s->next_time);
    } else {
        qemu_del_timer(s->timer);
    }
}

static void apic_timer(void *opaque)
{
    APICState *s = opaque;

    apic_local_deliver(s, APIC_LVT_TIMER);
    apic_timer_update(s, s->next_time);
}

static uint32_t apic_mem_readb(void *opaque, target_phys_addr_t addr)
{
    return 0;
}

static uint32_t apic_mem_readw(void *opaque, target_phys_addr_t addr)
{
    return 0;
}

static void apic_mem_writeb(void *opaque, target_phys_addr_t addr, uint32_t val)
{
}

static void apic_mem_writew(void *opaque, target_phys_addr_t addr, uint32_t val)
{
}

static uint32_t apic_mem_readl(void *opaque, target_phys_addr_t addr)
{
    DeviceState *d;
    APICState *s;
    uint32_t val;
    int index;

    d = cpu_get_current_apic();
    if (!d) {
        return 0;
    }
    s = DO_UPCAST(APICState, busdev.qdev, d);

    index = (addr >> 4) & 0xff;
    switch(index) {
    case 0x02: /* id */
        val = s->id << 24;
        break;
    case 0x03: /* version */
        val = 0x11 | ((APIC_LVT_NB - 1) << 16); /* version 0x11 */
        break;
    case 0x08:
        if (apic_report_tpr_access) {
#ifndef QEMU_UXEN
            cpu_report_tpr_access(s->cpu_env, TPR_ACCESS_READ);
#endif
        }
        val = s->tpr;
        break;
    case 0x09:
        val = apic_get_arb_pri(s);
        break;
    case 0x0a:
        /* ppr */
        val = apic_get_ppr(s);
        break;
    case 0x0b:
        val = 0;
        break;
    case 0x0d:
        val = s->log_dest << 24;
        break;
    case 0x0e:
        val = (s->dest_mode << 28) | 0xfffffff;
        break;
    case 0x0f:
        val = s->spurious_vec;
        break;
    case 0x10 ... 0x17:
        val = s->isr[index & 7];
        break;
    case 0x18 ... 0x1f:
        val = s->tmr[index & 7];
        break;
    case 0x20 ... 0x27:
        val = s->irr[index & 7];
        break;
    case 0x28:
        val = s->esr;
        break;
    case 0x30:
    case 0x31:
        val = s->icr[index & 1];
        break;
    case 0x32 ... 0x37:
        val = s->lvt[index - 0x32];
        break;
    case 0x38:
        val = s->initial_count;
        break;
    case 0x39:
        val = apic_get_current_count(s);
        break;
    case 0x3e:
        val = s->divide_conf;
        break;
    default:
        s->esr |= ESR_ILLEGAL_ADDRESS;
        val = 0;
        break;
    }
#ifndef QEMU_UXEN
    trace_apic_mem_readl(addr, val);
#endif

    return val;
}

static void apic_send_msi(target_phys_addr_t addr, uint32_t data)
{
    uint8_t dest = (addr & MSI_ADDR_DEST_ID_MASK) >> MSI_ADDR_DEST_ID_SHIFT;
    uint8_t vector = (data & MSI_DATA_VECTOR_MASK) >> MSI_DATA_VECTOR_SHIFT;
    uint8_t dest_mode = (addr >> MSI_ADDR_DEST_MODE_SHIFT) & 0x1;
    uint8_t trigger_mode = (data >> MSI_DATA_TRIGGER_SHIFT) & 0x1;
    uint8_t delivery = (data >> MSI_DATA_DELIVERY_MODE_SHIFT) & 0x7;
    /* XXX: Ignore redirection hint. */
    apic_deliver_irq(dest, dest_mode, delivery, vector, trigger_mode);
}

static void apic_mem_writel(void *opaque, target_phys_addr_t addr, uint32_t val)
{
    DeviceState *d;
    APICState *s;
    int index = (addr >> 4) & 0xff;
    if (addr > 0xfff || !index) {
        /* MSI and MMIO APIC are at the same memory location,
         * but actually not on the global bus: MSI is on PCI bus
         * APIC is connected directly to the CPU.
         * Mapping them on the global bus happens to work because
         * MSI registers are reserved in APIC MMIO and vice versa. */
        apic_send_msi(addr, val);
        return;
    }

    d = cpu_get_current_apic();
    if (!d) {
        return;
    }
    s = DO_UPCAST(APICState, busdev.qdev, d);

#ifndef QEMU_UXEN
    trace_apic_mem_writel(addr, val);
#endif

    switch(index) {
    case 0x02:
        s->id = (val >> 24);
        break;
    case 0x03:
        break;
    case 0x08:
        if (apic_report_tpr_access) {
#ifndef QEMU_UXEN
            cpu_report_tpr_access(s->cpu_env, TPR_ACCESS_WRITE);
#endif
        }
        s->tpr = val;
        apic_update_irq(s);
        break;
    case 0x09:
    case 0x0a:
        break;
    case 0x0b: /* EOI */
        apic_eoi(s);
        break;
    case 0x0d:
        s->log_dest = val >> 24;
        break;
    case 0x0e:
        s->dest_mode = val >> 28;
        break;
    case 0x0f:
        s->spurious_vec = val & 0x1ff;
        apic_update_irq(s);
        break;
    case 0x10 ... 0x17:
    case 0x18 ... 0x1f:
    case 0x20 ... 0x27:
    case 0x28:
        break;
    case 0x30:
        s->icr[0] = val;
        apic_deliver(d, (s->icr[1] >> 24) & 0xff, (s->icr[0] >> 11) & 1,
                     (s->icr[0] >> 8) & 7, (s->icr[0] & 0xff),
                     (s->icr[0] >> 15) & 1);
        break;
    case 0x31:
        s->icr[1] = val;
        break;
    case 0x32 ... 0x37:
        {
            int n = index - 0x32;
            s->lvt[n] = val;
            if (n == APIC_LVT_TIMER) {
                apic_timer_update(s, qemu_get_clock_ns(vm_clock));
            } else if (n == APIC_LVT_LINT0 && apic_check_pic(s)) {
                apic_update_irq(s);
            }
        }
        break;
    case 0x38:
        s->initial_count = val;
        s->initial_count_load_time = qemu_get_clock_ns(vm_clock);
        apic_timer_update(s, s->initial_count_load_time);
        break;
    case 0x39:
        break;
    case 0x3e:
        {
            int v;
            s->divide_conf = val & 0xb;
            v = (s->divide_conf & 3) | ((s->divide_conf >> 1) & 4);
            s->count_shift = (v + 1) & 7;
        }
        break;
    default:
        s->esr |= ESR_ILLEGAL_ADDRESS;
        break;
    }
}

static int apic_post_load(void *opaque, int version_id)
{
    APICState *s = opaque;

    if (s->timer_expiry != -1) {
        qemu_mod_timer(s->timer, s->timer_expiry);
    } else {
        qemu_del_timer(s->timer);
    }

    return 0;
}

static const VMStateDescription vmstate_apic = {
    .name = "apic",
    .version_id = 3,
    .minimum_version_id = 3,
    .minimum_version_id_old = 1,
    .post_load = apic_post_load,
    .fields      = (VMStateField []) {
        VMSTATE_UINT32(apicbase, APICState),
        VMSTATE_UINT8(id, APICState),
        VMSTATE_UINT8(arb_id, APICState),
        VMSTATE_UINT8(tpr, APICState),
        VMSTATE_UINT32(spurious_vec, APICState),
        VMSTATE_UINT8(log_dest, APICState),
        VMSTATE_UINT8(dest_mode, APICState),
        VMSTATE_UINT32_ARRAY(isr, APICState, 8),
        VMSTATE_UINT32_ARRAY(tmr, APICState, 8),
        VMSTATE_UINT32_ARRAY(irr, APICState, 8),
        VMSTATE_UINT32_ARRAY(lvt, APICState, APIC_LVT_NB),
        VMSTATE_UINT32(esr, APICState),
        VMSTATE_UINT32_ARRAY(icr, APICState, 2),
        VMSTATE_UINT32(divide_conf, APICState),
        VMSTATE_INT32(count_shift, APICState),
        VMSTATE_UINT32(initial_count, APICState),
        VMSTATE_INT64(initial_count_load_time, APICState),
        VMSTATE_INT64(next_time, APICState),
        VMSTATE_TIMER(timer, APICState),
        VMSTATE_INT64(timer_expiry, APICState),
        VMSTATE_END_OF_LIST()
    }
};

void apic_init_reset(DeviceState *d)
{
    APICState *s = DO_UPCAST(APICState, busdev.qdev, d);
    int i;

    if (!s)
        return;

    s->tpr = 0;
    s->spurious_vec = 0xff;
    s->log_dest = 0;
    s->dest_mode = 0xf;
    memset(s->isr, 0, sizeof(s->isr));
    memset(s->tmr, 0, sizeof(s->tmr));
    memset(s->irr, 0, sizeof(s->irr));
    for(i = 0; i < APIC_LVT_NB; i++)
        s->lvt[i] = 1 << 16; /* mask LVT */
    s->esr = 0;
    memset(s->icr, 0, sizeof(s->icr));
    s->divide_conf = 0;
    s->count_shift = 0;
    s->initial_count = 0;
    s->initial_count_load_time = 0;
    s->next_time = 0;
    s->wait_for_sipi = 1;
    s->timer_expiry = -1;
}


static void apic_reset(DeviceState *d)
{
    APICState *s = DO_UPCAST(APICState, busdev.qdev, d);
    int bsp;

    bsp = cpu_is_bsp(s->cpu_env);
    s->apicbase = 0xfee00000 |
        (bsp ? MSR_IA32_APICBASE_BSP : 0) | MSR_IA32_APICBASE_ENABLE;

    apic_init_reset(d);

    if (bsp) {
        /*
         * LINT0 delivery mode on CPU #0 is set to ExtInt at initialization
         * time typically by BIOS, so PIC interrupt can be delivered to the
         * processor when local APIC is enabled.
         */
        s->lvt[APIC_LVT_LINT0] = 0x700;
    }
}

static uint64_t apic_mem_read(void *opaque, target_phys_addr_t addr,
                                unsigned size)
{
  switch (size) {
  case 1: return apic_mem_readb(opaque, addr);
  case 2: return apic_mem_readw(opaque, addr);
  case 4: return apic_mem_readl(opaque, addr);
  default: assert(0); return 0;
  }
}

static void apic_mem_write(void *opaque, target_phys_addr_t addr,
                             uint64_t val, unsigned size)
{
  switch (size) {
  case 1: apic_mem_writeb(opaque, addr, val); break;
  case 2: apic_mem_writew(opaque, addr, val); break;
  case 4: apic_mem_writel(opaque, addr, val); break;
  default: assert(0); break;
  }
}

static const MemoryRegionOps apic_io_ops = {
    .read = apic_mem_read,
    .write = apic_mem_write
};

static void
mmio_ptr_update(void *ptr, void *opaque)
{
}

static int apic_init1(SysBusDevice *dev)
{
    APICState *s = FROM_SYSBUS(APICState, dev);
    static int last_apic_idx;

    if (last_apic_idx >= MAX_APICS) {
        return -1;
    }
    memory_region_init_io(&s->io_memory, &apic_io_ops, s, "apic",
                          MSI_ADDR_SIZE);
    memory_region_add_ram_range(&s->io_memory, 0, MSI_ADDR_SIZE,
                                mmio_ptr_update, s);
    memory_region_add_subregion(system_iomem, 0xfee00000, &s->io_memory);
#ifndef QEMU_UXEN
    sysbus_init_mmio_region(dev, &s->io_memory);
#endif
    s->timer = qemu_new_timer_ns(vm_clock, apic_timer, s);
    s->idx = last_apic_idx++;
    local_apics[s->idx] = s;
    return 0;
}

static SysBusDeviceInfo apic_info = {
    .init = apic_init1,
    .qdev.name = "apic",
    .qdev.size = sizeof(APICState),
    .qdev.vmsd = &vmstate_apic,
    .qdev.reset = apic_reset,
    .qdev.props = (Property[]) {
        DEFINE_PROP_UINT8("id", APICState, id, -1),
#ifndef QEMU_UXEN
        DEFINE_PROP_PTR("cpu_env", APICState, cpu_env),
#endif
        DEFINE_PROP_END_OF_LIST(),
    }
};

static void apic_register_devices(void)
{
    sysbus_register_withprop(&apic_info);
}

void apic_init(CPUState *env)
{
    APICState *s;
    DeviceState *dev = qdev_create(NULL, "apic");
    assert(dev);
    s = DO_UPCAST(APICState, busdev.qdev, dev);
    s->id = WHPX_LAPIC_ID(env->cpu_index);
    s->cpu_env = env;
    env->apic_state = dev;
    qdev_init_nofail(dev);
}

device_init(apic_register_devices)
