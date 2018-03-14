/*
 * QEMU 8253/8254 interval timer emulation
 *
 * Copyright (c) 2003-2004 Fabrice Bellard
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
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
#include <dm/qemu/hw/isa.h>
#include <dm/mr.h>
#include <dm/qemu/hw/sysbus.h>

//#define DEBUG_PIT

#define PIT_FREQ 1193182

#define RW_STATE_LSB 1
#define RW_STATE_MSB 2
#define RW_STATE_WORD0 3
#define RW_STATE_WORD1 4

typedef struct PITChannelState {
    int count; /* can be 65536 */
    uint16_t latched_count;
    uint8_t count_latched;
    uint8_t status_latched;
    uint8_t status;
    uint8_t read_state;
    uint8_t write_state;
    uint8_t write_latch;
    uint8_t rw_mode;
    uint8_t mode;
    uint8_t bcd; /* not supported */
    uint8_t gate; /* timer start */
    int64_t count_load_time;
    /* irq handling */
    int64_t next_transition_time;
    QEMUTimer *irq_timer;
    qemu_irq irq;
} PITChannelState;

typedef struct PITState {
    SysBusDevice dev;
    MemoryRegion ioports;
    uint32_t irq;
    uint32_t iobase;
    uint32_t dummy_refresh_clock;
    uint32_t speaker_data_on;
    PITChannelState channels[3];
} PITState;

static PITState pit_state;

static void pit_irq_timer_update(PITChannelState *s, int64_t current_time);

static int pit_get_count(PITChannelState *s)
{
    uint64_t d;
    int counter;

    d = muldiv64(qemu_get_clock_ns(vm_clock) - s->count_load_time, PIT_FREQ,
                 get_ticks_per_sec());
    switch(s->mode) {
    case 0:
    case 1:
    case 4:
    case 5:
        counter = (s->count - d) & 0xffff;
        break;
    case 3:
        /* XXX: may be incorrect for odd counts */
        counter = s->count - ((2 * d) % s->count);
        break;
    default:
        counter = s->count - (d % s->count);
        break;
    }
    return counter;
}

/* get pit output bit */
static int pit_get_out1(PITChannelState *s, int64_t current_time)
{
    uint64_t d;
    int out;

    d = muldiv64(current_time - s->count_load_time, PIT_FREQ,
                 get_ticks_per_sec());
    switch(s->mode) {
    default:
    case 0:
        out = (d >= s->count);
        break;
    case 1:
        out = (d < s->count);
        break;
    case 2:
        if ((d % s->count) == 0 && d != 0)
            out = 1;
        else
            out = 0;
        break;
    case 3:
        out = (d % s->count) < ((s->count + 1) >> 1);
        break;
    case 4:
    case 5:
        out = (d == s->count);
        break;
    }
    return out;
}

int pit_get_out(SysBusDevice *dev, int channel, int64_t current_time)
{
    PITState *pit = DO_UPCAST(PITState, dev, dev);
    PITChannelState *s = &pit->channels[channel];
    return pit_get_out1(s, current_time);
}

/* return -1 if no transition will occur.  */
static int64_t pit_get_next_transition_time(PITChannelState *s,
                                            int64_t current_time)
{
    uint64_t d, next_time, base;
    int period2;

    d = muldiv64(current_time - s->count_load_time, PIT_FREQ,
                 get_ticks_per_sec());
    switch(s->mode) {
    default:
    case 0:
    case 1:
        if (d < s->count)
            next_time = s->count;
        else
            return -1;
        break;
    case 2:
        base = (d / s->count) * s->count;
        if ((d - base) == 0 && d != 0)
            next_time = base + s->count;
        else
            next_time = base + s->count + 1;
        break;
    case 3:
        base = (d / s->count) * s->count;
        period2 = ((s->count + 1) >> 1);
        if ((d - base) < period2)
            next_time = base + period2;
        else
            next_time = base + s->count;
        break;
    case 4:
    case 5:
        if (d < s->count)
            next_time = s->count;
        else if (d == s->count)
            next_time = s->count + 1;
        else
            return -1;
        break;
    }
    /* convert to timer units */
    next_time = s->count_load_time + muldiv64(next_time, get_ticks_per_sec(),
                                              PIT_FREQ);
    /* fix potential rounding problems */
    /* XXX: better solution: use a clock at PIT_FREQ Hz */
    if (next_time <= current_time)
        next_time = current_time + 1;
    return next_time;
}

/* val must be 0 or 1 */
void pit_set_gate(SysBusDevice *dev, int channel, int val)
{
    PITState *pit = DO_UPCAST(PITState, dev, dev);
    PITChannelState *s = &pit->channels[channel];

    switch(s->mode) {
    default:
    case 0:
    case 4:
        /* XXX: just disable/enable counting */
        break;
    case 1:
    case 5:
        if (s->gate < val) {
            /* restart counting on rising edge */
            s->count_load_time = qemu_get_clock_ns(vm_clock);
            pit_irq_timer_update(s, s->count_load_time);
        }
        break;
    case 2:
    case 3:
        if (s->gate < val) {
            /* restart counting on rising edge */
            s->count_load_time = qemu_get_clock_ns(vm_clock);
            pit_irq_timer_update(s, s->count_load_time);
        }
        /* XXX: disable/enable counting */
        break;
    }
    s->gate = val;
}

int pit_get_gate(SysBusDevice *dev, int channel)
{
    PITState *pit = DO_UPCAST(PITState, dev, dev);
    PITChannelState *s = &pit->channels[channel];
    return s->gate;
}

int pit_get_initial_count(SysBusDevice *dev, int channel)
{
    PITState *pit = DO_UPCAST(PITState, dev, dev);
    PITChannelState *s = &pit->channels[channel];
    return s->count;
}

int pit_get_mode(SysBusDevice *dev, int channel)
{
    PITState *pit = DO_UPCAST(PITState, dev, dev);
    PITChannelState *s = &pit->channels[channel];
    return s->mode;
}

static inline void pit_load_count(PITChannelState *s, int val)
{
    if (val == 0)
        val = 0x10000;
    s->count_load_time = qemu_get_clock_ns(vm_clock);
    s->count = val;
    pit_irq_timer_update(s, s->count_load_time);
}

/* if already latched, do not latch again */
static void pit_latch_count(PITChannelState *s)
{
    if (!s->count_latched) {
        s->latched_count = pit_get_count(s);
        s->count_latched = s->rw_mode;
    }
}

static void pit_ioport_write(void *opaque, uint64_t addr, uint64_t val, unsigned size)
{
    PITState *pit = opaque;
    int channel, access;
    PITChannelState *s;

#ifdef DEBUG_PIT
    debug_printf("PIT IOPORT write @ %"PRIx64" val=0x%"PRIx64" size=%d\n",
                 addr, val, size);
#endif    
    addr &= 3;
    if (addr == 3) {
        channel = val >> 6;
        assert(channel >= 0 && channel <= 3);
        if (channel == 3) {
            /* read back command */
            for(channel = 0; channel < 3; channel++) {
                s = &pit->channels[channel];
                if (val & (2 << channel)) {
                    if (!(val & 0x20)) {
                        pit_latch_count(s);
                    }
                    if (!(val & 0x10) && !s->status_latched) {
                        /* status latch */
                        /* XXX: add BCD and null count */
                        s->status =  (pit_get_out1(s, qemu_get_clock_ns(vm_clock)) << 7) |
                            (s->rw_mode << 4) |
                            (s->mode << 1) |
                            s->bcd;
                        s->status_latched = 1;
                    }
                }
            }
        } else {
            s = &pit->channels[channel];
            access = (val >> 4) & 3;
            if (access == 0) {
                pit_latch_count(s);
            } else {
                s->rw_mode = access;
                s->read_state = access;
                s->write_state = access;

                s->mode = (val >> 1) & 7;
                s->bcd = val & 1;
                /* XXX: update irq timer ? */
            }
        }
    } else {
        s = &pit->channels[addr];
        switch(s->write_state) {
        default:
        case RW_STATE_LSB:
            pit_load_count(s, val);
            break;
        case RW_STATE_MSB:
            pit_load_count(s, val << 8);
            break;
        case RW_STATE_WORD0:
            s->write_latch = val;
            s->write_state = RW_STATE_WORD1;
            break;
        case RW_STATE_WORD1:
            pit_load_count(s, s->write_latch | (val << 8));
            s->write_state = RW_STATE_WORD0;
            break;
        }
    }
}

static uint64_t pit_ioport_read(void *opaque, uint64_t addr, unsigned size)
{
    PITState *pit = opaque;
    int ret, count;
    PITChannelState *s;

    addr &= 3;
#ifdef QEMU_UXEN
    if (addr == 3)
        return 0;
#endif
    s = &pit->channels[addr];
    if (s->status_latched) {
        s->status_latched = 0;
        ret = s->status;
    } else if (s->count_latched) {
        switch(s->count_latched) {
        default:
        case RW_STATE_LSB:
            ret = s->latched_count & 0xff;
            s->count_latched = 0;
            break;
        case RW_STATE_MSB:
            ret = s->latched_count >> 8;
            s->count_latched = 0;
            break;
        case RW_STATE_WORD0:
            ret = s->latched_count & 0xff;
            s->count_latched = RW_STATE_MSB;
            break;
        }
    } else {
        switch(s->read_state) {
        default:
        case RW_STATE_LSB:
            count = pit_get_count(s);
            ret = count & 0xff;
            break;
        case RW_STATE_MSB:
            count = pit_get_count(s);
            ret = (count >> 8) & 0xff;
            break;
        case RW_STATE_WORD0:
            count = pit_get_count(s);
            ret = count & 0xff;
            s->read_state = RW_STATE_WORD1;
            break;
        case RW_STATE_WORD1:
            count = pit_get_count(s);
            ret = (count >> 8) & 0xff;
            s->read_state = RW_STATE_WORD0;
            break;
        }
    }
#ifdef DEBUG_PIT    
    debug_printf("PIT IOPORT read @ %"PRIx64" val=0x%"PRIx64" size=%d\n",
                 addr, (uint64_t)ret, size);
#endif
    return ret;
}

static void pit_irq_timer_update(PITChannelState *s, int64_t current_time)
{
    int64_t expire_time;
    int irq_level;

    if (!s->irq_timer)
        return;
    expire_time = pit_get_next_transition_time(s, current_time);
    irq_level = pit_get_out1(s, current_time);
    qemu_set_irq(s->irq, irq_level);
#ifdef DEBUG_PIT
    debug_printf("PIT: irq_level=%d next_delay=%f\n",
           irq_level,
           (double)(expire_time - current_time) / get_ticks_per_sec());
#endif
    s->next_transition_time = expire_time;
    if (expire_time != -1)
        qemu_mod_timer(s->irq_timer, expire_time);
    else
        qemu_del_timer(s->irq_timer);
}

static void pit_irq_timer(void *opaque)
{
    PITChannelState *s = opaque;

    pit_irq_timer_update(s, s->next_transition_time);
}

static const VMStateDescription vmstate_pit_channel = {
    .name = "pit channel",
    .version_id = 2,
    .minimum_version_id = 2,
    .minimum_version_id_old = 2,
    .fields      = (VMStateField []) {
        VMSTATE_INT32(count, PITChannelState),
        VMSTATE_UINT16(latched_count, PITChannelState),
        VMSTATE_UINT8(count_latched, PITChannelState),
        VMSTATE_UINT8(status_latched, PITChannelState),
        VMSTATE_UINT8(status, PITChannelState),
        VMSTATE_UINT8(read_state, PITChannelState),
        VMSTATE_UINT8(write_state, PITChannelState),
        VMSTATE_UINT8(write_latch, PITChannelState),
        VMSTATE_UINT8(rw_mode, PITChannelState),
        VMSTATE_UINT8(mode, PITChannelState),
        VMSTATE_UINT8(bcd, PITChannelState),
        VMSTATE_UINT8(gate, PITChannelState),
        VMSTATE_INT64(count_load_time, PITChannelState),
        VMSTATE_INT64(next_transition_time, PITChannelState),
        VMSTATE_END_OF_LIST()
    }
};

#ifndef QEMU_UXEN
static int pit_load_old(QEMUFile *f, void *opaque, int version_id)
{
    PITState *pit = opaque;
    PITChannelState *s;
    int i;

    if (version_id != 1)
        return -EINVAL;

    for(i = 0; i < 3; i++) {
        s = &pit->channels[i];
        s->count=qemu_get_be32(f);
        qemu_get_be16s(f, &s->latched_count);
        qemu_get_8s(f, &s->count_latched);
        qemu_get_8s(f, &s->status_latched);
        qemu_get_8s(f, &s->status);
        qemu_get_8s(f, &s->read_state);
        qemu_get_8s(f, &s->write_state);
        qemu_get_8s(f, &s->write_latch);
        qemu_get_8s(f, &s->rw_mode);
        qemu_get_8s(f, &s->mode);
        qemu_get_8s(f, &s->bcd);
        qemu_get_8s(f, &s->gate);
        s->count_load_time=qemu_get_be64(f);
        if (s->irq_timer) {
            s->next_transition_time=qemu_get_be64(f);
            qemu_get_timer(f, s->irq_timer);
        }
    }
    return 0;
}
#endif

static const VMStateDescription vmstate_pit = {
    .name = "i8254",
    .version_id = 2,
    .minimum_version_id = 2,
    .minimum_version_id_old = 1,
#ifndef QEMU_UXEN
    .load_state_old = pit_load_old,
#endif
    .fields      = (VMStateField []) {
        VMSTATE_STRUCT_ARRAY(channels, PITState, 3, 2, vmstate_pit_channel, PITChannelState),
        VMSTATE_TIMER(channels[0].irq_timer, PITState),
        VMSTATE_UINT32(dummy_refresh_clock, PITState),
        VMSTATE_UINT32(speaker_data_on, PITState),
        VMSTATE_END_OF_LIST()
    }
};

static void pit_reset(DeviceState *dev)
{
    PITState *pit = container_of(dev, PITState, dev.qdev);
    PITChannelState *s;
    int i;

    for(i = 0;i < 3; i++) {
        s = &pit->channels[i];
        s->mode = 3;
        s->gate = (i != 2);
        pit_load_count(s, 0);
    }
}

/* When HPET is operating in legacy mode, i8254 timer0 is disabled */
void hpet_pit_disable(void) {
    PITChannelState *s;
    s = &pit_state.channels[0];
    if (s->irq_timer)
        qemu_del_timer(s->irq_timer);
}

/* When HPET is reset or leaving legacy mode, it must reenable i8254
 * timer 0
 */

void hpet_pit_enable(void)
{
    PITState *pit = &pit_state;
    PITChannelState *s;
    s = &pit->channels[0];
    s->mode = 3;
    s->gate = 1;
    pit_load_count(s, 0);
}

static const MemoryRegionOps pit_ioport_ops = {
    .read = pit_ioport_read,
    .write = pit_ioport_write,
    .impl = {
        .min_access_size = 1,
        .max_access_size = 1,
    }
};

static uint32_t pcspk_ioport_read(void *opaque, uint32_t addr)
{
    SysBusDevice *dev = (SysBusDevice*)opaque;
    PITState *pit = DO_UPCAST(PITState, dev, dev);
    int out;

    pit->dummy_refresh_clock ^= (1 << 4);
    out = pit_get_out(dev, 2, qemu_get_clock_ns(vm_clock)) << 5;

    return pit_get_gate(dev, 2) | (pit->speaker_data_on << 1) | pit->dummy_refresh_clock | out;
}

static void pcspk_ioport_write(void *opaque, uint32_t addr, uint32_t val)
{
    SysBusDevice *dev = (SysBusDevice*)opaque;
    PITState *pit = DO_UPCAST(PITState, dev, dev);
    const int gate = val & 1;

    pit->speaker_data_on = (val >> 1) & 1;
    pit_set_gate(dev, 2, gate);
}

static int pit_initfn(SysBusDevice *dev)
{
    PITState *pit = DO_UPCAST(PITState, dev, dev);
    PITChannelState *s;

    s = &pit->channels[0];
    /* the timer 0 is connected to an IRQ */
    s->irq_timer = qemu_new_timer_ns(vm_clock, pit_irq_timer, s);
    s->irq = isa_get_irq(pit->irq);

    memory_region_init_io(&pit->ioports, &pit_ioport_ops, pit, "pit", 4);
    memory_region_add_subregion(system_ioport, pit->iobase, &pit->ioports);

    // pcspkr ports
    register_ioport_read(0x61, 1, 1, pcspk_ioport_read, dev);
    register_ioport_write(0x61, 1, 1, pcspk_ioport_write, dev);

#ifndef QEMU_UXEN
    qdev_set_legacy_instance_id(&dev->qdev, pit->iobase, 2);
#endif
    return 0;
}

void pit_init(void)
{
    DeviceState *dev;
    dev = qdev_create(NULL, "isa-pit");
    qdev_prop_set_uint32(dev, "iobase", 0x40);
    qdev_prop_set_uint32(dev, "irq", 0);
    qdev_init_nofail(dev);
}

static SysBusDeviceInfo pit_info = {
    .qdev.name     = "isa-pit",
    .qdev.size     = sizeof(PITState),
    .qdev.vmsd     = &vmstate_pit,
    .qdev.reset    = pit_reset,
    .init          = pit_initfn,
    .qdev.props = (Property[]) {
        DEFINE_PROP_UINT32("irq", PITState, irq,  -1),
        DEFINE_PROP_HEX32("iobase", PITState, iobase,  -1),
        DEFINE_PROP_END_OF_LIST(),
    },
};

static void pit_register(void)
{
    sysbus_register_withprop(&pit_info);
}
device_init(pit_register)
