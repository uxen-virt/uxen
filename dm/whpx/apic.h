/*
 * Copyright 2018, Bromium, Inc.
 * SPDX-License-Identifier: ISC
 */

#ifndef APIC_H
#define APIC_H

#include <dm/cpu.h>

#define WHPX_LAPIC_ID(vcpu_idx) ((vcpu_idx) << 1)

/* i8259.c */
struct PicState;
typedef struct PicState PicState;

extern PicState *isa_pic;

int pic_read_irq(PicState *s);
int pic_get_output(PicState *s);
qemu_irq *i8259_init(qemu_irq parent_irq);

/* ioapic.c */
qemu_irq *ioapic_init(void);

/* apic.c */
void apic_init(CPUState *env);
void apic_deliver_irq(uint8_t dest, uint8_t dest_mode, uint8_t delivery_mode,
                      uint8_t vector_num, uint8_t trigger_mode);
int apic_accept_pic_intr(DeviceState *s);
void apic_deliver_pic_intr(DeviceState *s, int level);
int apic_get_interrupt(DeviceState *s);
void apic_poll_irq(DeviceState *s);
void apic_reset_irq_delivered(void);
int apic_get_irq_delivered(void);
void cpu_set_apic_base(DeviceState *s, uint64_t val);
uint64_t cpu_get_apic_base(DeviceState *s);
void cpu_set_apic_tpr(DeviceState *s, uint8_t val);
uint8_t cpu_get_apic_tpr(DeviceState *s);
void apic_init_reset(DeviceState *s);
void apic_sipi(DeviceState *s);
void apic_eoi(DeviceState *s);
uint8_t apic_get_taskpri(DeviceState *s);
uint32_t apic_get_icr(DeviceState *s);
uint32_t apic_get_icr2(DeviceState *s);
void apic_set_taskpri(DeviceState *s, uint8_t val);
void apic_set_icr(DeviceState *s, uint32_t v);
void apic_set_icr2(DeviceState *s, uint32_t v);

/* other */
int cpu_is_bsp(CPUState *env);
DeviceState *cpu_get_current_apic(void);

#endif
