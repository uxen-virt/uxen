/*
 * Copyright 2018, Bromium, Inc.
 * SPDX-License-Identifier: ISC
 */

#ifndef APIC_H
#define APIC_H

#include <dm/cpu.h>

#define WHPX_LAPIC_ID(vcpu_idx) ((vcpu_idx) << 1)

void apic_deliver_irq(uint8_t dest, uint8_t dest_mode, uint8_t delivery_mode,
                      uint8_t vector_num, uint8_t trigger_mode);

/* i8259.c */
struct PicState;
typedef struct PicState PicState;

extern PicState *isa_pic;

int pic_read_irq(PicState *s);
int pic_get_output(PicState *s);
qemu_irq *i8259_init(qemu_irq parent_irq);

/* ioapic.c */
qemu_irq *ioapic_init(void);

#endif
