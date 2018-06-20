/*
 * Copyright 2018, Bromium, Inc.
 * SPDX-License-Identifier: ISC
 */

#ifndef HPET_H_
#define HPET_H_

int hpet_init(qemu_irq *gsis, qemu_irq *out_rtc_irq);

#endif

