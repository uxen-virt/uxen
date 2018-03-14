/*
 * Copyright 2018, Bromium, Inc.
 * SPDX-License-Identifier: ISC
 */

#ifndef MC146818RTC_H
#define MC146818RTC_H

#include <dm/qemu/hw/isa.h>

#define RTC_ISA_IRQ 8

ISADevice *rtc_init(int base_year, qemu_irq intercept_irq);
void rtc_set_memory(ISADevice *dev, int addr, int val);
void rtc_set_date(ISADevice *dev, const struct tm *tm);

#endif /* !MC146818RTC_H */
