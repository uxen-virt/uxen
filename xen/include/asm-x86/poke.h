/*
 * Copyright 2017-2018, Bromium, Inc.
 * SPDX-License-Identifier: ISC
 */

#include <xen/config.h>
#include <xen/bitmap.h>
#include <xen/kernel.h>
#include <xen/cpu.h>
#include <xen/percpu.h>

DECLARE_PER_CPU(int, poke_ready);

extern void poke_cpu(unsigned);
