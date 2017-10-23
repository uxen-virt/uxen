/*
 * Copyright 2017, Bromium, Inc.
 * SPDX-License-Identifier: ISC
 */

#include <xen/config.h>
#include <xen/bitmap.h>
#include <xen/kernel.h>
#include <xen/cpu.h>
#include <xen/percpu.h>


DECLARE_PER_CPU(int, poke_ready);

extern void _poke_setup_cpu(void);
extern void poke_cpu(unsigned);


static inline void poke_setup_cpu(void)
{
    if (!this_cpu(poke_ready)) _poke_setup_cpu();
}