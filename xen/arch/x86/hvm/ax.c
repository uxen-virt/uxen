/*
 * Copyright 2017, Bromium, Inc.
 * SPDX-License-Identifier: ISC
 */

#include <xen/lib.h>
#include <asm/hvm/ax.h>

#include "attoxen-api/hv_tests.h"

int ax_present;

int ax_setup (void)
{
#ifndef __i386__

  if (hv_tests_hyperv_running() && hv_tests_ax_running()) {
    printk ("Hv and AX detected\n");
    ax_present = 1;
  }

#endif
  return 0;
}
