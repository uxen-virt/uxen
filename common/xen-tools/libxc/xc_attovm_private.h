/*
 * Copyright 2019, Bromium, Inc.
 * Author: Tomasz Wroblewski <tomasz.wroblewski@gmail.com>
 * SPDX-License-Identifier: ISC
 */

#ifndef XC_ATTOVM_PRIVATE_H_
#define XC_ATTOVM_PRIVATE_H_

#include <attoxen-api/ax_attovm.h>

int attovm_setup_guest(xc_interface *xch, uint32_t domid, xen_pfn_t *pfns,
  const char *image_file,
  struct attovm_definition_v1 *out_definition);
int attovm_seal_guest(xc_interface *xch, uint32_t domid, struct attovm_definition_v1 *definition);

#endif
