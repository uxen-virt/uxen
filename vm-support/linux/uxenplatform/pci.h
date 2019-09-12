/*
 * Copyright 2016-2019, Bromium, Inc.
 * Author: Paulian Marinca <paulian@marinca.net>
 * SPDX-License-Identifier: ISC
 */

#ifndef _UXEN_PLATFORM_PCI_H_
#define _UXEN_PLATFORM_PCI_H_

struct bus_type;
int pci_platform_init(struct bus_type *uxen_bus);
void pci_platform_exit(void);
#endif
