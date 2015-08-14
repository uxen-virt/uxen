/*
 * Copyright 2012-2015, Bromium, Inc.
 * Author: Christian Limpach <Christian.Limpach@gmail.com>
 * SPDX-License-Identifier: ISC
 */

#ifndef _HW_H_
#define _HW_H_

#define MAX_SERIAL_PORTS 4
extern struct CharDriverState *serial_hds[MAX_SERIAL_PORTS];

/* #include <xen/hvm/e820.h> */
#define PCI_HOLE_START HVM_BELOW_4G_MMIO_START
#define PCI_HOLE_END HVM_BELOW_4G_MMIO_END

#define MAX_IDE_BUS 2
#define MAX_IDE_DEVS 2
#define MAX_ICH_DEVS 6

void pc_init_xen(void);

#endif  /* _HW_H_ */
