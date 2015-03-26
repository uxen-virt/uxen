/*
 * Copyright 2012-2015, Bromium, Inc.
 * Author: Christian Limpach <Christian.Limpach@gmail.com>
 * SPDX-License-Identifier: ISC
 */

#ifndef _HW_H_
#define _HW_H_

#define MAX_SERIAL_PORTS 4
extern struct CharDriverState *serial_hds[MAX_SERIAL_PORTS];

#define PCI_HOLE_START 0xe0000000

#define MAX_IDE_BUS 2
#define MAX_IDE_DEVS 2
#define MAX_ICH_DEVS 6

void pc_init_xen(void);

#endif  /* _HW_H_ */
