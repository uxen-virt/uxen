/*
 * Copyright 2014-2015, Bromium, Inc.
 * Author: Kris Uchronski <kuchronski@gmail.com>
 * SPDX-License-Identifier: ISC
 */

#ifndef _BOCHS_H_
#define _BOCHS_H_

/*
 * Public interface to the bochs library.
 */

/* PCI vendor and device IDs. */
#define BOCHS_PCI_VEN    0x5853
#define BOCHS_PCI_DEV    0x5101


#define VBE_DISPI_IOPORT_INDEX           0x01CE
#define VBE_DISPI_IOPORT_DATA            0x01CF

#define VBE_DISPI_INDEX_ID               0x0
#define VBE_DISPI_INDEX_XRES             0x1
#define VBE_DISPI_INDEX_YRES             0x2
#define VBE_DISPI_INDEX_BPP              0x3
#define VBE_DISPI_INDEX_ENABLE           0x4
#define VBE_DISPI_INDEX_BANK             0x5

#define VBE_DISPI_ID0                    0xB0C0
#define VBE_DISPI_ID1                    0xB0C1
#define VBE_DISPI_ID2                    0xB0C2
#define VBE_DISPI_ID3                    0xB0C3
#define VBE_DISPI_ID4                    0xB0C4
#define VBE_DISPI_ID5                    0xB0C5

#define VBE_DISPI_DISABLED               0x00
#define VBE_DISPI_ENABLED                0x01
#define VBE_DISPI_8BIT_DAC               0x20
#define VBE_DISPI_NOCLEARMEM             0x80

#define VBE_DISPI_INDEX_HWCURSOR_HI     0x000D
#define VBE_DISPI_INDEX_HWCURSOR_LO     0x000E
#define VBE_DISPI_INDEX_HWCURSOR_FLUSH  0x000F


VP_STATUS bochs_init();
VP_STATUS bochs_set_mode(VIDEO_MODE_INFORMATION *mode);
VP_STATUS bochs_disable();

#endif /* _BOCHS_H_ */
