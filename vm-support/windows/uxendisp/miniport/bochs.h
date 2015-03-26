/*
 * Copyright 2012-2015, Bromium, Inc.
 * Author: Julian Pidancet <julian@pidancet.net>
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

VP_STATUS bochs_init(PDEVICE_EXTENSION dev);
ULONG bochs_get_nmodes(PDEVICE_EXTENSION dev);
VP_STATUS bochs_get_mode_info(PDEVICE_EXTENSION dev, ULONG i,
                              VIDEO_MODE_INFORMATION *info);
VP_STATUS bochs_set_mode(PDEVICE_EXTENSION dev, VIDEO_MODE_INFORMATION *mode);
VP_STATUS bochs_disable(PDEVICE_EXTENSION dev);
ULONG bochs_get_vram_size(PDEVICE_EXTENSION dev);

#endif /* _BOCHS_H_ */
