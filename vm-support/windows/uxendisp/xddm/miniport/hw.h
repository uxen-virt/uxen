/*
 * Copyright 2015-2016, Bromium, Inc.
 * Author: Julian Pidancet <julian@pidancet.net>
 * SPDX-License-Identifier: ISC
 */

#ifndef _BOCHS_H_
#define _BOCHS_H_

VP_STATUS hw_init(PDEVICE_EXTENSION dev);
ULONG hw_get_nmodes(PDEVICE_EXTENSION dev);
VP_STATUS hw_get_mode_info(PDEVICE_EXTENSION dev, ULONG i,
                              VIDEO_MODE_INFORMATION *info);
VP_STATUS hw_set_mode(PDEVICE_EXTENSION dev, VIDEO_MODE_INFORMATION *mode);
VP_STATUS hw_disable(PDEVICE_EXTENSION dev);
ULONG hw_get_vram_size(PDEVICE_EXTENSION dev);

#define POINTER_WIDTH_MAX         128
#define POINTER_HEIGHT_MAX        128
BOOLEAN hw_pointer_update(PDEVICE_EXTENSION dev, ULONG width, ULONG height,
                          ULONG hot_x, ULONG hot_y,
                          ULONG linesize, PUCHAR pixels,
                          BOOLEAN color);
BOOLEAN hw_pointer_setpos(PDEVICE_EXTENSION dev, SHORT x, SHORT y);
BOOLEAN hw_pointer_enable(PDEVICE_EXTENSION dev, BOOLEAN en);

void hw_disable_page_tracking(PDEVICE_EXTENSION dev);
void hw_enable_page_tracking(PDEVICE_EXTENSION dev);

VP_STATUS hw_is_virt_mode_enabled(PDEVICE_EXTENSION dev);

#endif /* _BOCHS_H_ */
