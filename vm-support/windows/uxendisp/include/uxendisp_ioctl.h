/*
 * Copyright 2012-2015, Bromium, Inc.
 * Author: Julian Pidancet <julian@pidancet.net>
 * SPDX-License-Identifier: ISC
 */

#ifndef _UXENDISP_IOCTL_H_
#define _UXENDISP_IOCTL_H_

/* IOCTL: display driver->miniport driver */
#define IOCTL_UXENDISP_SET_CUSTOM_MODE \
    CTL_CODE(FILE_DEVICE_VIDEO, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)

#endif /* _UXENDISP_IOCTL_H_ */
