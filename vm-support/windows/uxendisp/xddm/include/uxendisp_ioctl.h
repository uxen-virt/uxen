/*
 * Copyright 2012-2016, Bromium, Inc.
 * Author: Julian Pidancet <julian@pidancet.net>
 * SPDX-License-Identifier: ISC
 */

#ifndef _UXENDISP_IOCTL_H_
#define _UXENDISP_IOCTL_H_

/* IOCTL: display driver->miniport driver */
#define IOCTL_UXENDISP_SET_CUSTOM_MODE \
    CTL_CODE(FILE_DEVICE_VIDEO, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_UXENDISP_GET_UPDATE_RECT \
    CTL_CODE(FILE_DEVICE_VIDEO, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_UXENDISP_SET_VIRTUAL_MODE \
    CTL_CODE(FILE_DEVICE_VIDEO, 0x802, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_UXENDISP_IS_VIRT_MODE_ENABLED \
    CTL_CODE(FILE_DEVICE_VIDEO, 0x803, METHOD_BUFFERED, FILE_ANY_ACCESS)

struct rect {
    ULONG left;
    ULONG top;
    ULONG right;
    ULONG bottom;
};

typedef void (*safe_to_draw_ptr)(PVOID dev);
typedef void (*update_rect_ptr)(PVOID dev, struct rect *rect);

typedef struct _GET_UPDATE_RECT_DATA {
    PVOID dev;
    safe_to_draw_ptr safe_to_draw;
    update_rect_ptr update;
} GET_UPDATE_RECT_DATA;

#endif /* _UXENDISP_IOCTL_H_ */
