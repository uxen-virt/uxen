/*
 * Copyright 2015, Bromium, Inc.
 * Author: Kris Uchronski <kuchronski@gmail.com>
 * SPDX-License-Identifier: ISC
 */

#ifndef _HW_H_
#define _HW_H_

NTSTATUS hw_init(
    _Inout_ PUXEN_HW_RESOURCES pHw);

void hw_cleanup(
    _Inout_ PUXEN_HW_RESOURCES pHw);

void hw_query_mouse_pointer_caps(
    _Inout_ DXGK_DRIVERCAPS* pDriverCaps);

NTSTATUS hw_set_mode(
    _In_ PUXEN_HW_RESOURCES pHw,
    _In_ VIDEO_MODE_INFORMATION *mode);

NTSTATUS hw_disable(
    _In_ PUXEN_HW_RESOURCES pHw);

NTSTATUS hw_pointer_setpos(
    _In_ PUXEN_HW_RESOURCES pHw,
    _In_ CONST DXGKARG_SETPOINTERPOSITION *pSetPointerPosition);

NTSTATUS hw_pointer_update(
    _In_ PUXEN_HW_RESOURCES pHw,
    _In_ CONST DXGKARG_SETPOINTERSHAPE *pSetPointerShape);

void hw_disable_page_tracking(
    _In_ PUXEN_HW_RESOURCES pHw);

#endif /* _HW_H_ */
