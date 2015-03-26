/*
 * Copyright 2014-2015, Bromium, Inc.
 * Author: Kris Uchronski <kuchronski@gmail.com>
 * SPDX-License-Identifier: ISC
 */

#ifndef _POINTER_H_
#define _POINTER_H_


NTSTATUS UxenMousePointerInitialize(
    _In_ CONST DXGK_DEVICE_INFO* pDeviceInfo,
    _Inout_ PUXEN_MOUSE_RESOURCES pMouse);

VOID UxenMousePointerCleanup(
    _Inout_ PUXEN_MOUSE_RESOURCES pMouse);

VOID UxenQueryMousePointerCaps(
    _In_ DXGK_DRIVERCAPS* pDriverCaps);

NTSTATUS UxenSetPointerPosition(
    _In_ CONST DXGKARG_SETPOINTERPOSITION* pSetPointerPosition,
    _Inout_ PUXEN_MOUSE_RESOURCES pMouse);

NTSTATUS UxenSetPointerShape(
    _In_ CONST DXGKARG_SETPOINTERSHAPE* pSetPointerShape,
    _Inout_ PUXEN_MOUSE_RESOURCES pMouse);


#endif // _POINTER_H_
