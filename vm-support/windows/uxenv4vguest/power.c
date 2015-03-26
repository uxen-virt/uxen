/*
 * Copyright 2015, Bromium, Inc.
 * SPDX-License-Identifier: ISC
 */

#include "uxenv4vguest_private.h"

NTSTATUS
UxvgEvtDeviceD0Entry(
    IN  WDFDEVICE Device,
    IN  WDF_POWER_DEVICE_STATE PreviousState
)
{
    PDEVICE_EXTENSION   devExt;
    NTSTATUS            status;

    UNREFERENCED_PARAMETER(PreviousState);

    devExt = UxvgGetDeviceContext(Device);

    (void) devExt;

    status = STATUS_SUCCESS;

    //bring device up

    return status;
}

NTSTATUS
UxvgEvtDeviceD0Exit(
    IN  WDFDEVICE Device,
    IN  WDF_POWER_DEVICE_STATE TargetState
)
{
    PDEVICE_EXTENSION   devExt;

    PAGED_CODE();

    devExt = UxvgGetDeviceContext(Device);

    switch (TargetState) {
        case WdfPowerDeviceD1:
        case WdfPowerDeviceD2:
        case WdfPowerDeviceD3:

            //
            // Fill in any code to save hardware state here.
            //

            //
            // Fill in any code to put the device in a low-power state here.
            //
            break;

        case WdfPowerDevicePrepareForHibernation:

            //
            // Fill in any code to save hardware state here.  Do not put in any
            // code to shut the device off.  If this device cannot support being
            // in the paging path (or being a parent or grandparent of a paging
            // path device) then this whole case can be deleted.
            //

            break;

        case WdfPowerDeviceD3Final:
        default:

            //
            // Reset the hardware, as we're shutting down for the last time.
            //

            // shutdevice shown
            break;
    }

    return STATUS_SUCCESS;
}



