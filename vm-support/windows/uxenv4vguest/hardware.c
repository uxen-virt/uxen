/*
 * Copyright 2015, Bromium, Inc.
 * SPDX-License-Identifier: ISC
 */

#include "uxenv4vguest_private.h"

NTSTATUS
UxvgEvtDevicePrepareHardware (
    WDFDEVICE       Device,
    WDFCMRESLIST   Resources,
    WDFCMRESLIST   ResourcesTranslated
)
/*++

Routine Description:

    Performs whatever initialization is needed to setup the device, setting up
    a DMA channel or mapping any I/O port resources.  This will only be called
    as a device starts or restarts, not every time the device moves into the D0
    state.  Consequently, most hardware initialization belongs elsewhere.

Arguments:

    Device - A handle to the WDFDEVICE

    Resources - The raw PnP resources associated with the device.  Most of the
        time, these aren't useful for a PCI device.

    ResourcesTranslated - The translated PnP resources associated with the
        device.  This is what is important to a PCI device.

Return Value:

    NT status code - failure will result in the device stack being torn down

--*/
{
    NTSTATUS            status = STATUS_SUCCESS;
    PDEVICE_EXTENSION   devExt;

    UNREFERENCED_PARAMETER(Resources);
    UNREFERENCED_PARAMETER(ResourcesTranslated);

    PAGED_CODE();

    uxen_debug( "--> UxvgEvtDevicePrepareHardware");

    devExt = UxvgGetDeviceContext(Device);


    (void) devExt;

    //map registers &c


    uxen_debug( "<-- UxvgEvtDevicePrepareHardware, status %x", status);

    return status;
}

NTSTATUS
UxvgEvtDeviceReleaseHardware(
    IN  WDFDEVICE Device,
    IN  WDFCMRESLIST ResourcesTranslated
)
/*++

Routine Description:

    Unmap the resources that were mapped in UxvgEvtDevicePrepareHardware.
    This will only be called when the device stopped for resource rebalance,
    surprise-removed or query-removed.

Arguments:

    Device - A handle to the WDFDEVICE

    ResourcesTranslated - The translated PnP resources associated with the
        device.  This is what is important to a PCI device.

Return Value:

    NT status code - failure will result in the device stack being torn down

--*/
{
    PDEVICE_EXTENSION   devExt;
    NTSTATUS status = STATUS_SUCCESS;

    UNREFERENCED_PARAMETER(ResourcesTranslated);

    PAGED_CODE();

    uxen_debug( "--> UxvgEvtDeviceReleaseHardware");

    devExt = UxvgGetDeviceContext(Device);

    (void) devExt;

    //unmap registers &c.
#if 0
    if (devExt->RegsBase) {

        MmUnmapIoSpace(devExt->RegsBase, devExt->RegsLength);
        devExt->RegsBase = NULL;
    }

    if (devExt->SRAMBase) {
        MmUnmapIoSpace(devExt->SRAMBase, devExt->SRAMLength);
        devExt->SRAMBase = NULL;
    }
#endif

    uxen_debug( "<-- UxvgEvtDeviceReleaseHardware");

    return status;
}

