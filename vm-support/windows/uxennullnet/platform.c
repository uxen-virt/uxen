/*
 * Copyright 2015-2016, Bromium, Inc.
 * SPDX-License-Identifier: ISC
 */

#include <ntddk.h>

#include "uxenvmlib.h"

#include "uxennullnet.h"

#include "platform_public.h"
#include <uxen/platform_interface.h>

#define MAC_LENGTH 6

/*
Routine Description:
    General-purpose function called to send a request to the PDO.
    The IOCTL argument accepts the control method being passed down
    by the calling function

    This subroutine is only valid for the IOCTLS other than ASYNC EVAL.

Parameters:
    Pdo             - the request is sent to this device object
    Ioctl           - the request - specified by the calling function
    InputBuffer     - incoming request
    InputSize       - size of the incoming request
    OutputBuffer    - the answer
    OutputSize      - size of the answer buffer

Return Value:
    NT Status of the operation
*/
static NTSTATUS
SendDownStreamIrp(IN PDEVICE_OBJECT Pdo,
                  IN ULONG Ioctl,
                  IN PVOID InputBuffer,
                  IN ULONG InputSize,
                  IN PVOID OutputBuffer, IN ULONG OutputSize)
{
    IO_STATUS_BLOCK ioBlock;
    KEVENT myIoctlEvent;
    NTSTATUS status;
    PIRP irp;

    // Initialize an event to wait on
    KeInitializeEvent(&myIoctlEvent, SynchronizationEvent, FALSE);

    // Build the request
    irp = IoBuildDeviceIoControlRequest(Ioctl,
                                        Pdo,
                                        InputBuffer,
                                        InputSize,
                                        OutputBuffer,
                                        OutputSize,
                                        FALSE, &myIoctlEvent, &ioBlock);

    if (!irp) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    // Pass request to Pdo, always wait for completion routine
    status = IoCallDriver(Pdo, irp);

    if (status == STATUS_PENDING) {
        // Wait for the IRP to be completed, and then return the status code
        KeWaitForSingleObject(&myIoctlEvent,
                              Executive, KernelMode, FALSE, NULL);

        status = ioBlock.Status;
    }

    return status;
}


NTSTATUS
platform_get_mac_address(IN PDEVICE_OBJECT pdo, UCHAR *mac_address)
{
    NTSTATUS status;
    UCHAR property_id;

    ASSERT(mac_address != NULL);

    property_id = UXENBUS_PROPERTY_TYPE_MACADDR;

    memset(mac_address, 0, MAC_LENGTH);

    status = SendDownStreamIrp(pdo,
                               IOCTL_UXEN_PLATFORM_BUS_GET_DEVICE_PROPERTY,
                               &property_id, sizeof(property_id),
                               mac_address, MAC_LENGTH);

    if (!NT_SUCCESS(status)) {
        uxen_err("SendDownStreamIrp failed - 0x%.08X", status);
        return status;
    }

    return status;
}
