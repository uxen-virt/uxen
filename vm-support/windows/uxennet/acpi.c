#include "uxennet_private.h"
#include <acpiioct.h>

#define MAC_LENGTH 6

static NTSTATUS
SendDownStreamIrp(
    IN PDEVICE_OBJECT   Pdo,
    IN ULONG            Ioctl,
    IN PVOID            InputBuffer,
    IN ULONG            InputSize,
    IN PVOID            OutputBuffer,
    IN ULONG            OutputSize
)
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
/*
 * uXen changes:
 *
 * Copyright 2015, Bromium, Inc.
 * SPDX-License-Identifier: ISC
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
 * SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION
 * OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
 * CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

{
    IO_STATUS_BLOCK     ioBlock;
    KEVENT              myIoctlEvent;
    NTSTATUS            status;
    PIRP                irp;

    // Initialize an event to wait on
    KeInitializeEvent(&myIoctlEvent, SynchronizationEvent, FALSE);

    // Build the request
    irp = IoBuildDeviceIoControlRequest(
              Ioctl,
              Pdo,
              InputBuffer,
              InputSize,
              OutputBuffer,
              OutputSize,
              FALSE,
              &myIoctlEvent,
              &ioBlock);

    if (!irp) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    // Pass request to Pdo, always wait for completion routine
    status = IoCallDriver(Pdo, irp);

    if (status == STATUS_PENDING) {
        // Wait for the IRP to be completed, and then return the status code
        KeWaitForSingleObject(
            &myIoctlEvent,
            Executive,
            KernelMode,
            FALSE,
            NULL);

        status = ioBlock.Status;
    }

    return status;
}


NTSTATUS
uxen_net_get_mac_address( IN PDEVICE_OBJECT   pdo, uint8_t *mac_address)
{
    ACPI_EVAL_INPUT_BUFFER  input_buffer;
    UCHAR           output_buffer_buf[1024];
    ACPI_EVAL_OUTPUT_BUFFER *output_buffer = (ACPI_EVAL_OUTPUT_BUFFER *) output_buffer_buf;
    NTSTATUS                status;
    PACPI_METHOD_ARGUMENT   argument;

    ASSERT( mac_address != NULL );

    // Fill in the input data
    input_buffer.MethodNameAsUlong = (ULONG) ('CAMV'); //Windows oh you are so special
    input_buffer.Signature = ACPI_EVAL_INPUT_BUFFER_SIGNATURE;

    memset(output_buffer_buf, 0, sizeof(output_buffer_buf));

    // Send the request along
    status = SendDownStreamIrp(
                 pdo,
                 IOCTL_ACPI_EVAL_METHOD,
                 &input_buffer,
                 sizeof(ACPI_EVAL_INPUT_BUFFER),
                 output_buffer,
                 sizeof(output_buffer_buf)
             );

    if (!NT_SUCCESS(status)) {
        uxen_err("uxn: apci: SendDownStreamIrp returns %x", status);
        return status;
    }

    // Verify the data
//    if (output_buffer != NULL) {
    if ( ( output_buffer->Signature != ACPI_EVAL_OUTPUT_BUFFER_SIGNATURE ) ||
         ( output_buffer->Count == 0)) {
        return STATUS_ACPI_INVALID_DATA;
    }
    //}

    if (output_buffer->Count != 1) {
        uxen_err("uxn: acpi output_buffer->Count=%d", output_buffer->Count);
        return STATUS_ACPI_INVALID_DATA;
    }

    // Retrieve the output argument
    argument = output_buffer->Argument;

    if (argument->Type != ACPI_METHOD_ARGUMENT_BUFFER) {
        uxen_err("uxn: acpi argument->Type=0x%x", (unsigned) argument->Type);
        return STATUS_ACPI_INVALID_DATA;
    }
    if (argument->DataLength != MAC_LENGTH) {
        uxen_err("uxn: acpi argument->DataLength=%u", (unsigned) argument->DataLength);
        return STATUS_ACPI_INVALID_DATA;
    }

    memcpy(mac_address, argument->Data, MAC_LENGTH);

    return status;
}
NTSTATUS
uxen_net_get_mtu( IN PDEVICE_OBJECT   pdo, ULONG *mtu)
{
    ACPI_EVAL_INPUT_BUFFER  input_buffer;
    UCHAR           output_buffer_buf[1024];
    ACPI_EVAL_OUTPUT_BUFFER *output_buffer = (ACPI_EVAL_OUTPUT_BUFFER *) output_buffer_buf;
    NTSTATUS                status;
    PACPI_METHOD_ARGUMENT   argument;

    ASSERT( mtu != NULL );

    // Fill in the input data
    input_buffer.MethodNameAsUlong = (ULONG) ('UTMV'); //Windows oh you are so special
    input_buffer.Signature = ACPI_EVAL_INPUT_BUFFER_SIGNATURE;

    memset(output_buffer_buf, 0, sizeof(output_buffer_buf));

    // Send the request along
    status = SendDownStreamIrp(
                 pdo,
                 IOCTL_ACPI_EVAL_METHOD,
                 &input_buffer,
                 sizeof(ACPI_EVAL_INPUT_BUFFER),
                 output_buffer,
                 sizeof(output_buffer_buf)
             );

    if (!NT_SUCCESS(status)) {
        uxen_err("uxn: apci: SendDownStreamIrp returns %x", status);
        return status;
    }

    // Verify the data
//    if (output_buffer != NULL) {
    if ( ( output_buffer->Signature != ACPI_EVAL_OUTPUT_BUFFER_SIGNATURE ) ||
         ( output_buffer->Count == 0)) {
        return STATUS_ACPI_INVALID_DATA;
    }
    //}

    if (output_buffer->Count != 1) {
        uxen_err("uxn: acpi output_buffer->Count=%d", output_buffer->Count);
        return STATUS_ACPI_INVALID_DATA;
    }

    // Retrieve the output argument
    argument = output_buffer->Argument;

    if (argument->Type != ACPI_METHOD_ARGUMENT_INTEGER) {
        uxen_err("uxn: acpi argument->Type=0x%x", (unsigned) argument->Type);
        uxen_err("uxn: acpi argument->DataLength=%u", (unsigned) argument->DataLength);
        return STATUS_ACPI_INVALID_DATA;
    }

    *mtu = argument->Argument;

    return status;
}
