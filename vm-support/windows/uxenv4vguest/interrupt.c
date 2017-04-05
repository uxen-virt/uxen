/*
 * Copyright 2015-2017, Bromium, Inc.
 * SPDX-License-Identifier: ISC
 */

#include "uxenv4vguest_private.h"



BOOLEAN
UxvgEvtInterruptIsr(
    IN WDFINTERRUPT Interrupt,
    IN ULONG        MessageID
)
{
    PDEVICE_EXTENSION   devExt;
    BOOLEAN             isRecognized = FALSE;

    UNREFERENCED_PARAMETER(MessageID);

    //DbgPrint("--> EvtInterruptIsr\n");

    devExt  = UxvgGetDeviceContext(WdfInterruptGetDevice(Interrupt));

    //  read ISR here - if we had one then set isRecognized to say we liked the interrupt
    isRecognized = TRUE;

    if (isRecognized) {
        WdfInterruptQueueDpcForIsr( devExt->Interrupt );
    }
    //DbgPrint("<-- EvtInterruptIsr\n");

    return isRecognized;
}

VOID
UxvgEvtInterruptDpc(
    WDFINTERRUPT Interrupt,
    WDFOBJECT    Device
)
{
    PDEVICE_EXTENSION   devExt;

    UNREFERENCED_PARAMETER(Device);


    //DbgPrint("--> EvtInterruptDpc\n");

    devExt  = UxvgGetDeviceContext(WdfInterruptGetDevice(Interrupt));

    //WdfInterruptAcquireLock( Interrupt );
    uxen_v4vlib_deliver_signal();
    //WdfInterruptReleaseLock( Interrupt );

    //DbgPrint ("<-- EvtInterruptDpc\n");

    return;
}

NTSTATUS
UxvgEvtInterruptEnable(
    IN WDFINTERRUPT Interrupt,
    IN WDFDEVICE    Device
)
{
    PDEVICE_EXTENSION  devExt;

    uxen_msg( "Interrupt 0x%p, Device 0x%p", Interrupt, Device);

    devExt  = UxvgGetDeviceContext(WdfInterruptGetDevice(Interrupt));

    // write the registers to enable the interrupt

    return STATUS_SUCCESS;
}

NTSTATUS
UxvgEvtInterruptDisable(
    IN WDFINTERRUPT Interrupt,
    IN WDFDEVICE    Device
)
{
    PDEVICE_EXTENSION  devExt;

    uxen_msg( "Interrupt 0x%p, Device 0x%p", Interrupt, Device);

    devExt  = UxvgGetDeviceContext(WdfInterruptGetDevice(Interrupt));

    // write the registers to disenable the interrupt

    return STATUS_SUCCESS;
}


NTSTATUS
UxvgInterruptCreate(
    IN PDEVICE_EXTENSION devExt
)
{
    NTSTATUS                    status;
    WDF_INTERRUPT_CONFIG        InterruptConfig;

    WDF_INTERRUPT_CONFIG_INIT( &InterruptConfig,
                               UxvgEvtInterruptIsr,
                               UxvgEvtInterruptDpc );

    uxen_msg( "called");

    InterruptConfig.EvtInterruptEnable  = UxvgEvtInterruptEnable;
    InterruptConfig.EvtInterruptDisable = UxvgEvtInterruptDisable;

    InterruptConfig.AutomaticSerialization = TRUE;

    status = WdfInterruptCreate( devExt->Device,
                                 &InterruptConfig,
                                 WDF_NO_OBJECT_ATTRIBUTES,
                                 &devExt->Interrupt );

    if ( !NT_SUCCESS(status) ) {
        uxen_err( "WdfInterruptCreate failed: %x", status);
    }

    WdfInterruptSetPolicy(devExt->Interrupt, WdfIrqPolicySpecifiedProcessors,
        WdfIrqPriorityNormal, 1);

    return status;
}

