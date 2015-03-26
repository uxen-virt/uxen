/*
 * Copyright 2013-2015, Bromium, Inc.
 * SPDX-License-Identifier: ISC
 */

//
//  uxenzeroshare: uxenzeroshare.c
//

#include "zerothread.h"

//
//  Device extension
//

typedef struct UXENZEROSHARE_DEVICE_EXTENSION {
    UXENZEROSHARE_INTERNALS_INFO    * InternalsInfo;
} UXENZEROSHARE_DEVICE_EXTENSION;

//
//  Prototypes
//

__drv_requiresIRQL(PASSIVE_LEVEL)
__drv_sameIRQL
__checkReturn
NTSTATUS
create_device(
    __inout DEVICE_OBJECT       * * Device,
    __in    DRIVER_OBJECT       *   Driver,
    __in    PUNICODE_STRING         KernelModeDeviceName,
    __in    PUNICODE_STRING         UserModeDeviceName
    );

__drv_requiresIRQL(PASSIVE_LEVEL)
__drv_sameIRQL
void
delete_device(__in DEVICE_OBJECT * Device);

DRIVER_INITIALIZE   DriverEntry;
DRIVER_UNLOAD       DriverUnload;

__drv_dispatchType(IRP_MJ_CLOSE)
DRIVER_DISPATCH     irp_mj_close; 

__drv_dispatchType(IRP_MJ_CREATE)
DRIVER_DISPATCH     irp_mj_create;

__drv_dispatchType(IRP_MJ_DEVICE_CONTROL)
DRIVER_DISPATCH     irp_mj_device_control;

//
//  Implementation
//


//
//  create_device
//

__drv_requiresIRQL(PASSIVE_LEVEL)
__drv_sameIRQL
__checkReturn
NTSTATUS
create_device(
    __inout DEVICE_OBJECT       * * Device,
    __in    DRIVER_OBJECT       *   Driver,
    __in    PUNICODE_STRING         KernelModeDeviceName,
    __in    PUNICODE_STRING         UserModeDeviceName
    )
{
    UXENZEROSHARE_DEVICE_EXTENSION  * extension;
    NTSTATUS                          status;

    UXENZEROSHARE_ENTER();
    UXENZEROSHARE_ASSERT((Device != 0));
    UXENZEROSHARE_ASSERT((Driver != 0));
    UXENZEROSHARE_ASSERT((KernelModeDeviceName != 0));
    UXENZEROSHARE_ASSERT((UserModeDeviceName != 0));
    
    status  = IoCreateDevice(
        Driver,
        sizeof(UXENZEROSHARE_DEVICE_EXTENSION),
        KernelModeDeviceName,
        FILE_DEVICE_UNKNOWN,
        FILE_DEVICE_SECURE_OPEN,
        FALSE,
        Device
        );

    if (! NT_SUCCESS(status)) {
        UXENZEROSHARE_DUMP((" couldn't create device: 0x%.08X\n", status));

        return status;
    }

    extension = (UXENZEROSHARE_DEVICE_EXTENSION *) (* Device)->DeviceExtension;
    extension->InternalsInfo = 0;

    status = IoCreateSymbolicLink(UserModeDeviceName, KernelModeDeviceName);
    if (! NT_SUCCESS(status)) {
        UXENZEROSHARE_DUMP((" couldn't create symbolic link: 0x%.08X\n",
            status
            ));
        delete_device(* Device);
        * Device = 0;
        return status;
    }

    UXENZEROSHARE_DUMP(("  created symbolic link: %wZ -> %wZ\n",
        & UserModeDeviceName,
        & KernelModeDeviceName
        ));

    return status;
}

//
//  delete_device
//

__drv_requiresIRQL(PASSIVE_LEVEL)
__drv_sameIRQL
void
delete_device(__in DEVICE_OBJECT * Device)
{
    UXENZEROSHARE_DEVICE_EXTENSION * extension;

    UXENZEROSHARE_ENTER();

    UXENZEROSHARE_ASSERT((Device != 0));

    extension = (UXENZEROSHARE_DEVICE_EXTENSION *) Device->DeviceExtension;

    if ((extension) && (extension->InternalsInfo)) {
        ExFreePoolWithTag(extension->InternalsInfo, UXENZEROSHARE_POOL_TAG);
        extension->InternalsInfo = 0;
    }

    IoDeleteDevice(Device);

    UXENZEROSHARE_LEAVE();

    return;
}

//
//  irp_mj_close(DEVICE_OBJECT * Device, IRP * IRP)
//

NTSTATUS
irp_mj_close(__in DEVICE_OBJECT * Device, __inout IRP * Irp)
{
    UXENZEROSHARE_ENTER();
    UXENZEROSHARE_UNREFERENCED(Device);

    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;

    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return STATUS_SUCCESS;
}

//
//  irp_mj_create(DEVICE_OBJECT * Device, IRP * IRP)
//

NTSTATUS
irp_mj_create(DEVICE_OBJECT * Device, IRP * Irp)
{
    UXENZEROSHARE_ENTER();
    UXENZEROSHARE_UNREFERENCED(Device);

    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;

    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return STATUS_SUCCESS;
}

//
//  irp_mj_device_control()
//

NTSTATUS
irp_mj_device_control(__in DEVICE_OBJECT * Device, __inout IRP * Irp)
{
    static const ULONG kSizeOfCreateZeroingThreadInfo                  = \
        (ULONG) sizeof(UXENZEROSHARE_CREATE_ZEROING_THREAD_INFO);
    static const ULONG kSizeOfInternalsInfo                            = \
        (ULONG) sizeof(UXENZEROSHARE_INTERNALS_INFO);
    static const ULONG kSizeOfKernelBaseInfo                           = \
        (ULONG) sizeof(UXENZEROSHARE_KERNEL_BASE_INFO);

    UXENZEROSHARE_DEVICE_EXTENSION              * extension            = \
        (UXENZEROSHARE_DEVICE_EXTENSION *) Device->DeviceExtension;
    UXENZEROSHARE_CREATE_ZEROING_THREAD_INFO    * info;
    IO_STACK_LOCATION                           * iostack              = \
        IoGetCurrentIrpStackLocation(Irp);
    void                                        * input_buffer         = \
        Irp->AssociatedIrp.SystemBuffer;
    ULONG                                         input_buffer_length  = \
        iostack->Parameters.DeviceIoControl.InputBufferLength;
    UXENZEROSHARE_INTERNALS_INFO                * internals;
    ULONG                                         ioctl                = \
        iostack->Parameters.DeviceIoControl.IoControlCode;
    AUX_MODULE_BASIC_INFO                       * moduleInfo;
    void                                        * output_buffer        = \
        Irp->AssociatedIrp.SystemBuffer;
    ULONG                                         output_buffer_length = \
        iostack->Parameters.DeviceIoControl.OutputBufferLength;
    ULONG                                         sizeOfBuffer         = 0;
    NTSTATUS                                      status               = \
        STATUS_SUCCESS;
    
    UXENZEROSHARE_ENTER();
    UXENZEROSHARE_UNREFERENCED(Device);

    switch (ioctl) {
        case UXENZEROSHARE_IOCTL_CREATE_ZEROING_THREAD: {
            //
            //  Create our zeroing thread.
            //

            UXENZEROSHARE_DUMP((
                "  UXENZEROSHARE_IOCTL_CREATE_ZEROING_THREAD: "
                "input_buffer_length==%u (0x%.08X), "
                "output_buffer_length==%u (0x%.08X)\n",
                input_buffer_length,
                input_buffer_length,
                output_buffer_length,
                output_buffer_length
                ));
            
            Irp->IoStatus.Information = 0;

            UXENZEROSHARE_ASSERT((input_buffer_length == 
                kSizeOfCreateZeroingThreadInfo));
            UXENZEROSHARE_ASSERT((output_buffer_length == 0));

            if (input_buffer_length  != kSizeOfCreateZeroingThreadInfo ||
                output_buffer_length != 0) {
                status = STATUS_INVALID_PARAMETER;

                break;
            }
            

            //
            //  Check to see if the internals info has been initialized.
            //

            UXENZEROSHARE_ASSERT((g_ZeroingThreadContext.KeWaitForGate != 0));

            info = (UXENZEROSHARE_CREATE_ZEROING_THREAD_INFO *) input_buffer;

            //
            //  Hypercall: use a hypercall to zero pages.
            //

            g_ZeroingThreadContext.Hypercall = info->Hypercall;

	        if (g_ZeroingThreadContext.Hypercall) {
		        uxen_hypercall_init();
            }

            status = zt_create_zeroing_thread(
                zt_zeroing_thread,
                & g_ZeroingThreadContext
                );

            if (! NT_SUCCESS(status)) {
                UXENZEROSHARE_DUMP((
                    "  couldn't create zeroing thread: 0x%.08X\n", status
                    ));
            }
            else {
                UXENZEROSHARE_DUMP((
                    "  zeroing thread created: handle==0x%p\n",
                    g_ZeroingThreadContext.ThreadHandle
                    ));

                status = STATUS_SUCCESS;
            }

            break;
        }

#if (DBG == 1)
        //
        //  Thses are just used for debugging and should never be called in
        //  production.
        //

        case UXENZEROSHARE_IOCTL_DISABLE_ZEROING:
        case UXENZEROSHARE_IOCTL_ENABLE_ZEROING: {
            UXENZEROSHARE_DUMP((
                "  %s: "
                "input_buffer_length==%u (0x%.08X), "
                "output_buffer_length==%u (0x%.08X)\n",
                (ioctl == UXENZEROSHARE_IOCTL_DISABLE_ZEROING) ? 
                    "UXENZEROSHARE_IOCTL_DISABLE_ZEROING"      :
                    "UXENZEROSHARE_IOCTL_ENABLE_ZEROING",
                input_buffer_length,
                input_buffer_length,
                output_buffer_length,
                output_buffer_length
                ));
            
            Irp->IoStatus.Information = 0;

            UXENZEROSHARE_ASSERT((input_buffer_length == 0));
            UXENZEROSHARE_ASSERT((output_buffer_length == 0));
            UXENZEROSHARE_ASSERT((extension->InternalsInfo != 0));

            zt_enable_system_zeroing_thread(
                & g_ZeroingThreadContext,
                ioctl == UXENZEROSHARE_IOCTL_DISABLE_ZEROING ? FALSE : TRUE
                );

            status = STATUS_SUCCESS;

            break;
        }
#endif

        case UXENZEROSHARE_IOCTL_GET_KERNEL_BASE: {
            UXENZEROSHARE_DUMP((
                "  UXENZEROSHARE_IOCTL_GET_KERNEL_BASE: "
                "input_buffer_length==%u (0x%.08X), "
                "output_buffer_length==%u (0x%.08X)\n",
                input_buffer_length,
                input_buffer_length,
                output_buffer_length,
                output_buffer_length
                ));

            Irp->IoStatus.Information = 0;

            UXENZEROSHARE_ASSERT((input_buffer_length  == 0));
            UXENZEROSHARE_ASSERT((output_buffer_length ==
                kSizeOfKernelBaseInfo
                ));

            if (input_buffer_length != 0 ||
                output_buffer_length != kSizeOfKernelBaseInfo) {
                status = STATUS_INVALID_PARAMETER;

                break;
            }

            //
            //  Query the list of loaded modules to that we can determine the
            //  base address of ntoskrnl
            //
            //  First time through, pass size==0 so that it will tell us how
            //  much memory we need to allocate for the full list.
            //

            status = AuxKlibQueryModuleInformation(
                & sizeOfBuffer, sizeof(AUX_MODULE_BASIC_INFO), 0
                );
            if (! NT_SUCCESS(status)) {
                UXENZEROSHARE_DUMP((
                    "  AuxKlibQueryModuleInformation(): 0x%.08X\n", status
                    ));

                break;
            }

            moduleInfo = (AUX_MODULE_BASIC_INFO *)
                ExAllocatePoolWithTag(
                    NonPagedPool, sizeOfBuffer, UXENZEROSHARE_POOL_TAG
                    );
            if (! moduleInfo) {
                UXENZEROSHARE_DUMP((
                    "  couldn't allocate memory for AUX_MODULE_BASIC_INFO "
                    "array\n"
                    ));
                status = STATUS_INSUFFICIENT_RESOURCES;

                break;
            }

            status = AuxKlibQueryModuleInformation(
                & sizeOfBuffer, sizeof(AUX_MODULE_BASIC_INFO), moduleInfo
                );
            if (! NT_SUCCESS(status)) {
                UXENZEROSHARE_DUMP((
                    "  AuxKlibQueryModuleInformation(2): 0x%.08X\n", status
                    ));
                ExFreePoolWithTag((void *) moduleInfo, UXENZEROSHARE_POOL_TAG);
                
                break;
            }
            
            //
            //  NT is always first.  Variations in nt module names probably
            //  make it a better idea to   assume this than to assume that the
            //  module's name is always either 'ntoskrnl' or 'ntkrnlmp.'
            //

            UXENZEROSHARE_DUMP((
                "  ImageBase: 0x%p\n", moduleInfo[0].ImageBase
                ));
            
            Irp->IoStatus.Information = sizeof(UXENZEROSHARE_KERNEL_BASE_INFO);

            //
            //  Fill in the output buffer, free the module list and then
            //  complete the request.
            //

            RtlCopyMemory(
                output_buffer,
                & moduleInfo[0].ImageBase,
                Irp->IoStatus.Information
                );

            ExFreePoolWithTag((void *) moduleInfo, UXENZEROSHARE_POOL_TAG);

            status = STATUS_SUCCESS;

            break;
        }

        case UXENZEROSHARE_IOCTL_SET_INTERNALS_INFO: {
            UXENZEROSHARE_DUMP((
                "  UXENZEROSHARE_IOCTL_SET_INTERNALS_INFO: "
                "input_buffer_length==%u (0x%.08X), "
                "output_buffer_length==%u (0x%.08X)\n",
                input_buffer_length,
                input_buffer_length,
                output_buffer_length,
                output_buffer_length
                ));

            Irp->IoStatus.Information = 0;

            //
            //  perform a basic sanity check on the input buffer.
            //

            UXENZEROSHARE_ASSERT((
                input_buffer_length == kSizeOfInternalsInfo
                ));
            UXENZEROSHARE_ASSERT((output_buffer_length == 0));

            if (input_buffer_length  != kSizeOfInternalsInfo ||
                output_buffer_length != 0) {
                
                status = STATUS_INVALID_PARAMETER;

                break;
            }

            //
            //  If necessary, allocate memory in our device extension to hold
            //  the internals info.
            //

            if (! extension->InternalsInfo) {
                extension->InternalsInfo = (UXENZEROSHARE_INTERNALS_INFO *)
                    ExAllocatePoolWithTag(
                        NonPagedPool,
                        kSizeOfInternalsInfo,
                        UXENZEROSHARE_POOL_TAG
                        );
                UXENZEROSHARE_ASSERT((extension->InternalsInfo != 0));
                if (! extension->InternalsInfo) {

                    status = STATUS_INSUFFICIENT_RESOURCES;

                    break;
                }
            }

            internals = extension->InternalsInfo;

            //
            //  copy the input buffer of internals info to the device
            //  extensions internals info member.
            //
            RtlCopyMemory(internals, input_buffer, input_buffer_length);

            //
            //  dump the internals info the kd.
            //

            int_dump_internals_info(internals);

            //
            //  perform some basic sanity checks on the internals info.
            //

            int_validate_internals_info(internals);

            //
            //  initialize our zeroing context with the routines/variables
            //  required for zeroing (and then some).
            //

            g_ZeroingThreadContext.KeWaitForGate                  = \
                (KeWaitForGate_t) internals->KeWaitForGate.Va;
            g_ZeroingThreadContext.MiInsertPageInFreeOrZeroedList = \
                (MiInsertPageInFreeOrZeroedList_t)                  \
                    internals->MiInsertPageInFreeOrZeroedList.Va;
            g_ZeroingThreadContext.MiMapPageInHyperSpaceWorker    = \
                (MiMapPageInHyperSpaceWorker_t)                     \
                    internals->MiMapPageInHyperSpaceWorker.Va;
            g_ZeroingThreadContext.MiRemoveAnyPage                = \
                (MiRemoveAnyPage_t) internals->MiRemoveAnyPage.Va;
            g_ZeroingThreadContext.MiUnmapPageInHyperSpaceWorker  = \
                (MiUnmapPageInHyperSpaceWorker_t)                   \
                    internals->MiUnmapPageInHyperSpaceWorker.Va;
            g_ZeroingThreadContext.MiZeroingDisabled              = \
                (ULONG *) internals->MiZeroingDisabled.Va;
            g_ZeroingThreadContext.MmFreePageListHead             = \
                (MMPFNLIST *) internals->MmFreePageListHead.Va;
            g_ZeroingThreadContext.MmZeroingPageGate              = \
                (KGATE *) internals->MmZeroingPageGate.Va;

            status                                                = \
                STATUS_SUCCESS;

            break;
        }

#if (DBG == 1)
        //
        //  This is just used for debugging and should never be called in
        //  production.
        //

        case UXENZEROSHARE_IOCTL_TERMINATE_ZEROING_THREAD: {
            UXENZEROSHARE_DUMP((
                "  UXENZEROSHARE_IOCTL_TERMINATE_ZEROING_THREAD: "
                "input_buffer_length==%u (0x%.08X), "
                "output_buffer_length==%u (0x%.08X)\n",
                input_buffer_length,
                input_buffer_length,
                output_buffer_length,
                output_buffer_length
                ));

            Irp->IoStatus.Information = 0;

            UXENZEROSHARE_ASSERT((input_buffer_length == 0));
            UXENZEROSHARE_ASSERT((output_buffer_length == 0));

            //
            //  If the thread exists (PKTHREAD != 0) and the zeroing
            //  termination event exists, signal the eventto kill the thread
            //  (by calling stop_zeroing_thread).
            //

            if ((g_ZeroingThreadContext.Thread) &&
                (g_ZeroingThreadContext.EventExtant)) {
                UXENZEROSHARE_DUMP((
                    "  attempting to stop zeroing thread...\n"
                    ));
                zt_stop_zeroing_thread(& g_ZeroingThreadContext);
                UXENZEROSHARE_DUMP(("  zeroing thread stopped...\n"));
            }
            else {
                UXENZEROSHARE_DUMP((
                    "  zeroing thread/zeroing thread termination event(s) not "
                    "extant\n"
                    ));
            }

            status = STATUS_SUCCESS;

            break;
        }
#endif

        default: {
            UXENZEROSHARE_DUMP(("ERROR: unrecognized IOCTL %x\n", ioctl));

            status = STATUS_INVALID_DEVICE_REQUEST;

            break;
        }
    }

    Irp->IoStatus.Status = status;

    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return status;
}

//
//  DriverUnload()
//

void
DriverUnload(DRIVER_OBJECT * Driver)
{
    DEVICE_OBJECT       * device                = Driver->DeviceObject;
    UNICODE_STRING        user_mode_device_name = \
        RTL_CONSTANT_STRING(L"\\DosDevices\\" UXENZEROSHARE_DEVICE_NAME);

    UXENZEROSHARE_ENTER();
    UXENZEROSHARE_ASSERT((Driver != 0));
    
    if (g_ZeroingThreadContext.Thread) {
        UXENZEROSHARE_DUMP(("  stopping zeroing thread...\n"));

        //
        //  Make sure to stop/terminate the zeroing thread before we unload or
        //  else we'll definitely BSOD.
        //
        //  This also implicitly restores the original zeroing thread.
        //

        zt_stop_zeroing_thread(& g_ZeroingThreadContext);
    
        UXENZEROSHARE_DUMP(("  zeroing thread stopped...\n"));

        UXENZEROSHARE_DUMP(("  enabling system zeroing thread...\n"));

        zt_enable_system_zeroing_thread(& g_ZeroingThreadContext, TRUE);
    }
    else {
        UXENZEROSHARE_DUMP(("  zeroing thread not running...\n"));
    }

    IoDeleteSymbolicLink(& user_mode_device_name);

    UXENZEROSHARE_ASSERT((device != 0));

    if (device) {
        delete_device(device);
    }

    return;
}

//
//  DriverEntry()
//

NTSTATUS
DriverEntry(DRIVER_OBJECT * Driver, UNICODE_STRING * ServicesKey)
{
    DEVICE_OBJECT       *   device;
    UNICODE_STRING          kernel_mode_device_name = \
        RTL_CONSTANT_STRING(L"\\Device\\" UXENZEROSHARE_DEVICE_NAME);
    NTSTATUS                status;
    UNICODE_STRING          user_mode_device_name   = \
        RTL_CONSTANT_STRING(L"\\DosDevices\\" UXENZEROSHARE_DEVICE_NAME);

    UXENZEROSHARE_ENTER();
    UXENZEROSHARE_UNREFERENCED(ServicesKey);

    Driver->MajorFunction[IRP_MJ_CLOSE]          = irp_mj_close;
    Driver->MajorFunction[IRP_MJ_CREATE]         = irp_mj_create;
    Driver->MajorFunction[IRP_MJ_DEVICE_CONTROL] = irp_mj_device_control;
    Driver->DriverUnload                         = DriverUnload;

    status  = create_device(
        & device,
          Driver,
        & kernel_mode_device_name,
        & user_mode_device_name
        );

    if (! NT_SUCCESS(status)) {
        UXENZEROSHARE_DUMP(("  couldn't create device: 0x%.08X\n", status));

        return status;
    }

    return status;
}

//
//  uxenzeroshare: uxenzeroshare.c
//
