/*
 *  uxen.c
 *  uxen
 *
 * Copyright 2011-2017, Bromium, Inc.
 * Author: Christian Limpach <Christian.Limpach@gmail.com>
 * SPDX-License-Identifier: ISC
 * 
 */

#include "uxen.h"

#include <ntddk.h>
#include <ntstrsafe.h>
#include <wdmsec.h>

#define uxen_driver_load DriverEntry
DRIVER_INITIALIZE uxen_driver_load;
DRIVER_UNLOAD uxen_driver_unload;
__drv_dispatchType(IRP_MJ_CREATE)
DRIVER_DISPATCH uxen_create;
__drv_dispatchType(IRP_MJ_CLOSE)
DRIVER_DISPATCH uxen_close;
__drv_dispatchType(IRP_MJ_CLEANUP)
DRIVER_DISPATCH uxen_cleanup;

DECLSPEC_IMPORT void uxen_v4vlib_init_driver_hook(PDRIVER_OBJECT pdo);
DECLSPEC_IMPORT void uxen_v4vlib_free_driver_unhook(void );


struct device_extension *uxen_devext = NULL;
DRIVER_OBJECT *uxen_drvobj = NULL;

static KGUARDED_MUTEX uxen_mutex;

uint8_t *uxen_hv = NULL;
size_t uxen_size = 0;

#include <initguid.h>
//
// Since this driver is a legacy driver and gets installed as a service
// (without an INF file),  we will define a class guid for use in
// IoCreateDeviceSecure function. This would allow  the system to store
// Security, DeviceType, Characteristics and Exclusivity information of the
// deviceobject in the registery under
// HKLM\SYSTEM\CurrentControlSet\Control\Class\ClassGUID\Properties.
// This information can be overridden by an Administrator giving them the
// ability to control access to the device beyond what is initially allowed
// by the driver developer.
//
DEFINE_GUID (GUID_DEVCLASS_UXEN, /* dfe2c083-e564-4eb8-ba3a-4e1f125d605e */
	     0xdfe2c083,
	     0xe564,
	     0x4eb8,
	     0xba, 0x3a, 0x4e, 0x1f, 0x12, 0x5d, 0x60, 0x5e);

NTSTATUS
uxen_create(__in PDEVICE_OBJECT DeviceObject, __in PIRP Irp)
{
    PIO_STACK_LOCATION IrpSp = IoGetCurrentIrpStackLocation(Irp);
    PEPROCESS process;
    PACCESS_TOKEN token;
    struct fd_assoc *fda;
    NTSTATUS status;

    /* dprintk("%s: %p\n", __FUNCTION__, &IrpSp->FileObject->FsContext); */

    fda = associate_fd_assoc(&IrpSp->FileObject->FsContext);
    if (!fda) {
        status = STATUS_NO_MEMORY;
        fail_msg("associate_fd_assoc failed");
        goto out;
    }
    fda->admin_access = FALSE;

    process = IoGetRequestorProcess(Irp);
    if (!process)
        process = IoGetCurrentProcess();

    token = PsReferencePrimaryToken(process);
    if (token) {
        if (SeTokenIsAdmin(token) == TRUE)
            fda->admin_access = TRUE;
        PsDereferencePrimaryToken(token);
    }

    status = STATUS_SUCCESS;

  out:
    Irp->IoStatus.Information = 0;
    Irp->IoStatus.Status = status;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    /* dprintk("%s: %p done\n", __FUNCTION__, &IrpSp->FileObject->FsContext); */

    return status;
}

NTSTATUS
uxen_close(__in PDEVICE_OBJECT DeviceObject, __in PIRP Irp)
{
    PIO_STACK_LOCATION IrpSp = IoGetCurrentIrpStackLocation(Irp);

    /* dprintk("%s: %p\n", __FUNCTION__, &IrpSp->FileObject->FsContext); */

    final_release_fd_assoc(&IrpSp->FileObject->FsContext);

    Irp->IoStatus.Information = 0;
    Irp->IoStatus.Status = STATUS_SUCCESS;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    /* dprintk("%s: %p done\n", __FUNCTION__, &IrpSp->FileObject->FsContext); */

    return STATUS_SUCCESS;
}

NTSTATUS
uxen_cleanup(__in PDEVICE_OBJECT DeviceObject,
	    __in PIRP Irp)
{
    PIO_STACK_LOCATION IrpSp = IoGetCurrentIrpStackLocation(Irp);

    /* dprintk("%s: %p\n", __FUNCTION__, &IrpSp->FileObject->FsContext); */

    IrpSp = IoGetCurrentIrpStackLocation(Irp);
    release_fd_assoc(&IrpSp->FileObject->FsContext);

    Irp->IoStatus.Information = 0;
    Irp->IoStatus.Status = STATUS_SUCCESS;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    /* dprintk("%s: %p done\n", __FUNCTION__, &IrpSp->FileObject->FsContext); */

    return STATUS_SUCCESS;
}

static void
uxen_power(__in void *context, __in void *_arg1, __in void *_arg2)
{
    uintptr_t arg1 = (uintptr_t)_arg1;
    uintptr_t arg2 = (uintptr_t)_arg2;

    dprintk("%s\n", __FUNCTION__);

    switch (arg1) {
    case PO_CB_AC_STATUS:
        dprintk("PO_CB_AC_STATUS %s\n", arg2 ? "AC" : "BATT");
        break;
    case PO_CB_LID_SWITCH_STATE:
        dprintk("PO_CB_LID_SWITCH_STATE %s\n", arg2 ? "closed" : "open");
        break;
    case PO_CB_PROCESSOR_POWER_POLICY:
        dprintk("PO_CB_PROCESSOR_POWER_POLICY\n");
        break;
    case PO_CB_SYSTEM_POWER_POLICY:
        dprintk("PO_CB_PROCESSOR_POWER_POLICY\n");
        break;
    case PO_CB_SYSTEM_STATE_LOCK:
        dprintk("PO_CB_SYSTEM_STATE_LOCK %s S0\n", arg2 ? "enter" : "leave");
        uxen_power_state(arg2 ? 0 : 1);
        break;
    }

    dprintk("%s done\n", __FUNCTION__);
}

void
uxen_set_system_time(__in void *context, __in void *_arg1, __in void *_arg2)
{
    uintptr_t arg1 = (uintptr_t)_arg1;
    uintptr_t arg2 = (uintptr_t)_arg2;

    dprintk("%s\n", __FUNCTION__);

    uxen_update_unixtime_generation();

    dprintk("%s done\n", __FUNCTION__);
}

static NTSTATUS
reg_read_str(PUNICODE_STRING key_name, PWSTR val_name,
             PUNICODE_STRING out_val)
{
    NTSTATUS status;
    OBJECT_ATTRIBUTES obj_attr;
    HANDLE key;
    struct {
        KEY_VALUE_PARTIAL_INFORMATION info;
        UCHAR data[1];
    } *val = NULL;
    UNICODE_STRING val_name_us;
    ULONG val_len, bytes_read;

    ASSERT_IRQL(PASSIVE_LEVEL);

    InitializeObjectAttributes(&obj_attr, key_name,
                               OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
                               NULL, NULL);
    status = ZwOpenKey(&key, KEY_READ, &obj_attr);
    if (!NT_SUCCESS(status)) {
        fail_msg("ZwOpenKey([%wZ]) failed: 0x%08x", key_name, status);
        goto out;
    }

    val_len = sizeof(*val) + out_val->MaximumLength - 1;
    val = kernel_malloc(val_len);
    if (!val) {
        fail_msg("failed to allocate %d bytes", val_len);
        goto out;
    }

    RtlInitUnicodeString(&val_name_us, val_name);
    status = ZwQueryValueKey(key, &val_name_us, KeyValuePartialInformation,
                             val, val_len, &bytes_read);
    if ((!NT_SUCCESS(status) && status != STATUS_BUFFER_OVERFLOW) ||
        (val->info.Type != REG_SZ && val->info.Type != REG_EXPAND_SZ))
    {
        fail_msg("ZwQueryValueKey([%wZ:%wZ]) failed: 0x%08x",
                 key_name, &val_name_us, status);
        goto out;
    }

    status = RtlUnicodeStringCbCopyStringN(out_val, 
                                           (PWCHAR)&val->info.Data[0],
                                           val->info.DataLength);
    if (!NT_SUCCESS(status))
        fail_msg("RtlUnicodeStringCbCopyStringN() failed: 0x%08x", status);

  out:
    if (val)
        kernel_free(val, val_len);
    if (key)
        ZwClose(key);

    return status;
}

static
void print_uxen_drv_info(PUNICODE_STRING reg_path, char *caller)
{
    DECLARE_UNICODE_STRING_SIZE(uxen_path, 512);
    CHAR tmp[512];

    if (NT_SUCCESS(RtlStringCbPrintfA(tmp, sizeof(tmp), "%wZ", reg_path))) {
        printk("%s: reg: %s\n", caller, tmp);
        if (!NT_ERROR(reg_read_str(reg_path, L"ImagePath", &uxen_path)) &&
            NT_SUCCESS(RtlStringCbPrintfA(tmp, sizeof(tmp), "%wZ", &uxen_path)))
            printk("%s: bin: %s\n", caller, tmp);
    } else
        printk("%s\n", caller);
}

void
uxen_driver_unload(__in PDRIVER_OBJECT DriverObject)
{
    DEVICE_OBJECT *devobj;
    UNICODE_STRING devicename_dos;
    struct device_extension *devext;

    dprintk("uxen_driver_unload\n");

    /* We need to unhook first so that DeviceObject only contains one */
    /* thing */
    uxen_v4vlib_free_driver_unhook();

    devobj = DriverObject->DeviceObject;
    devext = devobj->DeviceExtension;

    uxen_unload();

    logging_free(NULL);

    mem_exit();

    if (devext->de_power_callback)
        ExUnregisterCallback(devext->de_power_callback);
    if (devext->de_power_callback_object)
        ObDereferenceObject(devext->de_power_callback_object);
    if (devext->de_system_time_callback)
        ExUnregisterCallback(devext->de_system_time_callback);
    if (devext->de_system_time_callback_object)
        ObDereferenceObject(devext->de_system_time_callback_object);

#ifdef __i386__
    IoUnregisterShutdownNotification(devobj);
    uxen_hibernation_cleanup();
#endif /* __i386__ */

    (void)RtlInitUnicodeString(&devicename_dos, UXEN_DEVICE_PATH_DOS_U);
    IoDeleteSymbolicLink(&devicename_dos);
    IoDeleteDevice(devobj);

    dprintk("uxen_driver_unload done\n");

    return;
}

NTSTATUS
uxen_driver_load(__in PDRIVER_OBJECT DriverObject,
                 __in PUNICODE_STRING RegistryPath)
{
    NTSTATUS status;
    UNICODE_STRING devicename, devicename_dos, secdesc, callback_name;
    OBJECT_ATTRIBUTES powerstate_attr;
    OBJECT_ATTRIBUTES setsystemtime_attr;
    DEVICE_OBJECT *devobj;
    struct device_extension *devext = NULL;

    ExInitializeDriverRuntime(DrvRtPoolNxOptIn);

    dprintk("uxen_driver_load\n");

    uxen_drvobj = DriverObject;

    (void)RtlInitUnicodeString(&devicename, UXEN_DEVICE_PATH_U);

    //
    // Refer
    // "Security Descriptor String Format" section in the platform
    // SDK documentation to understand the format of the sddl string.
    // We need to do because this is a legacy driver and there is no INF
    // involved in installing the driver. For PNP drivers, security descriptor
    // is typically specified for the FDO in the INF file.
    //
    // Security Descriptor
    //
    // D: means it's a DACL (Discretionary Access Control List), 
    // P  means it's protected.
    //
    // ACEs are enclosed in parameters and have 6 fields
    //  ACE type                                A       Allowed
    //  ACE flags                               .
    //  Permission                              GA      Generic All
    //  Object Type                             .
    //  Inherited Object Type                   .
    //  Trustee                                 BA      Built-in Administrators
    //
    // Details http://msdn.microsoft.com/en-us/library/aa379567(VS.85).aspx
    // http://blogs.dirteam.com/blogs/jorge/archive/2008/03/26/parsing-sddl-strings.aspx
    //

    (void)RtlInitUnicodeString(&secdesc,
			       L"D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GR;;;IU)");

    status = IoCreateDeviceSecure(DriverObject, sizeof(struct device_extension),
				  &devicename, FILE_DEVICE_UNKNOWN,
				  FILE_DEVICE_SECURE_OPEN, FALSE,
				  &secdesc, (LPCGUID)&GUID_DEVCLASS_UXEN,
				  &devobj);
    if (!NT_SUCCESS(status)) {
        fail_msg("IoCreateDeviceSecure failed: 0x%08X", status);
	return status;
    }

    (void)RtlInitUnicodeString(&devicename_dos, UXEN_DEVICE_PATH_DOS_U);

    status = IoCreateSymbolicLink(&devicename_dos, &devicename);
    if (!NT_SUCCESS(status)) {
        fail_msg("IoCreateSymbolicLink failed: 0x%08X", status);
        goto out;
    }

    devext = devobj->DeviceExtension;
    RtlZeroMemory(devext, sizeof(struct device_extension));

    uxen_devext = devext;

    DriverObject->MajorFunction[IRP_MJ_CREATE] = uxen_create;
    DriverObject->MajorFunction[IRP_MJ_CLOSE] = uxen_close;
    DriverObject->MajorFunction[IRP_MJ_CLEANUP] = uxen_cleanup;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = uxen_ioctl;
#ifdef __i386__
    DriverObject->MajorFunction[IRP_MJ_SHUTDOWN] = uxen_shutdown;
#endif /* __i386__ */

    DriverObject->DriverUnload = uxen_driver_unload;

    uxen_v4vlib_init_driver_hook(DriverObject);

    /* register for power state changes. */

    RtlInitUnicodeString(&callback_name, L"\\Callback\\PowerState");
    InitializeObjectAttributes(&powerstate_attr, &callback_name,
                               OBJ_CASE_INSENSITIVE, NULL, NULL);

    status = ExCreateCallback(&devext->de_power_callback_object,
                              &powerstate_attr, TRUE, TRUE);
    if (!NT_SUCCESS(status)) {
        fail_msg("ExCreateCallback(PowerState) failed: 0x%08X", status);
        goto out;
    }

    devext->de_power_callback = ExRegisterCallback(
        devext->de_power_callback_object, uxen_power, devext);
    if (!devext->de_power_callback) {
        fail_msg("ExRegisterCallback(PowerState) failed");
        status = STATUS_UNSUCCESSFUL;
        goto out;
    }

    /* register for system time changes. */

    RtlInitUnicodeString(&callback_name, L"\\Callback\\SetSystemTime");
    InitializeObjectAttributes(&setsystemtime_attr, &callback_name,
                               OBJ_CASE_INSENSITIVE, NULL, NULL);

    status = ExCreateCallback(&devext->de_system_time_callback_object,
                              &setsystemtime_attr, TRUE, TRUE);
    if (!NT_SUCCESS(status)) {
        fail_msg("ExCreateCallback(SetSystemTime) failed: 0x%08X", status);
        goto out;
    }

    devext->de_system_time_callback = ExRegisterCallback(
        devext->de_system_time_callback_object, uxen_set_system_time, devext);
    if (!devext->de_system_time_callback) {
        fail_msg("ExRegisterCallback(SetSystemTime) failed");
        status = STATUS_UNSUCCESSFUL;
        goto out;
    }

    KeInitializeGuardedMutex(&uxen_mutex);

#ifdef DBG
    if (pv_vmware())
        kdbgprint = 0;
#endif

    if (mem_init()) {
        fail_msg("mem_init failed");
        status = STATUS_UNSUCCESSFUL;
        goto out;
    }

    if (logging_init(NULL, 0)) {
        fail_msg("logging_init failed");
        status = STATUS_UNSUCCESSFUL;
        goto out;
    }

    print_uxen_drv_info(RegistryPath, "uxen_driver_load");

    rb_tree_init(&uxen_devext->de_vm_info_rbtree, &vm_info_rbtree_ops);

    uxen_devext->de_initialised = 0;
    KeInitializeEvent(&uxen_devext->de_init_done, NotificationEvent,
                      FALSE);
    KeInitializeEvent(&uxen_devext->de_shutdown_done, NotificationEvent, TRUE);

    KeInitializeEvent(&uxen_devext->de_vm_cleanup_event, NotificationEvent,
                      FALSE);

    KeInitializeEvent(&uxen_devext->de_resume_event, NotificationEvent,
                      FALSE);
    KeInitializeEvent(&uxen_devext->de_suspend_event, NotificationEvent,
                      FALSE);

  out:
    dprintk("uxen_driver_load done\n");

    if (!NT_SUCCESS(status)) {
        logging_free(NULL);
        mem_exit();
        if (devext) {
            if (devext->de_power_callback)
                ExUnregisterCallback(devext->de_power_callback);
            if (devext->de_power_callback_object)
                ObDereferenceObject(devext->de_power_callback_object);
            if (devext->de_system_time_callback)
                ExUnregisterCallback(devext->de_system_time_callback);
            if (devext->de_system_time_callback_object)
                ObDereferenceObject(devext->de_system_time_callback_object);
        }
        IoDeleteSymbolicLink(&devicename_dos);
        IoDeleteDevice(devobj);
        uxen_v4vlib_free_driver_unhook();
    }

    return status;
}

affinity_t
uxen_lock(void)
{
    affinity_t aff;

    aff = uxen_cpu_pin_current();
    KeAcquireGuardedMutex(&uxen_mutex);

    return aff;
}

void
uxen_unlock(affinity_t aff)
{
    KeReleaseGuardedMutex(&uxen_mutex);
    uxen_cpu_unpin(aff);
}

affinity_t
uxen_exec_dom0_start(void)
{

    return uxen_cpu_pin_current();
}

void
uxen_exec_dom0_end(affinity_t aff)
{

    uxen_cpu_unpin(aff);
}
