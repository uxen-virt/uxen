/*
 *  uxen_hiber.c
 *  uxen
 *
 * Copyright 2013-2015, Bromium, Inc.
 * Author: Kris Uchronski <kuchronski@gmail.com>
 * SPDX-License-Identifier: ISC
 * 
 */

#include "uxen.h"

#include <ntddk.h>
#include <wdmsec.h>

PIRP wait_for_s4_irp = NULL;
PIRP wait_for_resume_from_s4_irp = NULL;
LONG s4_in_progress = FALSE;
KEVENT continue_power_transition_event;

BOOLEAN uxen_hibernation_enabled = FALSE;

typedef struct SERVICE_DESCRIPTOR_ENTRY {
    void        **ServiceTableBase;
    uint32_t    *ServiceCounterTableBase;
    uint32_t    NumberOfServices;
    uint8_t     *ParamTableBase;
    uint32_t    unknown[16];
} SERVICE_DESCRIPTOR_ENTRY,*PSERVICE_DESCRIPTOR_ENTRY;
__declspec(dllimport) SERVICE_DESCRIPTOR_ENTRY KeServiceDescriptorTable[4];

typedef NTSTATUS NTSETSYSTEMPOWERSTATE(POWER_ACTION SystemAction, 
                                       SYSTEM_POWER_STATE MinSystemState,
                                       ULONG Flags);
typedef NTSTATUS NTPOWERINFORMATION(
    POWER_INFORMATION_LEVEL PowerInformationLevel,
    PVOID InputBuffer, ULONG InputBufferLength,
    PVOID OutputBuffer, ULONG OutputBufferLength);

static uint32_t saved_hibernation_state = TRUE;

typedef VOID KECLEAREVENT(PRKEVENT);
typedef LONG KESETEVENT(PRKEVENT, KPRIORITY, BOOLEAN);
typedef NTSTATUS KEWAITFORSINGLEOBJECT(PVOID, KWAIT_REASON, KPROCESSOR_MODE,
                                       BOOLEAN, PLARGE_INTEGER);

struct stub_lock {
    KEVENT lock_event;
    KEVENT no_readers_event;
    volatile uint32_t readers_cnt;
};

struct stub_info {
    volatile uint32_t magic;
    volatile uint32_t stub_size;

    struct stub_info *self;

    KECLEAREVENT *KeClearEvent;
    KESETEVENT *KeSetEvent;
    KEWAITFORSINGLEOBJECT *KeWaitForSingleObject;

    NTSETSYSTEMPOWERSTATE *nt_NtSetSystemPowerState;
    NTSETSYSTEMPOWERSTATE *impl_NtSetSystemPowerState;

    struct stub_lock lock;
};
C_ASSERT(0 == FIELD_OFFSET(struct stub_info, magic));
C_ASSERT(4 == FIELD_OFFSET(struct stub_info, stub_size));

static const ULONG stub_size = 1 << PAGE_SHIFT;
static const ULONG stub_func_size = 768;
static struct stub_info *stub_data = NULL;
static BOOLEAN unmap_stub_data = FALSE;

static NTSTATUS __stdcall
uxen_NtSetSystemPowerState(POWER_ACTION SystemAction,
                           SYSTEM_POWER_STATE MinSystemState,
                           ULONG Flags)
{
    NTSTATUS status;
    WORK_QUEUE_ITEM *work_item;
    LARGE_INTEGER timeout;
    PIRP irp;

    if (PowerSystemHibernate == MinSystemState) {
        InterlockedExchange(&s4_in_progress, TRUE);
        irp = InterlockedExchangePointer(&wait_for_s4_irp, NULL);
        if (irp && IoSetCancelRoutine(irp, NULL)) {
            /* notify user mode that transition to S4 has been requested */
            dprintk("uxen hiber: about to enter to S4, notify UM (%p)\n", irp);
            irp->IoStatus.Status = STATUS_SUCCESS;
            irp->IoStatus.Information = 0;
            IoCompleteRequest(irp, IO_NO_INCREMENT);

            /* wait for user mode to do whatever pre-hibernation cleanup 
             * it requires or timeout */
            dprintk("uxen hiber: waiting for UM to finish "
                    "pre-hibernation cleanup\n");
            timeout.QuadPart = TIME_RELATIVE(TIME_MS(60 * 1000));
            status = KeWaitForSingleObject(&continue_power_transition_event,
                                           Executive, KernelMode, FALSE,
                                           &timeout);
            if (!NT_SUCCESS(status) || STATUS_TIMEOUT == status)
                fail_msg("wait failed: %08x", status);
            else
                dprintk("uxen hiber: pre-hibernation cleanup completed\n");
        } else
            printk("uxen hiber: notification request already completed (%p)\n",
                   irp);
    }

    return stub_data->nt_NtSetSystemPowerState(SystemAction,
                                               MinSystemState,
                                               Flags);
}

#pragma runtime_checks("", off)
#pragma optimize("", off)

#define stub_lock_initialize(_sd) do {                                        \
    KeInitializeEvent(&_sd->lock.lock_event, SynchronizationEvent, TRUE);     \
    KeInitializeEvent(&_sd->lock.no_readers_event, NotificationEvent, TRUE);  \
    _sd->lock.readers_cnt = 0;                                                \
} while (0, 0)

#define stub_lock_acquire(_sd, exclusive) do {                                \
    if (exclusive) {                                                          \
        while (1, 1) {                                                        \
            _sd->KeWaitForSingleObject(&_sd->lock.lock_event,                 \
                                       Executive, KernelMode, FALSE, NULL);   \
            if (0 == _sd->lock.readers_cnt)                                   \
                break;                                                        \
            _sd->KeSetEvent(&_sd->lock.lock_event, IO_NO_INCREMENT, FALSE);   \
            _sd->KeWaitForSingleObject(&_sd->lock.no_readers_event,           \
                                       Executive, KernelMode, FALSE, NULL);   \
        }                                                                     \
    } else {                                                                  \
        _sd->KeWaitForSingleObject(&_sd->lock.lock_event,                     \
                                   Executive, KernelMode, FALSE, NULL);       \
        _sd->KeClearEvent(&_sd->lock.no_readers_event);                       \
        _InterlockedIncrement(&_sd->lock.readers_cnt);                        \
        _sd->KeSetEvent(&_sd->lock.lock_event, IO_NO_INCREMENT, FALSE);       \
    }                                                                         \
} while (0, 0)

#define stub_lock_release(_sd, exclusive) do {                                \
    if (exclusive)                                                            \
        _sd->KeSetEvent(&_sd->lock.lock_event, IO_NO_INCREMENT, FALSE);       \
    else {                                                                    \
        _sd->KeWaitForSingleObject(&_sd->lock.lock_event,                     \
                                   Executive, KernelMode, FALSE, NULL);       \
        if (0 == _InterlockedDecrement(&_sd->lock.readers_cnt))               \
            _sd->KeSetEvent(&_sd->lock.no_readers_event,                      \
                            IO_NO_INCREMENT, FALSE);                          \
        _sd->KeSetEvent(&_sd->lock.lock_event, IO_NO_INCREMENT, FALSE);       \
    }                                                                         \
} while (0, 0)

static NTSTATUS __stdcall
stub_NtSetSystemPowerState(POWER_ACTION SystemAction,
                           SYSTEM_POWER_STATE MinSystemState,
                           ULONG Flags)
{
    struct stub_info *sd;
    NTSTATUS status;

    /* stub_data structure is at the very beginning of the same page on which
       this code is located */
    __asm {
        call    load_eip
        jmp     done
      load_eip:
        mov     eax, [esp]
        ret
      done:
        and     eax, 0xfffff000
        mov     sd, eax
    }

    stub_lock_acquire(sd, 0);

    status = sd->impl_NtSetSystemPowerState(SystemAction,
                                            MinSystemState, Flags);

    stub_lock_release(sd, 0);

    return status;
}

#pragma optimize("", on)
#pragma runtime_checks("", restore)

static void *
patch_system_service(uint32_t service_number,
                     void *new_service)
{
    uint32_t service_table = service_number >> 12;
    uint32_t service_index = service_number & 0xfff;
    void **service_entry;
    void *old_service;

    /* only main system service table is supported */
    ASSERT(0 == service_table);

    /* switch WP off */
    _asm {
        mov     eax, cr0
        and     eax, not 0x000010000
        mov     cr0, eax
    }

    service_entry = &KeServiceDescriptorTable[service_table].
        ServiceTableBase[service_index];

    old_service = InterlockedExchangePointer(service_entry, new_service);

    dprintk("uxen hiber: patched entry %p(%p) with %p\n",
            service_entry, old_service, new_service);

    /* switch WP back on */
    __asm {
        mov     eax, cr0
        or      eax, 0x000010000
        mov     cr0, eax
    }

    return old_service;
}

static int
enable_hooking()
{
    const ULONG stub_magic = 0xD377050FUL;
    const ULONG range_size = 16 << 20;

    NTSTATUS status;
    PHYSICAL_ADDRESS phys_addr;
    struct stub_info *page_addr;
    ULONG *max_addr, *base_addr;
    int ret;
    MDL *mdl = NULL;
    void *stub_func_addr;

    /* check if stub region already exists */
    phys_addr.QuadPart = 0;
    base_addr = MmMapIoSpace(phys_addr, range_size, MmCached);
    if (!base_addr) {
        fail_msg("failed to map first %x bytes of physical space",
                 range_size);
        ret = -1;
        goto out;
    }
    max_addr = (ULONG *)((ULONG_PTR)base_addr + range_size);
    page_addr = (struct stub_info *)base_addr;
    while ((ULONG *)page_addr < max_addr) {
        if (page_addr->magic == stub_magic &&
            page_addr->stub_size == stub_size &&
            page_addr->self &&
            page_addr->KeWaitForSingleObject == KeWaitForSingleObject)
            break;
        page_addr = (struct stub_info *)((ULONG_PTR)page_addr + PAGE_SIZE);
    }

    if ((ULONG *)page_addr < max_addr) {
        /* it exists - extract its address */
        stub_data = ((struct stub_info *)page_addr)->self;
        printk("uxen hiber: found stub region: %I64x(%p)\n",
               MmGetPhysicalAddress(stub_data).QuadPart, stub_data);

    } else {

        /* it doesn't exists - allocate it and create new mapping */
        phys_addr.QuadPart = range_size - stub_size;
        page_addr = MmAllocateContiguousMemory(stub_size, phys_addr);
        if (!page_addr) {
            fail_msg("failed to allocate %x bytes below %08x for stub region",
                     stub_size, range_size);
            ret = -1;
            goto out;
        }
        phys_addr = MmGetPhysicalAddress(page_addr);
        stub_data = MmMapIoSpace(phys_addr, stub_size, MmCached);
        printk("uxen hiber: stub region allocated: %I64x(%p)\n",
               phys_addr.QuadPart, stub_data);

        /* set RWX on stub region */
        mdl = IoAllocateMdl(stub_data, stub_size, FALSE, FALSE, NULL);
        if (!mdl) {
            fail_msg("failed to allocate MDL");
            ret = -1;
            goto out;
        }
        MmBuildMdlForNonPagedPool(mdl);
        mdl->MdlFlags |= MDL_MAPPED_TO_SYSTEM_VA;
        status = MmProtectMdlSystemAddress(mdl, PAGE_EXECUTE_READWRITE);
        if (!NT_SUCCESS(status)) {
            fail_msg("MmProtectMdlSystemAddress(%p:%p) failed: %08x",
                     mdl, stub_data, status);
            ret = -1;
            goto out;
        }

        /* initialize stub struct */
        stub_data->self = stub_data;

        stub_lock_initialize(stub_data);

        stub_data->magic = stub_magic;
        stub_data->stub_size = stub_size;

        stub_data->KeSetEvent = KeSetEvent;
        stub_data->KeClearEvent = KeClearEvent;
        stub_data->KeWaitForSingleObject = KeWaitForSingleObject;

        /* copy stub functions */
        stub_func_addr = 
            (void *)((ULONG_PTR)stub_data + sizeof(*stub_data) + sizeof(ULONG));
        memcpy(stub_func_addr, stub_NtSetSystemPowerState, stub_func_size);
        stub_data->nt_NtSetSystemPowerState =
            patch_system_service(0x15f, stub_func_addr);
    }

    stub_lock_acquire(stub_data, 1);

    /* setup our versions of system calls */
    stub_data->impl_NtSetSystemPowerState = uxen_NtSetSystemPowerState;

    stub_lock_release(stub_data, 1);

    ret = 0;

  out:
    if (mdl)
        IoFreeMdl(mdl);
    if (base_addr)
        MmUnmapIoSpace(base_addr, range_size);

    return ret;
}

static void
disable_hooking()
{

    stub_lock_acquire(stub_data, 1);

    /* revert to original system calls */
    stub_data->impl_NtSetSystemPowerState = stub_data->nt_NtSetSystemPowerState;

    stub_lock_release(stub_data, 1);
}

int
uxen_hibernation_init(void)
{
    int ret = 0;

    if (uxen_hibernation_enabled) {
        dprintk("uxen hiber: power services already patched\n");
        return -1;
    }

    KeInitializeEvent(&continue_power_transition_event,
                      SynchronizationEvent, FALSE);

    if (0 == enable_hooking()) {
        uxen_hibernation_enabled = TRUE;
        printk("uxen hiber: power services patched\n");
    } else {
        fail_msg("uxen hiber: failed to patch power services");
        ret = -1;
    }

    return ret;
}

void
uxen_hibernation_cleanup(void)
{

    if (!uxen_hibernation_enabled)
        return;

    disable_hooking();
    printk("uxen hiber: power services restored\n");

    uxen_hibernation_enabled = FALSE;
}

void
hiber_cancel_routine(__inout PDEVICE_OBJECT devobj,
                     __in __drv_useCancelIRQL PIRP irp)
{

    UNREFERENCED_PARAMETER(devobj);

    IoReleaseCancelSpinLock(irp->CancelIrql);

    if (irp == InterlockedCompareExchangePointer(&wait_for_s4_irp,
                                                 NULL, irp) ||
        irp == InterlockedCompareExchangePointer(&wait_for_resume_from_s4_irp,
                                                 NULL, irp)) {
        irp->IoStatus.Status = STATUS_CANCELLED;
        irp->IoStatus.Information = 0;
        IoCompleteRequest(irp, IO_NO_INCREMENT);
        dprintk("uxen hiber: IRP:%p has been cancelled\n", irp);
    } else
        ASSERT(FALSE);
}

NTSTATUS
uxen_shutdown(__inout DEVICE_OBJECT *devobj, __inout IRP *irp)
{
    int ret;
    NTSTATUS status;

    UNREFERENCED_PARAMETER(devobj);

    if (uxen_hibernation_enabled) {
        /* invalidate stub header */
        stub_data->magic = 0xffccddee;
        stub_data->stub_size = 0;
        stub_data->self = NULL;
    }

    status = STATUS_SUCCESS;
    irp->IoStatus.Status = status;
    IoCompleteRequest(irp, IO_NO_INCREMENT);

    return status;
}
