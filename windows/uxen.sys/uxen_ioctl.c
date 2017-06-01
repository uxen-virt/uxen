/*
 *  uxen_ioctl.c
 *  uxen
 *
 * Copyright 2011-2017, Bromium, Inc.
 * Author: Christian Limpach <Christian.Limpach@gmail.com>
 * SPDX-License-Identifier: ISC
 * 
 */

#include "uxen.h"

#include <ntddk.h>
#include <xen/errno.h>
#include <xen/types.h>

#include <uxen_ioctl.h>

#define UXEN_DEFINE_SYMBOLS_PROTO
#include <uxen/uxen_link.h>

#if 0
#define IOCTL_TRACE(fmt, ...) dprintk(fmt, __VA_ARGS__)
#else
#define IOCTL_TRACE(fmt, ...)
#endif

static int uxen_mode;
#define UXEN_MODE_IDLE		0
#define UXEN_MODE_LOADED	1
#define UXEN_MODE_FAILED        2
#define UXEN_MODE_INITIALIZED	3
#define UXEN_MODE_SHUTDOWN      4

static struct fd_assoc *
lookup_fd_assoc(void *p)
{

    return *(struct fd_assoc **)p;
}

struct fd_assoc *
associate_fd_assoc(void *p)
{
    struct fd_assoc *fda;

    fda = lookup_fd_assoc(p);
    if (fda)
        return fda;

    fda = kernel_malloc(sizeof(struct fd_assoc));
    if (!fda) {
        fail_msg("kernel_malloc failed");
        return NULL;
    }

    KeInitializeGuardedMutex(&fda->user_malloc_mutex);
    KeInitializeSpinLock(&fda->user_mappings.lck);
    fda->file_creator = PsGetCurrentProcess();
    fda->file_creator_pid = PsGetCurrentProcessId();

    *(struct fd_assoc **)p = fda;

    return fda;
}

static void
prepare_release_fd_assoc(struct fd_assoc *fda)
{

    MemoryBarrier();
    if (fda->user_mappings.initialized) {
        user_free_all_user_mappings(fda);
        fda->user_mappings.initialized = FALSE;
    }
}

void
release_fd_assoc(void *p)
{
    struct fd_assoc *fda;
    struct vm_info *vmi;
    affinity_t aff;

    fda = lookup_fd_assoc(p);
    if (!fda)
        return;

    /* unmap logging buffer before freeing vmi,
     * in case logging is per-vm logging */
    if (fda->logging_mapping.user_mapping) {
        logging_unmap(&fda->logging_mapping, fda);
        fda->logging_mapping.user_mapping = NULL;
    }

    aff = uxen_lock();
    vmi = fda->vmi;
    if (vmi) {
        if (vmi->vmi_mdm_fda == fda)
            mdm_clear_all(vmi);
        prepare_release_fd_assoc(fda);
        if (fda->vmi_destroy_on_close)
            vmi->vmi_marked_for_destroy = 1;
    } else
        prepare_release_fd_assoc(fda);

    uxen_unlock(aff);
}

void
final_release_fd_assoc(void *p)
{
    struct fd_assoc *fda;
    struct vm_info *vmi;
    affinity_t aff;

    fda = lookup_fd_assoc(p);
    if (!fda)
        return;

    aff = uxen_lock();
    vmi = fda->vmi;
    if (vmi) {
        printk("%s: vm%u refs %d\n", __FUNCTION__,
               vmi->vmi_shared.vmi_domid, vmi->vmi_active_references);
        uxen_vmi_cleanup_vm(vmi);
        uxen_vmi_free(vmi);
        fda->vmi = NULL;
    } else
        printk("%s: no vmi\n", __FUNCTION__);
    uxen_unlock(aff);

    kernel_free(fda, sizeof(struct fd_assoc));
    *(struct fd_assoc **)p = NULL;
}

#define IOCTL_STATUS(s) do {			\
	IoStatus->Status = s;			\
    } while (0)
#define IOCTL_FAILURE(s, fmt, ...) do {		\
	IOCTL_STATUS(s);			\
	fail_msg(fmt, __VA_ARGS__);		\
	ret = -1;				\
    } while (0)

#define IOCTL_ADMIN_CHECK(id) do {                                      \
        if (!fda->admin_access) {                                       \
            IOCTL_FAILURE(UXEN_NTSTATUS_FROM_ERRNO(EPERM),              \
                          "(" id "): access denied");                   \
            goto out;                                                   \
        }                                                               \
    } while (0)

#define IOCTL_VM_ADMIN_CHECK(id) do {                                   \
        if (!fda->admin_access && !fda->vmi_owner) {                    \
            IOCTL_FAILURE(UXEN_NTSTATUS_FROM_ERRNO(EPERM),              \
                          "(" id "): access denied");                   \
            goto out;                                                   \
        }                                                               \
    } while (0)

#define SET_UXEN_MODE(m)			\
    uxen_mode = (m);
#define UXEN_CHECK_MODE(m, id) do {					\
	if (uxen_mode < (m)) {						\
            IOCTL_FAILURE(UXEN_NTSTATUS_FROM_ERRNO(EINVAL),             \
                          "(" id "): invalid sequence");                \
	    goto out;							\
	}								\
    } while (0)
#define UXEN_CHECK_MODE_NOT(m, id) do {					\
        if (uxen_mode >= (m))                                           \
	    goto out;							\
    } while (0)

#define UXEN_CHECK_INPUT_BUFFER(name, arg) do {				\
	if (InputBufferLength < sizeof(arg) || InputBuffer == NULL) {	\
	    IOCTL_FAILURE(UXEN_NTSTATUS_FROM_ERRNO(EINVAL),		\
                          "(" name "): input arguments");               \
	    goto out;							\
	}								\
    } while (0)

#define UXEN_CHECK_OUTPUT_BUFFER(name, arg) do {			\
	if (OutputBufferLength < sizeof(arg) || OutputBuffer == NULL) {	\
	    IOCTL_FAILURE(UXEN_NTSTATUS_FROM_ERRNO(EINVAL),		\
                          "(" name "): output arguments");              \
	    goto out;							\
	}								\
    } while (0)

#define UXEN_CHECK_VMI(name, vmi) do {                                  \
        if (!vmi) {                                                     \
            IOCTL_FAILURE(UXEN_NTSTATUS_FROM_ERRNO(EEXIST),             \
                          "(" name "): no target vm");                  \
	    goto out;							\
	}								\
    } while (0)

static int
init_fd_assoc_user_mappings(const char *ident, struct fd_assoc *fda)
{
    int rc = 0;
    KIRQL old_irql;

    if (!fda->user_mappings.initialized) {
        KeAcquireSpinLock(&fda->user_mappings.lck, &old_irql);
        if (!fda->user_mappings.initialized) {
            rb_tree_init(&fda->user_mappings.rbtree,
                         &user_mapping_rbtree_ops);
            fda->user_mappings.initialized = TRUE;
        }
        KeReleaseSpinLock(&fda->user_mappings.lck, old_irql);
    }

    return rc;
}

#define OP_CALL(name, fn, arg, ...) do {                                \
	IOCTL_TRACE("uxen_ioctl(" name ", %p, %x)\n", InputBuffer,	\
		    InputBufferLength);					\
	UXEN_CHECK_MODE(UXEN_MODE_INITIALIZED, name);			\
	UXEN_CHECK_INPUT_BUFFER(name, arg);				\
        ret = fn((arg *)InputBuffer, __VA_ARGS__);                      \
        if (ret)                                                        \
            IOCTL_FAILURE(UXEN_NTSTATUS_FROM_ERRNO(ret),                \
                          "uxen_ioctl(" name ") fail: %d", ret);        \
    } while (0)

#define DOM0_CALL(name, fn, arg, ...) do {                              \
	IOCTL_TRACE("uxen_ioctl(" name ", %p, %x)\n", InputBuffer,	\
		    InputBufferLength);					\
	UXEN_CHECK_MODE(UXEN_MODE_INITIALIZED, name);			\
	UXEN_CHECK_INPUT_BUFFER(name, arg);				\
        ret = fn((arg *)InputBuffer, __VA_ARGS__);                      \
        if (ret < 0)                                                    \
            IOCTL_FAILURE(UXEN_NTSTATUS_FROM_ERRNO(-ret),		\
                          "uxen_ioctl(" name ") fail: %d", -ret);       \
    } while (0)

#define ICC(ctl) ((ctl) & ((1ULL << UXEN_IOCTL_SIZE_SHIFT) - 1))

static VOID
processexit_cancel_routine(__inout PDEVICE_OBJECT pDeviceObject,
                           __in __drv_useCancelIRQL PIRP pIRP)
{
    IO_STATUS_BLOCK *IoStatus = &pIRP->IoStatus;
    struct fd_assoc *fda;

    printk("%s\n", __FUNCTION__);

    IoReleaseCancelSpinLock(pIRP->CancelIrql);

    fda = pIRP->Tail.Overlay.DriverContext[3];
    if (fda && fda->vmi) {
        if (fda->vmi_destroy_on_close)
            uxen_destroy_vm(fda->vmi);
        else
            fail_msg("vmi_destroy_on_close not set");
    }
    pIRP->Tail.Overlay.DriverContext[3] = NULL;

    IoStatus->Status = STATUS_CANCELLED;
    IoStatus->Information = 0;
    IoCompleteRequest(pIRP, IO_NO_INCREMENT);

    printk("%s done\n", __FUNCTION__);
}

static BOOLEAN is_restricted_caller()
{
    PACCESS_TOKEN Token;
    NTSTATUS Status;
    ULONG Level;

    Token = PsReferencePrimaryToken(PsGetCurrentProcess());
    Status = SeQueryInformationToken(Token, TokenIntegrityLevel,
                (PVOID)&Level);
    PsDereferencePrimaryToken(Token);

    if (!NT_SUCCESS(Status)) {
        fail_msg("SeQueryInformationToken returned 0x%x\n", Status);
        return TRUE;
    }

    if (Level < SECURITY_MANDATORY_MEDIUM_RID)
        return TRUE;
    else
        return FALSE;
}

NTSTATUS
uxen_ioctl(__inout DEVICE_OBJECT *DeviceObject, __inout IRP *pIRP)
{
    struct device_extension *devext;
    intptr_t ret = 0;
    struct fd_assoc *fda;
    struct vm_info *vmi;
    IO_STACK_LOCATION *pIoStack = IoGetCurrentIrpStackLocation(pIRP);
    VOID *InputBuffer = pIRP->AssociatedIrp.SystemBuffer;
    ULONG InputBufferLength =
        pIoStack->Parameters.DeviceIoControl.InputBufferLength;
    VOID *OutputBuffer = pIRP->AssociatedIrp.SystemBuffer;
    ULONG OutputBufferLength =
        pIoStack->Parameters.DeviceIoControl.OutputBufferLength;
    ULONG IoControlCode = pIoStack->Parameters.DeviceIoControl.IoControlCode;
    ULONG status;
    IO_STATUS_BLOCK *IoStatus = &pIRP->IoStatus;

    IoStatus->Status = STATUS_SUCCESS;
    IoStatus->Information = 0;

    devext = DeviceObject->DeviceExtension;

    if (METHOD_FROM_CTL_CODE(IoControlCode) != METHOD_BUFFERED) {
        IOCTL_FAILURE(STATUS_ACCESS_DENIED,
            "%s: method is not METHOD_BUFFERED", __FUNCTION__);
        goto out;
    }
    if (InputBufferLength < OutputBufferLength)
        memset((char *)OutputBuffer + InputBufferLength, 0,
               OutputBufferLength - InputBufferLength);

    if (is_restricted_caller()) {
        IOCTL_FAILURE(STATUS_ACCESS_DENIED,
            "%s: uxen_ioctl by a process with integrity<MEDIUM", __FUNCTION__);
        goto out;
    }
    fda = lookup_fd_assoc(&pIoStack->FileObject->FsContext);
    if (!fda) {
        IOCTL_FAILURE(UXEN_NTSTATUS_FROM_ERRNO(ENOMEM),
                      "%s: lookup_fd_assoc failed", __FUNCTION__);
        goto out;
    }
    if (fda->file_creator != PsGetCurrentProcess() ||
        fda->file_creator_pid != PsGetCurrentProcessId()) {
        IOCTL_FAILURE(STATUS_ACCESS_DENIED,
            "%s: caller is not CDO handle creator", __FUNCTION__);
        goto out;
    }
    vmi = fda->vmi;

    switch (IoControlCode) {
    case ICC(UXENVERSION):
	IOCTL_TRACE("uxen_ioctl(UXENVERSION, %p, %x)\n", OutputBuffer,
		    OutputBufferLength);
        IOCTL_ADMIN_CHECK("UXENVERSION");
	UXEN_CHECK_OUTPUT_BUFFER("UXENVERSION", struct uxen_version_desc);
        ret = uxen_op_version((struct uxen_version_desc *)OutputBuffer);
        if (ret < 0)
            IOCTL_FAILURE(UXEN_NTSTATUS_FROM_ERRNO(-ret),
                          "uxen_ioctl(UXENVERSION) fail: %d", -ret);
	break;
    case ICC(UXENLOAD):
	IOCTL_TRACE("uxen_ioctl(UXENLOAD, %p, %x)\n", InputBuffer,
		    InputBufferLength);
#if !defined(__UXEN_EMBEDDED__)
	UXEN_CHECK_MODE_NOT(UXEN_MODE_LOADED, "UXENLOAD");
        UXEN_CHECK_INPUT_BUFFER("UXENLOAD", struct uxen_load_desc);
        IOCTL_ADMIN_CHECK("UXENLOAD");
        ret = uxen_load((struct uxen_load_desc *)InputBuffer);
        if (ret == 0)
            SET_UXEN_MODE(UXEN_MODE_LOADED);
        else
            IOCTL_FAILURE(UXEN_NTSTATUS_FROM_ERRNO(-ret),
                          "uxen_ioctl(UXENLOAD) fail: %d", -ret);
#endif
	break;
    case ICC(UXENUNLOAD):
	IOCTL_TRACE("uxen_ioctl(UXENUNLOAD)\n");
	UXEN_CHECK_MODE(UXEN_MODE_LOADED, "UXENUNLOAD");
        IOCTL_ADMIN_CHECK("UXENUNLOAD");
	ret = uxen_unload();
	if (ret)
	    break;
	SET_UXEN_MODE(UXEN_MODE_IDLE);
	break;
    case ICC(UXENINIT):
	IOCTL_TRACE("uxen_ioctl(UXENINIT)\n");
	UXEN_CHECK_MODE_NOT(UXEN_MODE_FAILED, "UXENINIT");
#if !defined(__UXEN_EMBEDDED__)
	UXEN_CHECK_MODE(UXEN_MODE_LOADED, "UXENINIT");
#endif
        uxen_sys_start_v4v();
        /* uxen_op_init does UXEN_CHECK_INPUT_BUFFER(struct uxen_init_desc) */
        ret = uxen_op_init(fda, (struct uxen_init_desc *)InputBuffer,
                           InputBufferLength, DeviceObject);
	if (ret) {
            SET_UXEN_MODE(UXEN_MODE_FAILED);
            IOCTL_FAILURE(UXEN_NTSTATUS_FROM_ERRNO(-ret),
                          "uxen_ioctl(UXENINIT) fail: %d", -ret);
            break;
        }
        SET_UXEN_MODE(UXEN_MODE_INITIALIZED);
	break;
    case ICC(UXENSHUTDOWN):
	IOCTL_TRACE("uxen_ioctl(UXENSHUTDOWN)\n");
#if defined(__UXEN_EMBEDDED__)
	UXEN_CHECK_MODE_NOT(UXEN_MODE_SHUTDOWN, "UXENSHUTDOWN");
#endif
	UXEN_CHECK_MODE(UXEN_MODE_INITIALIZED, "UXENSHUTDOWN");
        IOCTL_ADMIN_CHECK("UXENSHUTDOWN");
	ret = uxen_op_shutdown();
	if (ret)
	    break;
        uxen_sys_stop_v4v();
#if !defined(__UXEN_EMBEDDED__)
        SET_UXEN_MODE(UXEN_MODE_LOADED);
#else
        SET_UXEN_MODE(UXEN_MODE_SHUTDOWN);
#endif
	break;
    case ICC(UXENPROCESSEXITHELPER): {
        KIRQL irql;
        UXEN_CHECK_MODE(UXEN_MODE_INITIALIZED, "UXENPROCESSEXITHELPER");
        pIRP->Tail.Overlay.DriverContext[3] = fda;
        IoAcquireCancelSpinLock(&irql);
        IoSetCancelRoutine(pIRP, processexit_cancel_routine);
        IoReleaseCancelSpinLock(irql);
        IoMarkIrpPending(pIRP);
        return STATUS_PENDING;
    }
    case ICC(UXENWAITVMEXIT):
        IOCTL_TRACE("uxen_ioctl(UXENWAITVMEXIT)\n");
        UXEN_CHECK_MODE(UXEN_MODE_LOADED, "UXENWAITVMEXIT");
        IOCTL_ADMIN_CHECK("UXENWAITVMEXIT");
        ret = uxen_op_wait_vm_exit();
        break;
    case ICC(UXENKEYHANDLER):
        IOCTL_ADMIN_CHECK("UXENKEYHANDLER");
        OP_CALL("UXENKEYHANDLER", uxen_op_keyhandler, char,
                InputBufferLength);
	break;
    case ICC(UXENHYPERCALL): {
        struct uxen_hypercall_desc *uhd =
            (struct uxen_hypercall_desc *)InputBuffer;
        IOCTL_TRACE("uxen_ioctl(UXENHYPERCALL, %p, %x)\n", InputBuffer,
                    InputBufferLength);
        UXEN_CHECK_MODE(UXEN_MODE_INITIALIZED, "UXENHYPERCALL");
        UXEN_CHECK_INPUT_BUFFER("UXENHYPERCALL", struct uxen_hypercall_desc);
        UXEN_CHECK_OUTPUT_BUFFER("UXENHYPERCALL", struct uxen_hypercall_desc);
        KeAcquireGuardedMutex(&fda->user_malloc_mutex);
        ret = uxen_hypercall(uhd, SNOOP_USER,
                             &vmi->vmi_shared, &fda->user_mappings,
                             (fda->admin_access ? UXEN_ADMIN_HYPERCALL : 0) |
                             (fda->vmi_owner ? UXEN_VMI_OWNER : 0));
        if (ret < 0)
            IOCTL_FAILURE(UXEN_NTSTATUS_FROM_ERRNO(-ret),
                          "uxen_ioctl(UXENHYPERCALL %d) fail: %d",
                          uhd->uhd_op, -ret);
        KeReleaseGuardedMutex(&fda->user_malloc_mutex);
        uhd->uhd_op = ret;
    }
	break;
    case ICC(UXENMALLOC):
        UXEN_CHECK_OUTPUT_BUFFER("UXENMALLOC", struct uxen_malloc_desc);
        ret = init_fd_assoc_user_mappings("UXENMALLOC", fda);
        if (ret)
            goto out;
        OP_CALL("UXENMALLOC", uxen_mem_malloc, struct uxen_malloc_desc, fda);
        break;
    case ICC(UXENFREE):
        ret = init_fd_assoc_user_mappings("UXENFREE", fda);
        if (ret)
            goto out;
        OP_CALL("UXENFREE", uxen_mem_free, struct uxen_free_desc, fda);
        break;
    case ICC(UXENMMAPBATCH):
        IOCTL_VM_ADMIN_CHECK("UXENMMAPBATCH");
        UXEN_CHECK_VMI("UXENMMAPBATCH", vmi);
        UXEN_CHECK_OUTPUT_BUFFER("UXENMMAPBATCH", struct uxen_mmapbatch_desc);
        ret = init_fd_assoc_user_mappings("UXENMMAPBATCH", fda);
        if (ret)
            goto out;
        OP_CALL("UXENMMAPBATCH", uxen_mem_mmapbatch,
                struct uxen_mmapbatch_desc, fda);
	break;
    case ICC(UXENMUNMAP):
        IOCTL_VM_ADMIN_CHECK("UXENMUNMAP");
        UXEN_CHECK_VMI("UXENMUNMAP", vmi);
        ret = init_fd_assoc_user_mappings("UXENMUNMAP", fda);
        if (ret)
            goto out;
        OP_CALL("UXENMUNMAP", uxen_mem_munmap, struct uxen_munmap_desc, fda);
	break;
    case ICC(UXENCREATEVM):
        UXEN_CHECK_OUTPUT_BUFFER("UXENCREATEVM", struct uxen_createvm_desc);
        DOM0_CALL("UXENCREATEVM", uxen_op_create_vm,
                  struct uxen_createvm_desc, fda);
	break;
    case ICC(UXENTARGETVM):
        IOCTL_ADMIN_CHECK("UXENTARGETVM");
        UXEN_CHECK_OUTPUT_BUFFER("UXENTARGETVM", struct uxen_targetvm_desc);
        DOM0_CALL("UXENTARGETVM", uxen_op_target_vm,
                  struct uxen_targetvm_desc, fda);
	break;
    case ICC(UXENDESTROYVM):
        DOM0_CALL("UXENDESTROYVM", uxen_op_destroy_vm,
                  struct uxen_destroyvm_desc, fda);
	break;
    case ICC(UXENEXECUTE):
        IOCTL_VM_ADMIN_CHECK("UXENEXECUTE");
        UXEN_CHECK_VMI("UXENEXECUTE", vmi);
        OP_CALL("UXENEXECUTE", uxen_op_execute,
                struct uxen_execute_desc, vmi);
	break;
    case ICC(UXENSETEVENT):
        IOCTL_VM_ADMIN_CHECK("UXENSETEVENT");
        UXEN_CHECK_VMI("UXENSETEVENT", vmi);
        OP_CALL("UXENSETEVENT", uxen_op_set_event, struct uxen_event_desc, vmi);
	break;
    case ICC(UXENSETEVENTCHANNEL):
        IOCTL_VM_ADMIN_CHECK("UXENSETEVENTCHANNEL");
        UXEN_CHECK_VMI("UXENSETEVENTCHANNEL", vmi);
        DOM0_CALL("UXENSETEVENTCHANNEL", uxen_op_set_event_channel,
                  struct uxen_event_channel_desc, vmi, fda);
	break;
    case ICC(UXENMEMCACHEINIT):
        IOCTL_VM_ADMIN_CHECK("UXENMEMCACHEINIT");
        UXEN_CHECK_VMI("UXENMEMCACHEINIT", vmi);
        UXEN_CHECK_OUTPUT_BUFFER("UXENMEMCACHEINIT",
                                 struct uxen_memcacheinit_desc);
        ret = init_fd_assoc_user_mappings("UXENMEMCACHEINIT", fda);
        if (ret)
            goto out;
        OP_CALL("UXENMEMCACHEINIT", mdm_init,
                struct uxen_memcacheinit_desc, fda);
	break;
    case ICC(UXENMEMCACHEMAP):
        IOCTL_VM_ADMIN_CHECK("UXENMEMCACHEMAP");
        UXEN_CHECK_VMI("UXENMEMCACHEMAP", vmi);
        OP_CALL("UXENMEMCACHEMAP", mdm_map,
                struct uxen_memcachemap_desc, fda);
	break;
    case ICC(UXENQUERYVM):
        IOCTL_ADMIN_CHECK("UXENQUERYVM");
        UXEN_CHECK_OUTPUT_BUFFER("UXENQUERYVM", struct uxen_queryvm_desc);
        DOM0_CALL("UXENQUERYVM", uxen_op_query_vm, struct uxen_queryvm_desc);
	break;
    case ICC(UXENPOWER):
        IOCTL_TRACE("uxen_ioctl(UXENPOWER)\n");
        UXEN_CHECK_MODE(UXEN_MODE_INITIALIZED, "UXENPOWER");
        IOCTL_ADMIN_CHECK("UXENPOWER");
        UXEN_CHECK_INPUT_BUFFER("UXENPOWER", uint32_t);
        uxen_power_state(*(uint32_t *)InputBuffer);
        break;
    case ICC(UXENLOGGING):
        IOCTL_TRACE("uxen_ioctl(UXENLOGGING)\n");
        IOCTL_VM_ADMIN_CHECK("UXENLOGGING");
        UXEN_CHECK_INPUT_BUFFER("UXENLOGGING", struct uxen_logging_desc);
        UXEN_CHECK_OUTPUT_BUFFER("UXENLOGGING", struct uxen_logging_desc);
        ret = init_fd_assoc_user_mappings("UXENLOGGING", fda);
        if (ret)
            goto out;
        ret = uxen_op_logging((struct uxen_logging_desc *)InputBuffer, fda);
        if (ret)
            IOCTL_FAILURE(UXEN_NTSTATUS_FROM_ERRNO(ret),
                          "uxen_ioctl(UXENLOGGING) fail: %d", ret);
        break;
    case ICC(UXENMAPHOSTPAGES):
        IOCTL_TRACE("uxen_ioctl(UXENMAPHOSTPAGES)\n");
        IOCTL_VM_ADMIN_CHECK("UXENMAPHOSTPAGES");
        ret = init_fd_assoc_user_mappings("UXENMAPHOSTPAGES", fda);
        if (ret)
            goto out;
        UXEN_CHECK_INPUT_BUFFER("UXENMAPHOSTPAGES",
                                struct uxen_map_host_pages_desc);
        ret = uxen_op_map_host_pages(
            (struct uxen_map_host_pages_desc *)InputBuffer, fda);
        if (ret)
            IOCTL_FAILURE(UXEN_NTSTATUS_FROM_ERRNO(ret),
                          "uxen_ioctl(UXENMAPHOSTPAGES) fail: %d", ret);
        break;
    case ICC(UXENUNMAPHOSTPAGES):
        IOCTL_TRACE("uxen_ioctl(UXENUNMAPHOSTPAGES)\n");
        IOCTL_VM_ADMIN_CHECK("UXENUNMAPHOSTPAGES");
        ret = init_fd_assoc_user_mappings("UXENUNMAPHOSTPAGES", fda);
        if (ret)
            goto out;
        UXEN_CHECK_INPUT_BUFFER("UXENUNMAPHOSTPAGES",
                                struct uxen_map_host_pages_desc);
        ret = uxen_op_unmap_host_pages(
            (struct uxen_map_host_pages_desc *)InputBuffer, fda);
        if (ret)
            IOCTL_FAILURE(UXEN_NTSTATUS_FROM_ERRNO(ret),
                          "uxen_ioctl(UXENUNMAPHOSTPAGES) fail: %d", ret);
        break;
#ifdef __i386__
    case ICC(UXENWAITFORS4): {
        KIRQL irql;
        IOCTL_TRACE("uxen_ioctl(UXENWAITFORS4)\n");
        if (!uxen_hibernation_enabled) {
            IOCTL_FAILURE(STATUS_UNSUCCESSFUL,
                          "hibernation services disabled");
            goto out;
        }
        if (wait_for_resume_from_s4_irp) {
            IOCTL_FAILURE(STATUS_UNSUCCESSFUL, "invalid IOCTL sequence");
            goto out;
        }
        if (wait_for_s4_irp) {
            IOCTL_FAILURE(STATUS_UNSUCCESSFUL,
                          "wait-for-s4 already registered");
            goto out;
        }
        IoAcquireCancelSpinLock(&irql);
        IoSetCancelRoutine(pIRP, hiber_cancel_routine);
        IoReleaseCancelSpinLock(irql);
        InterlockedExchangePointer(&wait_for_s4_irp, pIRP);
        IoMarkIrpPending(pIRP);
        return STATUS_PENDING;
    }
    case ICC(UXENWAITFORRESUMEFROMS4): {
        KIRQL irql;
        IOCTL_TRACE("uxen_ioctl(UXENWAITFORRESUMEFROMS4)\n");
        if (!uxen_hibernation_enabled) {
            IOCTL_FAILURE(STATUS_UNSUCCESSFUL,
                          "hibernation services disabled");
            goto out;
        }
        if (wait_for_s4_irp) {
            IOCTL_FAILURE(STATUS_UNSUCCESSFUL, "invalid IOCTL sequence");
            goto out;
        }
        if (!s4_in_progress) {
            IOCTL_FAILURE(STATUS_UNSUCCESSFUL, "hibernation not in progress");
            goto out;
        }
        if (wait_for_resume_from_s4_irp) {
            IOCTL_FAILURE(STATUS_UNSUCCESSFUL,
                          "wait-for-resume-from-s4 already registered");
            goto out;
        }
        IoAcquireCancelSpinLock(&irql);
        IoSetCancelRoutine(pIRP, hiber_cancel_routine);
        IoReleaseCancelSpinLock(irql);
        InterlockedExchangePointer(&wait_for_resume_from_s4_irp, pIRP);
        KeSetEvent(&continue_power_transition_event, IO_NO_INCREMENT, FALSE);
        IoMarkIrpPending(pIRP);
        return STATUS_PENDING;
    }
#endif /* __i386__ */
    default:
	IOCTL_TRACE("uxen_ioctl(%lx)\n", IoControlCode);
	IOCTL_FAILURE(STATUS_NOT_IMPLEMENTED,
		      "uxen_ioctl(%lx) not implemented", IoControlCode);
	break;
    }

  out:
    IoStatus->Information = OutputBufferLength;
    status = IoStatus->Status;
    IoCompleteRequest(pIRP, IO_NO_INCREMENT);
    return status;
}

int
copyin(const void *uaddr, void *kaddr, size_t size)
{
    int ret = 0;

    try {
        ProbeForRead((void *)uaddr, size, sizeof(uint8_t));
        memcpy(kaddr, uaddr, size);
    } except (HOSTDRV_EXCEPTION_EXECUTE_HANDLER("uaddr=0x%p, size=0x%x",
                                                uaddr, size)) {
        ret = EFAULT;
    }

    return ret;
}

int
copyout(const void *kaddr, void *uaddr, size_t size)
{
    int ret = 0;

    try {
        ProbeForWrite(uaddr, size, sizeof(uint8_t));
        memcpy(uaddr, kaddr, size);
    } except (HOSTDRV_EXCEPTION_EXECUTE_HANDLER("uaddr=0x%p, size=0x%x",
                                                uaddr, size)) {
        ret = EFAULT;
    }

    return ret;
}

int
copyin_kernel(const void *uaddr, void *kaddr, size_t size)
{
    int ret = 0;

    memcpy(kaddr, uaddr, size);

    return ret;
}
