/*
 * Copyright 2018, Bromium, Inc.
 * SPDX-License-Identifier: ISC
 */

#include "uxen.h"
#include <xen/errno.h>
#include <uxen_ioctl.h>

#include <stddef.h>
#include <Ntstrsafe.h>

#include "attoxen-api/ax_vars.h"

#define AX_PV_I_SERVICE_NAME L"\\Registry\\Machine\\System\\CurrentControlSet\\Services\\" UXEN_PVI_DRIVER_NAME

static int pvi_save_driver(PUNICODE_STRING uxen_path, PVOID buf, ULONG buf_len)
{
    NTSTATUS status;
    HANDLE file;
    OBJECT_ATTRIBUTES obj_attr;
    IO_STATUS_BLOCK io_status = {0};
    LARGE_INTEGER uxenpvi_size = {0};
    LARGE_INTEGER offset = {0};
    DECLARE_UNICODE_STRING_SIZE(pvi_path, UXEN_PATH_MAX_LEN);
    USHORT iter;
    int ret = 0;

    RtlUnicodeStringCopy(&pvi_path, uxen_path);

    iter = pvi_path.Length / sizeof(WCHAR);
    while ((iter > 0) && (pvi_path.Buffer[iter - 1] != L'\\'))
        --iter;
    pvi_path.Length = iter * sizeof(WCHAR);

    RtlUnicodeStringCatStringEx(&pvi_path, L"" UXEN_PVI_DRIVER_NAME L".sys", NULL,
                                STRSAFE_ZERO_LENGTH_ON_FAILURE | STRSAFE_FILL_BEHIND);

    InitializeObjectAttributes(&obj_attr, &pvi_path,
                               OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, NULL);

    status = ZwCreateFile(&file, GENERIC_WRITE, &obj_attr, &io_status,
                          &uxenpvi_size, FILE_ATTRIBUTE_NORMAL, 0, FILE_SUPERSEDE,
                          FILE_NON_DIRECTORY_FILE | FILE_SEQUENTIAL_ONLY, NULL, 0);
    if (!NT_SUCCESS(status)) {
        fail_msg("ZwCreateFile([%wZ]) failed: %08x", &pvi_path, status);
        ret = 1;
        goto out;
    }

    status = ZwWriteFile(file, NULL, NULL, NULL, &io_status, buf, buf_len, &offset, NULL);
    if (!NT_SUCCESS(status)) {
        fail_msg("ZwWriteFile([%wZ]) failed: %08x", &pvi_path, status);
        ret = 1;
        goto out;
    }

out:
    if (file)
        ZwClose(file);

    return ret;
}

int pvi_load_driver(struct device_extension *de)
{
    NTSTATUS status;
    UNICODE_STRING driver_name, callback_name;
    OBJECT_ATTRIBUTES callback_attr;
    PCALLBACK_OBJECT callback_obj = NULL;
    int ret = 0;
    void *driver = NULL;
    size_t driver_len = 0;
    UINT_PTR iface[AX_PV_I_MAX_IDX] = {0};

    pvi_unload_driver();

    ax_vars_read_symbol(AX_PV_I_GA_VAR_NAME, AX_GA_TYPE_PE_IMAGE, &ret, sizeof(ret), &driver_len);
    if (driver_len <= 1) {
        fail_msg("ax_vars_read_symbol(size) failed 0x%x", ret);
        goto out;
    }

    driver = kernel_malloc(driver_len);
    if (!driver) {
        fail_msg("kernel_malloc(%lld) failed", driver_len);
        goto out;
    }

    ret = ax_vars_read_symbol(AX_PV_I_GA_VAR_NAME, AX_GA_TYPE_PE_IMAGE, driver, driver_len, NULL);
    if (ret == 0) {
        fail_msg("ax_vars_read_symbol(blob) failed");
        goto out;
    }

    ret = pvi_save_driver(&de->de_uxen_path, driver, driver_len);
    if (ret != 0) {
        fail_msg("pvi_save_driver() failed");
        goto out;
    }

    RtlInitUnicodeString(&driver_name, AX_PV_I_SERVICE_NAME);
    status = ZwLoadDriver(&driver_name);
    if (!NT_SUCCESS(status) && (status != STATUS_IMAGE_ALREADY_LOADED)) {
        fail_msg("ZwLoadDriver failed: 0x%08X", status);
        ret = 1;
        goto out;
    }

    RtlInitUnicodeString(&callback_name, AX_PV_I_IFACE_NAME);
    InitializeObjectAttributes(&callback_attr, &callback_name,
                               OBJ_CASE_INSENSITIVE, NULL, NULL);

    status = ExCreateCallback(&callback_obj, &callback_attr, FALSE, FALSE);
    if (!NT_SUCCESS(status)) {
        fail_msg("ExCreateCallback failed 0x%08X", status);
        ret = 1;
        goto out;
    }

    ExNotifyCallback(callback_obj, &iface, (PVOID)sizeof(iface));
    de->de_pvi_vmread = iface[AX_PV_I_VMREAD_IDX];
    de->de_pvi_vmwrite = iface[AX_PV_I_VMWRITE_IDX];
    #ifdef DBG
        dprintk("pvi_load_driver completed - vmread:0x%llx vmwrite:0x%llx %s\n",
                de->de_pvi_vmread, de->de_pvi_vmwrite, iface[AX_PV_I_HASH_IDX]);
    #else
        printk("pvi_load_driver completed - %s", iface[AX_PV_I_HASH_IDX]);
    #endif

out:
    if (driver)
        kernel_free(driver, driver_len);
    if (callback_obj)
        ObDereferenceObject(callback_obj);

    return ret;
}

void pvi_unload_driver(void)
{
    NTSTATUS status;
    UNICODE_STRING driver_name;

    RtlInitUnicodeString(&driver_name, AX_PV_I_SERVICE_NAME);
    status = ZwUnloadDriver(&driver_name);
    if (!NT_SUCCESS(status) && (status != STATUS_OBJECT_NAME_NOT_FOUND)) {
        fail_msg("ZwUnloadDriver failed: 0x%08X", status);
    }
}
