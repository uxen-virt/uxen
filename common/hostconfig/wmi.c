/*
 * Copyright 2017, Bromium, Inc.
 * Author: Piotr Foltyn <piotr.foltyn@gmail.com>
 * SPDX-License-Identifier: ISC
 */

#define _WIN32_DCOM

#include <initguid.h>
#include <stdio.h>
#include <tchar.h>
#include <windows.h>
#include <wbemidl.h>
#include <stdint.h>

#include "smbios.h"

// {4590f811-1d3a-11d0-891f-00aa004b2e24}
DEFINE_GUID(CLSID_WbemLocator,
	0x4590f811, 0x1d3a, 0x11d0, 0x89, 0x1f, 0x00, 0xaa, 0x00, 0x4b, 0x2e, 0x24);

// {dc12a687-737f-11cf-884d-00aa004b2e24}
DEFINE_GUID(IID_IWbemLocator,
	0xdc12a687, 0x737f, 0x11cf, 0x88, 0x4d, 0x00, 0xaa, 0x00, 0x4b, 0x2e, 0x24);

int get_raw_smb_table_using_wmi(struct smbios_header **table, size_t *size)
{
    HRESULT hr = 0;
    int inited = 0;
    int ret = 0;

    struct smbios_header hdr = {};

    IWbemLocator         *locator  = NULL;
    IWbemServices        *services = NULL;
    IEnumWbemClassObject *results  = NULL;

    BSTR resource = NULL;
    BSTR language = NULL;
    BSTR query    = NULL;

    IWbemClassObject *result = NULL;
    ULONG returnedCount = 0;
    LONG data_idx = 0;
    VARIANT calling_method;
    VARIANT major_version;
    VARIANT minor_version;
    VARIANT dmi_revision;
    VARIANT length;
    VARIANT data;

    VariantInit(&calling_method);
    VariantInit(&major_version);
    VariantInit(&minor_version);
    VariantInit(&dmi_revision);
    VariantInit(&length);
    VariantInit(&data);

    if (!table || !size) {
        fprintf(stderr, "Table (0x%p) or size (0x%p) is NULL.\n", table, size);
        goto exit;
    }

    resource = SysAllocString(L"ROOT\\WMI");
    if (!resource) {
        fprintf(stderr, "SysAllocString(L\"ROOT\\WMI\") failed\n");
        goto exit;
    }

    language = SysAllocString(L"WQL");
    if (!language) {
        fprintf(stderr, "SysAllocString(L\"WQL\") failed\n");
        goto exit;
    }

    query = SysAllocString(L"SELECT * FROM MSSmBios_RawSMBiosTables");
    if (!query) {
        fprintf(stderr, "SysAllocString(L\"SELECT * FROM MSSmBios_RawSMBiosTables\") failed\n");
        goto exit;
    }

    hr = CoInitializeEx(0, COINIT_MULTITHREADED);
    if (FAILED(hr)) {
        fprintf(stderr, "Failed to initialize COM library. Error code = 0x%x\n", (unsigned)hr);
        goto exit;
    }
    inited = 1;

    hr = CoInitializeSecurity(NULL, -1, NULL, NULL, RPC_C_AUTHN_LEVEL_DEFAULT, RPC_C_IMP_LEVEL_IMPERSONATE, NULL, EOAC_NONE, NULL);
    if (FAILED(hr)) {
        fprintf(stderr, "Failed to initialize security. Error code = 0x%x\n", (unsigned)hr);
        goto exit;
    }

    hr = CoCreateInstance(&CLSID_WbemLocator, 0, CLSCTX_INPROC_SERVER, &IID_IWbemLocator, (LPVOID *) &locator);
    if (FAILED (hr)) {
        fprintf(stderr, "Failed to create IWbemLocator object. Error code = 0x%x\n", (unsigned)hr);
        goto exit;
    }

    hr = locator->lpVtbl->ConnectServer(locator, resource, NULL, NULL, NULL, 0, NULL, NULL, &services);
    if (FAILED(hr)) {
        fprintf(stderr, "Failed to connect. Error code = 0x%x\n", (unsigned)hr);
        goto exit;
    }

    hr = services->lpVtbl->ExecQuery(services, language, query, WBEM_FLAG_BIDIRECTIONAL, NULL, &results);
    if (FAILED(hr) || !results) {
        fprintf(stderr, "Query for BIOSSetting failed. Error code=0x%x\n", (unsigned)hr);
        goto exit;
    }

    hr = results->lpVtbl->Next(results, WBEM_INFINITE, 1, &result, &returnedCount);
    if (FAILED(hr)) {
        fprintf(stderr, "Getting next result failed. Error code=0x%x\n", (unsigned)hr);
        goto exit;
    }

    hr = result->lpVtbl->Get(result, L"Used20CallingMethod", 0, &calling_method, 0, 0);
    if (FAILED(hr))
        fprintf(stderr, "Getting Used20CallingMethod failed. Error code=0x%x\n", (unsigned)hr);
    else
        hdr.calling_method = calling_method.lVal;

    hr = result->lpVtbl->Get(result, L"SmbiosMajorVersion", 0, &major_version, 0, 0);
    if (FAILED(hr))
        fprintf(stderr, "Getting SmbiosMajorVersion failed. Error code=0x%x\n", (unsigned)hr);
    else
        hdr.major_version = major_version.lVal;

    hr = result->lpVtbl->Get(result, L"SmbiosMinorVersion", 0, &minor_version, 0, 0);
    if (FAILED(hr))
        fprintf(stderr, "Getting SmbiosMinorVersion failed. Error code=0x%x\n", (unsigned)hr);
    else
        hdr.minor_version = minor_version.lVal;

    hr = result->lpVtbl->Get(result, L"DmiRevision", 0, &dmi_revision, 0, 0);
    if (FAILED(hr))
        fprintf(stderr, "Getting DmiRevision failed. Error code=0x%x\n", (unsigned)hr);
    else
        hdr.dmi_revision = dmi_revision.lVal;

    hr = result->lpVtbl->Get(result, L"Size", 0, &length, 0, 0);
    if (FAILED(hr))
        fprintf(stderr, "Getting Size failed. Error code=0x%x\n", (unsigned)hr);
    else
        hdr.length = length.lVal;

    hr = result->lpVtbl->Get(result, L"SMBiosData", 0, &data, 0, 0);
    if (FAILED(hr))
        fprintf(stderr, "Getting SMBiosData failed. Error code=0x%x\n", (unsigned)hr);

    *size = sizeof(hdr) + hdr.length;
    *table = calloc(1, *size);
    if (*table == NULL) {
        fprintf(stderr, "Calloc for smbios data failed.\n");
        goto exit;
    }

    memcpy(*table, &hdr, sizeof(hdr));

    for (; (ULONG)data_idx < hdr.length; ++data_idx)
        SafeArrayGetElement(data.parray, &data_idx, (char *)(*table + 1) + data_idx);

    ret = 1;

exit:
    VariantClear(&calling_method);
    VariantClear(&major_version);
    VariantClear(&minor_version);
    VariantClear(&dmi_revision);
    VariantClear(&length);
    VariantClear(&data);

    if (result) result->lpVtbl->Release(result);

    if (results)  results->lpVtbl->Release(results);
    if (services) services->lpVtbl->Release(services);
    if (locator)  locator->lpVtbl->Release(locator);

    if (inited) CoUninitialize();

    if (query)    SysFreeString(query);
    if (language) SysFreeString(language);
    if (resource) SysFreeString(resource);

    return ret;
}
