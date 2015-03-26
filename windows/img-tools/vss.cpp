/*
 * Copyright 2011-2015, Bromium, Inc.
 * SPDX-License-Identifier: ISC
 */

#include <windows.h>
#include <vss.h>
#include <vsmgmt.h>
#include <vswriter.h>
#include <vsbackup.h>
#include <winbase.h>

#include <stdio.h>
#define printf_for_people_who_dont_know_how_to_use_va_args(...) \
    fprintf(stderr, __VA_ARGS__)
#define LogAlways(l) printf_for_people_who_dont_know_how_to_use_va_args l

extern "C" char *vss_from_guid(const char *sguid)
{
    CLSID clsid;
    VSS_SNAPSHOT_PROP prop = {0};
    HRESULT hres;
    size_t nchar;
    char *path = NULL;
    IVssBackupComponents *vss = NULL;

    OLECHAR *sOleText = (OLECHAR *)malloc((strlen(sguid)+1) * sizeof(OLECHAR));

    if (sOleText == NULL) {
        LogAlways(("%s fails on line %d unable to get OLE string buffer.\n", __FUNCTION__, __LINE__));
        goto out;
    }

    mbstowcs(sOleText, sguid, strlen(sguid) + 1);

    CoInitialize(NULL);

    if (FAILED( CLSIDFromString(sOleText, &clsid)) ) {
        LogAlways(("%s fails on line %d guid '%s'\n", __FUNCTION__, __LINE__, sguid));
        goto out;
    }

    hres = CreateVssBackupComponents(&vss);
    if ( hres != S_OK ) {
        LogAlways(("%s fails on line %d with error %x\n", __FUNCTION__, __LINE__, hres));
        goto out;
    }

    hres = vss->InitializeForBackup();
    if ( hres != S_OK ) {
        LogAlways(("%s fails on line %d with error %x\n", __FUNCTION__, __LINE__, hres));
        goto out;
    }

    hres = vss->SetContext(VSS_CTX_ALL);
    if ( hres != S_OK ) {
        LogAlways(("%s fails on line %d with error %x\n", __FUNCTION__, __LINE__, hres));
        goto out;
    }

    hres =vss->SetBackupState(true, true, VSS_BT_FULL, false);
    if ( hres != S_OK ) {
        LogAlways(("%s fails on line %d with error %x\n", __FUNCTION__, __LINE__, hres));
        goto out;
    }

    hres = vss->GetSnapshotProperties(clsid, &prop);
    if ( hres != S_OK ) {
        LogAlways(("%s fails on line %d with error %x\n", __FUNCTION__, __LINE__, hres));
        goto out;
    }

    nchar = wcslen(prop.m_pwszSnapshotDeviceObject);
    path = (char *)malloc(nchar + 1);

    if (!path) {
        LogAlways(("%s fails on line %d (out of memory)\n", __FUNCTION__, __LINE__));
        goto out;
    }

    wcstombs(path, prop.m_pwszSnapshotDeviceObject, nchar + 1);

out:
    CoUninitialize();
    free(sOleText);
    return path;
}
