/*
 * Copyright 2013-2016, Bromium, Inc.
 * Author: Julian Pidancet <julian@pidancet.net>
 * SPDX-License-Identifier: ISC
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>

#include "json.h"
#include "smbios.h"
#include "base64.h"
#include "urlencode.h"

#define _WIN32_DCOM
#include <windows.h>
#include <ntddscsi.h>
#include <iphlpapi.h>
#include <assert.h>

#ifndef RRF_SUBKEY_WOW6432KEY
#define RRF_SUBKEY_WOW6432KEY 0x00020000
#endif

#define ACPI 0x41435049
#define SLIC 0x43494C53
#define FADT 0x50434146
#define MSDM 0x4D44534D

#define RSMB 0x52534D42

WINBASEAPI UINT WINAPI
GetSystemFirmwareTable(DWORD FirmwareTableProviderSignature,
                       DWORD FirmwareTableID,
                       PVOID pFirmwareTableBuffer,
                       DWORD BufferSize);

struct acpi_header {
    uint8_t     signature[4];
    uint32_t    length;
    uint8_t     revision;
    uint8_t     checksum;
    uint8_t     oem_id[6];
    uint8_t     oem_table_id[8];
    uint32_t    oem_revision;
    uint8_t     creator_id[4];
    uint32_t    creator_revision;
};

struct smbios_header {
    uint8_t     calling_method;
    uint8_t     major_version;
    uint8_t     minor_version;
    uint8_t     dmi_revision;
    uint32_t    length;
};

static struct acpi_header *fadt = NULL;
static struct smbios_header *smbios_data = NULL;

static void *
get_table(uint32_t provider, uint32_t table, size_t *out_len)
{
    int rc;
    struct acpi_header *hdr = NULL;
    size_t len;

    rc = sizeof(*hdr);
    do {
        len = rc;
        hdr = realloc(hdr, len);

        rc = GetSystemFirmwareTable(provider, table, hdr, len);
        if (!rc) {
            fprintf(stderr, "GetSystemFirmwareTable failed: [0x%x,0x%x]: [0x%x]\n",
                (int)provider, (int)table, (int)GetLastError());
            return NULL;
        }
    } while (rc != len);

    if (out_len)
        *out_len = len;

    return hdr;
}

void *
acpi_get_slic(size_t *len)
{
    return get_table(ACPI, SLIC, len);
}

void *
acpi_get_msdm(size_t *len)
{
    return get_table(ACPI, MSDM, len);
}

unsigned char *
acpi_get_oem_id(void)
{
    if (!fadt)
        fadt = get_table(ACPI, FADT, NULL);

    assert(fadt);
    return fadt->oem_id;
}

unsigned char *
acpi_get_oem_table_id(void)
{
    if (!fadt)
        fadt = get_table(ACPI, FADT, NULL);

    assert(fadt);
    return fadt->oem_table_id;
}

int
acpi_get_oem_revision(void)
{
    if (!fadt)
        fadt = get_table(ACPI, FADT, NULL);

    assert(fadt);
    return fadt->oem_revision;
}

unsigned char *
acpi_get_creator_id(void)
{
    if (!fadt)
        fadt = get_table(ACPI, FADT, NULL);

    assert(fadt);
    return fadt->creator_id;
}

int
acpi_get_creator_revision(void)
{
    if (!fadt)
        fadt = get_table(ACPI, FADT, NULL);

    assert(fadt);
    return fadt->creator_revision;
}

static void
flip(unsigned char *dst, unsigned char *src, size_t len)
{
    size_t i;

    for (i = 0; i < len; i++)
        dst[i ^ 1] = src[i];
}

static int
drive_identify(HANDLE drive, unsigned char *model,
               unsigned char *serial, unsigned char *version)
{
    int rc;
    DWORD len;
    ATA_PASS_THROUGH_EX *data;

    data = calloc(1, sizeof(*data) + 512);
    if (!data)
        return -1;

    data->Length   = sizeof(ATA_PASS_THROUGH_EX);
    data->DataBufferOffset = sizeof(ATA_PASS_THROUGH_EX);
    data->DataTransferLength = 512;
    data->AtaFlags = ATA_FLAGS_DATA_IN;
    data->TimeOutValue = 2; //Seconds
    data->CurrentTaskFile[6] = 0xEC;

    rc = DeviceIoControl(drive, IOCTL_ATA_PASS_THROUGH,
                         data, sizeof(*data) + 512,
                         data, sizeof(*data) + 512,
                         &len, NULL);
    if (!rc) {
        fprintf(stderr,
                "DeviceIoControl(IOCTL_ATA_PASS_THROUGH) failed (%ld)\n",
                GetLastError());
        rc = -1;
        goto out;
    }

    flip(serial, (uint8_t *)data + sizeof (*data) + 20, 20);
    flip(version, (uint8_t *)data + sizeof (*data) + 46, 8);
    flip(model, (uint8_t *)data + sizeof (*data) + 54, 40);

    if (!model[0]) {
        fprintf(stderr, "Empty drive model string\n");
        rc = -1;
        goto out;
    }

    rc = 0;

out:
    free(data);
    return rc;
}

static unsigned char *
drive_query_storage_property(HANDLE drive, size_t *prop_len)
{
    int rc;
    DWORD len;
    STORAGE_PROPERTY_QUERY query;
    STORAGE_DEVICE_DESCRIPTOR *data;

    data = calloc(1, sizeof(*data) - 1 + 512);
    if (!data)
        return NULL;

    memset(&query, 0, sizeof(query));
    query.PropertyId = StorageDeviceProperty;
    query.QueryType = PropertyStandardQuery;

    rc = DeviceIoControl(drive, IOCTL_STORAGE_QUERY_PROPERTY,
                         &query, sizeof(query),
                         data, sizeof(*data) - 1 + 512,
                         &len, NULL);
    if (!rc || len < sizeof(*data)) {
        fprintf(stderr,
                "DeviceIoControl(IOCTL_STORAGE_QUERY_PROPERTY) failed (%ld)\n",
                GetLastError());
        free(data);
        return NULL;
    }

    *prop_len = len;

    return (unsigned char *)data;
}

static int
set_drive_info(int id, unsigned char *model, unsigned char *serial,
               unsigned char *version, unsigned char *prop,
               size_t prop_len, void *priv)
{
    yajl_gen g = (yajl_gen)priv;
    size_t sz;
    char drive_id[16];

    sz = snprintf(drive_id, 16, "ich%d", id);

    yajl_gen_map_open(g);
    SET_BUF("id", drive_id, sz);
    if (model)
        SET_BASE64("model", model, 40);
    if (serial)
        SET_BASE64("serial", serial, 20);
    if (version)
        SET_BASE64("version", version, 8);
    if (prop)
        SET_BASE64("properties", prop, prop_len);
    yajl_gen_map_close(g);

    return 0;
}

DWORD
get_system_drive_index(void)
{
    HANDLE drive;
    char windows_directory_path[MAX_PATH + 1] = { 0 };
    char windows_drive_path[MAX_PATH + 1] = { 0 };
    VOLUME_DISK_EXTENTS disk_extents;
    DWORD system_drive_index = 0;
    DWORD bytes_returned_count = 0;
    if (!GetSystemWindowsDirectoryA(windows_directory_path, MAX_PATH + 1)) {
        fprintf(stderr,
            "GetSystemWindowsDirectory failed, (%ld), defaulting to C drive\n",
            GetLastError());
        windows_directory_path[0] = 'C';
    }

    snprintf(windows_drive_path, sizeof(windows_drive_path), "\\\\.\\%c:",
        windows_directory_path[0]);
    drive = CreateFile(windows_drive_path, GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_DELETE | FILE_SHARE_READ | FILE_SHARE_WRITE,
        NULL, OPEN_EXISTING, 0, NULL);
    if (drive == INVALID_HANDLE_VALUE) {
        fprintf(stderr,
            "Unable to open windows system volume handle (%ld), "
            "defaulting to disk 0\n",
            GetLastError());
    } else {
        if (!DeviceIoControl(drive,
            IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS,
            NULL,
            0,
            &disk_extents,
            sizeof(disk_extents),
            &bytes_returned_count,
            NULL)) {
                fprintf(stderr, "IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS query failed (%ld), "
                    "using default system root drive\n", GetLastError());
        } else {
            system_drive_index = disk_extents.Extents->DiskNumber;
        }
        CloseHandle(drive);
    }
    return system_drive_index;
}

void
set_system_drive_config(void *priv)
{
    HANDLE drive;
    int rc;
    unsigned char model[40];
    unsigned char serial[20];
    unsigned char version[8];
    char name[32] = { 0 };
    DWORD system_root_drive_index = get_system_drive_index();
    snprintf(name, sizeof (name), "\\\\.\\PhysicalDrive%d", (unsigned int)system_root_drive_index);
    drive = CreateFile(name, GENERIC_READ | GENERIC_WRITE,
                       FILE_SHARE_DELETE| FILE_SHARE_READ | FILE_SHARE_WRITE,
                       NULL, OPEN_EXISTING, 0, NULL);

    if (drive != INVALID_HANDLE_VALUE) {
        unsigned char *prop;
        size_t prop_len;

        rc = drive_identify(drive, model, serial, version);
        prop = drive_query_storage_property(drive, &prop_len);

        set_drive_info(0,
                       rc ? NULL : model,
                       rc ? NULL : serial,
                       rc ? NULL : version,
                       prop,
                       prop ? prop_len : 0,
                       priv);

        if (prop)
            free(prop);
        CloseHandle(drive);
    } else {
        fprintf(stderr, "Failed to open %s, (%ld)\n", name, GetLastError());
    }
}

struct macaddr
{
    unsigned char b[6];
};

static struct macaddr *
get_wga_macs(size_t *len)
{
    LONG rc;
    DWORD sz = 0;
    char *p, *str = NULL;
    struct macaddr *macs = NULL;

    *len = 0;

    rc = RegGetValueA(HKEY_LOCAL_MACHINE,
                      "SOFTWARE\\Microsoft\\Windows Genuine Advantage",
                      "MAC",
                      RRF_RT_REG_SZ | RRF_SUBKEY_WOW6432KEY, NULL,
                      str, &sz);
    if (rc != ERROR_SUCCESS)
        return NULL;

    str = calloc(1, sz);
    if (!str)
        return NULL;

    rc = RegGetValueA(HKEY_LOCAL_MACHINE,
                      "SOFTWARE\\Microsoft\\Windows Genuine Advantage",
                      "MAC",
                      RRF_RT_REG_SZ | RRF_SUBKEY_WOW6432KEY, NULL,
                      str, &sz);
    if (rc != ERROR_SUCCESS) {
        free(str);
        return NULL;
    }

    p = str;
    do {
        int m[6];

        rc = sscanf(p, "%02x-%02x-%02x-%02x-%02x-%02x;",
                    &m[0], &m[1], &m[2], &m[3], &m[4], &m[5]);
        if (rc != 6)
            break;

        macs = realloc(macs, (*len + 1) * sizeof (*macs));
        if (!macs) {
            free(str);
            *len = 0;
            return NULL;
        }
        macs[*len].b[0] = (unsigned char)m[0];
        macs[*len].b[1] = (unsigned char)m[1];
        macs[*len].b[2] = (unsigned char)m[2];
        macs[*len].b[3] = (unsigned char)m[3];
        macs[*len].b[4] = (unsigned char)m[4];
        macs[*len].b[5] = (unsigned char)m[5];
        *len += 1;

        p += 18;
        if (p >= (str + sz))
            break;
    } while (1);

    free(str);

    return macs;
}

void
nic_enumerate(int (*callback)(int, unsigned char *, size_t, void *),
              void *priv)
{
    DWORD rc;
    void *buf = NULL;
    IP_ADAPTER_INFO *adapter = NULL;
    int i = 0;
    ULONG len = 0;
    struct macaddr *wga_macs;
    size_t nmacs;

    wga_macs = get_wga_macs(&nmacs);

    rc = GetAdaptersInfo(buf, &len);
    if (rc != ERROR_BUFFER_OVERFLOW) {
        fprintf(stderr, "GetAdapterInfo failed (%ld)\n", GetLastError());
        return;
    }
    buf = malloc(len);
    if (!buf) {
        fprintf(stderr, "Allocation failed\n");
        return;
    }

    rc = GetAdaptersInfo(buf, &len);
    if (rc != NO_ERROR) {
        fprintf(stderr, "GetAdapterInfo failed (%ld)\n", GetLastError());
        return;
    }
    adapter = buf;

    do {
        if (adapter->Type == MIB_IF_TYPE_ETHERNET ||
            adapter->Type == IF_TYPE_IEEE80211) {

            /*
             * If we have a list of "Windows Genuine Advantage" MAC addresses,
             * skip this mac address it does not appear in the list
             */
            if (wga_macs) {
                int i;

                for (i = 0; i < nmacs; i++) {
                    if (!memcmp(adapter->Address, wga_macs[i].b, 6))
                        break;
                }

                if (i == nmacs) {
                    adapter = adapter->Next;
                    continue;
                }
            }

            callback(i++, adapter->Address, adapter->AddressLength, priv);

#define IDENTIFY_ALL_NICS
#ifndef IDENTIFY_ALL_NICS
            break;
#endif
        }

        adapter = adapter->Next;
    } while (adapter);

    if (wga_macs) {
        free(wga_macs);
    }
    free(buf);
}


int smbios_get_version_major(void)
{
    if (!smbios_data)
        smbios_data = get_table(RSMB, 0, NULL);

    return smbios_data->major_version;
}

int smbios_get_version_minor(void)
{
    if (!smbios_data)
        smbios_data = get_table(RSMB, 0, NULL);

    return smbios_data->minor_version;
}

void *
smbios_get_struct(int type, size_t *out_len)
{
    char *start, *end;

    if (!smbios_data)
        smbios_data = get_table(RSMB, 0, NULL);

    start = (void *)(smbios_data + 1);
    end = (char *)(smbios_data + 1) + smbios_data->length;

    return __smbios_get_struct(start, end, type, type, out_len);
}

void
smbios_struct_iterate(int (*callback)(char *, size_t, void *),
                      void *priv)
{
    char *end, *start;
    char *s;
    int rc;

    if (!smbios_data)
        smbios_data = get_table(RSMB, 0, NULL);

    start = (void *)(smbios_data + 1);
    end = (char *)(smbios_data + 1) + smbios_data->length;

    do {
        size_t len;

        s = __smbios_get_struct(start, end, 0, 255, &len);
        if (s) {
            rc = callback(s, len, priv);
            if (rc)
                break;
            start = s + len;
        }
    } while (s);
}

void
smbios_oem_struct_iterate(int (*callback)(char *, size_t, void *),
                          void *priv)
{
    char *end, *start;
    char *s;
    int rc;

    if (!smbios_data)
        smbios_data = get_table(RSMB, 0, NULL);

    start = (void *)(smbios_data + 1);
    end = (char *)(smbios_data + 1) + smbios_data->length;

    do {
        size_t len;

        s = __smbios_get_struct(start, end, 128, 255, &len);
        if (s) {
            rc = callback(s, len, priv);
            if (rc)
                break;
            start = s + len;
        }
    } while (s);
}

static int
nic_callback(int id, unsigned char *addr, size_t addr_len, void *priv)
{
    yajl_gen g = (yajl_gen)priv;
    char *addr_str, *p;
    size_t i = 0;
    char nic_id[6];
    size_t sz;

    addr_str = malloc(3 * addr_len);
    if (!addr_str)
        return -1;
    p = addr_str;

    if (addr_len)
        p += snprintf(p, 3, "%02x", addr[i++]);
    for (; i < addr_len; i++)
        p += snprintf(p, 4, ":%02x", addr[i]);
    *p = '\0';

    sz = snprintf(nic_id, 6, "nic%d", id);

    yajl_gen_map_open(g);
    SET_BUF("type", "nic", 3);
    SET_BUF("id", nic_id, sz);
    SET_BUF("macaddr", addr_str, 3 * addr_len - 1);
    if (id == 0)
        SET_INT("vlan", 0);
    else
        SET_INT("vlan", 1);
    yajl_gen_map_close(g);

    free(addr_str);

    return 0;
}

static int
smbios_callback(char *buf, size_t len, void *priv)
{
    yajl_gen g = (yajl_gen)priv;

    SET_BASE64_ELEM((unsigned char *)buf, len);

    return 0;
}

int
main(int argc, char **argv)
{
    yajl_gen g;
    const unsigned char *output;
    size_t len;
    unsigned char *data; size_t data_len;

    g = yajl_gen_alloc(NULL);
    yajl_gen_config(g, yajl_gen_beautify, 1);
    yajl_gen_config(g, yajl_gen_validate_utf8, 0);

    yajl_gen_map_open(g);
    yajl_gen_string(g, (const unsigned char *)"firmware", 8);

    yajl_gen_map_open(g);

    /* 1. required ACPI tables */

    data = acpi_get_slic(&data_len);
    if (data) {
        SET_BASE64("slic", data, data_len);
        free(data);
    }
    data = acpi_get_msdm(&data_len);
    if (data) {
        SET_BASE64("msdm", data, data_len);
        free(data);
    }

    /* 2. ACPI OEM IDs */

    SET_URLENC("oem_id", acpi_get_oem_id(), 6);
    SET_URLENC("oem_table_id", acpi_get_oem_table_id(), 8);
    SET_INT("oem_revision", acpi_get_oem_revision());
    SET_URLENC("creator_id", acpi_get_creator_id(), 4);
    SET_INT("creator_revision", acpi_get_creator_revision());

    SET_INT("smbios_version_major", smbios_get_version_major());
    SET_INT("smbios_version_minor", smbios_get_version_minor());

    /* 3. SMBIOS structs */

    yajl_gen_string(g, (const unsigned char *)"smbios", 6);
    yajl_gen_array_open(g);

    smbios_struct_iterate(smbios_callback, (void *)g);

    yajl_gen_array_close(g);

    yajl_gen_map_close(g);

    /* 4. Block identifiers */

    yajl_gen_string(g, (const unsigned char *)"block", 5);

    yajl_gen_array_open(g);
    set_system_drive_config((void *)g);
    yajl_gen_array_close(g);

    /* 5. Network interfaces */

    yajl_gen_string(g, (const unsigned char *)"net", 3);

    yajl_gen_array_open(g);
    nic_enumerate(nic_callback, (void *)g);
    yajl_gen_array_close(g);

    yajl_gen_map_close(g);

    yajl_gen_get_buf(g, &output, &len);
    fwrite(output, len, 1, stdout);
    yajl_gen_clear(g);
    yajl_gen_free(g);

    return 0;
}

