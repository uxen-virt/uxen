/*
 * Copyright 2013-2015, Bromium, Inc.
 * Author: Julian Pidancet <julian@pidancet.net>
 * SPDX-License-Identifier: ISC
 */

#include <CoreFoundation/CoreFoundation.h>
#include <IOKit/IOKitLib.h>

#include "smbios.h"
#include "base64.h"
#include "json.h"
#include "smc.h"

static char *
get_smbios_data(size_t *out_len)
{

    CFDictionaryRef matchingDict = NULL;
    kern_return_t kr;
    io_iterator_t iter = 0;
    io_service_t service = 0;
    CFTypeRef smbios;
    char *ret = NULL;

    matchingDict = IOServiceNameMatching("AppleSMBIOS");
    kr = IOServiceGetMatchingServices(kIOMasterPortDefault, matchingDict,
                                      &iter);
    if (kr != KERN_SUCCESS)
        return NULL;

    service = IOIteratorNext(iter);
    if (!service) {
        IOObjectRelease(iter);
        return NULL;
    }

    smbios = IORegistryEntryCreateCFProperty(service, CFSTR("SMBIOS"),
                                             kCFAllocatorDefault, 0);
    if (smbios) {
        uint8_t *smbios_data = (uint8_t *)CFDataGetBytePtr(smbios);
        size_t smbios_len = CFDataGetLength(smbios);

        ret = malloc(smbios_len);
        if (ret) {
            memcpy(ret, smbios_data, smbios_len);
            *out_len = smbios_len;
        }

        CFRelease(smbios);
    }

    IOObjectRelease(service);

    return ret;
}

void
smbios_struct_iterate(int (*callback)(char *, size_t, void *),
                      void *priv)
{
    char *end, *start;
    size_t l;
    char *s;
    int rc;

    start = get_smbios_data(&l);
    if (!start)
        return;
    end = start + l;

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

static int
smbios_callback(char *buf, size_t len, void *priv)
{
    yajl_gen g = (yajl_gen)priv;

    SET_BASE64_ELEM((unsigned char *)buf, len);

    return 0;
}

#define SMC_ITERATE_ALL
int
smc_iterate(yajl_gen g)
{
    extern io_connect_t conn;

#ifdef SMC_ITERATE_ALL
    SMCKeyData_t  inputStructure;
    SMCKeyData_t  outputStructure;
    int           totalKeys;
#endif

    int           i, ret;
    UInt32Char_t  key;
    SMCVal_t      val;

    ret = smc_open(&conn);
    if (ret) {
        fprintf(stderr, "Failed to smc_open; giving up.\n");
        goto error0;
    }

#ifdef SMC_ITERATE_ALL
    totalKeys = smc_readindexcount();
    for (i = 0; i < totalKeys; i++)
    {
        memset(&inputStructure, 0, sizeof(SMCKeyData_t));
        memset(&outputStructure, 0, sizeof(SMCKeyData_t));
        memset(&val, 0, sizeof(SMCVal_t));

        inputStructure.data8 = SMC_CMD_READ_INDEX;
        inputStructure.data32 = i;

        ret = smc_call(KERNEL_INDEX_SMC, &inputStructure, &outputStructure);
        if (ret) {
            fprintf(stderr, "Failed smc_call (ret=%d) on i=%d; continuing.\n", ret, i);
            ret = 0;
            continue;
        }

        _ultostr(key, outputStructure.key);

        ret = smc_readkey(key, &val);
        if (ret) {
            fprintf(stderr, "Failed to smc_readkey (ret=%d) for \"%s\"; giving up.\n", ret, key);
            goto error1;
        } else {
            yajl_gen_map_open(g);
            SET_STR("key", key);
            SET_BASE64("value", (unsigned char *)val.bytes, val.dataSize);
            yajl_gen_map_close(g);
        }
    }
#endif

    //These keys are necessary; for some reason not enumerated by the above, but can be read "manually"
    char * keys[] = {"OSK0", "OSK1", "REV ", "NATJ", "MSSP", "MSSD"};
    int keycount  = 6;
    for (i=0; i<keycount; i++) {
        ret = smc_readkey(keys[i], &val);
        if (ret) {
            fprintf(stderr, "Failed to smc_readkey (ret=%d) for mandatory key \"%s\"; giving up.\n", ret, key);
            ret = -1;
            goto error1;
        } else {
            yajl_gen_map_open(g);
            SET_STR("key", keys[i]);
            SET_BASE64("value", (unsigned char *)val.bytes, val.dataSize);
            yajl_gen_map_close(g);
        }
    }
error1:
    smc_close(conn);
error0:
    return ret;
}

int main(int argc, char **argv)
{
    yajl_gen g;
    const unsigned char *output;
    size_t len;

    g = yajl_gen_alloc(NULL);
    yajl_gen_config(g, yajl_gen_beautify, 1);
    yajl_gen_config(g, yajl_gen_validate_utf8, 0);

    yajl_gen_map_open(g);
    yajl_gen_string(g, (const unsigned char *)"firmware", 8);

    yajl_gen_map_open(g);

    yajl_gen_string(g, (const unsigned char *)"smc", 3);
    yajl_gen_array_open(g);
    if (smc_iterate(g)) {
        fprintf(stderr, "smc iterate failed\n");
        return -1;
    }
    yajl_gen_array_close(g);

    yajl_gen_string(g, (const unsigned char *)"smbios", 6);
    yajl_gen_array_open(g);

    smbios_struct_iterate(smbios_callback, (void *)g);

    yajl_gen_array_close(g);

    yajl_gen_map_close(g);

    yajl_gen_map_close(g);

    yajl_gen_get_buf(g, &output, &len);
    fwrite(output, len, 1, stdout);
    yajl_gen_clear(g);
    yajl_gen_free(g);

    return 0;
}
