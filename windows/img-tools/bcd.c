/*
 * Copyright 2011-2015, Bromium, Inc.
 * Author: Gianni Tedesco
 * SPDX-License-Identifier: ISC
 *
 * Boot Configuration Database
 * For Windows Vista and above
 */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "disklib.h"
#include "reghive.h"
#include "bcd.h"

/* Well known object ID's */
#define OBJID_BOOTMGR           "{9dea862c-5cdd-4e70-acc1-f32b344d4795}"

/* Library elements, these are common to all types of objects */
#define LIBRARY_DESCRIPTION     "12000004"

/* Application specific elements for bootmgr */
#define BOOTMGR_APP_DEVICE      "11000001"
#define BOOTMGR_OS_DEVICE       "21000001"
#define BOOTMGR_APP_PATH        "12000002"
#define BOOTMGR_SYSROOT         "22000002"
#define BOOTMGR_DEFAULT_OBJECT  "23000003"

/* Represents a BCD */
struct _bcd {
    rhkey_t b_root;
    rhkey_t b_objects;
    rhkey_t b_bootmgr;
    uint8_t *b_app_device;
    size_t b_app_device_sz;
    unsigned int b_ref;
};

/* Represents a bootmgr object */
struct _bootmgr {
    struct _bcd *bm_owner;
    rhkey_t bm_obj;
    char *bm_desc;
    char *bm_sysroot;
    char *bm_app_path;
    uint8_t *bm_app_device;
    uint8_t *bm_os_device;
    size_t bm_app_device_sz;
    size_t bm_os_device_sz;
};

/* rip a string element from an object given a handle to its "Elements" key */
static char *element_str(rhkey_t key, const char *val)
{
    unsigned int type;
    size_t sz;
    char *str;

    if ( !reghive_get_value(key, val, "Element", NULL, &sz, &type) )
        return NULL;

    if ( type != REG_SZ )
        return NULL;

    str = RTMemAlloc(sz);
    if ( NULL == str )
        return NULL;

    if ( !reghive_get_value(key, val, "Element", (uint8_t *)str, &sz, &type) ) {
        RTMemFree(str);
        return NULL;
    }

    return str;
}

/* rip a binary element from an object given a handle to its "Elements" key */
static uint8_t *element_bin(rhkey_t key, const char *val, size_t *sz)
{
    unsigned int type;
    uint8_t *bin;

    if ( !reghive_get_value(key, val, "Element", NULL, sz, &type) )
        return NULL;

    if ( type != REG_BINARY )
        return NULL;

    bin = RTMemAlloc(*sz);
    if ( NULL == bin )
        return NULL;

    if ( !reghive_get_value(key, val, "Element", bin, sz, &type) ) {
        RTMemFree(bin);
        return NULL;
    }

    return bin;
}

const uint8_t *bcd_app_device(bcd_t bcd, size_t *sz)
{
    *sz = bcd->b_app_device_sz;
    return bcd->b_app_device;
}

/* key should be an open rehive found in /boot/bcd on the active partition */
bcd_t bcd_open(rhkey_t key)
{
    struct _bcd *bcd;

    bcd = RTMemAllocZ(sizeof(*bcd));
    if ( NULL == bcd )
        goto out;

    bcd->b_root = key;
    if ( !reghive_open_key(bcd->b_root, "Objects", &bcd->b_objects) )
        goto out_free;

    /* open the bootmgr object */
    if ( !reghive_open_key(bcd->b_objects,
                            OBJID_BOOTMGR "\\Elements",
                            &bcd->b_bootmgr) ) {
        goto out_close_obj;
    }

    bcd->b_app_device = element_bin(bcd->b_bootmgr, BOOTMGR_APP_DEVICE,
                                      &bcd->b_app_device_sz);
    /* success */
    bcd->b_ref = 1;
    goto out;

out_close_obj:
    reghive_close_key(bcd->b_objects);
out_free:
    RTMemFree(bcd);
    bcd = NULL;
out:
    return bcd;
}

/* We refcount the BCD object so that the objects created by it can
 * outlive it. The only lifetime rule to be aware of is that we can't take
 * a refcount on the root hive key so that can't be closed until all objects
 * referencing it die. Shouldn't be a big problem, if it is we can add
 * a rehive_clone_key() call.
*/
static struct _bcd *bcd_ref(struct _bcd *bcd)
{
    bcd->b_ref++;
    return bcd;
}

static void bcd_unref(struct _bcd *bcd)
{
    --bcd->b_ref;
    if ( 0 == bcd->b_ref ) {
        RTMemFree(bcd->b_app_device);
        reghive_close_key(bcd->b_bootmgr);
        reghive_close_key(bcd->b_objects);
        RTMemFree(bcd);
    }
}

void bcd_close(bcd_t bcd)
{
    if ( bcd ) {
        bcd_unref(bcd);
    }
}

/* return the default bootmgr object, this is the item in the boot menu
 * that will boot by default (ie. with no user input)
 */
bootmgr_t bcd_bootmgr_get_default(bcd_t bcd)
{
    struct _bootmgr *bmgr;
    char *guid;
    char *subkey;

    bmgr = RTMemAllocZ(sizeof(*bmgr));
    if ( NULL == bmgr )
        goto out;

    guid = element_str(bcd->b_bootmgr, BOOTMGR_DEFAULT_OBJECT);
    if ( NULL == guid )
        goto out_free;

    RTStrAPrintf(&subkey, "%s\\Elements", guid);
    if ( !reghive_open_key(bcd->b_objects, subkey, &bmgr->bm_obj) )
        goto out_free_strings;

    RTMemFree(guid);
    RTMemFree(subkey);

    /* rip out the elements we need, this is by no means a comprehensive
     * list. Just the stuff we might feasibly be interested in.
     */
    bmgr->bm_desc = element_str(bmgr->bm_obj, LIBRARY_DESCRIPTION);
    bmgr->bm_sysroot = element_str(bmgr->bm_obj, BOOTMGR_SYSROOT);
    bmgr->bm_app_path = element_str(bmgr->bm_obj, BOOTMGR_APP_PATH);

    bmgr->bm_app_device = element_bin(bmgr->bm_obj, BOOTMGR_APP_DEVICE,
                                      &bmgr->bm_app_device_sz);
    bmgr->bm_os_device = element_bin(bmgr->bm_obj, BOOTMGR_OS_DEVICE,
                                      &bmgr->bm_os_device_sz);

    /* success */
    bmgr->bm_owner = bcd_ref(bcd);
    goto out;

out_free_strings:
    RTMemFree(subkey);
    RTMemFree(guid);
out_free:
    RTMemFree(bmgr);
    bmgr = NULL;
out:
    return bmgr;
}

void bootmgr_close(bootmgr_t bmgr)
{
    if ( bmgr ) {
        RTMemFree(bmgr->bm_desc);
        RTMemFree(bmgr->bm_sysroot);
        RTMemFree(bmgr->bm_app_path);
        RTMemFree(bmgr->bm_app_device);
        RTMemFree(bmgr->bm_os_device);
        reghive_close_key(bmgr->bm_obj);
        bcd_unref(bmgr->bm_owner);
        RTMemFree(bmgr);
    }
}

const char *bootmgr_description(bootmgr_t bmgr)
{
    return bmgr->bm_desc;
}

const char *bootmgr_sysroot(bootmgr_t bmgr)
{
    return bmgr->bm_sysroot;
}

const char *bootmgr_app_path(bootmgr_t bmgr)
{
    return bmgr->bm_app_path;
}

const uint8_t *bootmgr_app_device(bootmgr_t bmgr, size_t *sz)
{
    *sz = bmgr->bm_app_device_sz;
    return bmgr->bm_app_device;
}

const uint8_t *bootmgr_os_device(bootmgr_t bmgr, size_t *sz)
{
    *sz = bmgr->bm_os_device_sz;
    return bmgr->bm_os_device;
}

bootmgr_t bootmgr_next(bootmgr_t bmgr)
{
    /* TODO */
    return NULL;
}
