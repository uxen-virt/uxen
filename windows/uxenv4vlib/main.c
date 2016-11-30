/* uxenvmlib: main.c */
/*
 * Copyright 2015-2017, Bromium, Inc.
 * SPDX-License-Identifier: ISC
 */

#include "uxenv4vlib_private.h"


/*
    DllInitialize()

    The routine must exist or the system can't keep track of the
    number of references to this driver, and then won't allow it
    to unload.
*/

NTSTATUS
DllInitialize (PUNICODE_STRING RegistryPath)
{
    static unsigned int calls = 0;
    static unsigned int initted = 0 ;

    RegistryPath;

    ExInitializeDriverRuntime(DrvRtPoolNxOptIn);

    //uxen_msg("uxenvmlib!DllInitialize() called %u time(s)", calls);
    calls++;

    if (!initted) {
        uxen_v4v_init_shared();
        initted++;
    }

    return STATUS_SUCCESS;
}

/*
    DllUnload()

    This routine must return STATUS_SUCCESS or the system will not
    unload the driver/library.
*/

NTSTATUS
DllUnload (void)
{
    static unsigned int calls = 0;

    //uxen_msg("uxenvmlib!DllUnload() called %u time(s)", calls);

    calls++;

    return STATUS_SUCCESS;
}

/*
    DriverEntry()

    This is never called.  It has to exist, however, in order to
    satisfy the build environment (WDK Build).
*/

NTSTATUS
DriverEntry (DRIVER_OBJECT *Driver, UNICODE_STRING *ServicesKey)
{
    Driver;
    ServicesKey;

    ExInitializeDriverRuntime(DrvRtPoolNxOptIn);

    return STATUS_SUCCESS;
}

/* uxenvmlib: main.c */
