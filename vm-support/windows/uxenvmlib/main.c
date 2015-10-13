/*
 * Copyright 2013-2015, Bromium, Inc.
 * SPDX-License-Identifier: ISC
 */

/* uxenvmlib: main.c */

#include <ntddk.h>

#include "../common/debug.h"
#include "../common/version.h"

/*
    DllInitialize()

    The routine must exist or the system can't keep track of the
    number of references to this driver, and then won't allow it
    to unload.
*/

NTSTATUS
DllInitialize(PUNICODE_STRING  RegistryPath)
{
    static unsigned int calls  = 0;
    
    RegistryPath;

    uxen_msg("uxenvmlib!DllInitialize() called %u time(s) version: %s", calls,
            UXEN_DRIVER_VERSION_CHANGESET);
    calls++;

    return STATUS_SUCCESS;
}

/*
    DllUnload()

    This routine must return STATUS_SUCCESS or the system will not
    unload the driver/library.
*/

NTSTATUS
DllUnload(void)
{
    static unsigned int calls = 0;

    uxen_msg("uxenvmlib!DllUnload() called %u time(s)", calls);

    calls++;

    return STATUS_SUCCESS;
}

/*
    DriverEntry()

    This is never called.  It has to exist, however, in order to
    satisfy the build environment (WDK Build).
*/

NTSTATUS
DriverEntry(DRIVER_OBJECT * Driver, UNICODE_STRING * ServicesKey)
{
    Driver;
    ServicesKey;

    return STATUS_SUCCESS;
}

/* uxenvmlib: main.c */
