/*
 * Copyright 2013-2015, Bromium, Inc.
 * SPDX-License-Identifier: ISC
 */

#include <windows.h>
#include <iphlpapi.h>

#define ANY_ROUTABLE_ADDRESS 0x08080808

DWORD get_default_route(void)
{
    int tryagain = 120;

    while (tryagain--) {
        MIB_IPFORWARDROW r;

        GetBestRoute(ANY_ROUTABLE_ADDRESS, 0, &r);
        if (r.dwForwardNextHop)
            return r.dwForwardNextHop;

        Sleep(500);
    }

    return 0;
}
