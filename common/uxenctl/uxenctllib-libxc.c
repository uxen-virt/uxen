/*
 *  uxenctllib.c
 *  uxen
 *
 * Copyright 2015, Bromium, Inc.
 * Author: Christian Limpach <Christian.Limpach@gmail.com>
 * SPDX-License-Identifier: ISC
 *
 */

#if defined(_WIN32)
#define ERR_WINDOWS
#define ERR_NO_PROGNAME
#define ERR_STDERR _uxenctllib_stderr
#endif
#include <err.h>

#include "uxenctllib.h"
#include "uxenctllib-libxc.h"
#include <xenctrl.h>

static xc_interface *xc_handle = NULL;

static inline int
check_xc_handle(UXEN_HANDLE_T h)
{
    int ret = 0;

    if (!xc_handle) {
        xc_handle = xc_interface_open(NULL, NULL, XC_OPENFLAG_DUMMY, NULL);
        if (xc_handle)
            ret = xc_interface_set_handle(xc_handle, (uintptr_t)h);
    }
    return ret;
}

int
uxen_physinfo(UXEN_HANDLE_T h, uxen_physinfo_t *up)
{
    int ret;

    ret = check_xc_handle(h);
    if (ret)
        return ret;

    return xc_physinfo(xc_handle, (xc_physinfo_t *)up);
}
