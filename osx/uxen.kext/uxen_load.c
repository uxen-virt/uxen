/*
 *  uxen_load.c
 *  uxen
 *
 * Copyright 2012-2018, Bromium, Inc.
 * Author: Julian Pidancet <julian@pidancet.net>
 * SPDX-License-Identifier: ISC
 * 
 */

#include "uxen.h"

#include <sys/errno.h>
#include <libkern/libkern.h>
#include <mach/vm_map.h>

#define UXEN_DEFINE_SYMBOLS_CODE
#include <uxen/uxen_link.h>
UXEN_GET_SYMS(uxen_get_symbols, _)
UXEN_CLEAR_SYMS(uxen_clear_symbols)

extern kmod_info_t KMOD_INFO_NAME;

int
uxen_load_symbols(void)
{
    int ret;
    const char *missing_symbol;

    ret = uxen_get_symbols(NULL, NULL, &missing_symbol);
    if (ret != 0) {
        fail_msg("uxen get symbol %s failed: %d", missing_symbol, ret);
	ret = EINVAL;
	goto error;
    }

 error:
    return ret;
}

int
uxen_unload(void)
{
    uxen_driver_shutdown_v4v_service();

    uxen_complete_shutdown();

    uxen_op_init_free_allocs();

    uxen_clear_symbols();

    dprintk("uxen_unload done\n");

    return 0;
}


