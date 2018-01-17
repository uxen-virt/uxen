/*
 *  uxen_load.c
 *  uxen
 *
 * Copyright 2011-2018, Bromium, Inc.
 * Author: Christian Limpach <Christian.Limpach@gmail.com>
 * SPDX-License-Identifier: ISC
 * 
 */

#include "uxen.h"

#include <ntddk.h>
#include <stdio.h>
#include <xen/errno.h>
#include <xen/types.h>

#include <uxen_ioctl.h>

#define UXEN_DEFINE_SYMBOLS_CODE
#include <uxen/uxen_link.h>
#ifdef __x86_64__
UXEN_GET_SYMS(uxen_get_symbols, _)
#else  /* __x86_64__ */
UXEN_GET_SYMS(uxen_get_symbols, )
#endif  /* __x86_64__ */
UXEN_CLEAR_SYMS(uxen_clear_symbols)

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

    uxen_complete_shutdown();

    uxen_op_init_free_allocs();

    uxen_clear_symbols();

    return 0;
}
