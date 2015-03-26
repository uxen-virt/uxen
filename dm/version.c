/*
 * Copyright 2013-2015, Bromium, Inc.
 * Author: Christian Limpach <Christian.Limpach@gmail.com>
 * SPDX-License-Identifier: ISC
 */

#include "config.h"

#include "debug.h"

#include "build_info.h"

void
log_version(void)
{

    debug_printf("dm changeset: " UXEN_DM_CHANGESET "\n");
    debug_printf("dm built on:  " UXEN_DM_BUILDDATE "\n");
}
