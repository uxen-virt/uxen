/*
 * Copyright 2013-2015, Bromium, Inc.
 * SPDX-License-Identifier: ISC
 */

/*  uxenplatform: balloon.h */

#ifndef _BALLOON_H_
#define _BALLOON_H_

#include <wdm.h>
#include <aux_klib.h>

#include "uxenvmlib.h"

#include <xen/xen.h>
#define __XEN_TOOLS__
#include <xen/xen.h>
#include <xen/memory.h>

__drv_requiresIRQL(PASSIVE_LEVEL)
__drv_sameIRQL
__checkReturn
NTSTATUS
balloon_cleanup(void);

__drv_sameIRQL
__checkReturn
BOOLEAN
balloon_enabled(void);

__drv_maxIRQL(APC_LEVEL)
__drv_sameIRQL
__checkReturn
NTSTATUS
balloon_get_configuration(
    __out struct uxen_platform_balloon_configuration * const configuration
    );

__drv_maxIRQL(APC_LEVEL)
__drv_sameIRQL
__checkReturn
NTSTATUS
balloon_get_statistics(
    __out struct uxen_platform_balloon_statistics * const statistics
    );

__drv_maxIRQL(APC_LEVEL)
__drv_sameIRQL
__checkReturn
NTSTATUS
balloon_init(void);

__drv_maxIRQL(APC_LEVEL)
__drv_sameIRQL
__checkReturn
NTSTATUS
balloon_set_configuration(
    __in const struct uxen_platform_balloon_configuration * const configuration
    );

#endif  /* #ifdef _BALLOON_H_ */

/*  uxenplatform: balloon.h */
