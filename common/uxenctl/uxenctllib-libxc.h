/*
 *  uxenctllib-libxc.h
 *  uxen
 *
 * Copyright 2015, Bromium, Inc.
 * Author: Christian Limpach <Christian.Limpach@gmail.com>
 * SPDX-License-Identifier: ISC
 *
 */

#ifndef _UXENCTLLIB_LIBXC_H_
#define _UXENCTLLIB_LIBXC_H_

#include <xen/sysctl.h>

typedef xen_sysctl_physinfo_t uxen_physinfo_t;

int uxen_physinfo(UXEN_HANDLE_T h, uxen_physinfo_t *up);

#endif  /* _UXENCTLLIB_LIBXC_H_ */
