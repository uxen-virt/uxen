/*
 * Copyright 2012-2015, Bromium, Inc.
 * Author: Christian Limpach <Christian.Limpach@gmail.com>
 * SPDX-License-Identifier: ISC
 */

#ifndef _OS_H_
#define _OS_H_

#define UXEN_PAGE_SHIFT 12
#define UXEN_PAGE_SIZE (1UL << UXEN_PAGE_SHIFT)
#define UXEN_PAGE_MASK (~(UXEN_PAGE_SIZE - 1))

#if defined(_WIN32)
#include "win32.h"
#elif defined(__APPLE__)
#include "osx.h"
#endif

int get_timeoffset(void);

#ifndef ENOMEDIUM
#define ENOMEDIUM ENODEV
#endif

#endif	/* _OS_H_ */
