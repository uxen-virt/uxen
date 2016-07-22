/*
 * Copyright 2012-2016, Bromium, Inc.
 * Author: Christian Limpach <Christian.Limpach@gmail.com>
 * SPDX-License-Identifier: ISC
 */

#ifndef _OS_H_
#define _OS_H_

#define UXEN_PAGE_SHIFT 12
#define UXEN_PAGE_SIZE (1UL << UXEN_PAGE_SHIFT)
#define UXEN_PAGE_MASK (~(UXEN_PAGE_SIZE - 1))

#ifdef PAGE_SHIFT
#undef PAGE_SHIFT
#endif  /* PAGE_SHIFT */
#define PAGE_SHIFT UXEN_PAGE_SHIFT
#ifdef PAGE_SIZE
#undef PAGE_SIZE
#endif  /* PAGE_SIZE */
#define PAGE_SIZE UXEN_PAGE_SIZE
#ifdef PAGE_MASK
#undef PAGE_MASK
#endif  /* PAGE_MASK */
#define PAGE_MASK UXEN_PAGE_MASK

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
