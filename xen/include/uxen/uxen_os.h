/*
 *  uxen_os.h
 *  uxen
 *
 * Copyright 2012-2015, Bromium, Inc.
 * Author: Christian Limpach <Christian.Limpach@gmail.com>
 * SPDX-License-Identifier: ISC
 * 
 */

#ifndef _UXEN_OS_H_
#define _UXEN_OS_H_

#ifdef __GNUC__
#define __WINPACKED__ __attribute__ ((aligned (8)))
#ifndef __cdecl
#define __cdecl
#endif
#else
#define __WINPACKED__
#endif

#if 0
#ifndef ASSERT
#define ASSERT(x) assert(x)
#endif
#endif

#endif	/* _UXEN_OS_H_ */
