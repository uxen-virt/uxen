/*
 * Copyright 2013-2015, Bromium, Inc.
 * SPDX-License-Identifier: ISC
 */

#ifndef _UXEN_TYPES_H_
#define _UXEN_TYPES_H_

typedef __int8 int8_t;
typedef unsigned __int8 uint8_t;
typedef __int16 int16_t;
typedef unsigned __int16 uint16_t;
typedef __int32 int32_t;
typedef unsigned __int32 uint32_t;
typedef __int64 int64_t;
typedef unsigned __int64 uint64_t;
#ifdef _M_AMD64
typedef __int64 intptr_t;
typedef unsigned __int64 uintptr_t;
#else
typedef __int32 intptr_t;
typedef unsigned __int32 uintptr_t;
#endif

#endif	/* _UXEN_TYPES_H_ */
