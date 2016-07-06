/*
 * Copyright 2016, Bromium, Inc.
 * SPDX-License-Identifier: ISC
 */

#ifndef _DEFENSIVE_H_
#define _DEFENSIVE_H_

#include "compiler.h"

#include <string.h>
#define SANE_SIZE_T 0x26021975UL

#define FORCED_INLINE extern inline __attribute__((always_inline))      \
    __attribute__((gnu_inline))

FORCED_INLINE void *memcpy_sane(void * dest, const void *src, size_t size)
{
    return memcpy(dest, src, ASSERT_ARG(size, ARG < SANE_SIZE_T));
}

FORCED_INLINE void *memset_sane( void * ptr, int value, size_t size)
{
    return memset(ptr, value, ASSERT_ARG(size, ARG < SANE_SIZE_T));
}

FORCED_INLINE void *memmove_sane(void * dest, const void *src, size_t size)
{
    return memmove(dest, src, ASSERT_ARG(size, ARG < SANE_SIZE_T));
}

#ifdef memcpy
#undef memcpy
#endif
#define memcpy memcpy_sane
#ifdef memset
#undef memset
#endif
#define memset  memset_sane
#ifdef memmove
#undef memmove
#endif
#define memmove memmove_sane

#ifdef CONFIG_CHECK_NAME
unsigned char __CONCAT_EXPAND(defensive_check_, CONFIG_CHECK_NAME);
#endif /* CONFIG_CHECK_NAME */

#endif  /* _DEFENSIVE_H_ */
