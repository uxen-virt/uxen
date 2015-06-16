/*
 * Copyright 2015, Bromium, Inc.
 * SPDX-License-Identifier: ISC
 */

#ifndef _COMPILER_H_
#define _COMPILER_H_

#define ___CONCAT_EXPAND(a, b) a##b
#define __CONCAT_EXPAND(a, b) ___CONCAT_EXPAND(a, b)
#ifdef __COUNTER__
# define BUILD_ASSERT(e) \
    enum { __CONCAT_EXPAND(__build_assert, __COUNTER__) = 1 / ((int)(e)) }
#else
# define BUILD_ASSERT(e) \
    enum { __CONCAT_EXPAND(__build_assert, __LINE__) = 1 / ((int)(e)) }
#endif

#define BUILD_ASSERT_SIZEOF(s, v)   BUILD_ASSERT(sizeof(s) == (v))
#define BUILD_ASSERT_SIZEOF_X(s, v) BUILD_ASSERT((sizeof(s) % (v)) == 0)

#endif /* _COMPILER_H_ */
