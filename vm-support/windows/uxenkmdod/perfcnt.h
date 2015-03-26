/*
 * Copyright 2014-2015, Bromium, Inc.
 * Author: Kris Uchronski <kuchronski@gmail.com>
 * SPDX-License-Identifier: ISC
 */

#ifndef _PERFCNT_H_
#define _PERFCNT_H_

#define PERFCNT(id) PERFCNT_ ## id,

enum {
#include "perfcnt_defs.h"
    PERFCNT_MAX
};

extern __int64 perfcnt[PERFCNT_MAX];

#define perfcnt_inc(id) (perfcnt[PERFCNT_ ## id]++)
#define perfcnt_dec(id) (perfcnt[PERFCNT_ ## id]--)
#define perfcnt_add(id, v) (perfcnt[PERFCNT_ ## id] += v)
#define perfcnt_sub(id, v) (perfcnt[PERFCNT_ ## id] -= v)

#define perfcnt_get(id) (perfcnt[PERFCNT_ ## id])

void perfcnt_dump();

#endif  /* _PERFCNT_H_ */
