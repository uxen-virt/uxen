/*
 * Copyright 2014-2015, Bromium, Inc.
 * Author: Kris Uchronski <kuchronski@gmail.com>
 * SPDX-License-Identifier: ISC
 */

#include "bdd.hxx"
#include "perfcnt.h"

#undef PERFCNT
#define PERFCNT(id) {# id},

static struct {
    const char *name;
} perfcnt_desc[PERFCNT_MAX] = {
#include "perfcnt_defs.h"
};

__int64 perfcnt[PERFCNT_MAX];

void perfcnt_dump()
{
    int i;

    for (i = 0; i < ARRAYSIZE(perfcnt_desc); i++)
        uxen_msg("%d. %s: %I64d", i, perfcnt_desc[i].name, perfcnt[i]);
}
