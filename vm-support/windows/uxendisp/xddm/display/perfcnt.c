/*
 * Copyright 2015, Bromium, Inc.
 * Author: Julian Pidancet <julian@pidancet.net>
 * SPDX-License-Identifier: ISC
 */

#include "driver.h"

#if PERFCNT_ENABLED

#include "perfcnt.h"

#undef PERFCNT
#define PERFCNT(id)
#undef PERFCNT_ARR
#define PERFCNT_ARR(id, len) + ((len) - 1)
#undef PERFCNT_ARR_ITEM
#define PERFCNT_ARR_ITEM(id, aid)
#undef PERFCNT_ARR_ITEM_NAME
#define PERFCNT_ARR_ITEM_NAME(id, aid, name)
#undef PERFCNT_END
#define PERFCNT_END + 0

static
struct {
    int arr_len;
    int id;
    char *name;
} perfcnt_desc[PERFCNT_MAX - (
    #include "perfcnt_defs.h"
)] = {
    #undef PERFCNT
    #define PERFCNT(id) {0, PERFCNT_ ## id, # id},
    #undef PERFCNT_ARR
    #define PERFCNT_ARR(id, len) {len, PERFCNT_ARR_B_ ## id, # id},
    #undef PERFCNT_END
    #define PERFCNT_END

    #include "perfcnt_defs.h"
};

#undef PERFCNT
#define PERFCNT(id)
#undef PERFCNT_ARR
#define PERFCNT_ARR(id, len)
#undef PERFCNT_ARR_ITEM
#define PERFCNT_ARR_ITEM(id, aid) {PERFCNT_ARR_B_ ## id, aid, # aid},
#undef PERFCNT_ARR_ITEM_NAME
#define PERFCNT_ARR_ITEM_NAME(id, aid, name) {PERFCNT_ARR_B_ ## id, aid, name},

static 
struct {
    int id;
    int aid;
    char *name;
} perfcnt_arr_items[PERFCNT_ARR_ITEM_MAX + 1] = {
    #include "perfcnt_defs.h"
    {-1, -1, 0}
};

unsigned __int64 perfcnt[PERFCNT_MAX];

#endif