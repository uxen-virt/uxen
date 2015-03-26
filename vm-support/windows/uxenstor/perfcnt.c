/*
 * Copyright 2015, Bromium, Inc.
 * SPDX-License-Identifier: ISC
 */

#include "uxenstor.h"
#include "perfcnt.h"

#undef PERFCNT
#define PERFCNT(id)
#undef PERFCNT_ARR
#define PERFCNT_ARR(id, len) + ((len) - 1)
#undef PERFCNT_ARR_ITEM
#define PERFCNT_ARR_ITEM(id, aid)
#undef PERFCNT_ARR_ITEM_NAME
#define PERFCNT_ARR_ITEM_NAME(id, aid, name)

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
    {-1, -1, NULL}
};

unsigned __int64 perfcnt[PERFCNT_MAX];

static
char * perfcnt_arr_item_name(int id, int aid)
{
    int i;

    for (i = 0; i < ARRAYSIZE(perfcnt_arr_items); i++)
        if (perfcnt_arr_items[i].id == id && perfcnt_arr_items[i].aid == aid)
            break;

    return i == ARRAYSIZE(perfcnt_arr_items) ? NULL : perfcnt_arr_items[i].name;
}

void perfcnt_dump(ULONG log_lvl, char *prefix, unsigned __int64 ignore_arr_val)
{
    int i, j, d;
    char *n = NULL;
    __int64 total;

    uxen_printk(log_lvl, "Dumping [%s] counters", __DRV_NAME__);
    d = 0;
    for (i = 0; i < ARRAYSIZE(perfcnt_desc); i++) {
        if (perfcnt_desc[i].arr_len > 0) {
            total = 0;
            for (j = 0; j < perfcnt_desc[i].arr_len; j++) 
                total += perfcnt[d + j];
            uxen_printk(log_lvl, "%s%d. %s = %I64d",
                        prefix, i, perfcnt_desc[i].name, total);
            for (j = 0; j < perfcnt_desc[i].arr_len; j++) 
                if (perfcnt[d + j] != ignore_arr_val) {
                    n = perfcnt_arr_item_name(perfcnt_desc[i].id, j);
                    if (n)
                        uxen_printk(log_lvl, "%s%s%s:0x%x = %I64d", 
                                    prefix, prefix, n, j, perfcnt[d + j]);
                    else 
                        uxen_printk(log_lvl, "%s%s%d = %I64d",
                                    prefix, prefix, j, perfcnt[d + j]);
                }
            d += perfcnt_desc[i].arr_len;
        } else {
            uxen_printk(log_lvl, "%s%d. %s = %I64d", 
                        prefix, i, perfcnt_desc[i].name, perfcnt[d]);
            d++;
        }
    }
}
