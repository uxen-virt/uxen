/*
 * Copyright 2015, Bromium, Inc.
 * SPDX-License-Identifier: ISC
 */

#ifndef _PERFCNT_H_
#define _PERFCNT_H_

#define PERFCNT(id) PERFCNT_ ## id,
#define PERFCNT_ARR(id, len)                                                  \
    PERFCNT_ARR_B_ ## id,                                                     \
    PERFCNT_ARR_E_ ## id =                                                    \
        PERFCNT_ARR_B_ ## id + (len) - sizeof(char[2 * !!(len) - 1]),
#define PERFCNT_ARR_ITEM(id, aid)
#define PERFCNT_ARR_ITEM_NAME(id, aid, name)

enum {
    #include "perfcnt_defs.h"
    PERFCNT_MAX
};

#undef PERFCNT
#define PERFCNT(id)
#undef PERFCNT_ARR
#define PERFCNT_ARR(id, len)
#undef PERFCNT_ARR_ITEM
#define PERFCNT_ARR_ITEM(id, aid) PERFCNT_ARR_ITEM_ID_ ## id ## _AID_ ## aid,
#undef PERFCNT_ARR_ITEM_NAME
#define PERFCNT_ARR_ITEM_NAME(id, aid, name) PERFCNT_ARR_ITEM_ID_ ## id ## _AID_ ## aid,

enum {
    #include "perfcnt_defs.h"
    PERFCNT_ARR_ITEM_MAX
};

extern unsigned __int64 perfcnt[PERFCNT_MAX];

#define perfcnt_inc(id) (perfcnt[PERFCNT_ ## id]++)
#define perfcnt_dec(id) (perfcnt[PERFCNT_ ## id]--)
#define perfcnt_add(id, v) (perfcnt[PERFCNT_ ## id] += (v))
#define perfcnt_sub(id, v) (perfcnt[PERFCNT_ ## id] -= (v))
#define perfcnt_set(id, v) (perfcnt[PERFCNT_ ## id] = (v))
#define perfcnt_get(id) (perfcnt[PERFCNT_ ## id])

#define perfcnt_inc_if(id, e) ((e) ? perfcnt[PERFCNT_ ## id]++ : 0)
#define perfcnt_dec_if(id, e) ((e) ? perfcnt[PERFCNT_ ## id]-- : 0)
#define perfcnt_add_if(id, v, e) ((e) ? perfcnt[PERFCNT_ ## id] += (v) : 0)
#define perfcnt_sub_if(id, v, e) ((e) ? perfcnt[PERFCNT_ ## id] -= (v) : 0)
#define perfcnt_set_if(id, v, e) ((e) ? perfcnt[PERFCNT_ ## id] = (v) : 0)
#define perfcnt_set_max(id, v)                                                \
    ((v) > perfcnt[PERFCNT_ ## id] ? perfcnt[PERFCNT_ ## id] = (v) : 0)

#define perfcnt_arr_inc(id, aid)                                              \
    ((aid) >= 0 && (aid) <= (PERFCNT_ARR_E_ ## id - PERFCNT_ARR_B_ ## id) ?   \
    perfcnt[PERFCNT_ARR_B_ ## id + (aid)]++ : 0)
#define perfcnt_arr_dec(id, aid)                                              \
    ((aid) >= 0 && (aid) <= (PERFCNT_ARR_E_ ## id - PERFCNT_ARR_B_ ## id) ?   \
    perfcnt[PERFCNT_ARR_B_ ## id + (aid)]-- : 0)
#define perfcnt_arr_add(id, aid, v)                                           \
    ((aid) >= 0 && (aid) <= (PERFCNT_ARR_E_ ## id - PERFCNT_ARR_B_ ## id) ?   \
    (perfcnt[PERFCNT_ARR_B_ ## id + (aid)] += (v)) : 0)
#define perfcnt_arr_sub(id, aid, v)                                           \
    ((aid) >= 0 && (aid) <= (PERFCNT_ARR_E_ ## id - PERFCNT_ARR_B_ ## id) ?   \
    (perfcnt[PERFCNT_ARR_B_ ## id + (aid)] -= (v)) : 0)
#define perfcnt_arr_set(id, aid, v)                                           \
    ((aid) >= 0 && (aid) <= (PERFCNT_ARR_E_ ## id - PERFCNT_ARR_B_ ## id) ?   \
    (perfcnt[PERFCNT_ARR_B_ ## id + (aid)] = (v)) : (unsigned __int64)-1)
#define perfcnt_arr_get(id, aid)                                              \
    ((aid) >= 0 && (aid) <= (PERFCNT_ARR_E_ ## id - PERFCNT_ARR_B_ ## id) ?   \
    (perfcnt[PERFCNT_ARR_B_ ## id + (aid)]) : (unsigned __int64)-1)

#define perfcnt_arr_add_if(id, aid, v, e)                                     \
    ((e) && (aid) >= 0 &&                                                     \
    (aid) <= (PERFCNT_ARR_E_ ## id - PERFCNT_ARR_B_ ## id) ?                  \
    (perfcnt[PERFCNT_ARR_B_ ## id + (aid)] += (v)) : 0)
#define perfcnt_arr_set_max(id, aid, v)                                       \
    ((aid) >= 0 && (aid) <= (PERFCNT_ARR_E_ ## id - PERFCNT_ARR_B_ ## id) &&  \
    (v) > perfcnt[PERFCNT_ARR_B_ ## id + (aid)] ?                             \
    perfcnt[PERFCNT_ARR_B_ ## id + (aid)] = (v) : 0)

void perfcnt_dump(ULONG log_lvl, char *prefix, unsigned __int64 ignore_arr_val);

#endif  /* _PERFCNT_H_ */
