/*
 * Copyright 2016, Bromium, Inc.
 * Author: Piotr Foltyn <piotr.foltyn@gmail.com>
 * SPDX-License-Identifier: ISC
 */

#ifndef _DM_FEATURES_H_
#define _DM_FEATURES_H_

#include <stdint.h>

union dm_features {
    struct {
        uint64_t run_patcher : 1;
        uint64_t reserved : 63;
    } bits;
    uint64_t blob;
};

#endif // _DM_FEATURES_H_
