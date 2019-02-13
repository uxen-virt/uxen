/*
 * Copyright 2019, Bromium, Inc.
 * SPDX-License-Identifier: ISC
 */

#ifndef _UXENCTLLIB_ARGS_H_
#define _UXENCTLLIB_ARGS_H_

struct uxen_param;

#define WHP_PARAM_NAME "whp"

struct uxen_param *lookup_uxen_param(const char *name);
int assign_string_param(struct uxen_init_desc *uid, struct uxen_param *param,
                        const char *val);
int assign_integer_param(struct uxen_init_desc *uid, struct uxen_param *param,
                         uint64_t val);

#endif

