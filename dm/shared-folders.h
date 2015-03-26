/*
 * Copyright 2015, Bromium, Inc.
 * SPDX-License-Identifier: ISC
 */

#ifndef __SHARED_FOLDERS_H_
#define __SHARED_FOLDERS_H_

int sf_parse_config(yajl_val config);
int sf_service_start(void);
void sf_service_stop(void);

#endif
